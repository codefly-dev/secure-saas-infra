import type { NetworkConfig, SpokeKind } from "../../config";
import {
  CloudAdapter,
  PlatformBlueprint,
  PlatformCapability,
  compileBlueprint,
  platformTenantScope,
} from "../../core";

export interface AwsNetworkBlueprintOptions {
  name: string;
  environment: string;
  requireInspectedEgress: boolean;
}

export interface AwsNetworkAdapterOptions {
  shareTransitGatewayWithOrganization: boolean;
  createEksByZoneId: Readonly<Record<string, boolean>>;
  spokeKindByZoneId: Readonly<Record<string, SpokeKind>>;
}

export interface AwsNetworkPlan {
  cloud: "aws";
  networkConfig: NetworkConfig;
  egress: { zoneId: string; networkDomainId: string };
  zoneToSpokeName: Readonly<Record<string, string>>;
  spokes: readonly AwsSpokeNetworkPlan[];
  routeTableIntents: readonly AwsRouteTableIntent[];
}

export interface AwsSpokeNetworkPlan {
  zoneId: string;
  networkDomainId: string;
  name: string;
  kind: SpokeKind;
  cidr: string;
  availabilityZoneCount: number;
  directInternetAccess: false;
}

export interface AwsRouteTableIntent {
  id: string;
  zoneId: string;
  routeTableRole: "spoke-private" | "egress-return";
  destinationCidr: string;
  target: "transit-gateway" | "spoke-attachment";
}

const capabilities = new Set<PlatformCapability>([
  "private-network",
  "centralized-egress",
  "managed-firewall",
  "private-control-plane",
  "workload-identity",
  "customer-managed-encryption",
  "immutable-audit-log",
  "dedicated-account-boundary",
  "microvm-runtime",
  "external-sandbox",
]);

export function blueprintFromAwsNetworkConfig(
  config: NetworkConfig,
  options: AwsNetworkBlueprintOptions,
): PlatformBlueprint {
  const externalZoneId = "zone:external-internet";
  const egressZoneId = "zone:central-egress";
  const spokeZoneIds = Object.fromEntries(
    config.spokes.map((spoke) => [spoke.name, `zone:${spoke.name}`]),
  );

  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: options.name,
    environment: options.environment,
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: options.requireInspectedEgress,
      requireImmutableAudit: false,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: [
      "private-network",
      "centralized-egress",
      ...(options.requireInspectedEgress
        ? (["managed-firewall"] as const)
        : []),
    ],
    trustZones: [
      {
        id: externalZoneId,
        kind: "external",
        publicAccess: true,
        tenantScope: platformTenantScope(),
      },
      {
        id: egressZoneId,
        kind: "egress",
        publicAccess: true,
        tenantScope: platformTenantScope(),
        isolationBoundary: "network-account",
      },
      ...config.spokes.map(
        (spoke) =>
          ({
            id: spokeZoneIds[spoke.name],
            kind: zoneKind(spoke.kind),
            publicAccess: false,
            tenantScope: platformTenantScope(),
            isolationBoundary: `${spoke.kind}-account`,
          }) as const,
      ),
    ],
    networkDomains: [
      {
        id: "network:central-egress",
        zoneId: egressZoneId,
        cidrs: [config.egress.cidr],
        availabilityZoneCount: config.egress.azCount,
        directInternetAccess: true,
        inspectedEgress: config.egress.networkFirewallEnabled,
      },
      ...config.spokes.map((spoke) => ({
        id: `network:${spoke.name}`,
        zoneId: spokeZoneIds[spoke.name],
        cidrs: [spoke.cidr],
        availabilityZoneCount: config.egress.azCount,
        directInternetAccess: false,
        inspectedEgress: false,
      })),
    ],
    flows: config.spokes.map((spoke) => ({
      id: `flow:${spoke.name}:internet`,
      fromZoneId: spokeZoneIds[spoke.name],
      toZoneId: externalZoneId,
      protocol: "https",
      ports: [443],
      purpose:
        "Allow approved outbound dependencies through centralized egress.",
      authorization: spoke.kind === "execution" ? "brokered" : "direct",
      viaZoneIds: [egressZoneId],
      externalDestinations: config.egress.allowedDomains,
    })),
    workloadPlanes: [],
    applications: [],
    tenants: [],
    dataBoundaries: [],
    identities: [],
    identityDelegations: [],
    grants: [],
    evidenceSinks: [],
    evidenceRequirements: [],
  };
}

export class AwsNetworkAdapter implements CloudAdapter<AwsNetworkPlan> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-network",
    capabilities,
  };

  constructor(private readonly options: AwsNetworkAdapterOptions) {}

  compile(blueprint: PlatformBlueprint): AwsNetworkPlan {
    const egressDomains = blueprint.networkDomains.filter(
      (domain) =>
        blueprint.trustZones.find((zone) => zone.id === domain.zoneId)?.kind ===
        "egress",
    );
    if (egressDomains.length !== 1) {
      throw new Error(
        "AWS network adapter requires exactly one central egress network domain.",
      );
    }

    const egress = egressDomains[0];
    if (egress.cidrs.length !== 1) {
      throw new Error(
        "AWS network adapter currently requires one IPv4 CIDR per network domain.",
      );
    }

    const externalZoneIds = new Set(
      blueprint.trustZones
        .filter((zone) => zone.kind === "external")
        .map((zone) => zone.id),
    );
    const allowedDomains = new Set(
      blueprint.flows
        .filter((flow) => externalZoneIds.has(flow.toZoneId))
        .flatMap((flow) => flow.externalDestinations ?? []),
    );

    const zoneToSpokeName: Record<string, string> = {};
    const spokePlans: AwsSpokeNetworkPlan[] = [];
    const spokes = blueprint.networkDomains
      .filter((domain) => domain.id !== egress.id)
      .map((domain) => {
        if (domain.cidrs.length !== 1) {
          throw new Error(
            `AWS network domain '${domain.id}' must declare exactly one IPv4 CIDR.`,
          );
        }
        const zone = blueprint.trustZones.find(
          (entry) => entry.id === domain.zoneId,
        );
        if (
          !zone ||
          zone.kind === "external" ||
          zone.kind === "edge" ||
          zone.kind === "egress"
        ) {
          throw new Error(
            `AWS spoke '${domain.id}' must belong to a private workload trust zone.`,
          );
        }
        const name = domain.id.replace(/^network:/, "");
        zoneToSpokeName[domain.zoneId] = name;
        const kind =
          this.options.spokeKindByZoneId[domain.zoneId] ??
          kindFromZone(zone.kind);
        if (domain.directInternetAccess) {
          throw new Error(
            `AWS workload spoke '${domain.id}' cannot compile a direct Internet or NAT path.`,
          );
        }
        spokePlans.push({
          zoneId: domain.zoneId,
          networkDomainId: domain.id,
          name,
          kind,
          cidr: domain.cidrs[0],
          availabilityZoneCount: domain.availabilityZoneCount,
          directInternetAccess: false,
        });
        return {
          name,
          cidr: domain.cidrs[0],
          kind,
          createEks: this.options.createEksByZoneId[domain.zoneId] ?? false,
        };
      });

    return {
      cloud: "aws",
      networkConfig: {
        egress: {
          cidr: egress.cidrs[0],
          azCount: egress.availabilityZoneCount,
          networkFirewallEnabled: egress.inspectedEgress,
          shareTransitGatewayWithOrganization:
            this.options.shareTransitGatewayWithOrganization,
          allowedDomains: [...allowedDomains],
        },
        spokes,
      },
      egress: { zoneId: egress.zoneId, networkDomainId: egress.id },
      zoneToSpokeName,
      spokes: spokePlans,
      routeTableIntents: spokePlans.flatMap((spoke) => [
        {
          id: `route:${spoke.networkDomainId}:default-egress`,
          zoneId: spoke.zoneId,
          routeTableRole: "spoke-private" as const,
          destinationCidr: "0.0.0.0/0",
          target: "transit-gateway" as const,
        },
        {
          id: `route:${spoke.networkDomainId}:return`,
          zoneId: spoke.zoneId,
          routeTableRole: "egress-return" as const,
          destinationCidr: spoke.cidr,
          target: "spoke-attachment" as const,
        },
      ]),
    };
  }
}

export function compileAwsNetworkBlueprint(
  blueprint: PlatformBlueprint,
  options: AwsNetworkAdapterOptions,
): AwsNetworkPlan {
  return compileBlueprint(blueprint, new AwsNetworkAdapter(options));
}

export function requireAwsSpokePlan(
  plan: AwsNetworkPlan,
  zoneId: string,
  networkDomainId: string,
): AwsSpokeNetworkPlan {
  const spoke = plan.spokes.find(
    (entry) =>
      entry.zoneId === zoneId && entry.networkDomainId === networkDomainId,
  );
  if (!spoke) {
    throw new Error(
      `AWS spoke binding '${zoneId}'/'${networkDomainId}' does not match a compiled neutral network domain.`,
    );
  }
  return spoke;
}

export function validateAwsSpokeStackOutputs(
  expected: Pick<AwsSpokeNetworkPlan, "zoneId" | "networkDomainId" | "cidr">,
  actual: { zoneId: string; networkDomainId: string; cidr: string },
): void {
  if (
    actual.zoneId !== expected.zoneId ||
    actual.networkDomainId !== expected.networkDomainId ||
    actual.cidr !== expected.cidr
  ) {
    throw new Error(
      `AWS spoke stack semantic output mismatch: expected zone '${expected.zoneId}', domain '${expected.networkDomainId}', CIDR '${expected.cidr}', received zone '${actual.zoneId}', domain '${actual.networkDomainId}', CIDR '${actual.cidr}'.`,
    );
  }
}

export function validateAndCompileAwsNetwork(
  config: NetworkConfig,
  options: AwsNetworkBlueprintOptions,
): AwsNetworkPlan {
  const blueprint = blueprintFromAwsNetworkConfig(config, options);
  return compileBlueprint(
    blueprint,
    new AwsNetworkAdapter({
      shareTransitGatewayWithOrganization:
        config.egress.shareTransitGatewayWithOrganization ?? false,
      createEksByZoneId: Object.fromEntries(
        config.spokes.map((spoke) => [
          `zone:${spoke.name}`,
          spoke.createEks ?? false,
        ]),
      ),
      spokeKindByZoneId: Object.fromEntries(
        config.spokes.map((spoke) => [`zone:${spoke.name}`, spoke.kind]),
      ),
    }),
  );
}

function zoneKind(kind: SpokeKind) {
  if (kind === "execution") return "execution" as const;
  if (kind === "data") return "data" as const;
  return "workload" as const;
}

function kindFromZone(kind: string): SpokeKind {
  if (kind === "execution") return "execution";
  if (kind === "data") return "data";
  return "platform";
}
