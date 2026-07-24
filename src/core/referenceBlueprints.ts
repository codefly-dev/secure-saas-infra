import {
  DataBoundary,
  Identity,
  IdentityGrant,
  IsolationTier,
  NetworkDomain,
  NetworkFlow,
  PlatformBlueprint,
  TenantPlacement,
  TenantScope,
  TrustZone,
  WorkloadPlane,
} from "./model";

export type ReferenceBlueprintName =
  | "pooled"
  | "dedicated-data"
  | "dedicated-network"
  | "dedicated-account"
  | "e2b-byoc"
  | "microvm-fallback";

const tenantIds = ["tenant-a", "tenant-b"] as const;

export function createReferenceBlueprint(
  name: ReferenceBlueprintName,
): PlatformBlueprint {
  const isolationTier = tierFor(name);
  const microvm = name === "microvm-fallback";
  const dedicatedNetwork =
    isolationTier === "dedicated-network" ||
    isolationTier === "dedicated-account";
  const dedicatedData =
    isolationTier === "dedicated-data" || isolationTier === "dedicated-account";

  const trustZones: TrustZone[] = [
    zone("internet", "external", { mode: "platform" }, true),
    zone("egress", "egress", { mode: "platform" }, true, "network-account"),
    zone(
      "control",
      "control-plane",
      { mode: "platform" },
      false,
      "platform-account",
    ),
  ];
  const networkDomains: NetworkDomain[] = [
    domain("egress-net", "egress", "10.0.0.0/16", true, true),
    domain("control-net", "control", "10.1.0.0/16"),
  ];
  const flows: NetworkFlow[] = [];
  const workloadPlanes: WorkloadPlane[] = [];
  const dataBoundaries: DataBoundary[] = [];
  const identities: Identity[] = [];
  const grants: IdentityGrant[] = [];
  const tenants: TenantPlacement[] = [];

  const sharedScope: TenantScope = { mode: "pooled", tenantIds };
  if (!dedicatedNetwork) {
    trustZones.push(zone("execution-shared", "execution", sharedScope));
    networkDomains.push(
      domain("execution-shared-net", "execution-shared", "10.10.0.0/16"),
    );
    workloadPlanes.push(
      executionPlane(
        "execution-shared-plane",
        "execution-shared",
        sharedScope,
        microvm,
      ),
    );
    flows.push(...executionFlows("execution-shared"));
  }
  if (!dedicatedData) {
    trustZones.push(zone("data-shared", "data", sharedScope));
    networkDomains.push(
      domain("data-shared-net", "data-shared", "10.20.0.0/16"),
    );
    dataBoundaries.push(
      dataBoundary("data-shared-boundary", "data-shared", sharedScope, false),
    );
  }

  tenantIds.forEach((tenantId, index) => {
    const tenantScope: TenantScope = { mode: "dedicated", tenantId };
    const executionZoneId = dedicatedNetwork
      ? `${tenantId}-execution`
      : "execution-shared";
    const dataZoneId = dedicatedData ? `${tenantId}-data-zone` : "data-shared";
    const dataId = dedicatedData ? `${tenantId}-data` : "data-shared-boundary";
    const identityId = `${tenantId}-workload`;

    if (dedicatedNetwork) {
      trustZones.push(
        zone(
          executionZoneId,
          "execution",
          tenantScope,
          false,
          isolationTier === "dedicated-account"
            ? `${tenantId}-account`
            : `${tenantId}-network`,
        ),
      );
      networkDomains.push(
        domain(
          `${tenantId}-execution-net`,
          executionZoneId,
          `10.${30 + index}.0.0/16`,
        ),
      );
      workloadPlanes.push(
        executionPlane(
          `${tenantId}-plane`,
          executionZoneId,
          tenantScope,
          microvm,
        ),
      );
      flows.push(...executionFlows(executionZoneId));
    }

    if (dedicatedData) {
      trustZones.push(
        zone(
          dataZoneId,
          "data",
          tenantScope,
          false,
          isolationTier === "dedicated-account"
            ? `${tenantId}-account`
            : `${tenantId}-data`,
        ),
      );
      networkDomains.push(
        domain(`${tenantId}-data-net`, dataZoneId, `10.${40 + index}.0.0/16`),
      );
      dataBoundaries.push(dataBoundary(dataId, dataZoneId, tenantScope, true));
    }

    identities.push({
      id: identityId,
      kind: "workload",
      tenantId,
      shortLived: true,
    });
    grants.push({
      id: `${tenantId}-data-access`,
      identityId,
      resourceIds: [dataId],
      actions: ["data:read", "data:write"],
      effect: "allow",
      tenantId,
      conditions: { brokered: "true" },
    });
    tenants.push({
      tenantId,
      isolationTier,
      zoneIds: [...new Set([executionZoneId, dataZoneId])],
      dataBoundaryIds: [dataId],
      identityIds: [identityId],
    });
  });

  const evidenceRequirements = dataBoundaries.map((boundary) => ({
    id: `${boundary.id}-audit`,
    sourceIds: [boundary.id],
    sinkId: "audit-log",
    eventTypes: ["read", "write", "delete", "backup", "restore-test"],
  }));

  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: `reference-${name}`,
    environment: "reference",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: true,
      requireImmutableAudit: true,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: [
      "private-network",
      "centralized-egress",
      "managed-firewall",
      "workload-identity",
      "customer-managed-encryption",
      "immutable-audit-log",
      ...(microvm
        ? (["microvm-runtime"] as const)
        : (["external-sandbox"] as const)),
      ...(isolationTier === "dedicated-account"
        ? (["dedicated-account-boundary"] as const)
        : []),
    ],
    trustZones,
    networkDomains,
    flows,
    workloadPlanes,
    applications: [],
    tenants,
    dataBoundaries,
    identities,
    identityDelegations: [],
    grants,
    evidenceSinks: [
      {
        id: "audit-log",
        immutable: true,
        retentionDays: 2555,
        tenantScope: { mode: "platform" },
      },
    ],
    evidenceRequirements,
  };
}

export function createHostileReferenceBlueprints(): Readonly<
  Record<string, { blueprint: PlatformBlueprint; expectedCode: string }>
> {
  const crossTenant = createReferenceBlueprint("dedicated-account");
  crossTenant.grants = crossTenant.grants.map((grant) =>
    grant.id === "tenant-a-data-access"
      ? { ...grant, resourceIds: ["tenant-b-data"] }
      : grant,
  );

  const directInternet = createReferenceBlueprint("dedicated-network");
  directInternet.networkDomains = directInternet.networkDomains.map(
    (domainEntry) =>
      domainEntry.id === "tenant-a-execution-net"
        ? { ...domainEntry, directInternetAccess: true }
        : domainEntry,
  );

  const weakRuntime = createReferenceBlueprint("e2b-byoc");
  weakRuntime.workloadPlanes = weakRuntime.workloadPlanes.map((workload) =>
    workload.id === "tenant-a-plane"
      ? {
          ...workload,
          orchestrator: "managed-kubernetes",
          runtimeIsolation: "container",
          credentialMode: "ambient",
        }
      : workload,
  );

  const sharedRegulatedKey = createReferenceBlueprint("dedicated-account");
  sharedRegulatedKey.dataBoundaries = sharedRegulatedKey.dataBoundaries.map(
    (boundary) =>
      boundary.id === "tenant-a-data"
        ? {
            ...boundary,
            classification: "regulated",
            encryption: { ...boundary.encryption, dedicatedPerTenant: false },
          }
        : boundary,
  );

  return {
    "cross-tenant-grant": {
      blueprint: crossTenant,
      expectedCode: "IDENTITY_CROSS_TENANT_GRANT",
    },
    "direct-workload-internet": {
      blueprint: directInternet,
      expectedCode: "NET_DIRECT_INTERNET",
    },
    "ordinary-container-execution": {
      blueprint: weakRuntime,
      expectedCode: "WORKLOAD_UNBROKERED_CREDENTIALS",
    },
    "shared-regulated-key": {
      blueprint: sharedRegulatedKey,
      expectedCode: "DATA_REGULATED_SHARED_KEY",
    },
  };
}

function tierFor(name: ReferenceBlueprintName): IsolationTier {
  if (name === "pooled") return "pooled";
  if (name === "dedicated-data") return "dedicated-data";
  if (name === "dedicated-network") return "dedicated-network";
  return "dedicated-account";
}

function zone(
  id: string,
  kind: TrustZone["kind"],
  tenantScope: TenantScope,
  publicAccess = false,
  isolationBoundary?: string,
): TrustZone {
  return { id, kind, publicAccess, tenantScope, isolationBoundary };
}

function domain(
  id: string,
  zoneId: string,
  cidr: string,
  directInternetAccess = false,
  inspectedEgress = false,
): NetworkDomain {
  return {
    id,
    zoneId,
    cidrs: [cidr],
    availabilityZoneCount: 3,
    directInternetAccess,
    inspectedEgress,
  };
}

function executionPlane(
  id: string,
  zoneId: string,
  tenantScope: TenantScope,
  microvm: boolean,
): WorkloadPlane {
  return {
    id,
    zoneId,
    tenantScope,
    executionTrust: "untrusted",
    orchestrator: microvm ? "microvm" : "external-sandbox",
    runtimeIsolation: microvm ? "microvm" : "dedicated-vm",
    controlPlanePublic: false,
    workloadIdentity: true,
    credentialMode: "brokered",
    maxExecutionMinutes: 60,
  };
}

function executionFlows(zoneId: string): NetworkFlow[] {
  return [
    {
      id: `${zoneId}-broker`,
      fromZoneId: zoneId,
      toZoneId: "control",
      protocol: "https",
      ports: [443],
      purpose: "Brokered platform API access.",
      authorization: "brokered",
    },
    {
      id: `${zoneId}-egress`,
      fromZoneId: zoneId,
      toZoneId: "internet",
      viaZoneIds: ["egress"],
      protocol: "https",
      ports: [443],
      purpose: "Approved dependency access.",
      authorization: "brokered",
      externalDestinations: ["api.github.com"],
    },
  ];
}

function dataBoundary(
  id: string,
  zoneId: string,
  tenantScope: TenantScope,
  dedicatedPerTenant: boolean,
): DataBoundary {
  return {
    id,
    zoneId,
    classification: "confidential",
    tenantScope,
    services: ["object"],
    encryption: {
      customerManagedKey: true,
      dedicatedPerTenant,
      rotationRequired: true,
    },
    recovery: {
      backupRequired: true,
      rpoMinutes: 60,
      rtoMinutes: 240,
      multiAzRequired: true,
      deletionProtectionRequired: true,
      finalSnapshotRequired: true,
      restoreTestIntervalDays: 30,
    },
    retentionDays: 365,
    versioningRequired: true,
    replicationRequired: false,
    objectAuditRequired: true,
    deletionEvidenceRequired: true,
    exportEvidenceRequired: true,
  };
}
