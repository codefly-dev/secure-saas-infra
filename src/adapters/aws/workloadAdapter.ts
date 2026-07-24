import type {
  PlatformBlueprint,
  PlatformCapability,
  TenantScope,
  WorkloadPlane,
} from "../../core";
import { CloudAdapter, compileBlueprint } from "../../core";
import type { E2bByocAccessConfig, EksConfig } from "../../config";

export type AwsWorkloadDeploymentKind =
  | "private-eks"
  | "private-eks-microvm"
  | "e2b-byoc";

export interface AwsEksProviderExtension {
  version: string;
  endpointPublicAccess: false;
  autoModeNodePools: readonly string[];
  networkPolicyMode: "strict";
  secretsEncryption: true;
  controlPlaneLogTypes: readonly (
    | "api"
    | "audit"
    | "authenticator"
    | "controllerManager"
    | "scheduler"
  )[];
}

export interface AwsE2bProviderExtension {
  vendorRoleConfigured: boolean;
  externalIdConfigured: boolean;
}

export interface AwsMicrovmProviderExtension {
  enabled: boolean;
  runtimeClassName: string;
  nodeIsolationLabel: string;
}

export interface AwsWorkloadProviderExtensions {
  eks: AwsEksProviderExtension;
  e2b: AwsE2bProviderExtension;
  microvm: AwsMicrovmProviderExtension;
}

export interface AwsWorkloadPlanePlan {
  planeId: string;
  zoneId: string;
  tenantScope: TenantScope;
  deploymentKind: AwsWorkloadDeploymentKind;
  credentialMode: "workload-identity" | "brokered";
  privateControlPlane: true;
  secretsEncryption: true;
  controlPlaneLogging: true;
  networkPolicy: "strict";
  runtimeClassName?: string;
  nodeIsolationLabel?: string;
  maxExecutionMinutes?: number;
  native: AwsEksProviderExtension | AwsE2bProviderExtension;
}

export interface AwsWorkloadPlan {
  cloud: "aws";
  planes: readonly AwsWorkloadPlanePlan[];
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

export class AwsWorkloadAdapter implements CloudAdapter<AwsWorkloadPlan> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-workload",
    capabilities,
  };

  constructor(private readonly extensions: AwsWorkloadProviderExtensions) {}

  compile(blueprint: PlatformBlueprint): AwsWorkloadPlan {
    const zones = new Map(blueprint.trustZones.map((zone) => [zone.id, zone]));
    const networkZones = new Set(
      blueprint.networkDomains.map((domain) => domain.zoneId),
    );
    return {
      cloud: "aws",
      planes: [...blueprint.workloadPlanes]
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((plane) => {
          const zone = zones.get(plane.zoneId);
          if (!zone || zone.publicAccess) {
            throw new Error(
              `AWS workload plane '${plane.id}' must resolve to a private trust zone.`,
            );
          }
          if (!networkZones.has(plane.zoneId)) {
            throw new Error(
              `AWS workload plane '${plane.id}' has no network domain in zone '${plane.zoneId}'.`,
            );
          }
          return compilePlane(plane, this.extensions);
        }),
    };
  }
}

export function compileAwsWorkloads(
  blueprint: PlatformBlueprint,
  extensions: AwsWorkloadProviderExtensions,
): AwsWorkloadPlan {
  return compileBlueprint(blueprint, new AwsWorkloadAdapter(extensions));
}

export function awsWorkloadProviderExtensionsFromConfig(
  eks: EksConfig,
  e2b: E2bByocAccessConfig,
  microvmEnabled = true,
): AwsWorkloadProviderExtensions {
  if (eks.endpointPublicAccess || eks.networkPolicyMode !== "strict") {
    throw new Error(
      "AWS blueprint workload compilation requires private EKS and strict network policy.",
    );
  }
  return {
    eks: {
      version: eks.version,
      endpointPublicAccess: false,
      autoModeNodePools: eks.autoModeNodePools,
      networkPolicyMode: "strict",
      secretsEncryption: true,
      controlPlaneLogTypes: [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
      ],
    },
    e2b: {
      vendorRoleConfigured: e2b.createVendorRole,
      externalIdConfigured: (e2b.externalId?.length ?? 0) >= 16,
    },
    microvm: {
      enabled: microvmEnabled,
      runtimeClassName: "deus-microvm",
      nodeIsolationLabel: "deus.dev/sandbox-runtime=microvm",
    },
  };
}

function compilePlane(
  plane: WorkloadPlane,
  extensions: AwsWorkloadProviderExtensions,
): AwsWorkloadPlanePlan {
  if (plane.controlPlanePublic || extensions.eks.endpointPublicAccess) {
    throw new Error(
      `AWS workload plane '${plane.id}' cannot expose a public control plane.`,
    );
  }
  if (
    !plane.workloadIdentity ||
    (plane.credentialMode !== "workload-identity" &&
      plane.credentialMode !== "brokered")
  ) {
    throw new Error(
      `AWS workload plane '${plane.id}' requires explicit workload identity or brokered credentials.`,
    );
  }

  if (plane.orchestrator === "external-sandbox") {
    if (
      plane.executionTrust !== "untrusted" ||
      plane.runtimeIsolation !== "dedicated-vm" ||
      plane.credentialMode !== "brokered"
    ) {
      throw new Error(
        `AWS E2B plane '${plane.id}' requires untrusted, brokered, dedicated-VM intent.`,
      );
    }
    if (
      !extensions.e2b.vendorRoleConfigured ||
      !extensions.e2b.externalIdConfigured
    ) {
      throw new Error(
        `AWS E2B plane '${plane.id}' requires a configured vendor role and external ID.`,
      );
    }
    return basePlan(plane, "e2b-byoc", extensions.e2b);
  }

  if (
    plane.orchestrator === "microvm" ||
    plane.runtimeIsolation === "microvm"
  ) {
    if (
      plane.executionTrust !== "untrusted" ||
      plane.credentialMode !== "brokered" ||
      !extensions.microvm.enabled
    ) {
      throw new Error(
        `AWS microVM plane '${plane.id}' requires enabled microVM isolation and brokered untrusted execution.`,
      );
    }
    return {
      ...basePlan(plane, "private-eks-microvm", extensions.eks),
      runtimeClassName: requiredText(
        extensions.microvm.runtimeClassName,
        "microVM runtime class",
      ),
      nodeIsolationLabel: requiredText(
        extensions.microvm.nodeIsolationLabel,
        "microVM node isolation label",
      ),
    };
  }

  if (plane.orchestrator === "managed-kubernetes") {
    if (plane.executionTrust === "untrusted") {
      throw new Error(
        `AWS workload plane '${plane.id}' cannot compile untrusted execution to ordinary EKS containers.`,
      );
    }
    if (
      extensions.eks.networkPolicyMode !== "strict" ||
      !extensions.eks.secretsEncryption ||
      !requiredEksLogTypes.every((logType) =>
        extensions.eks.controlPlaneLogTypes.includes(logType),
      )
    ) {
      throw new Error(
        `AWS EKS plane '${plane.id}' requires strict network policy, secret encryption, and all control-plane logs.`,
      );
    }
    return basePlan(plane, "private-eks", extensions.eks);
  }

  throw new Error(
    `AWS workload plane '${plane.id}' uses unsupported orchestrator '${plane.orchestrator}'.`,
  );
}

const requiredEksLogTypes: AwsEksProviderExtension["controlPlaneLogTypes"] = [
  "api",
  "audit",
  "authenticator",
  "controllerManager",
  "scheduler",
];

function basePlan(
  plane: WorkloadPlane,
  deploymentKind: AwsWorkloadDeploymentKind,
  native: AwsEksProviderExtension | AwsE2bProviderExtension,
): AwsWorkloadPlanePlan {
  return {
    planeId: plane.id,
    zoneId: plane.zoneId,
    tenantScope: plane.tenantScope,
    deploymentKind,
    credentialMode:
      plane.credentialMode === "brokered" ? "brokered" : "workload-identity",
    privateControlPlane: true,
    secretsEncryption: true,
    controlPlaneLogging: true,
    networkPolicy: "strict",
    maxExecutionMinutes: plane.maxExecutionMinutes,
    native,
  };
}

function requiredText(value: string, label: string): string {
  if (value.trim().length === 0) throw new Error(`AWS ${label} is required.`);
  return value;
}
