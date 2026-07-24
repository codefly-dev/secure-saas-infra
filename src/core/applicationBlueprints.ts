import type {
  ApplicationDeployment,
  DataBoundary,
  PlatformBlueprint,
} from "./model";
import { createReferenceBlueprint } from "./referenceBlueprints";

export const wardenMindNetworkDomainIds = [
  "egress-net",
  "control-net",
  "execution-shared-net",
  "data-shared-net",
] as const;

export type WardenMindNetworkDomainId =
  (typeof wardenMindNetworkDomainIds)[number];

export interface WardenMindBlueprintOptions {
  networkCidrs?: Partial<Record<WardenMindNetworkDomainId, string>>;
}

export function createWardenMindBlueprint(
  options: WardenMindBlueprintOptions = {},
): PlatformBlueprint {
  const blueprint = createReferenceBlueprint("pooled");
  const networkCidrs = options.networkCidrs ?? {};
  const knownNetworkDomains = new Set<string>(wardenMindNetworkDomainIds);
  for (const networkDomainId of Object.keys(networkCidrs)) {
    if (!knownNetworkDomains.has(networkDomainId)) {
      throw new Error(
        `Unknown Warden/Mind network domain '${networkDomainId}'.`,
      );
    }
  }
  blueprint.networkDomains = blueprint.networkDomains.map((domain) => ({
    ...domain,
    cidrs: networkCidrs[domain.id as WardenMindNetworkDomainId]
      ? [networkCidrs[domain.id as WardenMindNetworkDomainId]!]
      : domain.cidrs,
  }));
  const release = {
    digestPinnedImages: true,
    signatureVerification: true,
    provenanceVerification: true,
    rollbackRequired: true,
  } as const;
  const availability = { minimumReplicas: 3, maximumUnavailable: 1 } as const;
  const applications: ApplicationDeployment[] = [
    {
      id: "warden",
      workloadPlaneId: "platform-applications",
      serviceIdentityId: "warden-service",
      tenantScope: { mode: "platform" },
      ingress: "public",
      components: [
        {
          id: "platform",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "warden-platform-service",
          dataBoundaryIds: ["warden-platform-state"],
          ingress: "public",
          availability,
        },
        {
          id: "saas",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "warden-saas-service",
          dataBoundaryIds: ["warden-saas-state"],
          ingress: "public",
          availability,
        },
      ],
      dataBoundaryIds: ["warden-platform-state", "warden-saas-state"],
      componentDependencies: [
        {
          fromComponentId: "platform",
          toComponentId: "saas",
          protocol: "grpc",
          authorization: "workload-identity",
          audience: "warden-saas.internal",
          actions: ["accounts:read", "state:write"],
        },
        {
          fromComponentId: "saas",
          toComponentId: "platform",
          protocol: "https",
          authorization: "workload-identity",
          audience: "warden-platform.internal",
          actions: ["gateway:invoke"],
        },
      ],
      dependencies: [
        {
          deploymentId: "mind",
          fromComponentId: "platform",
          toComponentId: "mind",
          protocol: "grpc",
          authorization: "capability",
          audience: "mind.internal",
          actions: ["agents:request", "approvals:redeem"],
        },
      ],
      availability,
      release,
    },
    {
      id: "mind",
      workloadPlaneId: "platform-applications",
      serviceIdentityId: "mind-service",
      tenantScope: { mode: "platform" },
      dataBoundaryIds: [
        "mind-core-state",
        "mind-execution-state",
        "mind-infra-state",
        "mind-users-state",
      ],
      ingress: "public",
      components: [
        {
          id: "mind",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "mind-core-service",
          dataBoundaryIds: ["mind-core-state"],
          ingress: "public",
          availability,
        },
        {
          id: "execution",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "mind-execution-service",
          dataBoundaryIds: ["mind-execution-state"],
          ingress: "none",
          availability: { minimumReplicas: 2, maximumUnavailable: 1 },
        },
        {
          id: "infra",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "mind-infra-service",
          dataBoundaryIds: ["mind-infra-state"],
          ingress: "none",
          availability: { minimumReplicas: 1, maximumUnavailable: 0 },
        },
        {
          id: "users",
          workloadPlaneId: "platform-applications",
          serviceIdentityId: "mind-users-service",
          dataBoundaryIds: ["mind-users-state"],
          ingress: "private",
          availability,
        },
      ],
      componentDependencies: [
        {
          fromComponentId: "mind",
          toComponentId: "infra",
          protocol: "grpc",
          authorization: "workload-identity",
          audience: "mind-infra.internal",
          actions: ["state:read", "state:write"],
        },
      ],
      dependencies: [
        {
          deploymentId: "warden",
          fromComponentId: "mind",
          toComponentId: "platform",
          protocol: "grpc",
          authorization: "capability",
          audience: "warden.internal",
          actions: ["plugins:read", "approvals:request"],
        },
      ],
      availability,
      release,
    },
  ];

  blueprint.requiredCapabilities = [
    ...new Set([
      ...blueprint.requiredCapabilities,
      "private-control-plane" as const,
    ]),
  ];
  blueprint.workloadPlanes = [
    ...blueprint.workloadPlanes,
    {
      id: "platform-applications",
      zoneId: "control",
      tenantScope: { mode: "platform" },
      executionTrust: "trusted",
      orchestrator: "managed-kubernetes",
      runtimeIsolation: "container",
      controlPlanePublic: false,
      workloadIdentity: true,
      credentialMode: "workload-identity",
    },
  ];
  blueprint.identities = [
    ...blueprint.identities,
    {
      id: "warden-service",
      kind: "workload",
      shortLived: true,
    },
    { id: "mind-service", kind: "workload", shortLived: true },
    {
      id: "warden-platform-service",
      kind: "workload",
      shortLived: true,
    },
    { id: "warden-saas-service", kind: "workload", shortLived: true },
    { id: "mind-core-service", kind: "workload", shortLived: true },
    {
      id: "mind-execution-service",
      kind: "workload",
      shortLived: true,
    },
    { id: "mind-infra-service", kind: "workload", shortLived: true },
    { id: "mind-users-service", kind: "workload", shortLived: true },
    {
      id: "warden-saas-migration",
      kind: "automation",
      shortLived: true,
    },
    {
      id: "mind-infra-migration",
      kind: "automation",
      shortLived: true,
    },
    {
      id: "mind-users-migration",
      kind: "automation",
      shortLived: true,
    },
  ];
  const applicationData = [
    applicationDataBoundary("warden-platform-state", false),
    applicationDataBoundary("warden-saas-state", true),
    applicationDataBoundary("mind-core-state", false),
    applicationDataBoundary("mind-execution-state", false),
    applicationDataBoundary("mind-infra-state", true),
    applicationDataBoundary("mind-users-state", true),
  ];
  blueprint.dataBoundaries = [...blueprint.dataBoundaries, ...applicationData];
  blueprint.applications = applications;
  blueprint.evidenceRequirements = [
    ...blueprint.evidenceRequirements,
    ...applicationData.map((boundary) => ({
      id: `${boundary.id}-audit`,
      sourceIds: [boundary.id],
      sinkId: "audit-log",
      eventTypes: ["read", "write", "delete", "backup", "restore-test"],
    })),
    ...applications.map((application) => ({
      id: `${application.id}-deployment-audit`,
      sourceIds: [application.id],
      sinkId: "audit-log",
      eventTypes: ["deployment", "authorization"],
    })),
  ];
  blueprint.name = "warden-mind-platform";
  return blueprint;
}

function applicationDataBoundary(
  id: string,
  managedPostgres: boolean,
): DataBoundary {
  return {
    id,
    zoneId: "control",
    classification: "confidential",
    tenantScope: { mode: "platform" },
    services: managedPostgres ? ["object", "relational"] : ["object"],
    encryption: {
      customerManagedKey: true,
      dedicatedPerTenant: false,
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
    replicationRequired: true,
    objectAuditRequired: true,
    deletionEvidenceRequired: true,
    exportEvidenceRequired: true,
  };
}
