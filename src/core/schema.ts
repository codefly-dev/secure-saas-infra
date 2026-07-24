import {
  AccessException,
  ApplicationDeployment,
  DataBoundary,
  DataClassification,
  EvidenceRequirement,
  EvidenceSink,
  Identity,
  IdentityDelegation,
  IdentityGrant,
  IsolationTier,
  NetworkDomain,
  NetworkFlow,
  PlatformBlueprint,
  PlatformCapability,
  RuntimeIsolation,
  SecurityPosture,
  TenantPlacement,
  TenantScope,
  TrustZone,
  TrustZoneKind,
  WorkloadOrchestrator,
  WorkloadPlane,
} from "./model";

type JsonObject = Record<string, unknown>;

const forbiddenSecretKeys = new Set([
  "password",
  "privateKey",
  "secret",
  "secretMaterial",
  "secretString",
  "secretValue",
  "token",
]);

export class BlueprintSchemaError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path}: ${message}`);
    this.name = "BlueprintSchemaError";
  }
}

export function parsePlatformBlueprint(value: unknown): PlatformBlueprint {
  rejectSecretMaterial(value, "platformBlueprint");
  const input = object(value, "platformBlueprint", [
    "apiVersion",
    "name",
    "environment",
    "posture",
    "requiredCapabilities",
    "trustZones",
    "networkDomains",
    "flows",
    "workloadPlanes",
    "applications",
    "tenants",
    "dataBoundaries",
    "identities",
    "identityDelegations",
    "grants",
    "evidenceSinks",
    "evidenceRequirements",
  ]);

  return {
    apiVersion: literal(
      input.apiVersion,
      "security.deus.dev/v1alpha1",
      "platformBlueprint.apiVersion",
    ),
    name: nonEmptyString(input.name, "platformBlueprint.name"),
    environment: nonEmptyString(
      input.environment,
      "platformBlueprint.environment",
    ),
    posture: parsePosture(input.posture, "platformBlueprint.posture"),
    requiredCapabilities: array(
      input.requiredCapabilities,
      "platformBlueprint.requiredCapabilities",
      parseCapability,
    ),
    trustZones: array(
      input.trustZones,
      "platformBlueprint.trustZones",
      parseTrustZone,
    ),
    networkDomains: array(
      input.networkDomains,
      "platformBlueprint.networkDomains",
      parseNetworkDomain,
    ),
    flows: array(input.flows, "platformBlueprint.flows", parseFlow),
    workloadPlanes: array(
      input.workloadPlanes,
      "platformBlueprint.workloadPlanes",
      parseWorkloadPlane,
    ),
    applications: array(
      input.applications,
      "platformBlueprint.applications",
      parseApplicationDeployment,
    ),
    tenants: array(input.tenants, "platformBlueprint.tenants", parseTenant),
    dataBoundaries: array(
      input.dataBoundaries,
      "platformBlueprint.dataBoundaries",
      parseDataBoundary,
    ),
    identities: array(
      input.identities,
      "platformBlueprint.identities",
      parseIdentity,
    ),
    identityDelegations: array(
      input.identityDelegations,
      "platformBlueprint.identityDelegations",
      parseIdentityDelegation,
    ),
    grants: array(input.grants, "platformBlueprint.grants", parseGrant),
    evidenceSinks: array(
      input.evidenceSinks,
      "platformBlueprint.evidenceSinks",
      parseEvidenceSink,
    ),
    evidenceRequirements: array(
      input.evidenceRequirements,
      "platformBlueprint.evidenceRequirements",
      parseEvidenceRequirement,
    ),
  };
}

function parsePosture(value: unknown, path: string): SecurityPosture {
  const input = object(value, path, [
    "forbidPublicControlPlanes",
    "requireInspectedEgress",
    "requireImmutableAudit",
    "minimumAuditRetentionDays",
  ]);
  return {
    forbidPublicControlPlanes: boolean(
      input.forbidPublicControlPlanes,
      `${path}.forbidPublicControlPlanes`,
    ),
    requireInspectedEgress: boolean(
      input.requireInspectedEgress,
      `${path}.requireInspectedEgress`,
    ),
    requireImmutableAudit: boolean(
      input.requireImmutableAudit,
      `${path}.requireImmutableAudit`,
    ),
    minimumAuditRetentionDays: integer(
      input.minimumAuditRetentionDays,
      `${path}.minimumAuditRetentionDays`,
      0,
    ),
  };
}

function parseTrustZone(value: unknown, path: string): TrustZone {
  const input = object(value, path, [
    "id",
    "kind",
    "publicAccess",
    "tenantScope",
    "isolationBoundary",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    kind: enumeration<TrustZoneKind>(
      input.kind,
      [
        "edge",
        "control-plane",
        "workload",
        "execution",
        "data",
        "security",
        "egress",
        "external",
      ],
      `${path}.kind`,
    ),
    publicAccess: boolean(input.publicAccess, `${path}.publicAccess`),
    tenantScope: parseTenantScope(input.tenantScope, `${path}.tenantScope`),
    isolationBoundary: optionalString(
      input.isolationBoundary,
      `${path}.isolationBoundary`,
    ),
  };
}

function parseNetworkDomain(value: unknown, path: string): NetworkDomain {
  const input = object(value, path, [
    "id",
    "zoneId",
    "cidrs",
    "availabilityZoneCount",
    "directInternetAccess",
    "inspectedEgress",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    zoneId: nonEmptyString(input.zoneId, `${path}.zoneId`),
    cidrs: stringArray(input.cidrs, `${path}.cidrs`),
    availabilityZoneCount: integer(
      input.availabilityZoneCount,
      `${path}.availabilityZoneCount`,
      1,
    ),
    directInternetAccess: boolean(
      input.directInternetAccess,
      `${path}.directInternetAccess`,
    ),
    inspectedEgress: boolean(input.inspectedEgress, `${path}.inspectedEgress`),
  };
}

function parseFlow(value: unknown, path: string): NetworkFlow {
  const input = object(value, path, [
    "id",
    "fromZoneId",
    "toZoneId",
    "protocol",
    "ports",
    "purpose",
    "authorization",
    "viaZoneIds",
    "externalDestinations",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    fromZoneId: nonEmptyString(input.fromZoneId, `${path}.fromZoneId`),
    toZoneId: nonEmptyString(input.toZoneId, `${path}.toZoneId`),
    protocol: enumeration(
      input.protocol,
      ["tcp", "udp", "icmp", "https", "any"],
      `${path}.protocol`,
    ),
    ports: optionalIntegerArray(input.ports, `${path}.ports`, 1, 65535),
    purpose: nonEmptyString(input.purpose, `${path}.purpose`),
    authorization: enumeration(
      input.authorization,
      ["direct", "brokered"],
      `${path}.authorization`,
    ),
    viaZoneIds: optionalStringArray(input.viaZoneIds, `${path}.viaZoneIds`),
    externalDestinations: optionalStringArray(
      input.externalDestinations,
      `${path}.externalDestinations`,
    ),
  };
}

function parseWorkloadPlane(value: unknown, path: string): WorkloadPlane {
  const input = object(value, path, [
    "id",
    "zoneId",
    "tenantScope",
    "executionTrust",
    "orchestrator",
    "runtimeIsolation",
    "controlPlanePublic",
    "workloadIdentity",
    "credentialMode",
    "maxExecutionMinutes",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    zoneId: nonEmptyString(input.zoneId, `${path}.zoneId`),
    tenantScope: parseTenantScope(input.tenantScope, `${path}.tenantScope`),
    executionTrust: enumeration(
      input.executionTrust,
      ["trusted", "semi-trusted", "untrusted"],
      `${path}.executionTrust`,
    ),
    orchestrator: enumeration<WorkloadOrchestrator>(
      input.orchestrator,
      ["managed-kubernetes", "serverless", "microvm", "external-sandbox"],
      `${path}.orchestrator`,
    ),
    runtimeIsolation: enumeration<RuntimeIsolation>(
      input.runtimeIsolation,
      ["process", "container", "microvm", "dedicated-vm"],
      `${path}.runtimeIsolation`,
    ),
    controlPlanePublic: boolean(
      input.controlPlanePublic,
      `${path}.controlPlanePublic`,
    ),
    workloadIdentity: boolean(
      input.workloadIdentity,
      `${path}.workloadIdentity`,
    ),
    credentialMode: enumeration(
      input.credentialMode,
      ["ambient", "workload-identity", "brokered"],
      `${path}.credentialMode`,
    ),
    maxExecutionMinutes: optionalInteger(
      input.maxExecutionMinutes,
      `${path}.maxExecutionMinutes`,
      1,
    ),
  };
}

function parseApplicationDeployment(
  value: unknown,
  path: string,
): ApplicationDeployment {
  const input = object(value, path, [
    "id",
    "workloadPlaneId",
    "serviceIdentityId",
    "tenantScope",
    "dataBoundaryIds",
    "ingress",
    "components",
    "componentDependencies",
    "dependencies",
    "availability",
    "release",
  ]);
  const availability = object(input.availability, `${path}.availability`, [
    "minimumReplicas",
    "maximumUnavailable",
  ]);
  const release = object(input.release, `${path}.release`, [
    "digestPinnedImages",
    "signatureVerification",
    "provenanceVerification",
    "rollbackRequired",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    workloadPlaneId: nonEmptyString(
      input.workloadPlaneId,
      `${path}.workloadPlaneId`,
    ),
    serviceIdentityId: nonEmptyString(
      input.serviceIdentityId,
      `${path}.serviceIdentityId`,
    ),
    tenantScope: parseTenantScope(input.tenantScope, `${path}.tenantScope`),
    dataBoundaryIds: stringArray(
      input.dataBoundaryIds,
      `${path}.dataBoundaryIds`,
    ),
    ingress: enumeration(
      input.ingress,
      ["none", "private", "public"],
      `${path}.ingress`,
    ),
    components: array(
      input.components,
      `${path}.components`,
      (component, componentPath) => {
        const entry = object(component, componentPath, [
          "id",
          "workloadPlaneId",
          "serviceIdentityId",
          "dataBoundaryIds",
          "ingress",
          "availability",
        ]);
        const componentAvailability = object(
          entry.availability,
          `${componentPath}.availability`,
          ["minimumReplicas", "maximumUnavailable"],
        );
        return {
          id: nonEmptyString(entry.id, `${componentPath}.id`),
          workloadPlaneId: nonEmptyString(
            entry.workloadPlaneId,
            `${componentPath}.workloadPlaneId`,
          ),
          serviceIdentityId: nonEmptyString(
            entry.serviceIdentityId,
            `${componentPath}.serviceIdentityId`,
          ),
          dataBoundaryIds: stringArray(
            entry.dataBoundaryIds,
            `${componentPath}.dataBoundaryIds`,
          ),
          ingress: enumeration(
            entry.ingress,
            ["none", "private", "public"],
            `${componentPath}.ingress`,
          ),
          availability: {
            minimumReplicas: integer(
              componentAvailability.minimumReplicas,
              `${componentPath}.availability.minimumReplicas`,
              1,
            ),
            maximumUnavailable: integer(
              componentAvailability.maximumUnavailable,
              `${componentPath}.availability.maximumUnavailable`,
              0,
            ),
          },
        };
      },
    ),
    componentDependencies: array(
      input.componentDependencies,
      `${path}.componentDependencies`,
      (dependency, dependencyPath) => {
        const entry = object(dependency, dependencyPath, [
          "fromComponentId",
          "toComponentId",
          "protocol",
          "authorization",
          "audience",
          "actions",
        ]);
        return {
          fromComponentId: nonEmptyString(
            entry.fromComponentId,
            `${dependencyPath}.fromComponentId`,
          ),
          toComponentId: nonEmptyString(
            entry.toComponentId,
            `${dependencyPath}.toComponentId`,
          ),
          protocol: enumeration(
            entry.protocol,
            ["https", "grpc"],
            `${dependencyPath}.protocol`,
          ),
          authorization: enumeration(
            entry.authorization,
            ["workload-identity", "capability"],
            `${dependencyPath}.authorization`,
          ),
          audience: nonEmptyString(
            entry.audience,
            `${dependencyPath}.audience`,
          ),
          actions: stringArray(entry.actions, `${dependencyPath}.actions`),
        };
      },
    ),
    dependencies: array(
      input.dependencies,
      `${path}.dependencies`,
      (dependency, dependencyPath) => {
        const entry = object(dependency, dependencyPath, [
          "deploymentId",
          "fromComponentId",
          "toComponentId",
          "protocol",
          "authorization",
          "audience",
          "actions",
        ]);
        return {
          deploymentId: nonEmptyString(
            entry.deploymentId,
            `${dependencyPath}.deploymentId`,
          ),
          fromComponentId: nonEmptyString(
            entry.fromComponentId,
            `${dependencyPath}.fromComponentId`,
          ),
          toComponentId: nonEmptyString(
            entry.toComponentId,
            `${dependencyPath}.toComponentId`,
          ),
          protocol: enumeration(
            entry.protocol,
            ["https", "grpc"],
            `${dependencyPath}.protocol`,
          ),
          authorization: enumeration(
            entry.authorization,
            ["workload-identity", "capability"],
            `${dependencyPath}.authorization`,
          ),
          audience: nonEmptyString(
            entry.audience,
            `${dependencyPath}.audience`,
          ),
          actions: stringArray(entry.actions, `${dependencyPath}.actions`),
        };
      },
    ),
    availability: {
      minimumReplicas: integer(
        availability.minimumReplicas,
        `${path}.availability.minimumReplicas`,
        1,
      ),
      maximumUnavailable: integer(
        availability.maximumUnavailable,
        `${path}.availability.maximumUnavailable`,
        0,
      ),
    },
    release: {
      digestPinnedImages: boolean(
        release.digestPinnedImages,
        `${path}.release.digestPinnedImages`,
      ),
      signatureVerification: boolean(
        release.signatureVerification,
        `${path}.release.signatureVerification`,
      ),
      provenanceVerification: boolean(
        release.provenanceVerification,
        `${path}.release.provenanceVerification`,
      ),
      rollbackRequired: boolean(
        release.rollbackRequired,
        `${path}.release.rollbackRequired`,
      ),
    },
  };
}

function parseTenant(value: unknown, path: string): TenantPlacement {
  const input = object(value, path, [
    "tenantId",
    "isolationTier",
    "zoneIds",
    "dataBoundaryIds",
    "identityIds",
  ]);
  return {
    tenantId: nonEmptyString(input.tenantId, `${path}.tenantId`),
    isolationTier: enumeration<IsolationTier>(
      input.isolationTier,
      ["pooled", "dedicated-data", "dedicated-network", "dedicated-account"],
      `${path}.isolationTier`,
    ),
    zoneIds: stringArray(input.zoneIds, `${path}.zoneIds`),
    dataBoundaryIds: stringArray(
      input.dataBoundaryIds,
      `${path}.dataBoundaryIds`,
    ),
    identityIds: stringArray(input.identityIds, `${path}.identityIds`),
  };
}

function parseDataBoundary(value: unknown, path: string): DataBoundary {
  const input = object(value, path, [
    "id",
    "zoneId",
    "classification",
    "tenantScope",
    "services",
    "encryption",
    "recovery",
    "retentionDays",
    "versioningRequired",
    "replicationRequired",
    "objectAuditRequired",
    "deletionEvidenceRequired",
    "exportEvidenceRequired",
  ]);
  const encryption = object(input.encryption, `${path}.encryption`, [
    "customerManagedKey",
    "dedicatedPerTenant",
    "rotationRequired",
  ]);
  const recovery = object(input.recovery, `${path}.recovery`, [
    "backupRequired",
    "rpoMinutes",
    "rtoMinutes",
    "multiAzRequired",
    "deletionProtectionRequired",
    "finalSnapshotRequired",
    "restoreTestIntervalDays",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    zoneId: nonEmptyString(input.zoneId, `${path}.zoneId`),
    classification: enumeration<DataClassification>(
      input.classification,
      ["public", "internal", "confidential", "regulated"],
      `${path}.classification`,
    ),
    tenantScope: parseTenantScope(input.tenantScope, `${path}.tenantScope`),
    services: stringArray(input.services, `${path}.services`).map(
      (service, index) =>
        enumeration(
          service,
          ["object", "relational"],
          `${path}.services[${index}]`,
        ),
    ),
    encryption: {
      customerManagedKey: boolean(
        encryption.customerManagedKey,
        `${path}.encryption.customerManagedKey`,
      ),
      dedicatedPerTenant: boolean(
        encryption.dedicatedPerTenant,
        `${path}.encryption.dedicatedPerTenant`,
      ),
      rotationRequired: boolean(
        encryption.rotationRequired,
        `${path}.encryption.rotationRequired`,
      ),
    },
    recovery: {
      backupRequired: boolean(
        recovery.backupRequired,
        `${path}.recovery.backupRequired`,
      ),
      rpoMinutes: integer(
        recovery.rpoMinutes,
        `${path}.recovery.rpoMinutes`,
        1,
      ),
      rtoMinutes: integer(
        recovery.rtoMinutes,
        `${path}.recovery.rtoMinutes`,
        1,
      ),
      multiAzRequired: boolean(
        recovery.multiAzRequired,
        `${path}.recovery.multiAzRequired`,
      ),
      deletionProtectionRequired: boolean(
        recovery.deletionProtectionRequired,
        `${path}.recovery.deletionProtectionRequired`,
      ),
      finalSnapshotRequired: boolean(
        recovery.finalSnapshotRequired,
        `${path}.recovery.finalSnapshotRequired`,
      ),
      restoreTestIntervalDays: integer(
        recovery.restoreTestIntervalDays,
        `${path}.recovery.restoreTestIntervalDays`,
        1,
      ),
    },
    retentionDays: integer(input.retentionDays, `${path}.retentionDays`, 1),
    versioningRequired: boolean(
      input.versioningRequired,
      `${path}.versioningRequired`,
    ),
    replicationRequired: boolean(
      input.replicationRequired,
      `${path}.replicationRequired`,
    ),
    objectAuditRequired: boolean(
      input.objectAuditRequired,
      `${path}.objectAuditRequired`,
    ),
    deletionEvidenceRequired: boolean(
      input.deletionEvidenceRequired,
      `${path}.deletionEvidenceRequired`,
    ),
    exportEvidenceRequired: boolean(
      input.exportEvidenceRequired,
      `${path}.exportEvidenceRequired`,
    ),
  };
}

function parseIdentity(value: unknown, path: string): Identity {
  const input = object(value, path, ["id", "kind", "tenantId", "shortLived"]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    kind: enumeration(
      input.kind,
      ["workforce", "workload", "automation", "vendor"],
      `${path}.kind`,
    ),
    tenantId: optionalString(input.tenantId, `${path}.tenantId`),
    shortLived: boolean(input.shortLived, `${path}.shortLived`),
  };
}

function parseIdentityDelegation(
  value: unknown,
  path: string,
): IdentityDelegation {
  const input = object(value, path, [
    "id",
    "fromIdentityId",
    "toIdentityId",
    "conditions",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    fromIdentityId: nonEmptyString(
      input.fromIdentityId,
      `${path}.fromIdentityId`,
    ),
    toIdentityId: nonEmptyString(input.toIdentityId, `${path}.toIdentityId`),
    conditions: optionalStringRecord(input.conditions, `${path}.conditions`),
  };
}

function parseGrant(value: unknown, path: string): IdentityGrant {
  const input = object(value, path, [
    "id",
    "identityId",
    "resourceIds",
    "actions",
    "effect",
    "tenantId",
    "conditions",
    "exception",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    identityId: nonEmptyString(input.identityId, `${path}.identityId`),
    resourceIds: stringArray(input.resourceIds, `${path}.resourceIds`),
    actions: stringArray(input.actions, `${path}.actions`),
    effect: enumeration(input.effect, ["allow", "deny"], `${path}.effect`),
    tenantId: optionalString(input.tenantId, `${path}.tenantId`),
    conditions: optionalStringRecord(input.conditions, `${path}.conditions`),
    exception:
      input.exception === undefined
        ? undefined
        : parseAccessException(input.exception, `${path}.exception`),
  };
}

function parseAccessException(value: unknown, path: string): AccessException {
  const input = object(value, path, [
    "owner",
    "reason",
    "expiresAt",
    "auditRequirementId",
  ]);
  return {
    owner: nonEmptyString(input.owner, `${path}.owner`),
    reason: nonEmptyString(input.reason, `${path}.reason`),
    expiresAt: isoTimestamp(input.expiresAt, `${path}.expiresAt`),
    auditRequirementId: nonEmptyString(
      input.auditRequirementId,
      `${path}.auditRequirementId`,
    ),
  };
}

function parseEvidenceSink(value: unknown, path: string): EvidenceSink {
  const input = object(value, path, [
    "id",
    "immutable",
    "retentionDays",
    "tenantScope",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    immutable: boolean(input.immutable, `${path}.immutable`),
    retentionDays: integer(input.retentionDays, `${path}.retentionDays`, 0),
    tenantScope: parseTenantScope(input.tenantScope, `${path}.tenantScope`),
  };
}

function parseEvidenceRequirement(
  value: unknown,
  path: string,
): EvidenceRequirement {
  const input = object(value, path, [
    "id",
    "sourceIds",
    "sinkId",
    "eventTypes",
  ]);
  return {
    id: nonEmptyString(input.id, `${path}.id`),
    sourceIds: stringArray(input.sourceIds, `${path}.sourceIds`),
    sinkId: nonEmptyString(input.sinkId, `${path}.sinkId`),
    eventTypes: stringArray(input.eventTypes, `${path}.eventTypes`),
  };
}

function parseTenantScope(value: unknown, path: string): TenantScope {
  const input = record(value, path);
  const mode = enumeration(
    input.mode,
    ["platform", "pooled", "dedicated"],
    `${path}.mode`,
  );
  if (mode === "platform") {
    rejectUnknown(input, path, ["mode"]);
    return { mode };
  }
  if (mode === "pooled") {
    rejectUnknown(input, path, ["mode", "tenantIds"]);
    return {
      mode,
      tenantIds: stringArray(input.tenantIds, `${path}.tenantIds`),
    };
  }
  rejectUnknown(input, path, ["mode", "tenantId"]);
  return { mode, tenantId: nonEmptyString(input.tenantId, `${path}.tenantId`) };
}

function parseCapability(value: unknown, path: string): PlatformCapability {
  return enumeration<PlatformCapability>(
    value,
    [
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
      "serverless-runtime",
    ],
    path,
  );
}

function object(
  value: unknown,
  path: string,
  allowedKeys: readonly string[],
): JsonObject {
  const input = record(value, path);
  rejectUnknown(input, path, allowedKeys);
  return input;
}

function record(value: unknown, path: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BlueprintSchemaError(path, "must be an object");
  }
  return value as JsonObject;
}

function rejectUnknown(
  value: JsonObject,
  path: string,
  allowedKeys: readonly string[],
) {
  const allowed = new Set(allowedKeys);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new BlueprintSchemaError(
      path,
      `contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
    );
  }
}

function array<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) {
    throw new BlueprintSchemaError(path, "must be an array");
  }
  return value.map((entry, index) => parse(entry, `${path}[${index}]`));
}

function stringArray(value: unknown, path: string): string[] {
  return array(value, path, nonEmptyString);
}

function optionalStringArray(
  value: unknown,
  path: string,
): string[] | undefined {
  return value === undefined ? undefined : stringArray(value, path);
}

function optionalIntegerArray(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number[] | undefined {
  if (value === undefined) return undefined;
  return array(value, path, (entry, entryPath) =>
    integer(entry, entryPath, minimum, maximum),
  );
}

function nonEmptyString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new BlueprintSchemaError(path, "must be a non-empty string");
  }
  return value;
}

function optionalString(value: unknown, path: string): string | undefined {
  return value === undefined ? undefined : nonEmptyString(value, path);
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new BlueprintSchemaError(path, "must be a boolean");
  }
  return value;
}

function integer(
  value: unknown,
  path: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new BlueprintSchemaError(
      path,
      `must be an integer between ${minimum} and ${maximum}`,
    );
  }
  return value;
}

function optionalInteger(
  value: unknown,
  path: string,
  minimum: number,
): number | undefined {
  return value === undefined ? undefined : integer(value, path, minimum);
}

function literal<T extends string>(
  value: unknown,
  expected: T,
  path: string,
): T {
  if (value !== expected) {
    throw new BlueprintSchemaError(path, `must equal '${expected}'`);
  }
  return expected;
}

function enumeration<T extends string>(
  value: unknown,
  values: readonly T[],
  path: string,
): T {
  if (typeof value !== "string" || !values.includes(value as T)) {
    throw new BlueprintSchemaError(
      path,
      `must be one of: ${values.join(", ")}`,
    );
  }
  return value as T;
}

function optionalStringRecord(
  value: unknown,
  path: string,
): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const input = record(value, path);
  return Object.fromEntries(
    Object.entries(input).map(([key, entry]) => [
      key,
      nonEmptyString(entry, `${path}.${key}`),
    ]),
  );
}

function isoTimestamp(value: unknown, path: string): string {
  const timestamp = nonEmptyString(value, path);
  if (Number.isNaN(Date.parse(timestamp))) {
    throw new BlueprintSchemaError(path, "must be an ISO-8601 timestamp");
  }
  return timestamp;
}

function rejectSecretMaterial(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      rejectSecretMaterial(entry, `${path}[${index}]`),
    );
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value as JsonObject)) {
    if (forbiddenSecretKeys.has(key)) {
      throw new BlueprintSchemaError(
        `${path}.${key}`,
        "secret material is not permitted; use a provider-managed secret reference",
      );
    }
    rejectSecretMaterial(entry, `${path}.${key}`);
  }
}
