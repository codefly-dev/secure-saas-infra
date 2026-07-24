import type {
  DataBoundary,
  PlatformBlueprint,
  PlatformCapability,
  TenantScope,
} from "../../core";
import { CloudAdapter, compileBlueprint } from "../../core";

export interface AwsDataProviderExtensions {
  noncurrentVersionExpirationDays: number;
  replicationRegion?: string;
  replicationAccountId?: string;
}

export interface AwsArtifactStoragePlan {
  boundaryId: string;
  zoneId: string;
  tenantScope: TenantScope;
  bucketBoundaryId: string;
  keyBoundaryId: string;
  evidenceSinkId: string;
  classification: DataBoundary["classification"];
  retentionDays: number;
  noncurrentVersionExpirationDays: number;
  versioning: true;
  replication?: { region: string; accountId?: string };
  customerManagedKey: true;
  keyRotation: true;
  dedicatedKeyPerTenant: boolean;
  objectAuditEvents: readonly ["read", "write", "delete"];
  deletionManifestRequired: true;
  exportManifestRequired: true;
  ownership: {
    ownerTenantIds: readonly string[];
    shared: boolean;
  };
}

export interface AwsDataPlan {
  cloud: "aws";
  artifactStores: readonly AwsArtifactStoragePlan[];
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

export class AwsDataAdapter implements CloudAdapter<AwsDataPlan> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-data",
    capabilities,
  };

  constructor(private readonly extensions: AwsDataProviderExtensions) {}

  compile(blueprint: PlatformBlueprint): AwsDataPlan {
    return {
      cloud: "aws",
      artifactStores: [...blueprint.dataBoundaries]
        .filter((boundary) => boundary.services.includes("object"))
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((boundary) =>
          compileBoundary(blueprint, boundary, this.extensions),
        ),
    };
  }
}

export function compileAwsDataBoundaries(
  blueprint: PlatformBlueprint,
  extensions: AwsDataProviderExtensions,
): AwsDataPlan {
  return compileBlueprint(blueprint, new AwsDataAdapter(extensions));
}

function compileBoundary(
  blueprint: PlatformBlueprint,
  boundary: DataBoundary,
  extensions: AwsDataProviderExtensions,
): AwsArtifactStoragePlan {
  if (
    !boundary.encryption.customerManagedKey ||
    !boundary.encryption.rotationRequired ||
    !boundary.versioningRequired ||
    !boundary.objectAuditRequired ||
    !boundary.deletionEvidenceRequired ||
    !boundary.exportEvidenceRequired
  ) {
    throw new Error(
      `AWS confidential data boundary '${boundary.id}' is missing encryption, versioning, audit, deletion, or export requirements.`,
    );
  }
  if (
    boundary.classification === "regulated" &&
    !boundary.encryption.dedicatedPerTenant
  ) {
    throw new Error(
      `AWS regulated data boundary '${boundary.id}' cannot use a shared encryption key.`,
    );
  }
  if (
    extensions.noncurrentVersionExpirationDays < 1 ||
    extensions.noncurrentVersionExpirationDays > boundary.retentionDays
  ) {
    throw new Error(
      `AWS data boundary '${boundary.id}' has invalid noncurrent version retention.`,
    );
  }
  const audit = blueprint.evidenceRequirements.find(
    (requirement) =>
      requirement.sourceIds.includes(boundary.id) &&
      ["read", "write", "delete"].every((event) =>
        requirement.eventTypes.includes(event),
      ),
  );
  if (!audit) {
    throw new Error(
      `AWS data boundary '${boundary.id}' requires object-level read, write, and delete audit coverage.`,
    );
  }
  const ownerTenantIds = tenantIds(boundary.tenantScope);
  if (
    boundary.encryption.dedicatedPerTenant &&
    boundary.tenantScope.mode !== "dedicated"
  ) {
    throw new Error(
      `AWS data boundary '${boundary.id}' requests a tenant-dedicated key without a dedicated tenant scope.`,
    );
  }
  const replication = boundary.replicationRequired
    ? {
        region: requiredText(
          extensions.replicationRegion,
          `replication region for '${boundary.id}'`,
        ),
        accountId: extensions.replicationAccountId,
      }
    : undefined;
  return {
    boundaryId: boundary.id,
    zoneId: boundary.zoneId,
    tenantScope: boundary.tenantScope,
    bucketBoundaryId: `aws:s3:${boundary.id}`,
    keyBoundaryId: `aws:kms:${boundary.id}`,
    evidenceSinkId: audit.sinkId,
    classification: boundary.classification,
    retentionDays: boundary.retentionDays,
    noncurrentVersionExpirationDays: extensions.noncurrentVersionExpirationDays,
    versioning: true,
    replication,
    customerManagedKey: true,
    keyRotation: true,
    dedicatedKeyPerTenant: boundary.encryption.dedicatedPerTenant,
    objectAuditEvents: ["read", "write", "delete"],
    deletionManifestRequired: true,
    exportManifestRequired: true,
    ownership: {
      ownerTenantIds,
      shared: boundary.tenantScope.mode === "pooled",
    },
  };
}

function tenantIds(scope: TenantScope): readonly string[] {
  if (scope.mode === "dedicated") return [scope.tenantId];
  if (scope.mode === "pooled") return [...scope.tenantIds].sort();
  return [];
}

function requiredText(value: string | undefined, label: string): string {
  if (!value || value.trim().length === 0) {
    throw new Error(`AWS ${label} is required.`);
  }
  return value;
}
