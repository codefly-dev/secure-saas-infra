import type {
  DataBoundary,
  PlatformBlueprint,
  PlatformCapability,
  TenantScope,
} from "../../core";
import { CloudAdapter, compileBlueprint } from "../../core";

export interface AwsDatabaseProviderExtensions {
  engine: "aurora-postgresql" | "aurora-mysql";
  engineVersion: string;
  instanceClass: string;
  instanceCount: number;
  backupRetentionDays: number;
  continuousPointInTimeRecovery: boolean;
  replicaRegion?: string;
}

export interface AwsDatabasePlan {
  boundaryId: string;
  zoneId: string;
  tenantScope: TenantScope;
  clusterBoundaryId: string;
  keyBoundaryId: string;
  engine: AwsDatabaseProviderExtensions["engine"];
  engineVersion: string;
  instanceClass: string;
  instanceCount: number;
  multiAz: boolean;
  backupRetentionDays: number;
  continuousPointInTimeRecovery: boolean;
  rpoMinutes: number;
  rtoMinutes: number;
  deletionProtection: boolean;
  finalSnapshot: boolean;
  dedicatedKeyPerTenant: boolean;
  regionalRecoveryCopy?: { region: string; mechanism: "aws-backup-copy" };
  restoreTestIntervalDays: number;
  evidenceSinkId: string;
}

export interface AwsDatabaseCompilation {
  cloud: "aws";
  databases: readonly AwsDatabasePlan[];
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

export class AwsDatabaseAdapter implements CloudAdapter<AwsDatabaseCompilation> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-database",
    capabilities,
  };

  constructor(private readonly extensions: AwsDatabaseProviderExtensions) {}

  compile(blueprint: PlatformBlueprint): AwsDatabaseCompilation {
    return {
      cloud: "aws",
      databases: [...blueprint.dataBoundaries]
        .filter((boundary) => boundary.services.includes("relational"))
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((boundary) =>
          compileDatabase(blueprint, boundary, this.extensions),
        ),
    };
  }
}

export function compileAwsDatabases(
  blueprint: PlatformBlueprint,
  extensions: AwsDatabaseProviderExtensions,
): AwsDatabaseCompilation {
  return compileBlueprint(blueprint, new AwsDatabaseAdapter(extensions));
}

function compileDatabase(
  blueprint: PlatformBlueprint,
  boundary: DataBoundary,
  extensions: AwsDatabaseProviderExtensions,
): AwsDatabasePlan {
  const recovery = boundary.recovery;
  if (
    !boundary.encryption.customerManagedKey ||
    !boundary.encryption.rotationRequired
  ) {
    throw new Error(
      `AWS database '${boundary.id}' requires a rotating customer-managed key.`,
    );
  }
  if (
    boundary.classification === "regulated" &&
    !boundary.encryption.dedicatedPerTenant
  ) {
    throw new Error(
      `AWS regulated database '${boundary.id}' requires tenant-dedicated encryption.`,
    );
  }
  if (recovery.multiAzRequired && extensions.instanceCount < 2) {
    throw new Error(
      `AWS database '${boundary.id}' requires at least two instances for multi-AZ availability.`,
    );
  }
  if (
    recovery.deletionProtectionRequired === false ||
    recovery.finalSnapshotRequired === false
  ) {
    throw new Error(
      `AWS database '${boundary.id}' requires deletion protection and a final snapshot.`,
    );
  }
  if (
    recovery.rpoMinutes < 5 ||
    (recovery.rpoMinutes < 1440 && !extensions.continuousPointInTimeRecovery)
  ) {
    throw new Error(
      `AWS database '${boundary.id}' cannot satisfy its ${recovery.rpoMinutes}-minute RPO.`,
    );
  }
  const requiredRetention = Math.min(boundary.retentionDays, 35);
  if (extensions.backupRetentionDays < requiredRetention) {
    throw new Error(
      `AWS database '${boundary.id}' requires ${requiredRetention} days of automated backup retention.`,
    );
  }
  const regionalRecoveryCopy = boundary.replicationRequired
    ? {
        region: requiredText(
          extensions.replicaRegion,
          `recovery-copy region for '${boundary.id}'`,
        ),
        mechanism: "aws-backup-copy" as const,
      }
    : undefined;
  const evidenceSinkId = restoreEvidenceSink(blueprint, boundary);
  return {
    boundaryId: boundary.id,
    zoneId: boundary.zoneId,
    tenantScope: boundary.tenantScope,
    clusterBoundaryId: `aws:rds:${boundary.id}`,
    keyBoundaryId: `aws:kms:${boundary.id}:database`,
    engine: extensions.engine,
    engineVersion: extensions.engineVersion,
    instanceClass: extensions.instanceClass,
    instanceCount: extensions.instanceCount,
    multiAz: extensions.instanceCount >= 2,
    backupRetentionDays: extensions.backupRetentionDays,
    continuousPointInTimeRecovery: extensions.continuousPointInTimeRecovery,
    rpoMinutes: recovery.rpoMinutes,
    rtoMinutes: recovery.rtoMinutes,
    deletionProtection: true,
    finalSnapshot: true,
    dedicatedKeyPerTenant: boundary.encryption.dedicatedPerTenant,
    regionalRecoveryCopy,
    restoreTestIntervalDays: recovery.restoreTestIntervalDays,
    evidenceSinkId,
  };
}

function restoreEvidenceSink(
  blueprint: PlatformBlueprint,
  boundary: DataBoundary,
): string {
  const requirement = blueprint.evidenceRequirements.find(
    (candidate) =>
      candidate.sourceIds.includes(boundary.id) &&
      candidate.eventTypes.includes("backup") &&
      candidate.eventTypes.includes("restore-test"),
  );
  const sink = requirement
    ? blueprint.evidenceSinks.find(
        (candidate) => candidate.id === requirement.sinkId,
      )
    : undefined;
  if (
    !requirement ||
    !sink ||
    !sink.immutable ||
    sink.retentionDays < boundary.retentionDays
  ) {
    throw new Error(
      `AWS database '${boundary.id}' requires an immutable backup and restore-test evidence sink.`,
    );
  }
  return sink.id;
}

function requiredText(value: string | undefined, label: string): string {
  if (!value?.trim()) throw new Error(`AWS ${label} is required.`);
  return value;
}
