import type {
  PlatformBlueprint,
  PlatformCapability,
  TenantScope,
} from "../../core";
import { CloudAdapter, compileBlueprint } from "../../core";

export interface AwsBackupProviderExtensions {
  vaultLockEnabled: boolean;
  backupIntervalMinutes: number;
  coldStorageAfterDays: number;
  deleteAfterDays: number;
  replicaRegion?: string;
}

export interface AwsBoundaryBackupPlan {
  boundaryId: string;
  tenantScope: TenantScope;
  vaultBoundaryId: string;
  keyBoundaryId: string;
  immutableVault: boolean;
  backupIntervalMinutes: number;
  rpoMinutes: number;
  retentionDays: number;
  coldStorageAfterDays: number;
  restoreTestIntervalDays: number;
  evidenceSinkId: string;
  regionalCopy?: { region: string };
  protectedResourceTypes: readonly ("Aurora" | "S3")[];
}

export interface AwsBackupCompilation {
  cloud: "aws";
  backups: readonly AwsBoundaryBackupPlan[];
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

export class AwsBackupAdapter implements CloudAdapter<AwsBackupCompilation> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-backup",
    capabilities,
  };
  constructor(private readonly extensions: AwsBackupProviderExtensions) {}

  compile(blueprint: PlatformBlueprint): AwsBackupCompilation {
    return {
      cloud: "aws",
      backups: [...blueprint.dataBoundaries]
        .filter((boundary) => boundary.recovery.backupRequired)
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((boundary) => {
          const recovery = boundary.recovery;
          if (recovery.restoreTestIntervalDays < 1) {
            throw new Error(
              `AWS backup '${boundary.id}' has no tested restore requirement.`,
            );
          }
          if (this.extensions.backupIntervalMinutes > recovery.rpoMinutes) {
            throw new Error(
              `AWS backup '${boundary.id}' cannot satisfy its ${recovery.rpoMinutes}-minute RPO.`,
            );
          }
          if (this.extensions.deleteAfterDays < boundary.retentionDays) {
            throw new Error(
              `AWS backup '${boundary.id}' does not meet its retention requirement.`,
            );
          }
          if (
            boundary.classification !== "public" &&
            !this.extensions.vaultLockEnabled
          ) {
            throw new Error(
              `AWS backup '${boundary.id}' requires an immutable locked vault.`,
            );
          }
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
            !sink ||
            !sink.immutable ||
            sink.retentionDays < boundary.retentionDays
          ) {
            throw new Error(
              `AWS backup '${boundary.id}' requires immutable backup and restore-test evidence.`,
            );
          }
          const regionalCopy = boundary.replicationRequired
            ? {
                region: requiredText(
                  this.extensions.replicaRegion,
                  `replica region for '${boundary.id}'`,
                ),
              }
            : undefined;
          return {
            boundaryId: boundary.id,
            tenantScope: boundary.tenantScope,
            vaultBoundaryId: `aws:backup:${boundary.id}`,
            keyBoundaryId: `aws:kms:${boundary.id}:backup`,
            immutableVault: this.extensions.vaultLockEnabled,
            backupIntervalMinutes: this.extensions.backupIntervalMinutes,
            rpoMinutes: recovery.rpoMinutes,
            retentionDays: this.extensions.deleteAfterDays,
            coldStorageAfterDays: this.extensions.coldStorageAfterDays,
            restoreTestIntervalDays: recovery.restoreTestIntervalDays,
            evidenceSinkId: sink.id,
            regionalCopy,
            protectedResourceTypes: boundary.services
              .map((service) =>
                service === "relational"
                  ? ("Aurora" as const)
                  : ("S3" as const),
              )
              .sort(),
          };
        }),
    };
  }
}

export function compileAwsBackups(
  blueprint: PlatformBlueprint,
  extensions: AwsBackupProviderExtensions,
): AwsBackupCompilation {
  return compileBlueprint(blueprint, new AwsBackupAdapter(extensions));
}

function requiredText(value: string | undefined, label: string): string {
  if (!value?.trim()) throw new Error(`AWS ${label} is required.`);
  return value;
}
