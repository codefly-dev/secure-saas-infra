import * as aws from "@pulumi/aws";
import type { DatabaseConfig } from "../config";
import type { DatabaseResult } from "../database";
import type {
  ManagedPostgresBinding,
  ManagedPostgresIntent,
  PlatformBlueprint,
} from "../core";
import {
  awsManagedPostgresDatabaseUser,
  compileAwsManagedPostgres,
  type AwsManagedPostgresClaimPlan,
  type AwsManagedPostgresPlan,
} from "../adapters/aws";

const supportedAuroraPostgresExtensions = new Set(["pgcrypto", "vector"]);

export function compileManagedPostgresMaterializationPlan(args: {
  intent: ManagedPostgresIntent;
  blueprint: PlatformBlueprint;
  config: DatabaseConfig;
  accountId: string;
  region: string;
}): AwsManagedPostgresPlan {
  assertAwsManagedPostgresMaterialization(args.intent.bindings, args.config);
  if (!/^\d{12}$/.test(args.accountId)) {
    throw new Error(
      "AWS Managed Postgres canonical planning requires one exact allowed AWS account ID.",
    );
  }
  if (!args.config.replicaRegion) {
    throw new Error(
      "AWS Managed Postgres canonical planning requires a replica region.",
    );
  }
  const partition = args.region.startsWith("cn-")
    ? "aws-cn"
    : args.region.startsWith("us-gov-")
      ? "aws-us-gov"
      : "aws";
  return compileAwsManagedPostgres(
    args.intent,
    args.blueprint,
    {
      partition,
      accountId: args.accountId,
      region: args.region,
      replicaRegion: args.config.replicaRegion,
      engineVersion: args.config.engineVersion,
      instanceClass: args.config.instanceClass,
      instanceCount: args.config.instanceCount,
      backupRetentionDays: args.config.backupRetentionDays,
      supportedMajorVersions: [args.config.engineMajorVersion],
      supportedExtensions: [...supportedAuroraPostgresExtensions].sort(),
      rdsProxy: args.config.createProxy,
      endToEndIamAuthentication: true,
      awsManagedMasterPassword: true,
    },
    Object.fromEntries(args.intent.bindings.map((binding) => [binding.id, 1])),
  );
}

export function assertManagedPostgresPlanMatchesDatabases(
  plan: AwsManagedPostgresPlan,
  databasePlans: readonly {
    boundaryId: string;
    clusterBoundaryId: string;
    keyBoundaryId: string;
    evidenceSinkId: string;
    engineVersion: string;
    instanceClass: string;
    instanceCount: number;
    backupRetentionDays: number;
    restoreTestIntervalDays: number;
  }[],
): void {
  const physical = new Map(
    databasePlans.map((entry) => [entry.boundaryId, entry]),
  );
  if (physical.size !== plan.claims.length) {
    throw new Error(
      "AWS Managed Postgres physical database plan must exactly match canonical claims.",
    );
  }
  for (const claim of plan.claims) {
    const entry = physical.get(claim.dataBoundaryId);
    if (
      !entry ||
      entry.clusterBoundaryId !== claim.provider.clusterBoundaryId ||
      entry.keyBoundaryId !== claim.provider.keyBoundaryId ||
      entry.evidenceSinkId !== claim.provider.evidenceSinkId ||
      entry.engineVersion !== claim.provider.engineVersion ||
      entry.instanceClass !== claim.provider.instanceClass ||
      entry.instanceCount !== claim.provider.instanceCount ||
      entry.backupRetentionDays !== claim.provider.backupRetentionDays ||
      entry.restoreTestIntervalDays !== claim.provider.restoreTestIntervalDays
    ) {
      throw new Error(
        `AWS Managed Postgres physical database '${claim.dataBoundaryId}' diverges from canonical claim '${claim.claimId}'.`,
      );
    }
  }
}

export function managedPostgresClaimForBoundary(
  plan: AwsManagedPostgresPlan,
  boundaryId: string,
): AwsManagedPostgresClaimPlan {
  const claim = plan.claims.find(
    (candidate) => candidate.dataBoundaryId === boundaryId,
  );
  if (!claim) {
    throw new Error(
      `Relational data boundary '${boundaryId}' has no canonical Managed Postgres claim.`,
    );
  }
  return claim;
}

export function assertAwsManagedPostgresMaterialization(
  bindings: readonly ManagedPostgresBinding[],
  config: DatabaseConfig,
) {
  if (config.engine !== "aurora-postgresql") {
    throw new Error(
      "AWS Managed Postgres materialization requires aurora-postgresql; the generic MySQL path cannot satisfy a ManagedPostgres contract.",
    );
  }
  if (!config.createProxy) {
    throw new Error(
      "AWS Managed Postgres materialization requires an end-to-end IAM RDS Proxy.",
    );
  }
  if (!config.replicaRegion) {
    throw new Error(
      "AWS Managed Postgres materialization requires one explicit regional recovery-copy target.",
    );
  }
  for (const binding of bindings) {
    if (
      config.engineMajorVersion !== binding.database.majorVersion ||
      !config.engineVersion.startsWith(`${binding.database.majorVersion}.`)
    ) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requires PostgreSQL major ${binding.database.majorVersion}; configured engine version is '${config.engineVersion}' with major '${config.engineMajorVersion}'.`,
      );
    }
    if (config.port !== binding.database.port) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requires port ${binding.database.port}; configured port is ${config.port}.`,
      );
    }
    if (config.backupRetentionDays < binding.provisioning.backupRetentionDays) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requires at least ${binding.provisioning.backupRetentionDays} backup days.`,
      );
    }
    const unsupported = binding.database.extensions.filter(
      (extension) => !supportedAuroraPostgresExtensions.has(extension),
    );
    if (unsupported.length > 0) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requests unsupported Aurora PostgreSQL extensions: ${unsupported.join(", ")}.`,
      );
    }
  }
}

export function managedPostgresBindingForBoundary(
  intent: ManagedPostgresIntent,
  boundaryId: string,
): ManagedPostgresBinding {
  const binding = intent.bindings.find(
    (candidate) => candidate.dataBoundaryId === boundaryId,
  );
  if (!binding) {
    throw new Error(
      `Relational data boundary '${boundaryId}' has no Managed Postgres binding.`,
    );
  }
  return binding;
}

export function managedPostgresDatabaseOverrides(
  binding: ManagedPostgresBinding,
) {
  return {
    databaseName: binding.database.name,
    accessBoundaryIds: {
      runtime: binding.access.networkAccess.runtimeBoundaryId,
      migration: binding.access.networkAccess.migrationBoundaryId,
      bootstrap: `${binding.id}-bootstrap-db-access`,
    },
    databaseIdentityUsers: {
      runtime: awsManagedPostgresDatabaseUser(binding.access.runtimeIdentityId),
      migration: awsManagedPostgresDatabaseUser(
        binding.access.migrationIdentityId,
      ),
    },
  };
}

export function materializeManagedPostgresBindingOutputs(
  intent: ManagedPostgresIntent,
  plan: AwsManagedPostgresPlan,
  databases: Readonly<Record<string, DatabaseResult>>,
) {
  const region = aws.getRegionOutput({}).name;
  return Object.fromEntries(
    Object.entries(databases)
      .map(([boundaryId, database]) => {
        const binding = managedPostgresBindingForBoundary(intent, boundaryId);
        const claim = managedPostgresClaimForBoundary(plan, boundaryId);
        if (!database.proxy || !database.proxyResourceId) {
          throw new Error(
            `Managed Postgres binding '${binding.id}' requires an end-to-end IAM RDS Proxy.`,
          );
        }
        return [
          binding.id,
          {
            claim: claimProjection(claim),
            clusterResourceId: database.cluster.clusterResourceId,
            proxyResourceId: database.proxyResourceId,
            endpoint: database.proxy.endpoint,
            port: binding.database.port,
            databaseName: binding.database.name,
            authentication: {
              kind: "aws-rds-iam",
              region,
              target: "rds-proxy",
              tokenDelivery: "per-physical-connection",
            },
            tls: {
              mode: "verify-full",
              caCertIdentifier: database.caCertIdentifier,
              caBundleRef: "aws-rds://truststore/global/global-bundle.pem",
            },
            runtimeIdentityId: binding.access.runtimeIdentityId,
            runtimeDatabaseUser: database.runtimeDatabaseUser,
            runtimeAccessSecurityGroupId:
              database.runtimeAccessSecurityGroup.id,
            status: {
              state: "pending-infrastructure",
              reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
              blockers: [
                "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
                "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
                "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
              ],
            },
          },
        ] as const;
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function materializeManagedPostgresMigrationBindingOutputs(
  intent: ManagedPostgresIntent,
  plan: AwsManagedPostgresPlan,
  databases: Readonly<Record<string, DatabaseResult>>,
) {
  const region = aws.getRegionOutput({}).name;
  return Object.fromEntries(
    Object.entries(databases)
      .map(([boundaryId, database]) => {
        const binding = managedPostgresBindingForBoundary(intent, boundaryId);
        const claim = managedPostgresClaimForBoundary(plan, boundaryId);
        if (!database.proxy || !database.proxyResourceId) {
          throw new Error(
            `Managed Postgres migration binding '${binding.id}' requires an end-to-end IAM RDS Proxy.`,
          );
        }
        return [
          binding.id,
          {
            claim: claimProjection(claim),
            clusterResourceId: database.cluster.clusterResourceId,
            proxyResourceId: database.proxyResourceId,
            endpoint: database.proxy.endpoint,
            port: binding.database.port,
            databaseName: binding.database.name,
            authentication: {
              kind: "aws-rds-iam",
              region,
              target: "rds-proxy",
              tokenDelivery: "per-physical-connection",
            },
            tls: {
              mode: "verify-full",
              caCertIdentifier: database.caCertIdentifier,
              caBundleRef: "aws-rds://truststore/global/global-bundle.pem",
            },
            migrationIdentityId: binding.access.migrationIdentityId,
            migrationDatabaseUser: database.migrationDatabaseUser,
            migrationAccessSecurityGroupId:
              database.migrationAccessSecurityGroup.id,
            status: {
              state: "pending-infrastructure",
              reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
              blockers: [
                "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
                "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
                "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
              ],
            },
          },
        ] as const;
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function materializeManagedPostgresBootstrapBindingOutputs(
  intent: ManagedPostgresIntent,
  plan: AwsManagedPostgresPlan,
  databases: Readonly<Record<string, DatabaseResult>>,
) {
  return Object.fromEntries(
    Object.entries(databases)
      .map(([boundaryId, database]) => {
        const binding = managedPostgresBindingForBoundary(intent, boundaryId);
        const claim = managedPostgresClaimForBoundary(plan, boundaryId);
        return [
          binding.id,
          {
            claim: claimProjection(claim),
            bindingId: binding.id,
            endpoint: database.cluster.endpoint,
            port: binding.database.port,
            databaseName: binding.database.name,
            masterSecretArn: database.masterUserSecretArn,
            accessSecurityGroupId: database.bootstrapAccessSecurityGroup.id,
            status: {
              state: "pending-infrastructure",
              reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
              blockers: [
                "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
                "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
                "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
              ],
            },
          },
        ] as const;
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function claimProjection(claim: AwsManagedPostgresClaimPlan) {
  return {
    apiVersion: claim.brokerClaim.apiVersion,
    claimId: claim.claimId,
    generation: claim.brokerClaim.generation,
    tenantId: claim.tenantId,
    desiredStateDigest: claim.desiredStateDigest,
  };
}
