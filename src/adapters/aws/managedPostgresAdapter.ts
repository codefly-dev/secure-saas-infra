import {
  RESOURCE_CLAIM_API_VERSION,
  RESOURCE_PROVIDER_PROTOCOL_VERSION,
  assertManagedPostgresIntent,
  codeflyServiceRef,
  managedPostgresBindingDigest,
  managedPostgresIntentDigest,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
  type ResourceClaimRequest,
  type ResourceProviderDescriptor,
} from "../../core";
import { compileAwsDatabases, type AwsDatabasePlan } from "./databaseAdapter";

export const AWS_MANAGED_POSTGRES_PLAN_API_VERSION =
  "infrastructure.deus.dev/aws-managed-postgres-plan/v1alpha1" as const;

export const AWS_MANAGED_POSTGRES_PROVIDER_DESCRIPTOR: ResourceProviderDescriptor =
  {
    id: "aws-aurora-postgresql",
    protocolVersion: RESOURCE_PROVIDER_PROTOCOL_VERSION,
    resourceKinds: ["ManagedPostgres"],
    capabilities: [
      "private-network",
      "explicit-source-boundaries",
      "customer-managed-encryption",
      "multi-zone",
      "point-in-time-recovery",
      "workload-identity",
      "end-to-end-iam-proxy",
      "reference-only-outputs",
    ],
    mutationMode: "broker-only",
    acceptsProviderCredentials: false,
    outputMode: "reference-only",
    deterministicPlanning: true,
  };

export interface AwsManagedPostgresProviderExtensions {
  partition: "aws" | "aws-us-gov" | "aws-cn";
  accountId: string;
  region: string;
  replicaRegion: string;
  engineVersion: string;
  instanceClass: string;
  instanceCount: number;
  backupRetentionDays: number;
  supportedMajorVersions: readonly string[];
  supportedExtensions: readonly string[];
  rdsProxy: boolean;
  endToEndIamAuthentication: boolean;
  awsManagedMasterPassword: boolean;
}

export interface AwsManagedPostgresClaimPlan {
  claimId: string;
  tenantId: string;
  environment: string;
  codeflyService: string;
  dataBoundaryId: string;
  desiredStateDigest: string;
  resourceKind: "ManagedPostgres";
  resourceApiVersion: ManagedPostgresIntent["apiVersion"];
  brokerClaim: ResourceClaimRequest;
  provider: {
    cloud: "aws";
    adapterId: "aws-aurora-postgresql";
    partition: "aws" | "aws-us-gov" | "aws-cn";
    accountId: string;
    service: "aurora-postgresql";
    region: string;
    replicaRegion: string;
    engineVersion: string;
    databaseName: string;
    port: 5432;
    extensions: readonly string[];
    instanceClass: string;
    instanceCount: number;
    subnetPlacement: "private";
    publiclyAccessible: false;
    multiAz: true;
    storageEncrypted: true;
    encryptionKey: "customer-managed";
    encryptionKeyRotation: true;
    iamDatabaseAuthentication: true;
    masterCredentialManagement: "aws-managed-secret";
    credentialsPersistedInIacState: false;
    deletionProtection: true;
    finalSnapshot: true;
    pointInTimeRecovery: true;
    backupRetentionDays: number;
    restoreTestIntervalDays: number;
    rdsProxy: {
      required: true;
      requireTls: true;
      defaultAuthenticationScheme: "IAM_AUTH";
      endToEndIamAuthentication: true;
    };
    clusterBoundaryId: string;
    keyBoundaryId: string;
    evidenceSinkId: string;
    networkAccess: {
      mode: "security-group-source-boundaries";
      allowVpcCidr: false;
      proxyOnly: true;
      runtimeBoundaryId: string;
      migrationBoundaryId: string;
    };
  };
  identities: {
    runtime: AwsManagedPostgresIdentityPlan;
    migration: AwsManagedPostgresIdentityPlan;
    separate: true;
    authentication: "workload-identity";
  };
  outputs: {
    endpointRef: string;
    port: 5432;
    databaseName: string;
    caBundleRef: string;
    runtimeIdentityRef: string;
    migrationIdentityRef: string;
    authentication: {
      kind: "aws-rds-iam";
      region: string;
      target: "rds-proxy";
      resourceIdRef: string;
    };
    credentialValue: null;
  };
}

export interface AwsManagedPostgresIdentityPlan {
  identityId: string;
  role: "runtime" | "migration";
  databaseUser: string;
  accessBoundaryId: string;
  authentication: "iam-database-authentication";
  connectionTarget: "rds-proxy";
  resourceIdRef: string;
  iamAction: "rds-db:connect";
  wildcardCluster: false;
  wildcardDatabaseUser: false;
  administrator: false;
  grantOption: false;
  databasePrivileges: readonly string[];
}

export interface AwsManagedPostgresIdentityPolicies {
  runtime: AwsRdsDbConnectPolicyDocument;
  migration: AwsRdsDbConnectPolicyDocument;
}

export interface AwsManagedPostgresIamTarget {
  kind: "rds-proxy";
  resourceId: string;
}

export interface AwsRdsDbConnectPolicyDocument {
  Version: "2012-10-17";
  Statement: readonly [
    {
      Sid: string;
      Effect: "Allow";
      Action: "rds-db:connect";
      Resource: string;
    },
  ];
}

export interface AwsPostgresBootstrapSecretPolicyDocument {
  Version: "2012-10-17";
  Statement: readonly [
    {
      Sid: "ReadExactRdsManagedMasterSecret";
      Effect: "Allow";
      Action: "secretsmanager:GetSecretValue";
      Resource: string;
      Condition: { StringEquals: { "aws:SourceVpce": string } };
    },
    {
      Sid: "DecryptExactRdsManagedMasterSecret";
      Effect: "Allow";
      Action: "kms:Decrypt";
      Resource: string;
      Condition: {
        StringEquals: {
          "kms:ViaService": string;
          "kms:EncryptionContext:SecretARN": string;
        };
      };
    },
  ];
}

export interface AwsManagedPostgresPlan {
  apiVersion: typeof AWS_MANAGED_POSTGRES_PLAN_API_VERSION;
  cloud: "aws";
  intentDigest: string;
  broker: {
    authorization: "capability";
    tenantBindingRequired: true;
    idempotencyRequired: true;
    conditionalReconciliation: true;
    directPluginProviderCredentials: false;
    outputMode: "reference-only";
  };
  claims: readonly AwsManagedPostgresClaimPlan[];
}

export function compileAwsManagedPostgres(
  intent: ManagedPostgresIntent,
  blueprint: PlatformBlueprint,
  extensions: AwsManagedPostgresProviderExtensions,
  claimGenerations: Readonly<Record<string, number>>,
): AwsManagedPostgresPlan {
  assertManagedPostgresIntent(intent, blueprint);
  validateExtensions(intent, extensions);
  const databasePlans = new Map(
    compileAwsDatabases(blueprint, {
      engine: "aurora-postgresql",
      engineVersion: extensions.engineVersion,
      instanceClass: extensions.instanceClass,
      instanceCount: extensions.instanceCount,
      backupRetentionDays: extensions.backupRetentionDays,
      continuousPointInTimeRecovery: true,
      replicaRegion: extensions.replicaRegion,
    }).databases.map((database) => [database.boundaryId, database]),
  );
  return {
    apiVersion: AWS_MANAGED_POSTGRES_PLAN_API_VERSION,
    cloud: "aws",
    intentDigest: managedPostgresIntentDigest(intent),
    broker: {
      authorization: "capability",
      tenantBindingRequired: true,
      idempotencyRequired: true,
      conditionalReconciliation: true,
      directPluginProviderCredentials: false,
      outputMode: "reference-only",
    },
    claims: [...intent.bindings]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((binding) => {
        const databasePlan = databasePlans.get(binding.dataBoundaryId);
        if (!databasePlan) {
          throw new Error(
            `AWS Managed Postgres binding '${binding.id}' has no compiled database boundary.`,
          );
        }
        const generation = claimGenerations[binding.id];
        if (!Number.isSafeInteger(generation) || generation < 1) {
          throw new Error(
            `AWS Managed Postgres binding '${binding.id}' requires one broker-owned positive claim generation.`,
          );
        }
        return compileClaim(
          intent,
          binding,
          databasePlan,
          extensions,
          generation,
        );
      }),
  };
}

function compileClaim(
  intent: ManagedPostgresIntent,
  binding: ManagedPostgresIntent["bindings"][number],
  databasePlan: AwsDatabasePlan,
  extensions: AwsManagedPostgresProviderExtensions,
  generation: number,
): AwsManagedPostgresClaimPlan {
  return {
    claimId: binding.id,
    tenantId: binding.tenantId,
    environment: intent.environment,
    codeflyService: codeflyServiceRef(binding),
    dataBoundaryId: binding.dataBoundaryId,
    desiredStateDigest: managedPostgresBindingDigest(intent, binding),
    resourceKind: "ManagedPostgres",
    resourceApiVersion: intent.apiVersion,
    brokerClaim: {
      apiVersion: RESOURCE_CLAIM_API_VERSION,
      kind: "ResourceClaim",
      claimId: binding.id,
      tenantId: binding.tenantId,
      generation,
      resourceKind: "ManagedPostgres",
      resourceApiVersion: intent.apiVersion,
      desiredStateDigest: managedPostgresBindingDigest(intent, binding),
      desiredStateRef: `broker://${binding.id}/desired-state`,
      requiredProviderCapabilities: [
        "private-network",
        "explicit-source-boundaries",
        "customer-managed-encryption",
        "multi-zone",
        "point-in-time-recovery",
        "workload-identity",
        "end-to-end-iam-proxy",
        "reference-only-outputs",
      ],
      lifecycle: {
        deletionProtection: true,
        destructionApprovalRequired: true,
        finalizationEvidenceRequired: true,
        maxReconcileAttempts: 5,
      },
    },
    provider: {
      cloud: "aws",
      adapterId: "aws-aurora-postgresql",
      partition: extensions.partition,
      accountId: extensions.accountId,
      service: "aurora-postgresql",
      region: extensions.region,
      replicaRegion: extensions.replicaRegion,
      engineVersion: extensions.engineVersion,
      databaseName: binding.database.name,
      port: 5432,
      extensions: [...binding.database.extensions].sort(),
      instanceClass: extensions.instanceClass,
      instanceCount: extensions.instanceCount,
      subnetPlacement: "private",
      publiclyAccessible: false,
      multiAz: true,
      storageEncrypted: true,
      encryptionKey: "customer-managed",
      encryptionKeyRotation: true,
      iamDatabaseAuthentication: true,
      masterCredentialManagement: "aws-managed-secret",
      credentialsPersistedInIacState: false,
      deletionProtection: true,
      finalSnapshot: true,
      pointInTimeRecovery: true,
      backupRetentionDays: databasePlan.backupRetentionDays,
      restoreTestIntervalDays: databasePlan.restoreTestIntervalDays,
      rdsProxy: {
        required: true,
        requireTls: true,
        defaultAuthenticationScheme: "IAM_AUTH",
        endToEndIamAuthentication: true,
      },
      clusterBoundaryId: databasePlan.clusterBoundaryId,
      keyBoundaryId: databasePlan.keyBoundaryId,
      evidenceSinkId: databasePlan.evidenceSinkId,
      networkAccess: {
        mode: "security-group-source-boundaries",
        allowVpcCidr: false,
        proxyOnly: true,
        runtimeBoundaryId: binding.access.networkAccess.runtimeBoundaryId,
        migrationBoundaryId: binding.access.networkAccess.migrationBoundaryId,
      },
    },
    identities: {
      runtime: identityPlan(
        binding.access.runtimeIdentityId,
        "runtime",
        binding.access.networkAccess.runtimeBoundaryId,
        binding.id,
      ),
      migration: identityPlan(
        binding.access.migrationIdentityId,
        "migration",
        binding.access.networkAccess.migrationBoundaryId,
        binding.id,
      ),
      separate: true,
      authentication: "workload-identity",
    },
    outputs: {
      endpointRef: `broker://${binding.id}/endpoint`,
      port: 5432,
      databaseName: binding.database.name,
      caBundleRef: `broker://${binding.id}/ca-bundle`,
      runtimeIdentityRef: `identity://${binding.access.runtimeIdentityId}`,
      migrationIdentityRef: `identity://${binding.access.migrationIdentityId}`,
      authentication: {
        kind: "aws-rds-iam",
        region: extensions.region,
        target: "rds-proxy",
        resourceIdRef: `broker://${binding.id}/proxy-resource-id`,
      },
      credentialValue: null,
    },
  };
}

export function compileAwsManagedPostgresIdentityPolicies(
  claim: AwsManagedPostgresClaimPlan,
  target: AwsManagedPostgresIamTarget,
): AwsManagedPostgresIdentityPolicies {
  if (
    target.kind !== "rds-proxy" ||
    !/^prx-[A-Za-z0-9]{1,255}$/.test(target.resourceId)
  ) {
    throw new Error(
      "AWS Managed Postgres requires one exact RDS Proxy resource ID for Proxy endpoint authentication.",
    );
  }
  if (
    claim.identities.runtime.identityId ===
      claim.identities.migration.identityId ||
    claim.identities.runtime.databaseUser ===
      claim.identities.migration.databaseUser
  ) {
    throw new Error(
      `AWS Managed Postgres claim '${claim.claimId}' must separate runtime and migration database identities.`,
    );
  }
  return {
    runtime: connectPolicy(claim, target.resourceId, claim.identities.runtime),
    migration: connectPolicy(
      claim,
      target.resourceId,
      claim.identities.migration,
    ),
  };
}

function identityPlan(
  identityId: string,
  role: "runtime" | "migration",
  accessBoundaryId: string,
  claimId: string,
): AwsManagedPostgresIdentityPlan {
  return {
    identityId,
    role,
    databaseUser: awsManagedPostgresDatabaseUser(identityId),
    accessBoundaryId,
    authentication: "iam-database-authentication",
    connectionTarget: "rds-proxy",
    resourceIdRef: `broker://${claimId}/proxy-resource-id`,
    iamAction: "rds-db:connect",
    wildcardCluster: false,
    wildcardDatabaseUser: false,
    administrator: false,
    grantOption: false,
    databasePrivileges:
      role === "runtime"
        ? ["CONNECT", "USAGE", "SELECT", "INSERT", "UPDATE", "DELETE"]
        : [
            "CONNECT",
            "USAGE",
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "CREATE",
            "ALTER",
          ],
  };
}

function connectPolicy(
  claim: AwsManagedPostgresClaimPlan,
  proxyResourceId: string,
  identity: AwsManagedPostgresIdentityPlan,
): AwsRdsDbConnectPolicyDocument {
  return compileAwsRdsProxyConnectPolicy({
    partition: claim.provider.partition,
    region: claim.provider.region,
    accountId: claim.provider.accountId,
    proxyResourceId,
    databaseUser: identity.databaseUser,
    role: identity.role,
  });
}

export function compileAwsRdsProxyConnectPolicy(args: {
  partition: "aws" | "aws-us-gov" | "aws-cn";
  region: string;
  accountId: string;
  proxyResourceId: string;
  databaseUser: string;
  role: "runtime" | "migration";
}): AwsRdsDbConnectPolicyDocument {
  if (
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(args.region) ||
    !/^\d{12}$/.test(args.accountId) ||
    !/^prx-[A-Za-z0-9]{1,255}$/.test(args.proxyResourceId) ||
    !/^[a-z_][a-z0-9_]{0,62}$/.test(args.databaseUser)
  ) {
    throw new Error(
      "AWS RDS Proxy IAM connection policy requires an exact Region, account, Proxy resource ID, and PostgreSQL user.",
    );
  }
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid:
          args.role === "runtime"
            ? "RuntimeDatabaseConnect"
            : "MigrationDatabaseConnect",
        Effect: "Allow",
        Action: "rds-db:connect",
        Resource: `arn:${args.partition}:rds-db:${args.region}:${args.accountId}:dbuser:${args.proxyResourceId}/${args.databaseUser}`,
      },
    ],
  };
}

export function compileAwsPostgresBootstrapSecretPolicy(args: {
  partition: "aws" | "aws-us-gov" | "aws-cn";
  region: string;
  accountId: string;
  masterSecretArn: string;
  kmsKeyArn: string;
  secretsManagerVpcEndpointId: string;
}): AwsPostgresBootstrapSecretPolicyDocument {
  const secretPattern = new RegExp(
    `^arn:${args.partition}:secretsmanager:${args.region}:${args.accountId}:secret:[A-Za-z0-9/!_+=.@-]+$`,
  );
  const keyPattern = new RegExp(
    `^arn:${args.partition}:kms:${args.region}:${args.accountId}:key/[A-Fa-f0-9-]{8,}$`,
  );
  if (
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(args.region) ||
    !/^\d{12}$/.test(args.accountId) ||
    !secretPattern.test(args.masterSecretArn) ||
    !keyPattern.test(args.kmsKeyArn) ||
    !/^vpce-[a-f0-9]{8,17}$/.test(args.secretsManagerVpcEndpointId)
  ) {
    throw new Error(
      "AWS PostgreSQL bootstrap policy requires exact same-account Secret, KMS key, Region, and Secrets Manager VPC endpoint references.",
    );
  }
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadExactRdsManagedMasterSecret",
        Effect: "Allow",
        Action: "secretsmanager:GetSecretValue",
        Resource: args.masterSecretArn,
        Condition: {
          StringEquals: {
            "aws:SourceVpce": args.secretsManagerVpcEndpointId,
          },
        },
      },
      {
        Sid: "DecryptExactRdsManagedMasterSecret",
        Effect: "Allow",
        Action: "kms:Decrypt",
        Resource: args.kmsKeyArn,
        Condition: {
          StringEquals: {
            "kms:ViaService": `secretsmanager.${args.region}.amazonaws.com`,
            "kms:EncryptionContext:SecretARN": args.masterSecretArn,
          },
        },
      },
    ],
  };
}

export function awsManagedPostgresDatabaseUser(identityId: string): string {
  const normalized = identityId.replace(/[^a-z0-9_]/g, "_");
  if (/^[a-z_][a-z0-9_]{0,62}$/.test(normalized)) return normalized;
  throw new Error(
    `AWS Managed Postgres identity '${identityId}' cannot become a safe PostgreSQL IAM user.`,
  );
}

function validateExtensions(
  intent: ManagedPostgresIntent,
  extensions: AwsManagedPostgresProviderExtensions,
) {
  if (
    !new Set(["aws", "aws-us-gov", "aws-cn"]).has(extensions.partition) ||
    !/^\d{12}$/.test(extensions.accountId)
  ) {
    throw new Error(
      "AWS Managed Postgres requires an exact partition and 12-digit account ID.",
    );
  }
  if (
    !regionValue(extensions.region) ||
    !regionValue(extensions.replicaRegion)
  ) {
    throw new Error(
      "AWS Managed Postgres requires valid primary and replica regions.",
    );
  }
  if (extensions.region === extensions.replicaRegion) {
    throw new Error(
      "AWS Managed Postgres replica region must differ from the primary region.",
    );
  }
  if (
    !extensions.rdsProxy ||
    !extensions.endToEndIamAuthentication ||
    !extensions.awsManagedMasterPassword
  ) {
    throw new Error(
      "AWS Managed Postgres requires RDS Proxy, end-to-end IAM authentication, and AWS-managed master credentials.",
    );
  }
  if (!/^\d+\.\d+(?:\.\d+)?$/.test(extensions.engineVersion)) {
    throw new Error("AWS Managed Postgres engineVersion must be exact.");
  }
  const engineMajor = extensions.engineVersion.split(".")[0];
  const supportedMajors = new Set(extensions.supportedMajorVersions);
  const supportedExtensions = new Set(extensions.supportedExtensions);
  for (const binding of intent.bindings) {
    if (
      binding.database.majorVersion !== engineMajor ||
      !supportedMajors.has(binding.database.majorVersion)
    ) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requires unsupported PostgreSQL major '${binding.database.majorVersion}'.`,
      );
    }
    const unsupported = binding.database.extensions.filter(
      (extension) => !supportedExtensions.has(extension),
    );
    if (unsupported.length) {
      throw new Error(
        `AWS Managed Postgres binding '${binding.id}' requires unsupported extension(s): ${unsupported.sort().join(", ")}.`,
      );
    }
  }
}

function regionValue(value: string): boolean {
  return /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(value);
}
