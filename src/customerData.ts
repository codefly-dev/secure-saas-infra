import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { CustomerDataConfig, baseTags, named } from "./config";
import type { PlatformBlueprint } from "./core";
import {
  AwsArtifactStoragePlan,
  compileAwsDataBoundaries,
} from "./adapters/aws";

export interface CustomerDataStoreResult {
  artifactBucket?: aws.s3.Bucket;
  artifactKmsKey?: aws.kms.Key;
}

export interface CustomerDataStoresResult extends CustomerDataStoreResult {
  stores: Readonly<Record<string, CustomerDataStoreResult>>;
  plan: readonly AwsArtifactStoragePlan[];
}

export function createCustomerDataStoresFromBlueprint(
  blueprint: PlatformBlueprint,
  config: CustomerDataConfig,
): CustomerDataStoresResult {
  const dataPlan = compileAwsDataBoundaries(blueprint, {
    noncurrentVersionExpirationDays: config.noncurrentVersionExpirationDays,
    replicationRegion: config.replicationRegion,
    replicationAccountId: config.replicationAccountId,
  });
  const stores = Object.fromEntries(
    dataPlan.artifactStores.map((storePlan) => [
      storePlan.boundaryId,
      createCustomerDataStore(
        {
          ...config,
          createArtifactStore: true,
          artifactRetentionDays: storePlan.retentionDays,
          requireTenantScopedPrefixes:
            storePlan.tenantScope.mode !== "platform",
          requireDeletionManifests: storePlan.deletionManifestRequired,
          requireExportManifests: storePlan.exportManifestRequired,
          enterpriseDedicatedKmsRequired: storePlan.dedicatedKeyPerTenant,
        },
        {
          resourceName: `customer-artifacts-${safeName(storePlan.boundaryId)}`,
          plan: storePlan,
        },
      ),
    ]),
  );
  const first = Object.values(stores)[0];
  return {
    stores,
    plan: dataPlan.artifactStores,
    artifactBucket: first?.artifactBucket,
    artifactKmsKey: first?.artifactKmsKey,
  };
}

export function createCustomerDataStore(
  config: CustomerDataConfig,
  options: { resourceName?: string; plan?: AwsArtifactStoragePlan } = {},
): CustomerDataStoreResult {
  if (!config.createArtifactStore) {
    return {};
  }

  const current = aws.getCallerIdentityOutput({});
  const partition = aws.getPartitionOutput({});
  const resourceName = options.resourceName ?? "customer-artifacts";

  const artifactKmsKey = new aws.kms.Key(named(`${resourceName}-key`), {
    description: "KMS key for customer code artifacts and execution outputs.",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    policy: pulumi
      .all([current.accountId, partition.partition])
      .apply(([accountId, partitionName]) =>
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "EnableRootAccountAdministration",
              Effect: "Allow",
              Principal: { AWS: `arn:${partitionName}:iam::${accountId}:root` },
              Action: "kms:*",
              Resource: "*",
            },
          ],
        }),
      ),
    tags: tag(`${resourceName}-key`, ownershipTags(options.plan)),
  });

  new aws.kms.Alias(named(`${resourceName}-key-alias`), {
    name: `alias/${named(resourceName)}`,
    targetKeyId: artifactKmsKey.keyId,
  });

  const artifactBucket = new aws.s3.Bucket(named(resourceName), {
    forceDestroy: false,
    tags: tag(resourceName, {
      ...ownershipTags(options.plan),
      TenantScopedPrefixes: String(config.requireTenantScopedPrefixes),
      DeletionManifests: String(config.requireDeletionManifests),
      ExportManifests: String(config.requireExportManifests),
    }),
  });

  const publicAccessBlock = new aws.s3.BucketPublicAccessBlock(
    named(`${resourceName}-public-access-block`),
    {
      bucket: artifactBucket.id,
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
  );

  const versioning = new aws.s3.BucketVersioning(
    named(`${resourceName}-versioning`),
    {
      bucket: artifactBucket.id,
      versioningConfiguration: {
        status: "Enabled",
      },
    },
  );

  const encryption = new aws.s3.BucketServerSideEncryptionConfiguration(
    named(`${resourceName}-encryption`),
    {
      bucket: artifactBucket.id,
      rules: [
        {
          applyServerSideEncryptionByDefault: {
            kmsMasterKeyId: artifactKmsKey.arn,
            sseAlgorithm: "aws:kms",
          },
          bucketKeyEnabled: true,
          blockedEncryptionTypes: ["SSE-C"],
        },
      ],
    },
  );

  new aws.s3.BucketLifecycleConfiguration(named(`${resourceName}-lifecycle`), {
    bucket: artifactBucket.id,
    rules: [
      {
        id: `expire-${resourceName}`,
        status: "Enabled",
        filter: {},
        expiration: {
          days: config.artifactRetentionDays,
        },
        noncurrentVersionExpiration: {
          noncurrentDays: config.noncurrentVersionExpirationDays,
        },
        abortIncompleteMultipartUpload: {
          daysAfterInitiation: 7,
        },
      },
    ],
  });

  const tenantPrefixStatements = config.requireTenantScopedPrefixes
    ? [
        {
          Sid: "DenyWritesOutsideTenantJobPrefix",
          Effect: "Deny",
          Principal: "*",
          Action: ["s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"],
          NotResource: [
            "${bucketArn}/tenant/*/job/*/artifact/*",
            "${bucketArn}/tenant/*/job/*/manifest/*",
          ],
          // Object writes must use the broker-controlled tenant/<id>/job/<id>/...
          // prefix described in docs/customer-data.md.
        },
      ]
    : [];

  new aws.s3.BucketPolicy(
    named(`${resourceName}-policy`),
    {
      bucket: artifactBucket.id,
      policy: artifactBucket.arn.apply((bucketArn) => {
        const renderedTenantStatements = tenantPrefixStatements.map(
          (statement) => ({
            ...statement,
            NotResource: statement.NotResource.map((entry) =>
              entry.replace("${bucketArn}", bucketArn),
            ),
          }),
        );

        return JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "DenyInsecureTransport",
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: [bucketArn, `${bucketArn}/*`],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
            {
              Sid: "DenyCustomerProvidedEncryptionKeys",
              Effect: "Deny",
              Principal: "*",
              Action: "s3:PutObject",
              Resource: `${bucketArn}/*`,
              Condition: {
                Null: {
                  "s3:x-amz-server-side-encryption-customer-algorithm": "false",
                },
              },
            },
            ...renderedTenantStatements,
          ],
        });
      }),
    },
    { dependsOn: [publicAccessBlock, encryption, versioning] },
  );

  return { artifactBucket, artifactKmsKey };
}

function ownershipTags(
  plan: AwsArtifactStoragePlan | undefined,
): Record<string, string> {
  if (!plan) {
    return { DataClass: "customer-code", EvidenceSinkId: "audit-log" };
  }
  return {
    DataClass: plan.classification,
    DataBoundaryId: plan.boundaryId,
    BucketBoundaryId: plan.bucketBoundaryId,
    KeyBoundaryId: plan.keyBoundaryId,
    TenantOwners: plan.ownership.ownerTenantIds.join(","),
    SharedBoundary: String(plan.ownership.shared),
    ObjectAuditEvents: plan.objectAuditEvents.join(","),
    EvidenceSinkId: plan.evidenceSinkId,
  };
}

function safeName(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  if (!normalized || normalized.length > 40) {
    throw new Error(
      `Data boundary ID '${value}' cannot produce an AWS resource name.`,
    );
  }
  return normalized;
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
