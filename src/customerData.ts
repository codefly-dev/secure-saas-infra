import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { CustomerDataConfig, baseTags, named } from "./config";

export interface CustomerDataStoreResult {
  artifactBucket?: aws.s3.Bucket;
  artifactKmsKey?: aws.kms.Key;
}

export function createCustomerDataStore(config: CustomerDataConfig): CustomerDataStoreResult {
  if (!config.createArtifactStore) {
    return {};
  }

  const current = aws.getCallerIdentityOutput({});
  const partition = aws.getPartitionOutput({});

  const artifactKmsKey = new aws.kms.Key(named("customer-artifacts-key"), {
    description: "KMS key for customer code artifacts and execution outputs.",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    policy: pulumi.all([current.accountId, partition.partition]).apply(([accountId, partitionName]) =>
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
    tags: tag("customer-artifacts-key", { DataClass: "customer-code" }),
  });

  new aws.kms.Alias(named("customer-artifacts-key-alias"), {
    name: `alias/${named("customer-artifacts")}`,
    targetKeyId: artifactKmsKey.keyId,
  });

  const artifactBucket = new aws.s3.Bucket(named("customer-artifacts"), {
    forceDestroy: false,
    tags: tag("customer-artifacts", {
      DataClass: "customer-code",
      TenantScopedPrefixes: String(config.requireTenantScopedPrefixes),
      DeletionManifests: String(config.requireDeletionManifests),
      ExportManifests: String(config.requireExportManifests),
    }),
  });

  const publicAccessBlock = new aws.s3.BucketPublicAccessBlock(
    named("customer-artifacts-public-access-block"),
    {
      bucket: artifactBucket.id,
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
  );

  const versioning = new aws.s3.BucketVersioning(named("customer-artifacts-versioning"), {
    bucket: artifactBucket.id,
    versioningConfiguration: {
      status: "Enabled",
    },
  });

  const encryption = new aws.s3.BucketServerSideEncryptionConfiguration(
    named("customer-artifacts-encryption"),
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

  new aws.s3.BucketLifecycleConfiguration(named("customer-artifacts-lifecycle"), {
    bucket: artifactBucket.id,
    rules: [
      {
        id: "expire-customer-artifacts",
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
    named("customer-artifacts-policy"),
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

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
