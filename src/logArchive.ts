import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { LogArchiveConfig, baseTags, named, awsRegion } from "./config";

export interface LogArchiveResult {
  bucket: aws.s3.Bucket;
  kmsKey: aws.kms.Key;
  trail?: aws.cloudtrail.Trail;
  organizationTrailName: string;
  cloudTrailSourceAccountId: pulumi.Output<string>;
}

export function createLogArchive(config: LogArchiveConfig): LogArchiveResult {
  const current = aws.getCallerIdentityOutput({});
  const partition = aws.getPartitionOutput({});
  const sourceAccountId = config.cloudTrailSourceAccountId
    ? pulumi.output(config.cloudTrailSourceAccountId)
    : current.accountId;
  const trailName = config.organizationTrailName;
  const trailArn = pulumi
    .all([partition.partition, sourceAccountId])
    .apply(
      ([partitionName, accountId]) =>
        `arn:${partitionName}:cloudtrail:${awsRegion}:${accountId}:trail/${trailName}`,
    );

  const key = new aws.kms.Key(named("log-archive-key"), {
    description: "KMS key for immutable audit log archive.",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    policy: pulumi
      .all([current.accountId, partition.partition, trailArn, sourceAccountId])
      .apply(
        ([accountId, partitionName, cloudTrailArn, trailSourceAccountId]) =>
          JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "EnableRootAccountAdministration",
                Effect: "Allow",
                Principal: {
                  AWS: `arn:${partitionName}:iam::${accountId}:root`,
                },
                Action: "kms:*",
                Resource: "*",
              },
              {
                Sid: "AllowCloudTrailEncryption",
                Effect: "Allow",
                Principal: { Service: "cloudtrail.amazonaws.com" },
                Action: ["kms:GenerateDataKey*", "kms:DescribeKey"],
                Resource: "*",
                Condition: {
                  StringEquals: {
                    "aws:SourceArn": cloudTrailArn,
                    "aws:SourceAccount": trailSourceAccountId,
                  },
                },
              },
            ],
          }),
      ),
    tags: tag("log-archive-key"),
  });

  new aws.kms.Alias(named("log-archive-key-alias"), {
    name: `alias/${named("log-archive")}`,
    targetKeyId: key.keyId,
  });

  const bucket = new aws.s3.Bucket(named("audit-logs"), {
    bucket: config.bucketName,
    objectLockEnabled: true,
    forceDestroy: false,
    tags: tag("audit-logs", { DataClass: "audit" }),
  });

  const publicAccessBlock = new aws.s3.BucketPublicAccessBlock(
    named("audit-logs-public-access-block"),
    {
      bucket: bucket.id,
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
  );

  const versioning = new aws.s3.BucketVersioning(
    named("audit-logs-versioning"),
    {
      bucket: bucket.id,
      versioningConfiguration: {
        status: "Enabled",
      },
    },
  );

  const encryption = new aws.s3.BucketServerSideEncryptionConfiguration(
    named("audit-logs-encryption"),
    {
      bucket: bucket.id,
      rules: [
        {
          applyServerSideEncryptionByDefault: {
            kmsMasterKeyId: key.arn,
            sseAlgorithm: "aws:kms",
          },
          bucketKeyEnabled: true,
          blockedEncryptionTypes: ["SSE-C"],
        },
      ],
    },
  );

  new aws.s3.BucketObjectLockConfiguration(
    named("audit-logs-object-lock"),
    {
      bucket: bucket.id,
      objectLockEnabled: "Enabled",
      rule: {
        defaultRetention: {
          mode: "COMPLIANCE",
          days: config.objectLockRetentionDays,
        },
      },
    },
    { dependsOn: versioning },
  );

  new aws.s3.BucketLifecycleConfiguration(named("audit-logs-lifecycle"), {
    bucket: bucket.id,
    rules: [
      {
        id: "transition-audit-logs",
        status: "Enabled",
        filter: {},
        transitions: [
          {
            days: config.transitionToGlacierDays,
            storageClass: "DEEP_ARCHIVE",
          },
        ],
        noncurrentVersionTransitions: [
          {
            noncurrentDays: config.transitionToGlacierDays,
            storageClass: "DEEP_ARCHIVE",
          },
        ],
        abortIncompleteMultipartUpload: {
          daysAfterInitiation: 7,
        },
      },
    ],
  });

  const bucketPolicy = new aws.s3.BucketPolicy(
    named("audit-logs-policy"),
    {
      bucket: bucket.id,
      policy: pulumi
        .all([bucket.arn, trailArn, sourceAccountId])
        .apply(([bucketArn, cloudTrailArn, trailSourceAccountId]) =>
          JSON.stringify({
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
                Sid: "AWSCloudTrailAclCheck",
                Effect: "Allow",
                Principal: { Service: "cloudtrail.amazonaws.com" },
                Action: "s3:GetBucketAcl",
                Resource: bucketArn,
                Condition: {
                  StringEquals: {
                    "aws:SourceArn": cloudTrailArn,
                    "aws:SourceAccount": trailSourceAccountId,
                  },
                },
              },
              {
                Sid: "AWSCloudTrailWrite",
                Effect: "Allow",
                Principal: { Service: "cloudtrail.amazonaws.com" },
                Action: "s3:PutObject",
                Resource: `${bucketArn}/${config.cloudTrailPrefix}/AWSLogs/*`,
                Condition: {
                  StringEquals: {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "aws:SourceArn": cloudTrailArn,
                    "aws:SourceAccount": trailSourceAccountId,
                  },
                },
              },
            ],
          }),
        ),
    },
    { dependsOn: [publicAccessBlock, encryption] },
  );

  const dataResources = config.s3DataEventBucketArns.flatMap((arn) => [
    arn,
    `${arn}/`,
  ]);

  const trail = config.createOrganizationTrail
    ? new aws.cloudtrail.Trail(
        trailName,
        {
          name: trailName,
          s3BucketName: bucket.id,
          s3KeyPrefix: config.cloudTrailPrefix,
          kmsKeyId: key.arn,
          isOrganizationTrail: true,
          isMultiRegionTrail: true,
          includeGlobalServiceEvents: true,
          enableLogFileValidation: true,
          enableLogging: true,
          insightSelectors: [
            { insightType: "ApiCallRateInsight" },
            { insightType: "ApiErrorRateInsight" },
          ],
          eventSelectors: [
            {
              readWriteType: "All",
              includeManagementEvents: true,
              ...(dataResources.length > 0
                ? {
                    dataResources: [
                      {
                        type: "AWS::S3::Object",
                        values: dataResources,
                      },
                    ],
                  }
                : {}),
            },
          ],
          tags: tag(`${config.organizationTrailName}-trail`),
        },
        { dependsOn: [bucketPolicy] },
      )
    : undefined;

  return {
    bucket,
    kmsKey: key,
    trail,
    organizationTrailName: trailName,
    cloudTrailSourceAccountId: sourceAccountId,
  };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
