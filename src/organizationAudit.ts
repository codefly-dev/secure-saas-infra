import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { OrganizationAuditConfig, baseTags, named } from "./config";

export function createOrganizationAudit(config: OrganizationAuditConfig) {
  const logArchive = new pulumi.StackReference("log-archive", {
    name: config.logArchiveStackRef,
  });
  const bucketName = logArchive.requireOutput(
    "logArchiveBucketName",
  ) as pulumi.Output<string>;
  const kmsKeyArn = logArchive.requireOutput(
    "logArchiveKmsKeyArn",
  ) as pulumi.Output<string>;
  const archiveTrailName = logArchive.requireOutput(
    "logArchiveOrganizationTrailName",
  ) as pulumi.Output<string>;
  const archiveSourceAccountId = logArchive.requireOutput(
    "logArchiveCloudTrailSourceAccountId",
  ) as pulumi.Output<string>;

  const callerAccountId = aws.getCallerIdentityOutput({}).accountId;

  const trailName = pulumi
    .all([archiveTrailName, archiveSourceAccountId, callerAccountId])
    .apply(([expectedTrailName, expectedAccountId, currentAccountId]) => {
      if (expectedTrailName !== config.organizationTrailName) {
        throw new Error(
          `organizationAudit.organizationTrailName '${config.organizationTrailName}' must match log-archive '${expectedTrailName}' so the bucket policy and KMS key trust the same trail ARN.`,
        );
      }

      if (expectedAccountId !== currentAccountId) {
        throw new Error(
          `organization-audit must run in the AWS Organizations management account. log-archive expects trail source account '${expectedAccountId}' but this stack is in '${currentAccountId}'.`,
        );
      }

      return expectedTrailName;
    });

  const dataResources = config.s3DataEventBucketArns.flatMap((arn) => [
    arn,
    `${arn}/`,
  ]);

  const eventSelectors: aws.types.input.cloudtrail.TrailEventSelector[] = [
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
  ];

  const trail = new aws.cloudtrail.Trail(config.organizationTrailName, {
    name: trailName,
    s3BucketName: bucketName,
    s3KeyPrefix: config.cloudTrailPrefix,
    kmsKeyId: kmsKeyArn,
    isOrganizationTrail: true,
    isMultiRegionTrail: true,
    includeGlobalServiceEvents: true,
    enableLogFileValidation: true,
    enableLogging: true,
    insightSelectors: [
      { insightType: "ApiCallRateInsight" },
      { insightType: "ApiErrorRateInsight" },
    ],
    eventSelectors,
    tags: tag("organization-trail"),
  });

  return { trail };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
