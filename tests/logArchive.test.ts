import test from "node:test";
import assert from "node:assert/strict";
import { installPulumiMocks, flushPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("log archive creates immutable encrypted audit storage", async () => {
  const { resources } = await installPulumiMocks();
  const { createLogArchive } = await import("../src/logArchive.js");

  createLogArchive({
    objectLockRetentionDays: 2555,
    transitionToGlacierDays: 90,
    cloudTrailPrefix: "cloudtrail",
    createOrganizationTrail: true,
    organizationTrailName: "deus-organization-trail",
    cloudTrailSourceAccountId: "111111111111",
    s3DataEventBucketArns: [
      "arn:aws:s3:::deus-customer-artifacts",
      "arn:aws:s3:::deus-vault-backups",
    ],
  });

  await flushPulumiMocks();

  const bucket = resourcesOfType(resources, "aws:s3/bucket:Bucket")[0];
  const publicAccessBlock = resourcesOfType(resources, "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock")[0];
  const versioning = resourcesOfType(resources, "aws:s3/bucketVersioning:BucketVersioning")[0];
  const objectLock = resourcesOfType(
    resources,
    "aws:s3/bucketObjectLockConfiguration:BucketObjectLockConfiguration",
  )[0];
  const encryption = resourcesOfType(
    resources,
    "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
  )[0];
  const kmsKey = resourcesOfType(resources, "aws:kms/key:Key")[0];
  const policy = resourcesOfType(resources, "aws:s3/bucketPolicy:BucketPolicy")[0];
  const trail = resourcesOfType(resources, "aws:cloudtrail/trail:Trail")[0];

  assert.equal(bucket.inputs.objectLockEnabled, true);
  assert.equal(bucket.inputs.forceDestroy, false);
  assert.equal(publicAccessBlock.inputs.blockPublicAcls, true);
  assert.equal(publicAccessBlock.inputs.blockPublicPolicy, true);
  assert.equal(publicAccessBlock.inputs.ignorePublicAcls, true);
  assert.equal(publicAccessBlock.inputs.restrictPublicBuckets, true);
  assert.equal(versioning.inputs.versioningConfiguration.status, "Enabled");
  assert.equal(objectLock.inputs.rule.defaultRetention.mode, "COMPLIANCE");
  assert.equal(objectLock.inputs.rule.defaultRetention.days, 2555);
  assert.equal(encryption.inputs.rules[0].applyServerSideEncryptionByDefault.sseAlgorithm, "aws:kms");
  assert.equal(encryption.inputs.rules[0].blockedEncryptionTypes[0], "SSE-C");
  assert.equal(kmsKey.inputs.enableKeyRotation, true);

  const parsedKmsPolicy = JSON.parse(kmsKey.inputs.policy);
  const cloudTrailKmsStatement = parsedKmsPolicy.Statement.find(
    (statement: { Sid: string }) => statement.Sid === "AllowCloudTrailEncryption",
  );
  assert.equal(
    cloudTrailKmsStatement.Condition.StringEquals["aws:SourceAccount"],
    "111111111111",
  );
  assert.match(
    cloudTrailKmsStatement.Condition.StringEquals["aws:SourceArn"],
    /:cloudtrail:.+:trail\/deus-organization-trail$/,
  );

  const parsedBucketPolicy = JSON.parse(policy.inputs.policy);
  for (const sid of ["AWSCloudTrailAclCheck", "AWSCloudTrailWrite"]) {
    const statement = parsedBucketPolicy.Statement.find(
      (entry: { Sid: string }) => entry.Sid === sid,
    );
    assert.ok(statement, `expected statement ${sid}`);
    assert.equal(
      statement.Condition.StringEquals["aws:SourceAccount"],
      "111111111111",
    );
  }

  assert.match(policy.inputs.policy, /DenyInsecureTransport/);
  assert.match(policy.inputs.policy, /AWSCloudTrailWrite/);

  assert.deepEqual(trail.inputs.eventSelectors[0].dataResources, [
    {
      type: "AWS::S3::Object",
      values: [
        "arn:aws:s3:::deus-customer-artifacts",
        "arn:aws:s3:::deus-customer-artifacts/",
        "arn:aws:s3:::deus-vault-backups",
        "arn:aws:s3:::deus-vault-backups/",
      ],
    },
  ]);
});

test("organization audit stack creates the management-account organization trail", async () => {
  const { resources } = await installPulumiMocks();
  const { createOrganizationAudit } = await import("../src/organizationAudit.js");

  createOrganizationAudit({
    logArchiveStackRef: "org/secure-saas-infra/log-archive",
    organizationTrailName: "deus-organization-trail",
    cloudTrailPrefix: "cloudtrail",
    s3DataEventBucketArns: ["arn:aws:s3:::deus-customer-artifacts"],
  });

  await flushPulumiMocks();

  const trail = resourcesOfType(resources, "aws:cloudtrail/trail:Trail")[0];
  assert.equal(trail.inputs.isOrganizationTrail, true);
  assert.equal(trail.inputs.isMultiRegionTrail, true);
  assert.equal(trail.inputs.enableLogFileValidation, true);
  assert.equal(trail.inputs.eventSelectors[0].readWriteType, "All");
  assert.equal(trail.inputs.eventSelectors[0].includeManagementEvents, true);
  assert.deepEqual(trail.inputs.eventSelectors[0].dataResources, [
    {
      type: "AWS::S3::Object",
      values: [
        "arn:aws:s3:::deus-customer-artifacts",
        "arn:aws:s3:::deus-customer-artifacts/",
      ],
    },
  ]);
});
