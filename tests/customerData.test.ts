import test from "node:test";
import assert from "node:assert/strict";
import { flushPulumiMocks, installPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("customer data store creates encrypted tenant-scoped artifact storage", async () => {
  const { resources } = await installPulumiMocks();
  const { createCustomerDataStore } = await import("../src/customerData.js");

  createCustomerDataStore({
    createArtifactStore: true,
    artifactRetentionDays: 90,
    noncurrentVersionExpirationDays: 30,
    requireTenantScopedPrefixes: true,
    requireDeletionManifests: true,
    requireExportManifests: true,
    enterpriseDedicatedKmsRequired: true,
  });

  await flushPulumiMocks();

  const kmsKeys = resourcesOfType(resources, "aws:kms/key:Key");
  const buckets = resourcesOfType(resources, "aws:s3/bucket:Bucket");
  const publicAccessBlocks = resourcesOfType(resources, "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock");
  const versioning = resourcesOfType(resources, "aws:s3/bucketVersioning:BucketVersioning");
  const encryption = resourcesOfType(
    resources,
    "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
  );
  const lifecycle = resourcesOfType(resources, "aws:s3/bucketLifecycleConfiguration:BucketLifecycleConfiguration");
  const policies = resourcesOfType(resources, "aws:s3/bucketPolicy:BucketPolicy");

  assert.equal(kmsKeys.length, 1);
  assert.equal(kmsKeys[0].inputs.enableKeyRotation, true);
  assert.equal(kmsKeys[0].inputs.deletionWindowInDays, 30);

  assert.equal(buckets.length, 1);
  assert.equal(buckets[0].inputs.forceDestroy, false);
  assert.equal(buckets[0].inputs.tags.DataClass, "customer-code");
  assert.equal(buckets[0].inputs.tags.TenantScopedPrefixes, "true");
  assert.equal(buckets[0].inputs.tags.DeletionManifests, "true");
  assert.equal(buckets[0].inputs.tags.ExportManifests, "true");

  assert.equal(publicAccessBlocks[0].inputs.blockPublicAcls, true);
  assert.equal(publicAccessBlocks[0].inputs.blockPublicPolicy, true);
  assert.equal(versioning[0].inputs.versioningConfiguration.status, "Enabled");
  assert.equal(encryption[0].inputs.rules[0].applyServerSideEncryptionByDefault.sseAlgorithm, "aws:kms");
  assert.equal(encryption[0].inputs.rules[0].blockedEncryptionTypes[0], "SSE-C");
  assert.equal(lifecycle[0].inputs.rules[0].expiration.days, 90);
  assert.equal(lifecycle[0].inputs.rules[0].noncurrentVersionExpiration.noncurrentDays, 30);
  assert.match(policies[0].inputs.policy, /DenyInsecureTransport/);
  assert.match(policies[0].inputs.policy, /DenyCustomerProvidedEncryptionKeys/);
  assert.match(policies[0].inputs.policy, /DenyWritesOutsideTenantJobPrefix/);

  const parsed = JSON.parse(policies[0].inputs.policy);
  const tenantStatement = parsed.Statement.find(
    (entry: { Sid: string }) => entry.Sid === "DenyWritesOutsideTenantJobPrefix",
  );
  assert.deepEqual(tenantStatement.Action, [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
  ]);
  assert.ok(
    tenantStatement.NotResource.some((entry: string) =>
      entry.endsWith("/tenant/*/job/*/artifact/*"),
    ),
  );
  assert.ok(
    tenantStatement.NotResource.some((entry: string) =>
      entry.endsWith("/tenant/*/job/*/manifest/*"),
    ),
  );
});
