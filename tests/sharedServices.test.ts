import test from "node:test";
import assert from "node:assert/strict";
import { installPulumiMocks, flushPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("shared services bootstraps Vault KMS, backup storage, and Tailscale secrets", async () => {
  const { resources } = await installPulumiMocks();
  const { createSharedServices } = await import("../src/sharedServices");

  createSharedServices({
    createVaultAutoUnsealKey: true,
    createVaultBackupBucket: true,
    vaultBackupRetentionDays: 90,
    createTailscaleBootstrapSecrets: true,
  });

  await flushPulumiMocks();

  const kmsKey = resourcesOfType(resources, "aws:kms/key:Key")[0];
  const bucket = resourcesOfType(resources, "aws:s3/bucket:Bucket")[0];
  const publicAccessBlock = resourcesOfType(resources, "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock")[0];
  const secrets = resourcesOfType(resources, "aws:secretsmanager/secret:Secret");

  assert.equal(kmsKey.inputs.enableKeyRotation, true);
  assert.equal(bucket.inputs.objectLockEnabled, true);
  assert.equal(bucket.inputs.forceDestroy, false);
  assert.equal(publicAccessBlock.inputs.restrictPublicBuckets, true);
  assert.deepEqual(
    secrets.map((secret) => secret.inputs.name).sort(),
    ["deus-unit-tailscale-oauth-client-id", "deus-unit-tailscale-oauth-client-secret"],
  );
});
