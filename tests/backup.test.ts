import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("backup stack creates locked vaults, multi-region KMS, and a cross-region copy plan", async () => {
  const { resources } = await installPulumiMocks();
  const { createBackupStack } = await import("../src/backup");

  createBackupStack({
    replicaRegion: "us-west-2",
    vaultLockEnabled: true,
    vaultLockMinRetentionDays: 35,
    vaultLockMaxRetentionDays: 2555,
    vaultLockChangeableForDays: 3,
    createPlan: true,
    dailyScheduleExpression: "cron(0 5 ? * * *)",
    backupIntervalMinutes: 1440,
    restoreTestIntervalDays: 30,
    coldStorageAfterDays: 90,
    deleteAfterDays: 365,
    selectionTags: [{ key: "Backup", value: "required" }],
  });

  await flushPulumiMocks();

  const primaryKey = resourcesOfType(resources, "aws:kms/key:Key")[0];
  assert.equal(primaryKey.inputs.multiRegion, true);
  assert.equal(primaryKey.inputs.enableKeyRotation, true);

  const replicaKeys = resourcesOfType(
    resources,
    "aws:kms/replicaKey:ReplicaKey",
  );
  assert.equal(replicaKeys.length, 1);

  const vaults = resourcesOfType(resources, "aws:backup/vault:Vault");
  assert.equal(vaults.length, 2);
  assert.ok(vaults.every((vault) => vault.inputs.forceDestroy === false));
  assert.ok(vaults.every((vault) => vault.inputs.kmsKeyArn));

  const locks = resourcesOfType(
    resources,
    "aws:backup/vaultLockConfiguration:VaultLockConfiguration",
  );
  assert.equal(locks.length, 2);
  assert.ok(locks.every((lock) => lock.inputs.minRetentionDays === 35));
  assert.ok(locks.every((lock) => lock.inputs.changeableForDays === 3));

  const plans = resourcesOfType(resources, "aws:backup/plan:Plan");
  assert.equal(plans.length, 1);
  const rule = plans[0].inputs.rules[0];
  assert.equal(rule.enableContinuousBackup, true);
  assert.equal(rule.lifecycle.deleteAfter, 365);
  assert.equal(rule.copyActions.length, 1);

  const selections = resourcesOfType(
    resources,
    "aws:backup/selection:Selection",
  );
  assert.equal(selections.length, 1);
  assert.equal(selections[0].inputs.selectionTags[0].key, "Backup");

  const restorePlans = resourcesOfType(
    resources,
    "aws:backup/restoreTestingPlan:RestoreTestingPlan",
  );
  assert.equal(restorePlans.length, 1);
  assert.equal(
    restorePlans[0].inputs.recoveryPointSelection.algorithm,
    "LATEST_WITHIN_WINDOW",
  );
  assert.equal(restorePlans[0].inputs.scheduleExpression, "cron(0 6 1 * ? *)");
  const restoreSelections = resourcesOfType(
    resources,
    "aws:backup/restoreTestingSelection:RestoreTestingSelection",
  );
  assert.equal(restoreSelections.length, 1);
  assert.equal(restoreSelections[0].inputs.protectedResourceType, "Aurora");
  assert.equal(
    restoreSelections[0].inputs.protectedResourceConditions.stringEquals[0].key,
    "aws:ResourceTag/Backup",
  );
});
