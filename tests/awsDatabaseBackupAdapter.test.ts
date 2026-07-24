import test from "node:test";
import assert from "node:assert/strict";
import { compileAwsBackups, compileAwsDatabases } from "../src/adapters/aws";
import { createReferenceBlueprint } from "../src/core";

function relationalBlueprint() {
  const blueprint = createReferenceBlueprint("dedicated-data");
  blueprint.dataBoundaries = blueprint.dataBoundaries.map((boundary) => ({
    ...boundary,
    classification: "regulated" as const,
    services: ["relational"] as const,
    objectAuditRequired: false,
    replicationRequired: true,
  }));
  return blueprint;
}

const databaseExtensions = {
  engine: "aurora-postgresql" as const,
  engineVersion: "16.4",
  instanceClass: "db.r6g.large",
  instanceCount: 2,
  backupRetentionDays: 35,
  continuousPointInTimeRecovery: true,
  replicaRegion: "us-west-2",
};

test("AWS database plans compile HA, tenant keys, regional recovery copy, and evidence", () => {
  const plan = compileAwsDatabases(relationalBlueprint(), databaseExtensions);
  assert.equal(plan.databases.length, 2);
  assert.ok(plan.databases.every((database) => database.multiAz));
  assert.ok(plan.databases.every((database) => database.deletionProtection));
  assert.ok(plan.databases.every((database) => database.finalSnapshot));
  assert.ok(plan.databases.every((database) => database.dedicatedKeyPerTenant));
  assert.ok(
    plan.databases.every(
      (database) =>
        database.regionalRecoveryCopy?.region === "us-west-2" &&
        database.regionalRecoveryCopy.mechanism === "aws-backup-copy",
    ),
  );
  assert.ok(
    plan.databases.every((database) => database.evidenceSinkId === "audit-log"),
  );
  assert.equal(
    new Set(plan.databases.map((database) => database.keyBoundaryId)).size,
    2,
  );
});

test("AWS database plans fail closed on weak HA and missing restore evidence", () => {
  assert.throws(
    () =>
      compileAwsDatabases(relationalBlueprint(), {
        ...databaseExtensions,
        instanceCount: 1,
      }),
    /at least two instances/,
  );

  const noRestoreEvidence = relationalBlueprint();
  noRestoreEvidence.evidenceRequirements =
    noRestoreEvidence.evidenceRequirements.map((requirement) => ({
      ...requirement,
      eventTypes: requirement.eventTypes.filter(
        (event) => event !== "restore-test",
      ),
    }));
  assert.throws(
    () => compileAwsDatabases(noRestoreEvidence, databaseExtensions),
    /restore-test evidence sink/,
  );
});

test("AWS backups enforce RPO, retention, vault lock, restore cadence, and regional copy", () => {
  const plan = compileAwsBackups(relationalBlueprint(), {
    vaultLockEnabled: true,
    backupIntervalMinutes: 60,
    coldStorageAfterDays: 90,
    deleteAfterDays: 365,
    replicaRegion: "us-west-2",
  });
  assert.equal(plan.backups.length, 2);
  assert.ok(plan.backups.every((backup) => backup.immutableVault));
  assert.ok(plan.backups.every((backup) => backup.retentionDays === 365));
  assert.ok(
    plan.backups.every((backup) => backup.regionalCopy?.region === "us-west-2"),
  );

  assert.throws(
    () =>
      compileAwsBackups(relationalBlueprint(), {
        vaultLockEnabled: true,
        backupIntervalMinutes: 1440,
        coldStorageAfterDays: 90,
        deleteAfterDays: 365,
        replicaRegion: "us-west-2",
      }),
    /cannot satisfy.*RPO/,
  );
  assert.throws(
    () =>
      compileAwsBackups(relationalBlueprint(), {
        vaultLockEnabled: false,
        backupIntervalMinutes: 60,
        coldStorageAfterDays: 90,
        deleteAfterDays: 365,
        replicaRegion: "us-west-2",
      }),
    /locked vault/,
  );
});
