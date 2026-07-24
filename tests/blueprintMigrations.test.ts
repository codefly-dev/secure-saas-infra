import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadPlatformBlueprint } from "../src/core";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(`tests/fixtures/blueprints/${name}.json`, "utf8"),
  );
}

test("v1alpha0 migration is lossless and matches the frozen v1alpha1 fixture", () => {
  const source = fixture("v1alpha0") as Record<string, unknown>;
  const loaded = loadPlatformBlueprint(source);
  assert.equal(loaded.migrationReport.migrated, true);
  assert.equal(
    loaded.migrationReport.targetVersion,
    "security.deus.dev/v1alpha1",
  );
  assert.deepEqual(loaded.blueprint, fixture("v1alpha1"));
  assert.deepEqual(loaded.blueprint.posture, source.posture);
});

test("current-version loading emits an empty migration report", () => {
  const loaded = loadPlatformBlueprint(fixture("v1alpha1"));
  assert.equal(loaded.migrationReport.migrated, false);
  assert.deepEqual(loaded.migrationReport.changes, []);
});

test("unknown future versions fail closed", () => {
  assert.throws(
    () =>
      loadPlatformBlueprint({
        ...(fixture("v1alpha1") as Record<string, unknown>),
        apiVersion: "security.deus.dev/v99",
      }),
    /unsupported version.*v99/,
  );
});
