import test from "node:test";
import assert from "node:assert/strict";
import { compileAwsDataBoundaries } from "../src/adapters/aws";
import {
  createHostileReferenceBlueprints,
  createReferenceBlueprint,
} from "../src/core";

test("AWS pooled storage plan has explicit shared bucket/key ownership", () => {
  const plan = compileAwsDataBoundaries(createReferenceBlueprint("pooled"), {
    noncurrentVersionExpirationDays: 30,
  });
  assert.equal(plan.artifactStores.length, 1);
  assert.equal(plan.artifactStores[0].ownership.shared, true);
  assert.deepEqual(plan.artifactStores[0].ownership.ownerTenantIds, [
    "tenant-a",
    "tenant-b",
  ]);
  assert.deepEqual(plan.artifactStores[0].objectAuditEvents, [
    "read",
    "write",
    "delete",
  ]);
});

test("AWS dedicated-data tenants receive distinct bucket and key boundaries", () => {
  const plan = compileAwsDataBoundaries(
    createReferenceBlueprint("dedicated-data"),
    { noncurrentVersionExpirationDays: 30 },
  );
  assert.equal(plan.artifactStores.length, 2);
  assert.equal(
    new Set(plan.artifactStores.map((entry) => entry.bucketBoundaryId)).size,
    2,
  );
  assert.equal(
    new Set(plan.artifactStores.map((entry) => entry.keyBoundaryId)).size,
    2,
  );
  assert.ok(plan.artifactStores.every((entry) => entry.dedicatedKeyPerTenant));
});

test("AWS data compilation fails closed on cross-tenant access and weak audit", () => {
  const hostile = createHostileReferenceBlueprints()["cross-tenant-grant"];
  assert.throws(
    () =>
      compileAwsDataBoundaries(hostile.blueprint, {
        noncurrentVersionExpirationDays: 30,
      }),
    /IDENTITY_CROSS_TENANT_GRANT/,
  );

  const noAudit = createReferenceBlueprint("pooled");
  noAudit.dataBoundaries = noAudit.dataBoundaries.map((boundary) => ({
    ...boundary,
    objectAuditRequired: false,
  }));
  assert.throws(
    () =>
      compileAwsDataBoundaries(noAudit, {
        noncurrentVersionExpirationDays: 30,
      }),
    /DATA_OBJECT_AUDIT_MISSING/,
  );
});

test("AWS required replication needs an explicit provider target", () => {
  const blueprint = createReferenceBlueprint("pooled");
  blueprint.dataBoundaries = blueprint.dataBoundaries.map((boundary) => ({
    ...boundary,
    replicationRequired: true,
  }));
  assert.throws(
    () =>
      compileAwsDataBoundaries(blueprint, {
        noncurrentVersionExpirationDays: 30,
      }),
    /replication region/,
  );
});
