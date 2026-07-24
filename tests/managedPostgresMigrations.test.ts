import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  createWardenMindBlueprint,
  downgradeManagedPostgresV1alpha2ToV1alpha1,
  managedPostgresIntentDigest,
  migrateManagedPostgresV1alpha1ToV1alpha2,
  parseManagedPostgresIntent,
} from "../src/core";

const blueprint = createWardenMindBlueprint();
const v1alpha1Source = readFileSync(
  "contracts/managed-postgres-v1alpha1.json",
  "utf8",
);
const v1alpha1 = JSON.parse(v1alpha1Source);
const v1alpha2 = JSON.parse(
  readFileSync("contracts/managed-postgres-v1alpha2.json", "utf8"),
);

test("Managed Postgres v1alpha1 bytes and semantic digest remain frozen", () => {
  assert.equal(
    createHash("sha256").update(v1alpha1Source).digest("hex"),
    "d7958702201bf0f9c183e872edf81b983bba7c75658d475bdc04831d2e1c9422",
  );
  assert.equal(
    managedPostgresIntentDigest(
      parseManagedPostgresIntent(v1alpha1, "development", blueprint),
    ),
    "a4585bffe16a8282b96705f36af1809981b446f4b8d6112645e8153f641e843e",
  );
});

test("v1alpha1 migration deterministically produces the checked v1alpha2 contract", () => {
  const migrated = migrateManagedPostgresV1alpha1ToV1alpha2(v1alpha1, {
    environment: "development",
    blueprint,
    organizationId: "deus",
    platformTenantIds: {
      warden: "tenant-warden",
      mind: "tenant-mind",
    },
  });
  assert.deepEqual(migrated, v1alpha2);
  const parsed = parseManagedPostgresIntent(migrated, "development", blueprint);
  assert.ok(
    parsed.bindings.every(
      (binding) =>
        binding.tenancy?.applicationId === binding.tenantId &&
        binding.tenancy.resourceOwnerId === binding.access.runtimeIdentityId,
    ),
  );
});

test("v1alpha2 rejects tenant substitution and resource-owner substitution", () => {
  const tenantSubstitution = structuredClone(v1alpha2);
  tenantSubstitution.bindings[1].tenancy.platformTenantId = "tenant-warden";
  assert.throws(
    () =>
      parseManagedPostgresIntent(tenantSubstitution, "development", blueprint),
    /platform tenant boundary/i,
  );

  const ownerSubstitution = structuredClone(v1alpha2);
  ownerSubstitution.bindings[0].tenancy.resourceOwnerId = "mind-infra-service";
  assert.throws(
    () =>
      parseManagedPostgresIntent(ownerSubstitution, "development", blueprint),
    /tenancy owner chain/i,
  );
});

test("Managed Postgres versions fail closed on future versions and lossy downgrade", () => {
  assert.throws(
    () =>
      parseManagedPostgresIntent(
        { ...v1alpha2, apiVersion: "security.deus.dev/managed-postgres/v9" },
        "development",
        blueprint,
      ),
    /apiVersion/,
  );
  assert.throws(
    () => downgradeManagedPostgresV1alpha2ToV1alpha1(),
    /MANAGED_POSTGRES_DOWNGRADE_DENIED/,
  );
  assert.throws(
    () =>
      migrateManagedPostgresV1alpha1ToV1alpha2(v1alpha2, {
        environment: "development",
        blueprint,
        organizationId: "deus",
        platformTenantIds: {},
      }),
    /MIGRATION_SOURCE_DENIED/,
  );
});
