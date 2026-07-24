import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  AWS_MANAGED_POSTGRES_PROVIDER_DESCRIPTOR,
  compileAwsManagedPostgres,
  type AwsManagedPostgresProviderExtensions,
} from "../src/adapters/aws";
import {
  createWardenMindBlueprint,
  parseManagedPostgresIntent,
} from "../src/core";

function fixture() {
  const blueprint = createWardenMindBlueprint({
    networkCidrs: {
      "egress-net": "10.0.0.0/16",
      "control-net": "10.10.0.0/16",
      "execution-shared-net": "10.20.0.0/16",
      "data-shared-net": "10.30.0.0/16",
    },
  });
  const intent = parseManagedPostgresIntent(
    JSON.parse(
      readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
    ),
    "development",
    blueprint,
  );
  return { blueprint, intent };
}

const extensions: AwsManagedPostgresProviderExtensions = {
  partition: "aws",
  accountId: "111111111111",
  region: "us-east-1",
  replicaRegion: "us-west-2",
  engineVersion: "16.4",
  instanceClass: "db.r6g.large",
  instanceCount: 2,
  backupRetentionDays: 35,
  supportedMajorVersions: ["16"],
  supportedExtensions: ["pgcrypto", "vector"],
  rdsProxy: true,
  endToEndIamAuthentication: true,
  awsManagedMasterPassword: true,
};

test("AWS Managed Postgres claims require end-to-end IAM Proxy and broker-owned generations", () => {
  const { blueprint, intent } = fixture();
  const generations = Object.fromEntries(
    intent.bindings.map((binding, index) => [binding.id, index + 2]),
  );
  const plan = compileAwsManagedPostgres(
    intent,
    blueprint,
    extensions,
    generations,
  );
  assert.equal(plan.claims.length, 3);
  for (const claim of plan.claims) {
    assert.equal(claim.brokerClaim.generation, generations[claim.claimId]);
    assert.ok(
      claim.brokerClaim.requiredProviderCapabilities.includes(
        "end-to-end-iam-proxy",
      ),
    );
    assert.ok(
      AWS_MANAGED_POSTGRES_PROVIDER_DESCRIPTOR.capabilities.includes(
        "end-to-end-iam-proxy",
      ),
    );
    assert.equal(claim.outputs.credentialValue, null);
  }
});

test("AWS Managed Postgres compiler rejects absent, invalid, and partial broker generations", () => {
  const { blueprint, intent } = fixture();
  for (const generations of [
    {},
    { [intent.bindings[0].id]: 0 },
    { [intent.bindings[0].id]: 1 },
  ]) {
    assert.throws(
      () =>
        compileAwsManagedPostgres(intent, blueprint, extensions, generations),
      /broker-owned positive claim generation/,
    );
  }
});
