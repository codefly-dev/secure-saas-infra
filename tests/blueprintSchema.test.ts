import test from "node:test";
import assert from "node:assert/strict";
import { parsePlatformBlueprint } from "../src/core";

function minimalBlueprint(): Record<string, unknown> {
  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: "minimal",
    environment: "test",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: false,
      requireImmutableAudit: false,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: [],
    trustZones: [],
    networkDomains: [],
    flows: [],
    workloadPlanes: [],
    applications: [],
    tenants: [],
    dataBoundaries: [],
    identities: [],
    identityDelegations: [],
    grants: [],
    evidenceSinks: [],
    evidenceRequirements: [],
  };
}

test("strict blueprint parser accepts the supported version", () => {
  const blueprint = parsePlatformBlueprint(minimalBlueprint());
  assert.equal(blueprint.apiVersion, "security.deus.dev/v1alpha1");
  assert.equal(blueprint.name, "minimal");
});

test("strict blueprint parser rejects unknown versions and fields", () => {
  assert.throws(
    () =>
      parsePlatformBlueprint({
        ...minimalBlueprint(),
        apiVersion: "security.deus.dev/v2",
      }),
    /apiVersion.*v1alpha1/,
  );
  assert.throws(
    () => parsePlatformBlueprint({ ...minimalBlueprint(), surprise: true }),
    /unknown field.*surprise/,
  );
  assert.throws(
    () =>
      parsePlatformBlueprint({
        ...minimalBlueprint(),
        posture: {
          ...(minimalBlueprint().posture as Record<string, unknown>),
          unsafeOverride: true,
        },
      }),
    /unknown field.*unsafeOverride/,
  );
});

test("strict blueprint parser rejects malformed values and secret material", () => {
  assert.throws(
    () =>
      parsePlatformBlueprint({
        ...minimalBlueprint(),
        requiredCapabilities: ["magic-cloud"],
      }),
    /requiredCapabilities\[0\].*must be one of/,
  );
  assert.throws(
    () =>
      parsePlatformBlueprint({
        ...minimalBlueprint(),
        password: "do-not-put-secrets-in-intent",
      }),
    /secret material is not permitted/,
  );
});
