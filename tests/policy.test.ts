import test from "node:test";
import assert from "node:assert/strict";
import { resourcePolicies } from "../policy/index";
import { stackPolicies } from "../policy/stackRules";

test("policy pack registration is unique, mandatory-capable, and executable", () => {
  assert.ok(resourcePolicies.length >= 24);
  assert.equal(
    new Set(resourcePolicies.map((policy) => policy.name)).size,
    resourcePolicies.length,
  );
  for (const policy of resourcePolicies) {
    assert.match(policy.name, /^[a-z0-9-]+$/);
    assert.ok(policy.description.length > 0);
    assert.ok(["high", "critical"].includes(policy.severity ?? ""));
    assert.equal(typeof policy.validateResource, "function");
  }
});

test("stack policy registration is unique and executable", () => {
  assert.equal(
    new Set(stackPolicies.map((policy) => policy.name)).size,
    stackPolicies.length,
  );
  assert.ok(stackPolicies.length >= 6);
  for (const policy of stackPolicies) {
    assert.match(policy.name, /^[a-z0-9-]+$/);
    assert.ok(["high", "critical"].includes(policy.severity ?? ""));
    assert.equal(typeof policy.validateStack, "function");
  }
});
