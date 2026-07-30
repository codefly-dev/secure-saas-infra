import test from "node:test";
import assert from "node:assert/strict";
import { AgenticAiConfig, validateAgenticAiConfig } from "../src/config";

const baseline: AgenticAiConfig = {
  modelGatewayHostnames: ["api.openai.com", "api.anthropic.com"],
  permittedModelProviders: ["openai", "anthropic", "bedrock"],
  brokerEgressNamespaces: ["agent-broker", "agent-egress"],
  requirePromptAuditLog: true,
  requireToolCallAuditLog: true,
  requireOutputFiltering: true,
  perTenantTokenBudget: 1_000_000,
  perTenantInferenceTimeoutSeconds: 60,
};

test("validateAgenticAiConfig accepts the baseline", () => {
  assert.doesNotThrow(() => validateAgenticAiConfig(baseline));
});

test("validateAgenticAiConfig rejects unsafe agent control plane configuration", () => {
  assert.throws(
    () => validateAgenticAiConfig({ ...baseline, brokerEgressNamespaces: [] }),
    /brokerEgressNamespaces/,
  );

  assert.throws(
    () =>
      validateAgenticAiConfig({
        ...baseline,
        requirePromptAuditLog: false,
      }),
    /Per-tenant agent replay/,
  );

  assert.throws(
    () =>
      validateAgenticAiConfig({ ...baseline, requireOutputFiltering: false }),
    /requireOutputFiltering/,
  );

  assert.throws(
    () => validateAgenticAiConfig({ ...baseline, perTenantTokenBudget: 0 }),
    /perTenantTokenBudget/,
  );

  assert.throws(
    () =>
      validateAgenticAiConfig({
        ...baseline,
        perTenantInferenceTimeoutSeconds: 0,
      }),
    /perTenantInferenceTimeoutSeconds/,
  );
});
