import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  AgenticAiConfig,
  validateAgenticAiConfig,
} from "../src/config";

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
    () =>
      validateAgenticAiConfig({ ...baseline, brokerEgressNamespaces: [] }),
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
    () =>
      validateAgenticAiConfig({ ...baseline, perTenantTokenBudget: 0 }),
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

test("agent broker GitOps manifests gate the namespace and require audit metadata", () => {
  const namespace = readFileSync(
    "gitops/base/namespaces/agent-broker.yaml",
    "utf8",
  );
  const networkPolicy = readFileSync(
    "gitops/base/network-policies/default-deny-agent-broker.yaml",
    "utf8",
  );
  const allowEgress = readFileSync(
    "gitops/base/network-policies/allow-broker-to-egress.yaml",
    "utf8",
  );
  const kyverno = readFileSync(
    "gitops/base/kyverno/require-agent-audit.yaml",
    "utf8",
  );

  assert.match(namespace, /pod-security.kubernetes.io\/enforce: restricted/);
  assert.match(networkPolicy, /policyTypes:\s*\n\s*-\s*Ingress\s*\n\s*-\s*Egress/);
  assert.match(allowEgress, /agent-egress/);
  assert.match(kyverno, /security.deus.dev\/tenant-id/);
  assert.match(kyverno, /security.deus.dev\/principal-id/);
  assert.match(kyverno, /security.deus.dev\/turn-id/);
  assert.match(kyverno, /security.deus.dev\/prompt-audit-sink/);
  assert.match(kyverno, /security.deus.dev\/tool-audit-sink/);
  assert.match(kyverno, /deny-broker-direct-model-call/);
});
