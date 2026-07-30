# Agentic AI Guardrails

Customer code paired with agentic AI changes the threat model: the platform
runs LLMs on behalf of tenants, calls third-party tools, and persists prompts,
completions, and tool-call traces. Treat that as confidential customer data
with extra controls around model egress, prompt injection, output filtering,
and per-tenant isolation.

## Boundary

| Namespace      | Trust zone          | Talks to                                                 |
| -------------- | ------------------- | -------------------------------------------------------- |
| `agent-broker` | agent-control-plane | `agent-egress` only (8443).                              |
| `agent-egress` | agent-egress        | Approved model providers via the centralized egress VPC. |
| `execution`    | untrusted-code      | brokered tool calls only.                                |

`agent-broker` is where the per-tenant orchestrator runs. It owns the
prompt+tool-call+completion ledger, signs tool calls, enforces per-tenant
quotas, and writes the audit trail. It is _not_ allowed to make direct calls
to OpenAI / Anthropic / Bedrock — those go through `agent-egress`.

`agent-egress` runs the model gateway (LiteLLM, your own gateway, or Bedrock
endpoints). The gateway terminates client mTLS from `agent-broker`, enforces
model allowlists, redacts known PII, and forwards to the provider through the
centralized egress VPC.

Both namespaces run with `pod-security.kubernetes.io/enforce: restricted`, the
default-deny NetworkPolicy, and Istio ambient mode.

## Kyverno policy

The platform repository's
[`require-agent-audit.yaml`](https://github.com/codefly-dev/secure-saas-platform/blob/v0.1.0/gitops/base/kyverno/require-agent-audit.yaml)
enforces:

- pods in `agent-broker` and `agent-egress` carry tenant/principal/turn
  metadata labels and prompt/tool audit annotations;
- containers declare CPU, memory, and ephemeral-storage limits;
- pods in `agent-broker` are denied if they request
  `security.deus.dev/direct-model-call: "true"` — the broker must route
  through `agent-egress`.

## Pulumi config

`secure-saas-infra:agenticAi` (defaults below) is enforced by the
`validateAgenticAiConfig` validator on `platform` and `execution` stacks:

```yaml
secure-saas-infra:agenticAi:
  modelGatewayHostnames:
    - api.openai.com
    - api.anthropic.com
  permittedModelProviders:
    - openai
    - anthropic
    - bedrock
  brokerEgressNamespaces:
    - agent-broker
    - agent-egress
  requirePromptAuditLog: true
  requireToolCallAuditLog: true
  requireOutputFiltering: true
  perTenantTokenBudget: 1000000
  perTenantInferenceTimeoutSeconds: 60
```

Audit logging requirements are not optional. Per-tenant agent replay is the
forensic anchor — the validator rejects `requirePromptAuditLog` or
`requireToolCallAuditLog` set to false. Output filtering is also non-negotiable
so completions are scanned for cross-tenant data and secret leaks before they
reach the caller.

## WAF on the model gateway

The `waf` stack adds a strict rate-based statement scoped to the model gateway
URI prefixes (`/v1/models`, `/v1/agents`) on top of the global per-IP rate
limit, plus AWS managed rule sets (Common, KnownBadInputs, IpReputation,
AnonymousIp, BotControl). Logging is sent to a 365-day CloudWatch log group
with redacted `authorization`, `cookie`, and `x-api-key` headers.

## Broker contract

Every agent turn must persist:

- `tenantId`, `principalId`, `turnId`;
- input prompt (raw + redacted);
- selected model + provider + model version;
- list of tool calls (name + arguments + signed authorization claim);
- completion (raw + filtered);
- token usage and cost;
- timestamps and outcome (success/error/blocked).

Persist into a per-tenant immutable ledger. The recommended target is the
customer artifact bucket under `tenant/<id>/agent/<turnId>/...`, which is
covered by the `DenyWritesOutsideTenantJobPrefix` policy via the broker
extending the prefix contract (`docs/customer-data.md`).

## Prompt injection defense

- Treat customer-supplied prompts and tool-call outputs as untrusted input.
- Run input + output content moderation. Refuse responses that contain
  cross-tenant identifiers or known prompt-leak markers.
- Keep system prompts and broker tokens out of the customer-visible context
  window. Tool-call results that reference brokered credentials must be
  scrubbed before they enter another inference call.
- Apply the `permittedModelProviders` allowlist; block direct calls to other
  providers via the egress NetworkFirewall allowlist + agent-egress NetPol.

## Cost controls

`perTenantTokenBudget` is the soft cap; the broker must enforce it before
calling the model gateway. `perTenantInferenceTimeoutSeconds` caps wall clock
per inference. Per-tenant AWS Budgets in the `cost-controls` stack catch the
hard cost-impact case (`docs/cost-controls.md`).
