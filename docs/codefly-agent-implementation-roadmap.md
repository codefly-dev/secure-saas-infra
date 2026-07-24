# Codefly Implementation Roadmap and Agent Handoff

Status: authoritative implementation handoff for the next Codefly agent
Primary implementation workspace: `/Users/antoine/development/deus/codefly`
Planning repository: `/Users/antoine/development/deus/secure-saas-infra`
Date: 2026-07-16

## Instructions to the implementing agent

Read this entire document before editing code. Treat it as the ordered delivery
contract, not as permission to mutate every referenced repository.

Default mutation scope is the Codefly component repository named by the active
task. Mind, Warden, and `secure-saas-infra` are read-only integration references
unless the user explicitly authorizes changes there. Creating or publishing a
new remote Git repository, pushing a branch, opening a pull request, deploying
AWS, or mutating a Kubernetes cluster also requires the authority implied by a
specific user request.

At the start of each implementation turn:

1. Identify the first incomplete task whose dependencies are complete.
2. Inspect the relevant component's current files and tests; this roadmap is
   architecture guidance, but local code is the source of truth.
3. Run `git status --short` in every component repository you may modify.
4. Preserve all existing changes. Never reset or overwrite unrelated work.
5. State the task IDs being implemented and the verification level targeted.
6. Implement the smallest complete vertical slice, including negative tests.
7. Run targeted tests, then the component's broader gate.
8. Report files changed, tests run, remaining risks, and the next unblocked IDs.

Do not mark a task complete merely because code compiles. Its stated acceptance
criteria and tests must pass.

## Purpose

Codefly is evolving from a local service-agent CLI into a secure application
platform with two distinct responsibilities:

1. application lifecycle inside an approved cloud context; and
2. eventually, brokered infrastructure provisioning for missing capabilities.

The immediate goal is application lifecycle plus safe agent capabilities. The
platform must let Mind use PostgreSQL and operational telemetry without giving
the model reusable credentials, and must let Codefly plan, deploy, observe,
promote, abort, and roll back Warden or Mind through GitOps.

The first production-shaped result is:

> One authenticated Codefly request deploys an immutable Warden or Mind release
> into a pre-provisioned AWS cloud context. Mind can use tenant-scoped Postgres
> and observability toolboxes. Every tool and release effect is policy checked,
> bounded, recoverable, and linked to signed evidence. No service plugin or
> agent receives cloud, cluster-admin, database-owner, or observability-admin
> credentials.

This document is self-contained for Codefly implementation. Related platform
and infrastructure detail is in:

- `secure-saas-infra/docs/codefly-capability-tooling-delivery-roadmap.md`;
- `secure-saas-infra/docs/codefly-paas-implementation-plan.md`;
- `secure-saas-infra/docs/codefly-bootstrap-paas-roadmap.md`; and
- `secure-saas-infra/docs/rootless-aws-codefly-execution-roadmap.md`.

## Workspace topology

`/Users/antoine/development/deus/codefly` is an aggregate Go workspace, not a
single Git repository. Important children such as `core`, `cli`,
`service-postgres`, and each external toolbox are independent repositories.

Never run a destructive Git command at the aggregate root. Check and modify
each repository separately:

```sh
git -C /Users/antoine/development/deus/codefly/core status --short
git -C /Users/antoine/development/deus/codefly/cli status --short
git -C /Users/antoine/development/deus/codefly/service-postgres status --short
```

Add other component repositories only when their task is active. Do not assume
one commit can atomically cover core, CLI, plugins, Mind, and IaC. Cross-repo
changes require compatible commit order and temporary local `go.work` testing.

### Repository ownership

| Component                      | Owns on this roadmap                                                                                                                                | Must not own                                                            |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Codefly `core`                 | Protobuf contracts, Toolbox SDK/runtime, policy, scoped authorization, capability/resource/release domain types, conformance fixtures               | Durable PaaS state, AWS resources, application-specific queries         |
| Codefly `cli`                  | Local CLI, remote CLI UX, control-plane client/server composition, durable jobs initially if no separate server repo exists, delivery orchestration | Service-specific semantics, unrestricted production cluster access      |
| `service-postgres`             | Abstract Postgres service, local runtime, settings, migrations, workload binding compatibility                                                      | RDS lifecycle, agent query authority, production admin credentials      |
| Future `toolbox-postgres`      | Schema resources, named queries, bounded read execution                                                                                             | Database ownership, migrations by default, arbitrary SQL, RDS lifecycle |
| Future `toolbox-observability` | Provider-neutral telemetry queries and release health                                                                                               | OTLP ingest ownership, alert/dashboard mutation initially               |
| Codefly control plane          | Authentication, authorization, release/job state, scheduling, policy, audit, plugin/toolbox dispatch                                                | Raw host shell, application logic, direct cloud SDK access              |
| Infrastructure provider/broker | Typed resource claims and privileged provider reconciliation                                                                                        | Model-facing tools, application release semantics                       |
| Mind                           | Objective policy, canonical tool registry, model interaction, effect approval                                                                       | Codefly resource policy or plugin-granted authority                     |
| `secure-saas-infra`            | AWS accounts/network/EKS/RDS/Argo/collector canvas, cloud contexts, workload identities, provider adapters, release evidence                        | Codefly product implementation                                          |

## Observed Codefly baseline

The next agent must reuse the following implementation rather than recreate it.

### Toolbox foundation already exists

- `core/resources/toolbox.go` defines the `codefly:toolbox` plugin kind,
  `toolbox.codefly.yaml`, sandbox declarations, canonical binary ownership, and
  manifest permission ceilings.
- `core/proto/codefly/services/toolbox/v0/toolbox.proto` defines Identity,
  two-phase `ListToolSummaries`/`DescribeTool`, `CallTool`, resources, and
  prompts with structured content and JSON schemas.
- `core/toolbox/registry/registry.go` provides one source of truth for summaries,
  full specs, schema validation, examples, idempotency, error modes, and dispatch.
- `core/toolbox/launch/launch.go` launches toolbox agents through the standard
  agent manager and applies the declared sandbox.
- `core/toolbox/policyguard/guard.go` gates tool/resource/prompt calls.
- `core/policy/scoped_auth.go` implements expiring, audience-bound,
  action/resource/principal-bound, use-limited scoped authorization with
  caveats and replay tracking.
- `core/policy/gateway.go` evaluates host policy and mints scoped authorization.
- `core/toolbox/mcp` and `core/toolbox/mcprev` already translate Toolbox to MCP
  and MCP to Toolbox.
- `core/toolbox/launch/permission_e2e_test.go` already exercises significant
  permission, callback, and sandbox behavior.
- `core/policy/MIND_INTEGRATION.md` describes an intended host integration, but
  it is documentation, not proof that Mind currently uses the integration.

### Service and deployment foundation already exists

- `service-postgres` version `0.0.103` starts local Postgres, manages extensions,
  validates/applies migrations, and publishes a secret connection string.
- `core/proto/codefly/services/builder/v0/deployment.proto` currently models
  Kubernetes/Kustomize deployment output only.
- `cli/pkg/orchestration/builder_deploy.go` renders service deployment output.
- `cli/pkg/deployments/kustomize.go` directly applies rendered objects.
- `codefly deploy --render-only` exists for a pull-based GitOps path.
- `cli/pkg/deployments/version_control.go` is an early Git implementation;
  `cli/pkg/deployments/github.go` is mostly a stub.
- The SaaS starter contains static Argo CD application manifests and topology
  compilation, but there is no general release intent, durable release state,
  delivery provider interface, Git commit/PR flow, progressive strategy model,
  or controller-status ingestion.

### Observability foundation is partial

- `core/wool/otel/provider.go` configures an OTLP trace exporter or stdout
  fallback.
- gRPC tracing exists, but a production telemetry sink contract and complete
  trace/metric/log pipeline do not.
- `core/proto/codefly/observability/v0` is not a provider-neutral query API.

## Known baseline risks to resolve, not hide

1. The aggregate Codefly root has no `.git`; component commits and clean-state
   evidence must be handled independently.
2. Toolbox sandbox comments and behavior are not fully aligned. An empty policy
   is currently allowed to launch unconfined because fail-closed loopback
   sandboxing failed on some Linux user-namespace environments. Production
   admission must require an explicit sandbox/capacity profile; do not flip the
   global default casually without solving the underlying platform support.
3. Some external toolbox manifests use `network: allow`, while the current
   `policy.NetworkPolicy` values are `deny`, `loopback`, and `open`. Confirm and
   correct manifest/parser drift before using those manifests as templates.
4. `service-postgres` emits a reusable database URL. That remains a workload
   compatibility binding only; it must never become a Mind/toolbox binding.
5. Current SaaS-starter RLS examples still document superuser role switching
   and an application-settable bypass. They are test/reference inputs, not the
   production agent-tool security model.
6. Current direct Kubernetes apply is useful locally but is not the production
   delivery authority.
7. Codefly/Mind authorization integration documentation may be ahead of actual
   host wiring. Only executable end-to-end tests close that gap.

## Architecture decisions

### Keep capabilities orthogonal

Use these platform capabilities:

| Capability            | Responsibility                                                             |
| --------------------- | -------------------------------------------------------------------------- |
| `resource.lifecycle`  | Provision/observe/update/delete a physical or logical resource             |
| `service.binding`     | Give a workload a typed endpoint/configuration/secret reference            |
| `toolbox`             | Give an agent mediated typed operations without its underlying credentials |
| `telemetry.sink`      | Give workloads an OTLP ingest destination                                  |
| `observability.query` | Query traces/logs/metrics/SLO/release health                               |
| `delivery`            | Plan/commit/observe/promote/abort/rollback an application release          |
| `policy.audit`        | Authorize and record all capability use                                    |

Do not extend the existing `AgentInformation.Capability` enum merely to restate
that an installed `codefly:toolbox` manifest exists. Add protocol fields only
when a concrete consumer needs version/schema/transport negotiation that the
existing agent/toolbox identity cannot express. Prefer an additive generic
descriptor over an enum entry per product or provider.

### Separate service and toolbox processes

The Postgres service agent and Postgres agent toolbox are separate security
principals and processes:

```text
service-postgres
  local runtime + service settings + migration source validation
  workload binding -> secret reference or local compatibility URL

toolbox-postgres
  schema resources + named read queries
  toolbox binding -> opaque toolbox identity and database resource scope
  its own DB login, policy ceiling, sandbox, network boundary, limits, audit

AWS RDS provider
  RDS/proxy/network/IAM/backup lifecycle
  produces workload, migration, and toolbox database bindings
```

They may share release/version conventions and Go libraries, but they must not
share a database owner credential or an agent process identity.

The likely long-term home is a sibling component repository
`/Users/antoine/development/deus/codefly/toolbox-postgres`. Creating or
publishing that repository is a deliberate user/organization action. Until it
is authorized, implement only reusable core contracts and an in-process
conformance fixture; do not quietly hide a second published agent inside the
service plugin.

### Native Toolbox first, MCP at the edge

Codefly Toolbox is the native contract because it already carries Codefly
identity, schema, sandbox, permission, and scoped-authorization semantics. MCP
is a compatibility transport for external providers.

MCP annotations such as read-only/destructive/idempotent are untrusted hints.
Codefly manifest admission and operator policy determine actual authority.

### Workload binding is not an agent credential

Never put a workload connection URL into:

- a tool description or result;
- Mind prompt/model context;
- release plans or diffs;
- logs, traces, errors, evidence, or Git;
- toolbox environment variables that are model-visible; or
- long-lived Codefly state as plaintext.

A toolbox receives a short-lived credential or workload identity internally,
then exposes only typed operations. The model receives results, not the
credential.

### Release intent sits above Kubernetes and Argo

Codefly defines provider-neutral release semantics. Providers map them to local
Kubernetes, Argo CD/Rollouts, or a future Flux implementation.

```text
ReleaseIntent
  -> deterministic DeliveryPlan + policy result + digest
  -> approved Commit
  -> Git desired state
  -> Argo CD reconciliation
  -> Argo Rollouts progression/analysis
  -> Codefly Observe
  -> Promote | Abort | Git-revert Rollback
```

Codefly owns intent, policy, audit, and durable state. It must not compete with
Argo CD for reconciliation or with Argo Rollouts for ReplicaSet/traffic state.

## Verification levels

| Level | Meaning                                             | Environment                 | Mutation allowed               |
| ----- | --------------------------------------------------- | --------------------------- | ------------------------------ |
| V0    | Static/protobuf/schema/build                        | Component checkout          | None outside build artifacts   |
| V1    | Unit/model/property tests                           | Local                       | None                           |
| V2    | Cross-component compatibility fixtures              | Local aggregate workspace   | None                           |
| V3    | Real local dependencies and installed local agents  | Docker/Nix/local Codefly    | Local only                     |
| V4    | Hostile, replay, crash, timeout, and recovery tests | Disposable local processes  | Local only                     |
| V5    | GitOps/progressive delivery in disposable k3d/K3s   | Disposable cluster          | Cluster only                   |
| V6    | Fixture release in AWS dev                          | Pre-provisioned dev context | Reviewed dev mutation          |
| V7    | Warden, then Mind in AWS dev/release candidate      | Dev or ephemeral preprod    | Approved non-production        |
| V8    | Exact-candidate production promotion                | Production                  | Explicit digest-bound approval |

V0-V4 are mandatory before Kubernetes deployment. V5 is mandatory before AWS.
No Codefly implementation task may silently trigger V6-V8.

## Roadmap and dependency graph

```text
CF0 baseline/conformance
  -> CF1 Toolbox host contract
      -> CF2 Postgres toolbox
      -> CF3 observability toolbox
  -> CF4 release domain/protocol
      -> CF5 durable control-plane jobs
      -> CF6 remote CLI
      -> CF7 GitOps delivery provider
          -> CF8 progressive delivery

CF2 + CF3 + CF5 + CF6 + CF8
  -> CF9 Warden
  -> CF10 Mind
  -> CF11 joint production gate

later: CF12 infrastructure-on-demand and additional clouds/providers
```

## Task status

- `READY`: implementation may start.
- `BLOCKED`: named dependency or authority is missing.
- `LATER`: deliberately not on the initial critical path.
- `DONE`: implementation, positive/negative tests, compatibility, docs, and
  required evidence all pass.

## CF0 — Baseline and conformance lock

Status: `READY`
Repositories: `core`, `cli`, `service-postgres`, relevant external toolboxes
Required verification: V0-V2
Deployment: none

- [ ] `CF0-001` Record independent Git revision and dirty-state evidence for
      every component touched by the active slice.
- [ ] `CF0-002` Run and record baseline targeted tests for core policy/toolbox,
      CLI deployment/orchestration, and service-postgres.
- [ ] `CF0-003` Add a small machine-readable Toolbox conformance fixture with
      Identity, summary, description, structured read result, deterministic
      error, and one denied effect.
- [ ] `CF0-004` Golden-test Toolbox JSON/protobuf projection and canonical tool
      names across generated bindings.
- [ ] `CF0-005` Verify scoped authorization: principal, organization, audience,
      action, resource, expiry, max uses, caveats, revocation, and replay.
- [ ] `CF0-006` Define typed well-known caveat names and validation helpers for
      organization, tenant, environment, resource binding, query IDs, result
      budgets, release ID, and approval ID.
- [ ] `CF0-007` Preserve unknown provider-specific caveats only when an explicit
      verifier is registered; otherwise fail closed.
- [ ] `CF0-008` Reconcile Toolbox sandbox documentation with actual launch
      behavior and add production-admission terminology distinct from local
      compatibility behavior.
- [ ] `CF0-009` Validate every external `toolbox.codefly.yaml` against current
      network enum values and correct `allow`/`open` drift in its owning repo.
- [ ] `CF0-010` Add a strict production admission mode that rejects empty
      sandbox and permission declarations without breaking explicit local/test
      compatibility mode.
- [ ] `CF0-011` Test strict-mode startup denial for empty policy, unknown
      network mode, unknown placeholder, missing callback/PDP, and manifest
      permission mismatch.
- [ ] `CF0-012` Run `buf lint` and compatibility checks for any proto change;
      commit source and generated bindings together.

Acceptance:

- The baseline conformance fixture passes under allow policy and fails under
  deny policy.
- Expired/replayed/wrong-audience/wrong-resource authorization is rejected.
- Production mode cannot start an unconstrained toolbox.
- Existing local toolboxes retain an explicit, documented migration path.

Do not proceed to CF2 or CF3 until CF0 authorization and admission tests pass.

## CF1 — Host-facing Toolbox session contract

Status: `BLOCKED` by CF0
Repository: primarily `core`; Mind integration itself remains in Mind
Required verification: V0-V4
Deployment: local processes only

Goal: give any host—Mind, Codefly server, or CLI—one correct way to discover,
authorize, invoke, observe, and close a Toolbox.

- [ ] `CF1-001` Define a host-side `ToolboxSession` abstraction around manifest,
      launched process, typed client, principal, decider, scoped-authorization
      minting, trace context, and cleanup.
- [ ] `CF1-002` Keep two-phase `ListToolSummaries`/`DescribeTool` as the default;
      retain `ListTools` only for compatibility/transcoding.
- [ ] `CF1-003` Add catalog snapshot identity/version/digest so a call can prove
      it used the descriptor the host approved.
- [ ] `CF1-004` Bind authorization to toolbox canonical identity, tool name,
      resource, principal, organization, catalog digest, request digest, and
      short deadline.
- [ ] `CF1-005` Propagate request, session, objective/task when supplied,
      invocation, trace, and release IDs without trusting caller-supplied
      principal/tenant fields.
- [ ] `CF1-006` Define retry classes from tool idempotency and actual outcome;
      never let free-text metadata alone authorize an automatic retry.
- [ ] `CF1-007` Normalize protocol errors, validation errors, policy denial,
      timeout, cancellation, partial result, backend unavailable, and internal
      failure into stable machine-readable categories.
- [ ] `CF1-008` Add structured audit hooks for discovery, describe, authorize,
      invoke, result summary, denial, cancellation, and cleanup.
- [ ] `CF1-009` Redact arguments/results using schema/classification metadata
      before logs, traces, and audit serialization.
- [ ] `CF1-010` Provide a minimal external-host conformance harness that Mind can
      import/run without depending on Codefly CLI internals.
- [ ] `CF1-011` Update `core/policy/MIND_INTEGRATION.md` only after the harness
      proves the documented wiring.
- [ ] `CF1-012` Add crash tests before authorization, after authorization,
      during execution, after side effect, and during response serialization.
- [ ] `CF1-013` Add concurrent session/principal tests proving callback,
      authorization, replay tracker, and trace context cannot cross sessions.

Acceptance:

- A non-Codefly host can launch the fixture toolbox through one supported API.
- Both host policy and plugin guard enforcement are observable and tested.
- One-use authorization stays consumed across success, tool error, timeout, and
  process loss according to explicit semantics.
- No principal, tenant, credential, or authorization token appears in model
  content or ordinary logs.

Mind-owned follow-up, not part of the default Codefly mutation scope:

- mount this host/session client at Mind's `toolbind.BuildToolbox`;
- map Codefly `ToolSpec` to Mind `ToolDescriptor`;
- intersect Mind objective/tool policy before Codefly authorization; and
- upgrade Mind's MCP adapter without bypassing its canonical registry.

## CF2 — PostgreSQL toolbox

Status: `BLOCKED` by CF1 and authorization to create/use `toolbox-postgres`
Repositories: new `toolbox-postgres`, `core` helpers if generally reusable,
`service-postgres` only for binding compatibility
Required verification: V0-V4 locally; V6 before product AWS release
Deployment: real local Postgres first, existing AWS binding later

### Packaging and binding

- [ ] `CF2-001` Create or obtain explicit authority for a separate
      `toolbox-postgres` component repository and agent identity.
- [ ] `CF2-002` Add `agent.codefly.yaml` with kind `codefly:toolbox` and a
      matching `toolbox.codefly.yaml`; do not reuse the service agent identity.
- [ ] `CF2-003` Declare explicit sandbox, permission ceiling, network capacity,
      binary provenance, and supported protocol/core range.
- [ ] `CF2-004` Define `WorkloadDatabaseBinding` separately from
      `PostgresToolboxBinding`.
- [ ] `CF2-005` Ensure the toolbox binding contains resource identity, endpoint
      reference, database, TLS reference, role class, lease metadata, and
      policy reference—but no plaintext password or model-visible URL.
- [ ] `CF2-006` Keep the current service connection URL only for explicit local
      workload compatibility and prevent it from entering toolbox discovery.
- [ ] `CF2-007` Define provider-neutral credential acquisition so local
      password, Vault dynamic credentials, RDS IAM, Cloud SQL, or Azure identity
      can be used internally without changing tools.
- [ ] `CF2-008` In production, run the toolbox in a network boundary that can
      reach only the bound database and required identity endpoints. Do not
      describe `network: open` alone as sufficient confinement.

### Read-only surface

- [ ] `CF2-010` Implement `postgres.schema.list`.
- [ ] `CF2-011` Implement `postgres.schema.describe` for explicitly permitted
      schemas/tables/views/columns/constraints/indexes/RLS metadata.
- [ ] `CF2-012` Expose schema through stable read-only resource URIs.
- [ ] `CF2-013` Exclude row samples, secret defaults, function bodies, and
      restricted object names from default schema resources.
- [ ] `CF2-014` Implement a versioned named-query catalog owned by application
      code/configuration, with parameter and output JSON schemas.
- [ ] `CF2-015` Implement `postgres.query.named` with prepared parameter binding,
      no string interpolation, and no caller-supplied SQL.
- [ ] `CF2-016` Implement metadata-only `postgres.migration.status` if it can be
      exposed without migration authority.
- [ ] `CF2-017` Optionally implement bounded `postgres.query.explain` without
      `ANALYZE`, using an explicit cost ceiling.
- [ ] `CF2-018` Return structured results with truncation/partial-result metadata
      and stable error types.

### Database authority

- [ ] `CF2-020` Define separate database roles for schema reader, tenant reader,
      named command (future), migration owner, workload runtime, and privileged
      workers.
- [ ] `CF2-021` Require toolbox roles to be non-owner, non-superuser,
      non-`BYPASSRLS`, and unable to `SET ROLE` into stronger roles.
- [ ] `CF2-022` Require `FORCE ROW LEVEL SECURITY` for tenant data exposed to
      the toolbox.
- [ ] `CF2-023` Derive organization/tenant/environment/database from verified
      authorization caveats and set context transaction-locally.
- [ ] `CF2-024` Never accept an application-settable RLS bypass from a tool
      argument or untrusted connection setting.
- [ ] `CF2-025` Audit table/function ownership, `PUBLIC` execution,
      `SECURITY DEFINER` search paths, `COPY`, `REFERENCES`, `TRUNCATE`, locking,
      and volatile/unsafe functions.

### Budgets and audit

- [ ] `CF2-030` Use read-only transactions for agent reads.
- [ ] `CF2-031` Apply server-side statement, transaction, lock, and idle
      transaction timeouts.
- [ ] `CF2-032` Enforce maximum rows, response bytes, query duration,
      concurrency, rate, schemas, functions, and named-query IDs.
- [ ] `CF2-033` Optionally enforce estimated planner cost without executing
      `EXPLAIN ANALYZE`.
- [ ] `CF2-034` Classify sensitive columns/results and redact or reject output.
- [ ] `CF2-035` Audit query ID, parameter digest, scope, limits, duration, role,
      row/byte count, truncation, and outcome—never SQL values or returned data.
- [ ] `CF2-036` Make server-side timeout authoritative; client cancellation is
      supplementary and cannot be the only query-stop mechanism.

### Verification

- [ ] `CF2-040` Unit-test schema filtering, catalog loading, parameter schemas,
      output schemas, budgets, error mapping, and redaction.
- [ ] `CF2-041` Test against real local Postgres started by installed local
      Codefly agents/`WithDependencies`, not only mocks.
- [ ] `CF2-042` Create at least two organizations and two tenants per
      organization and test every exposed query/resource across the full matrix.
- [ ] `CF2-043` Test connection-pool reuse after success, rollback, panic,
      cancellation, timeout, and backend termination for leaked context/role.
- [ ] `CF2-044` Inject SQL metacharacters into every parameter and identifier
      field; prove no statement structure changes.
- [ ] `CF2-045` Test wrong database/schema/query/tenant/environment, expired,
      replayed, revoked, wrong-audience, and budget-escalation authorization.
- [ ] `CF2-046` Test row, byte, cost, duration, lock, connection, concurrency,
      and rate-limit exhaustion.
- [ ] `CF2-047` Scan logs, traces, errors, results, crash dumps, and evidence for
      database URLs, passwords, IAM tokens, authorization tokens, and seeded
      sensitive values.
- [ ] `CF2-048` Fuzz catalog, parameter, resource URI, result truncation, and
      authorization decoding.
- [ ] `CF2-049` Repeat TLS, IAM, RLS, timeout, pool, and denial tests against an
      existing RDS/RDS Proxy binding in AWS dev only after V0-V5 pass.

Acceptance:

- A host can inspect permitted schema and run named tenant-scoped reads without
  receiving a database credential.
- Cross-tenant, arbitrary SQL, stronger-role, and unbounded-query attempts fail.
- Local Postgres and AWS RDS use the same toolbox contract.
- No write/general SQL tool is included in the first release.

## CF3 — Telemetry and observability toolbox

Status: `BLOCKED` by CF1
Repositories: `core`, future `toolbox-observability`, optional provider package
Required verification: V0-V5 locally; V6 before product AWS release
Deployment: collector/query fixture, disposable cluster, AWS dev

### Ingest contract

- [ ] `CF3-001` Define `TelemetrySinkBinding`: OTLP endpoint/protocol, TLS,
      credential reference, trusted resource attributes, and availability.
- [ ] `CF3-002` Extend standard Codefly instrumentation to traces, metrics, and
      logs or explicitly document which standard OTEL SDK owns each signal.
- [ ] `CF3-003` Remove silent production stdout fallback; require explicit local
      mode for stdout.
- [ ] `CF3-004` Propagate organization, environment, cloud context, application,
      service, release, artifact, Git, request, job, and trace identity.
- [ ] `CF3-005` Accept Mind session/task/objective/tool invocation correlation as
      context, without letting it assert trusted tenant identity.

### Query contract

- [ ] `CF3-010` Define provider-neutral typed operations for service listing,
      trace search/get, log search/aggregate, metrics query, SLO status, and
      release health.
- [ ] `CF3-011` Do not call this an OTEL query API; OTLP remains ingest/export.
- [ ] `CF3-012` Require organization/environment/service/release scope and
      enforce time, cardinality, series, row, byte, and concurrency budgets.
- [ ] `CF3-013` Define stable pagination, partial-result, backend-unavailable,
      invalid-query, limit, and timeout results.
- [ ] `CF3-014` Keep alert/dashboard/view/notification mutations outside the
      initial read-only capability.

### SigNoz adapter

- [ ] `CF3-020` Implement the provider behind an interface so SigNoz does not
      define Codefly's public tool schema.
- [ ] `CF3-021` Use a Viewer/read-only service identity.
- [ ] `CF3-022` If the official SigNoz MCP server is used downstream, mount only
      an explicit read allowlist and translate structured results through the
      native Codefly Toolbox.
- [ ] `CF3-023` Exclude raw query-builder/admin/write tools in the initial gate.
- [ ] `CF3-024` Implement release health by joining bounded telemetry with
      Codefly release/controller state for one exact release.

### Verification

- [ ] `CF3-030` Send deterministic fixture traces, metrics, and logs through a
      real collector.
- [ ] `CF3-031` Prove the collector replaces/rejects forged tenant attributes.
- [ ] `CF3-032` Inject secrets and sensitive values and prove redaction before
      provider export.
- [ ] `CF3-033` Test wrong scope, replay, expiry, time/cardinality/byte limits,
      pagination, partial response, backend timeout, and outage.
- [ ] `CF3-034` Attempt every known SigNoz mutation under the provider identity
      and require denial.
- [ ] `CF3-035` Diagnose one deliberately unhealthy fixture release from the
      disposable cluster.
- [ ] `CF3-036` Repeat private endpoint, TLS, identity, tenant, and release
      correlation tests in AWS dev.

Acceptance:

- A host can explain an exact unhealthy release with read-only bounded traces,
  logs, metrics, and rollout state.
- Application telemetry cannot forge trusted tenant/environment identity.
- The same public query contract can support another backend later.

## CF4 — Release domain and protocol

Status: `BLOCKED` by CF0
Repository: `core`
Required verification: V0-V2
Deployment: none

- [ ] `CF4-001` Add an additive `codefly/releases/v1` or agreed versioned
      package; do not expand Kubernetes deployment output into the platform API.
- [ ] `CF4-002` Define `ReleaseIntent` with scope, cloud context, immutable
      source/artifact, configuration/binding generations, strategy, gates,
      migrations, deadline, and approvals.
- [ ] `CF4-003` Define `DeliveryPlan` with provider/renderer versions, rendered
      digest, policy result, diff summary, Git target, controller target, and
      required effects.
- [ ] `CF4-004` Define release states: draft, planned, approved, committed,
      reconciling, progressing, healthy, degraded, aborted, and rolled back.
- [ ] `CF4-005` Define typed transition reason, sequence, timestamp, actor,
      attempt, correlation, and evidence references.
- [ ] `CF4-006` Define provider operations: Plan, Commit, Observe/Watch, Promote,
      Abort, and Rollback.
- [ ] `CF4-007` Define rolling, canary, and blue-green intent without Argo or
      Istio field names.
- [ ] `CF4-008` Define analysis gates: metric/query reference, success/failure,
      inconclusive, interval, count, timeout, and manual approval.
- [ ] `CF4-009` Define expand/contract migration phases and forbid automatic
      reversal of committed destructive schema.
- [ ] `CF4-010` Bind source, artifact, configuration, binding, policy, render,
      plugin, and plan digests into approval/apply.
- [ ] `CF4-011` Define stable error/status semantics for unsupported strategy,
      policy denied, stale plan, conflict, controller failure, analysis failure,
      deadline, cancellation, and irreversible migration.
- [ ] `CF4-012` Add canonicalization and cross-language golden fixtures.
- [ ] `CF4-013` Add a fake delivery provider and conformance suite.
- [ ] `CF4-014` Adapt current local Kubernetes rendering/apply behind the
      interface without making it the remote production provider.

Acceptance:

- Fake and local providers execute the same release intent.
- Identical clean input produces an identical plan digest.
- A changed artifact, binding, policy, render, or plan invalidates approval.
- Legal/illegal transition property tests pass.

## CF5 — Durable control-plane release jobs

Status: `BLOCKED` by CF4
Repositories: `cli` initially or a deliberately created server repository;
shared domain remains in `core`
Required verification: V0-V4
Deployment: local server/worker only

Do not put durable PaaS truth in CLI process memory. If the current Codefly
repository organization has no server component suitable for durable state,
pause and obtain an explicit ownership decision before creating one.

- [ ] `CF5-001` Define the public authenticated ControlPlane API separately from
      raw Builder, Runtime, Code, terminal, Toolbox, and provider services.
- [ ] `CF5-002` Add PlanRelease, CommitRelease, Get/List/WatchRelease,
      PromoteRelease, AbortRelease, and RollbackRelease operations.
- [ ] `CF5-003` Define authentication principal, organization/platform scope,
      environment/cloud context, request ID, idempotency key, deadline, and
      trace requirements for every operation.
- [ ] `CF5-004` Implement storage interfaces with deterministic in-memory/fake
      tests and a transactional Postgres implementation for production.
- [ ] `CF5-005` Persist release desired state, events, idempotency, sequence,
      attempts, locks, leases/fences, deadlines, cancellation, and bounded
      history atomically.
- [ ] `CF5-006` Guarantee one writer per release with a lease/fencing token;
      reject late workers after replacement.
- [ ] `CF5-007` Separate API, scheduler, planner, builder, migration, delivery,
      provider, and audit worker identities.
- [ ] `CF5-008` Run plugins/toolboxes in declared sandboxes without control-plane
      store credentials, host sockets, ambient service tokens, or provider SDK
      credentials.
- [ ] `CF5-009` Dispatch privileged resource operations only through typed
      broker/provider interfaces.
- [ ] `CF5-010` Implement resumable event/log watches with cursor and
      backpressure.
- [ ] `CF5-011` Implement bounded retry using failure class and operation
      idempotency; do not retry uncertain effects blindly.
- [ ] `CF5-012` Implement cancellation and cleanup at planning, build, migration,
      Git commit, reconciliation, rollout, and analysis boundaries.
- [ ] `CF5-013` Hash-chain or sign audit batches before immutable export.
- [ ] `CF5-014` Enforce source snapshot path/symlink/credential exclusions and
      bind jobs to the snapshot digest.
- [ ] `CF5-015` Add quotas and fairness for active releases, builds, tool calls,
      provider operations, log volume, and retained evidence.
- [ ] `CF5-016` Add readiness/liveness that distinguish API availability from
      scheduler/provider/controller health.

Verification:

- [ ] `CF5-020` Test duplicate requests before/during/after commit.
- [ ] `CF5-021` Kill API/server/worker at every transition and verify recovery.
- [ ] `CF5-022` Test lost lease, stale fence, partition, late completion,
      conflicting update, cancellation race, and event cursor resume.
- [ ] `CF5-023` Test authorization matrices for every public operation and exact
      release resource.
- [ ] `CF5-024` Test source/artifact/config/binding/policy/plan substitution.
- [ ] `CF5-025` Scan state, logs, traces, errors, and evidence for credentials.
- [ ] `CF5-026` Load-test fairness and backpressure with multiple organizations
      and releases.

Acceptance:

- A fixture release survives duplicate delivery and server/worker restart.
- A stale worker cannot mutate state after losing its fence.
- No remote request becomes control-plane host shell/file/provider execution.

## CF6 — Remote CLI

Status: `BLOCKED` by CF5
Repository: `cli`
Required verification: V0-V4
Deployment: local control-plane fixture

- [ ] `CF6-001` Add OIDC/device-flow login, refresh, status, and logout for a
      configured Codefly server.
- [ ] `CF6-002` Store refresh material in the OS keychain; never workspace YAML.
- [ ] `CF6-003` Define named contexts with server, organization/platform scope,
      environment, and cloud context.
- [ ] `CF6-004` Keep explicit `--local`; `--remote` must never fall back to host
      execution.
- [ ] `CF6-005` Add plan commands with human and stable JSON output.
- [ ] `CF6-006` Show artifact, configuration, binding, migration, identity,
      policy, delivery, and denial changes.
- [ ] `CF6-007` Require the exact plan digest and idempotency key for commit.
- [ ] `CF6-008` Add release list/get/watch/promote/abort/rollback.
- [ ] `CF6-009` Add resumable logs/events and distinct exit codes for denial,
      stale plan, failed migration, failed rollout, abort, timeout, and network.
- [ ] `CF6-010` Require interactive or signed CI approval for production effects.
- [ ] `CF6-011` Never print tokens, secrets, raw connection URLs, or unredacted
      provider/controller diagnostics.
- [ ] `CF6-012` Preserve current local workflows and document migration.
- [ ] `CF6-013` Test context confusion, server substitution, expired login,
      wrong organization/environment, cancellation, watch resume, and JSON
      compatibility.

Acceptance:

- A user can plan and operate a durable local fixture release remotely.
- Remote mode has no implicit local/host execution path.
- Production approval is bound to the exact candidate plan.

## CF7 — GitOps delivery provider

Status: `BLOCKED` by CF4 and CF5
Repositories: `cli`/server delivery package plus `core` provider interface
Required verification: V0-V5
Deployment: disposable Git remote and cluster

- [ ] `CF7-001` Implement a managed Git repository/path/branch provider with
      deterministic ownership and canonical file ordering.
- [ ] `CF7-002` Produce signed commits and optional pull requests containing
      release/plan identity and no secret material.
- [ ] `CF7-003` Detect stale base, concurrent edits, path ownership conflict,
      non-fast-forward, unsigned/untrusted commits, and unexpected files.
- [ ] `CF7-004` Use render-only output as an input but verify and digest the
      complete final Git tree before commit.
- [ ] `CF7-005` Model Argo CD application identity, project, destination, sync,
      health, drift, and operation status behind the delivery provider.
- [ ] `CF7-006` Observe Argo through read-only, resource-scoped authority; do not
      require cluster admin.
- [ ] `CF7-007` Treat Git desired state as rollback authority: rollback creates a
      reviewed revert/new desired-state commit.
- [ ] `CF7-008` Define pruning, finalizer, orphan, sync-window, and deletion
      behavior explicitly per environment.
- [ ] `CF7-009` Reject wildcard source repository/destination/resource authority
      in production AppProject configuration.
- [ ] `CF7-010` Test Git outage, Argo outage, invalid manifest, failed admission,
      drift/self-heal, controller restart, stale commit, and untrusted signature.

Acceptance:

- An immutable fixture artifact becomes a signed Git commit and reconciled Argo
  application in a disposable cluster.
- Codefly observes sync/health/drift without production cluster-admin authority.
- Rollback is auditable desired state, not an invisible imperative mutation.

## CF8 — Progressive delivery

Status: `BLOCKED` by CF3 and CF7
Repositories: release renderer/delivery packages; IaC owns controller bootstrap
Required verification: V0-V6
Deployment: disposable cluster first, AWS dev fixture second

- [ ] `CF8-001` Render Kubernetes `Deployment` for rolling strategy and Argo
      `Rollout` for progressive strategies; never let both own one workload.
- [ ] `CF8-002` Map generic canary weights, pauses, experiments, analysis, and
      manual promotion to Argo Rollouts.
- [ ] `CF8-003` Map blue/green active/preview services, pre/post analysis,
      promotion delay, and abort.
- [ ] `CF8-004` Use the provider-neutral observability contract or a narrow
      metrics/web hook for analysis.
- [ ] `CF8-005` Implement Istio stable/canary routing first.
- [ ] `CF8-006` Configure Argo CD ignore rules only for fields Argo Rollouts
      legitimately owns, such as transient traffic weights.
- [ ] `CF8-007` Keep traffic intent neutral; qualify Gateway API later through a
      pinned provider/plugin conformance gate.
- [ ] `CF8-008` Separate authorization for deploy, production promote, retry,
      abort, and rollback.
- [ ] `CF8-009` Block workload promotion when pre-migration, admission,
      readiness, or analysis fails.
- [ ] `CF8-010` Do not automatically reverse committed database schema when an
      application rollout aborts.

Verification:

- [ ] `CF8-020` Test rolling, canary, blue/green, manual/automatic promotion,
      failed/inconclusive analysis, abort, retry, and rollback.
- [ ] `CF8-021` Verify stable/canary traffic ratios and revision identity at
      every step.
- [ ] `CF8-022` Prove a failed canary cannot change stable configuration,
      bindings, secrets, another release, or another tenant.
- [ ] `CF8-023` Restart Argo CD, Rollouts, traffic, observability, and Codefly
      workers during progression and verify convergence.
- [ ] `CF8-024` Repeat fixture delivery in AWS dev using ECR, private EKS,
      workload identity, private DNS, Argo, Rollouts, Istio, and telemetry.

Acceptance:

- A bad fixture canary aborts automatically and stable traffic remains healthy.
- A good canary promotes with exact evidence and no rebuild/re-render drift.
- Application rollback and migration forward-fix state remain explicit.

## CF9 — Warden vertical slice

Status: `BLOCKED` by CF2, CF3, CF5, CF6, and CF8
Codefly repositories plus read-only Warden/IaC integration unless separately authorized
Required verification: V0-V7

- [ ] `CF9-001` Freeze clean Warden source, service graph, agent pins,
      migrations, bindings, health, SLOs, and rollout strategy.
- [ ] `CF9-002` Generate one deterministic Codefly release plan for all Warden
      services in an approved pre-provisioned cloud context.
- [ ] `CF9-003` Resolve existing database, telemetry, registry, DNS, identity,
      network, and policy bindings without provider credentials.
- [ ] `CF9-004` Run checksum-bound migrations with separate identity before
      workload promotion.
- [ ] `CF9-005` Build immutable signed artifacts and deploy through GitOps and
      progressive delivery.
- [ ] `CF9-006` Test health, telemetry correlation, cancellation, failed
      migration, failed canary, abort, rollback, restart, and recovery.
- [ ] `CF9-007` Prove Warden release/tool/data/identity state cannot access or
      mutate Mind state.
- [ ] `CF9-008` Produce signed evidence binding Codefly/core/CLI/plugins,
      Warden, IaC, context, policy, plan, migrations, artifacts, Git,
      controllers, telemetry, and test results.

Acceptance:

- One authenticated request deploys and observes Warden in AWS dev.
- Warden can independently abort/rollback without touching Mind.
- Positive and denial paths pass under real dependencies.

## CF10 — Mind vertical slice

Status: `BLOCKED` by CF9 and the Mind-owned native Toolbox bridge
Codefly repositories plus read-only Mind/IaC integration unless separately authorized
Required verification: V0-V7

- [ ] `CF10-001` Freeze clean Mind source, service graph, agent pins,
      migrations, tool catalog, bindings, health, SLOs, and rollout strategy.
- [ ] `CF10-002` Plan trusted Mind control services in the platform context and
      customer-code execution only in the isolated execution context.
- [ ] `CF10-003` Resolve Postgres, telemetry, Warden API, execution, registry,
      DNS, identity, network, and policy capabilities explicitly.
- [ ] `CF10-004` Build and deploy all Mind services through the same release and
      GitOps contracts as Warden.
- [ ] `CF10-005` Execute a real Mind objective using `postgres.schema.describe`,
      `postgres.query.named`, and bounded observability tools.
- [ ] `CF10-006` Prove the objective cannot widen toolbox catalog, tenant,
      database, query, row/byte/time budget, environment, release, or effect.
- [ ] `CF10-007` Test cancellation/recovery across Mind, Toolbox, Codefly,
      Postgres, observability, GitOps, and execution workers.
- [ ] `CF10-008` Prove Mind rollback leaves Warden release/database/telemetry/
      identity state unchanged.
- [ ] `CF10-009` Produce signed cross-repository evidence.

Acceptance:

- One authenticated request deploys Mind across approved AWS contexts.
- Mind safely uses Codefly-provided data and operational capabilities without
  receiving their credentials.
- Warden/Mind communication is an explicit authenticated API dependency, not
  shared database, identity, release, or implicit network authority.

## CF11 — Joint production gate

Status: `BLOCKED` by CF10
Required verification: V0-V8

- [ ] `CF11-001` Run concurrent Warden/Mind deploy, cancellation, migration
      failure, canary failure, rollback, restart, and recovery.
- [ ] `CF11-002` Run cross-organization, tenant, environment, context, product,
      database, toolbox, release, identity, network, artifact, and evidence
      denial tests.
- [ ] `CF11-003` Load-test release scheduling, Toolbox calls, Postgres queries,
      telemetry queries, event watches, audit export, and controller processing.
- [ ] `CF11-004` Restore database and control-plane state and verify RPO/RTO.
- [ ] `CF11-005` Exercise break-glass, plugin revocation, authorization-key
      rotation, Git outage, controller outage, provider outage, and telemetry
      outage.
- [ ] `CF11-006` Complete external penetration testing and remediate blockers.
- [ ] `CF11-007` Publish SLOs, alerts, dashboards, paging ownership, runbooks,
      kill switches, rollback, migration forward-fix, and incident procedures.
- [ ] `CF11-008` Generate and independently verify the signed release bundle.
- [ ] `CF11-009` Bind production approval to the exact candidate/evidence/plan.
- [ ] `CF11-010` Promote the candidate without rebuilding or re-rendering.
- [ ] `CF11-011` Run post-deploy smoke, isolation, telemetry, and rollback
      readiness checks before normal traffic.

Acceptance:

- Production runs the exact verified candidate.
- No model, application, plugin, toolbox, or ordinary worker has administrator
  authority over its underlying platform.
- Restore, abort, rollback, and forward-fix procedures have current evidence and
  named operators.

## CF12 — Deferred expansion

Status: `LATER`, only after CF11

- [ ] `CF12-001` Controlled arbitrary read-only SQL using a real PostgreSQL
      parser/AST and explicit opt-in policy.
- [ ] `CF12-002` Named Postgres command tools with typed stored procedures,
      idempotency, budgets, and exact effect approval.
- [ ] `CF12-003` Observability administration tools.
- [ ] `CF12-004` Flux/Flagger delivery provider.
- [ ] `CF12-005` Gateway API traffic provider qualification.
- [ ] `CF12-006` OpAMP-managed collector fleets.
- [ ] `CF12-007` GCP and Azure resource/delivery providers.
- [ ] `CF12-008` Logical resource pools and fully on-demand physical
      infrastructure reconciliation.
- [ ] `CF12-009` Multi-region application, database, and telemetry failover.

Not planned:

- unrestricted SQL or database administration for agents;
- direct cloud SDK access from service plugins;
- raw production `kubectl` from the public Codefly API;
- automatic destructive database rollback;
- policy decisions based solely on MCP hints;
- two reconcilers owning the same workload; or
- agent/model bypass of plan, policy, approval, or evidence.

## Test commands

Commands must be run in the component repository shown. Use installed local
Codefly agents. Do not download agents with `curl` during integration tests.

### Core

```sh
cd /Users/antoine/development/deus/codefly/core
go test ./policy/... ./toolbox/... ./resources/... ./agents/...
go test -race ./policy/... ./toolbox/...
cd proto && buf lint
```

For any protobuf change, return to `core/` and regenerate using the repository's
documented local generator:

```sh
codefly generate proto --proto ../proto --output ./generated --local
```

Commit proto sources and generated Go bindings together. Run the full core suite
before a core release:

```sh
go test ./...
```

### CLI

```sh
cd /Users/antoine/development/deus/codefly/cli
go test ./pkg/deployments/... ./pkg/orchestration/... ./cmd/...
go test -race ./pkg/deployments/... ./pkg/orchestration/...
go test ./...
```

### Postgres service

```sh
cd /Users/antoine/development/deus/codefly/service-postgres
go test ./...
go test -race ./...
```

### Toolbox components

Run component-local full and race tests, then exercise launch through the local
aggregate workspace and installed agents. A future Postgres toolbox must include
real-Postgres integration tests, not only an in-process fake.

### Dependency-backed service tests

From the service workspace under test:

```sh
codefly test service --suite integration --race --coverage
codefly test service --suite e2e --verbose
```

Tests requiring programmatic lifecycle should use `sdk.WithDependencies()` with
a unique naming scope, bounded timeout, and guaranteed cleanup. The default
Codefly service test path starts declared dependencies unless explicitly run
stand-alone.

### Cross-platform roadmap gates

The supporting IaC repository currently provides:

```sh
cd /Users/antoine/development/deus/secure-saas-infra
npm run validate:local
```

This command validates the current IaC development scope only. It does not
build or execute the Codefly CLI, core, SDK, plugins, Warden, or Mind.
`verify:all` is reserved for the management-seed sealed fixed execution root on
the dedicated native-Linux qualifier; it is not a Codefly gate.

Do not run AWS apply merely because these pass. Real AWS preview/apply follows
the rootless AWS roadmap and requires explicit approval plus the reviewed plan
digest.

## Required test matrix

Every security-sensitive capability must cover:

| Dimension     | Required cases                                                                                 |
| ------------- | ---------------------------------------------------------------------------------------------- |
| Identity      | human, service, agent, missing, malformed, expired                                             |
| Scope         | correct org/tenant/env/context/resource and every cross-scope denial                           |
| Authorization | allow, deny, approval required, revoked, replayed, wrong audience, substituted action/resource |
| Input         | valid, unknown field, malformed, oversized, injection, path/URI traversal                      |
| Budget        | time, rows, bytes, concurrency, rate, cardinality, storage                                     |
| Lifecycle     | initial, duplicate, retry, cancellation, timeout, crash, stale fence, late completion          |
| Secrets       | plan/log/trace/error/result/state/evidence scans                                               |
| Supply chain  | wrong digest, unsigned, revoked, vulnerable, stale schema/protocol                             |
| Network       | expected endpoint, forbidden endpoint, direct egress, metadata, Unix socket                    |
| Recovery      | restart, dependency outage, controller outage, restore, rollback/forward-fix                   |

## Evidence per completed gate

Record:

- component repository URL, revision, dirty-state result, Go/core version;
- protocol/schema versions and generated-binding digest;
- plugin/toolbox manifest, binary/container digest, signature, SBOM, provenance;
- organization/environment/context/application/release/resource identities;
- policy bundle, authorization decision, approval, caveats, and plan digests;
- binding generations and safe reference IDs, never secret values;
- positive, denial, replay, crash, recovery, restore, and rollback results;
- rendered manifests, Git commit, controller/rollout/analysis identities;
- telemetry correlation and redaction evidence; and
- verifier version, timestamp, actor/workload identity, and pass/fail outcome.

Waivers must be explicit, owned, scoped, and time-limited. No waiver is allowed
for credential exposure, tenant isolation, missing authorization, unsigned
production artifacts, or unreviewed production mutation.

## First implementation assignment

The next agent should not start with Postgres SQL or Argo. Start with CF0 and
the smallest CF1 proof:

1. Run the independent clean-state and targeted baseline tests for `core`,
   `cli`, and `service-postgres`.
2. Audit current toolbox manifests for network enum drift and current strict
   admission behavior.
3. Add or certify the Toolbox conformance fixture.
4. Standardize typed well-known caveats without breaking existing generic
   caveats.
5. Build one host-side Toolbox session path using the fixture.
6. Prove allow, deny, expiry, replay, wrong audience/resource/tenant, timeout,
   cancellation, process crash, redaction, and cleanup.
7. Update documentation only after tests prove the described wiring.

The first demonstrable result is:

```text
host
  -> list summaries
  -> describe fixture.identity.describe
  -> evaluate host policy
  -> mint single-use scoped authorization
  -> launch/call guarded toolbox
  -> receive structured identity result
  -> emit redacted correlated audit
```

Once that is green, request/confirm authority for the separate
`toolbox-postgres` component and implement only:

```text
postgres.schema.list
postgres.schema.describe
postgres.query.named
```

No AWS environment is needed for these assignments.

## Definition of Codefly platform completion

The Codefly portion of this roadmap is complete when:

- native Toolbox sessions are safe and usable by Mind through its canonical
  registry;
- workload and agent-tool bindings are separate and credential-safe;
- Postgres schema/named-query tools pass real multi-tenant hostile tests;
- provider-neutral observability queries diagnose an exact release read-only;
- one release contract drives local and Argo delivery;
- release state is durable, idempotent, cancellable, recoverable, and auditable;
- remote CLI cannot fall back to control-plane host execution;
- Warden and Mind deploy independently through signed GitOps releases;
- rolling, canary, blue-green, abort, Git-revert rollback, migration
  forward-fix, restart, restore, and denial paths pass;
- AWS dev validates real IAM/EKS/ECR/RDS/network/DNS/controller behavior;
- production promotes the exact verified candidate; and
- no ordinary Codefly component exposes ambient provider, cluster-admin,
  database-owner, observability-admin, or cross-tenant authority.

## Standards references

- MCP tools revision 2025-11-25:
  <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP authorization/security:
  <https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization>
- PostgreSQL row security:
  <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>
- PostgreSQL privileges:
  <https://www.postgresql.org/docs/current/ddl-priv.html>
- OpenTelemetry OTLP:
  <https://opentelemetry.io/docs/specs/otlp/>
- OpenTelemetry Collector:
  <https://opentelemetry.io/docs/collector/>
- Argo CD automatic sync:
  <https://argo-cd.readthedocs.io/en/stable/user-guide/auto_sync/>
- Argo CD Projects:
  <https://argo-cd.readthedocs.io/en/stable/user-guide/projects/>
- Argo Rollouts:
  <https://argoproj.github.io/argo-rollouts/>
