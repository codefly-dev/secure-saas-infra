# Codefly Capability, Tooling, Observability, and Delivery Roadmap

Status: proposed execution roadmap
Scope: Codefly core/CLI/server, Codefly service plugins, Mind tool integration,
GitOps delivery, observability, and the supporting contracts and infrastructure
in this repository
Critical path: secure Postgres tools -> observability tools -> provider-neutral
release intent -> Argo CD/Argo Rollouts -> Warden -> Mind -> production gate

This roadmap turns the platform research into an incrementally verifiable
implementation plan. It complements, rather than replaces:

- [Codefly PaaS implementation plan](codefly-paas-implementation-plan.md), which
  defines the full CLI/server/plugin/resource-broker architecture;
- [Codefly bootstrap and Pulumi PaaS roadmap](codefly-bootstrap-paas-roadmap.md),
  which defines AWS organization, environment, and infrastructure-controller
  sequencing; and
- [Rootless AWS and Codefly execution roadmap](rootless-aws-codefly-execution-roadmap.md),
  which defines rootless bootstrap, short-lived AWS authority, and the real-AWS
  gates.

For a single self-contained document that can be handed directly to an agent
working in the multi-repository Codefly workspace, use
[Codefly implementation roadmap and agent handoff](codefly-agent-implementation-roadmap.md).
For the active IaC-only task queue and its executable validation gates, use
[IaC validation-first execution TODO](iac-validation-first-execution-todo.md).

This file owns the missing capability/tooling/delivery sequence: how Postgres
and observability become safe agent tools, how Mind consumes them, how Codefly
models an application release above Kubernetes, and how that release is
progressively delivered and verified.

## Outcome

The first complete outcome is:

> Mind can use Codefly-provided Postgres and observability capabilities without
> receiving their underlying credentials, and Codefly can plan, deploy,
> observe, promote, abort, and roll back Warden or Mind through GitOps in a
> pre-provisioned AWS cloud context with complete tenant-bound evidence.

Physical infrastructure-on-demand remains a platform goal, but it is not on
this roadmap's initial critical path. RDS, EKS, networking, registries, and the
GitOps controllers may be pre-provisioned while the application/tooling plane
is proven.

## Non-negotiable decisions

1. A plugin package may implement several capabilities, but capability
   contracts and authorities remain separate.
2. Service plugins never receive unrestricted AWS, Kubernetes, Pulumi, or
   control-plane credentials.
3. RDS lifecycle belongs to an infrastructure provider adapter. PostgreSQL
   semantics, local runtime, migration validation, workload bindings, and safe
   Postgres tools belong to the PostgreSQL capability package.
4. Workload bindings and agent-tool bindings are different products. A
   workload may receive a secret reference; an LLM or agent must not receive a
   reusable database or observability credential.
5. Codefly Toolbox is the native capability protocol. MCP is an interoperability
   adapter and never the authorization boundary.
6. Codefly policy and Mind policy intersect. Both must allow a tool call;
   neither layer may widen the other.
7. OTLP is telemetry ingest/export. Provider-neutral telemetry query is a
   separate Codefly contract.
8. Codefly owns release intent, authorization, plan identity, and audit. Argo
   CD owns Git-to-cluster reconciliation. Argo Rollouts owns progressive
   rollout state. Istio or Gateway API owns traffic routing.
9. Git is the production desired-state boundary. Codefly must not require
   standing production cluster-admin credentials after controller bootstrap.
10. No milestone is complete because a happy-path demo worked. Its denial,
    replay, expiry, cancellation, recovery, and tenant-isolation tests must
    also pass.

## Capability model

| Capability            | Owns                                                                 | Example implementation                    | Must not own                                |
| --------------------- | -------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------------- |
| `resource.lifecycle`  | Provision, observe, update, and delete physical or logical resources | AWS RDS provider, local Docker provider   | Application behavior or agent authorization |
| `service.binding`     | Produce typed, reference-only workload configuration                 | PostgreSQL runtime binding                | Exposing secrets to an LLM                  |
| `toolbox`             | Describe and invoke mediated operations                              | PostgreSQL toolbox, observability toolbox | Granting its own authority                  |
| `telemetry.sink`      | Describe an OTLP ingest destination                                  | OTEL Collector binding                    | Telemetry queries                           |
| `observability.query` | Query traces, logs, metrics, SLOs, and release health                | SigNoz adapter                            | OTLP ingest or deployment ownership         |
| `delivery`            | Plan, commit, observe, promote, abort, and roll back releases        | Local Kubernetes, Argo CD                 | Infrastructure provisioning                 |
| `policy.audit`        | Evaluate authority and record evidence                               | Codefly gateway plus Mind policy          | Service-specific lifecycle logic            |

The first manifest/protocol revision should advertise capabilities by stable
identifier and version, with schemas and transport endpoints. Do not create a
different top-level plugin kind for every provider or product.

## Repository ownership

| Repository or package           | Primary ownership on this roadmap                                                                                                             |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `secure-saas-infra`             | Cloud contexts, resource-provider contracts, AWS adapters, EKS/RDS/collector/Argo bootstrap, policies, release evidence, AWS deployment gates |
| Codefly `core`                  | Capability advertisement, Toolbox contract, scoped authorization, release intent and delivery interfaces                                      |
| Codefly CLI/server              | Authentication, plan UX, durable release jobs, Git provider orchestration, status/watch/promote/abort/rollback                                |
| Codefly `service-postgres`      | Abstract PostgreSQL settings, local runtime, migration validation, workload binding, schema and safe-query toolbox                            |
| Mind                            | Native Codefly Toolbox provider, descriptor mapping, intersecting policy, effect approval, MCP compatibility                                  |
| Warden and Mind product modules | Application requirements, migrations, release strategy preferences, health/SLO declarations                                                   |
| Argo CD                         | Pull-based reconciliation from Git                                                                                                            |
| Argo Rollouts                   | Canary/blue-green execution and analysis state                                                                                                |
| SigNoz adapter                  | Provider-specific read queries behind the neutral observability toolbox                                                                       |

Cross-repository changes require explicit changes in their owning repositories.
This IaC repository remains the contract, environment, evidence, and bootstrap
home; it must not duplicate Codefly or Mind product code.

## Task status and completion rules

Task statuses:

- `READY`: all prerequisites exist and implementation can start;
- `BLOCKED`: a named prerequisite is missing;
- `LATER`: deliberately outside the initial critical path; and
- `DONE`: code, tests, documentation, and required evidence have landed.

A task may move to `DONE` only when:

- its versioned contract and compatibility behavior are documented;
- positive and negative unit tests pass;
- relevant cross-repository contract fixtures pass;
- secrets are absent from plans, logs, traces, errors, and evidence;
- its required verification level has passed; and
- generated artifacts and exact source revisions are recorded where the task
  crosses a trust boundary.

## Incremental verification ladder

Every phase declares the highest required level. Lower levels are mandatory and
must remain green.

| Level | Name                      | Where                                                  | What it proves                                                                           | AWS mutation               |
| ----- | ------------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------- | -------------------------- |
| V0    | Static contract           | Developer machine and CI                               | Schemas, protobuf compatibility, strict parsing, canonical digests, lint/build           | Never                      |
| V1    | Unit/model                | Developer machine and CI                               | State machines, policy decisions, limits, failure classification, deterministic planning | Never                      |
| V2    | Cross-repository contract | Isolated checkout fixtures                             | Codefly, Mind, IaC, plugins, and products agree on exact versioned envelopes             | Never                      |
| V3    | Real local dependencies   | Docker/local agents through Codefly                    | Real Postgres, collector, Git, and service dependencies behave correctly                 | Never                      |
| V4    | Hostile/chaos             | Local processes and disposable dependencies            | Tenant crossing, replay, expiry, injection, crash, cancellation, stale worker, redaction | Never                      |
| V5    | Disposable cluster        | k3d/K3s in CI or developer machine                     | Server-side Kubernetes admission, GitOps reconciliation, rollout, traffic, and recovery  | Never                      |
| V6    | AWS dev                   | Dedicated non-production AWS accounts                  | IAM, EKS, ECR, RDS IAM/Proxy, private DNS/network, controller identity                   | Dev only, reviewed plan    |
| V7    | Release candidate         | Optional ephemeral pre-production or dedicated preprod | Production-equivalent configuration, load, restore, failover, operator runbooks          | Approved non-prod only     |
| V8    | Production promotion      | Production accounts                                    | Exact signed candidate is promoted with human/CI approval and rollback evidence          | Explicit approved mutation |

Rules:

- V0-V4 run before any cluster deployment.
- V5 runs before the first AWS application deployment.
- V6 starts with a fixture application, then Warden, then Mind.
- V7 may use an ephemeral release environment; a permanent staging account is
  not required initially.
- V8 never deploys an artifact, plugin, plan, policy result, or manifest digest
  different from the V7 candidate.
- A failed denial-path test blocks promotion even when all happy paths pass.

## Environment and deployment strategy

### Local developer loop

Use installed local Codefly agents and real local dependencies. Do not download
or `curl` agents during tests. Prefer Codefly's dependency graph and
`sdk.WithDependencies()`/`codefly test service`, which start declared service
dependencies using their actual agents.

Local is authoritative for:

- parser and protocol work;
- Codefly-to-Mind Toolbox integration;
- PostgreSQL roles, RLS, queries, migrations, and pool behavior;
- collector processing and SigNoz adapter contract tests;
- release state-machine and deterministic renderer tests; and
- policy, replay, cancellation, and failure-injection tests.

### Disposable cluster loop

Use a new disposable k3d/K3s cluster per suite or uniquely named run. Install
only pinned controllers and apply server-side admission. The cluster suite must
cover:

- Argo CD reconciliation from a disposable Git remote;
- exact AppProject source/destination/resource restrictions;
- Argo Rollouts rolling, canary, blue/green, promotion, and abort;
- Istio routing first, with Gateway API compatibility later;
- OTEL Collector filtering and tenant attribute stamping;
- SigNoz or a deterministic query-adapter fixture;
- NetworkPolicy, pod security, identity, secret-reference, and image admission;
- failed canary analysis and stable-version recovery; and
- cluster deletion after the suite.

### AWS dev deployment

The first AWS mutation happens only after the fixture release passes V5.
Deploy in this order:

1. bootstrap or verify a credential-free dev `CloudContext`;
2. verify private EKS, ECR, DNS, workload identities, collector, Argo CD, and
   Argo Rollouts independently;
3. verify an existing managed-Postgres binding with separate runtime,
   migration, schema-reader, and toolbox-reader identities;
4. deploy a fixture service through the full GitOps path;
5. induce a failed canary and prove abort/recovery;
6. deploy Warden and complete its independent rollback gate; and
7. deploy Mind and complete cross-context and cross-product denial tests.

Every AWS preview must run under an observation or narrowly scoped mutation
role, through the policy pack, with the reviewed plan digest saved. Apply must
consume that exact reviewed plan. No plugin receives the role credentials.

### Production promotion

Production requires:

- all phase exit gates through V7;
- clean pinned Codefly, Mind, Warden, plugin, IaC, and GitOps revisions;
- signed images, SBOMs, provenance, plugins, Git commits, and evidence;
- successful backup restore and application rollback drills;
- reviewed migration classification and forward-fix plan;
- explicit production approval bound to the exact release/plan digest;
- active alerts, dashboards, SLOs, kill switches, and operator ownership; and
- a change window for the initial release.

Application rollback and database rollback are deliberately separate. Codefly
may abort or revert an application release. It must not automatically reverse a
committed destructive schema migration.

## Roadmap overview

| Gate | Outcome                                             | Required verification | AWS needed       | Status                |
| ---- | --------------------------------------------------- | --------------------- | ---------------- | --------------------- |
| C0   | Capability and security contracts frozen            | V0-V2                 | No               | READY                 |
| C1   | Mind invokes a native Codefly Toolbox safely        | V0-V4                 | No               | BLOCKED by C0         |
| C2   | Tenant-safe Postgres schema and named-query tools   | V0-V4                 | No               | BLOCKED by C1         |
| C3   | Provider-neutral observability query through SigNoz | V0-V5                 | No               | BLOCKED by C1         |
| C4   | Provider-neutral durable release core               | V0-V5                 | No               | BLOCKED by C0         |
| C5   | Argo CD/Rollouts GitOps provider                    | V0-V6                 | Dev AWS after V5 | BLOCKED by C4         |
| C6   | Warden AWS vertical slice                           | V0-V7                 | Yes              | BLOCKED by C2, C3, C5 |
| C7   | Mind AWS vertical slice using safe tools            | V0-V7                 | Yes              | BLOCKED by C6         |
| C8   | Joint production release gate                       | V0-V8                 | Yes              | BLOCKED by C7         |
| C9   | Additional providers and infra-on-demand            | Provider-specific     | Yes              | LATER                 |

Contract work for C1, C2, C3, and C4 may be designed together. Implementation
should keep one integrated vertical slice green rather than creating four
disconnected frameworks.

## C0 — Capability and security contract freeze

Status: `READY`
Required verification: V0-V2
Deployment: none

- [ ] `CAP-001` Publish stable identifiers and versions for
      `resource.lifecycle`, `service.binding`, `toolbox`, `telemetry.sink`,
      `observability.query`, `delivery`, and `policy.audit`.
- [ ] `CAP-002` Extend agent/plugin advertisement with capability version,
      schema digest, transport, protocol range, and sandbox profile.
- [ ] `CAP-003` Define common organization, platform-scope, tenant,
      environment, cloud-context, application, release, and resource identity.
- [ ] `CAP-004` Define reference-only secret and credential lease types that
      cannot serialize secret material.
- [ ] `CAP-005` Define compatibility negotiation, deprecation, and unsupported
      capability errors.
- [ ] `AUTH-001` Define the exact Codefly-to-plugin authorization envelope:
      principal, organization, audience, action, resource, expiry, max uses,
      caveats, policy digest, request digest, and approval reference.
- [ ] `AUTH-002` Define mandatory caveats for tenant, environment, resource,
      query/release operation, row/byte/time limit, and mutation class.
- [ ] `AUTH-003` Define the two-gate rule: Codefly grants an upper bound and
      Mind intersects it with the active objective/tool policy.
- [ ] `AUD-001` Define mandatory audit correlation fields and redaction rules.
- [ ] `THREAT-001` Threat-model prompt injection, confused deputy, credential
      exfiltration, query DoS, schema leakage, replay, Git substitution,
      controller conflict, and compromised plugins.
- [ ] `TEST-CAP-001` Add schema/protobuf golden fixtures shared by Codefly,
      Mind, and this repository.
- [ ] `TEST-CAP-002` Add old/new/unknown-version and capability-downgrade tests.

Exit criteria:

- One read-only fixture capability is described identically in Codefly, Mind,
  and IaC fixtures.
- Unknown versions, missing identity, credential-bearing fields, and weaker
  capability negotiation fail closed.
- The threat model assigns an owner and executable verification to every
  identified boundary.

## C1 — Native Codefly Toolbox integration in Mind

Status: `BLOCKED` by C0
Required verification: V0-V4
Deployment: local processes only

- [ ] `TOOL-001` Add a native Codefly Toolbox catalog provider at Mind's
      canonical `toolbind.BuildToolbox` join point.
- [ ] `TOOL-002` Map Codefly summaries and descriptions to Mind
      `ToolDescriptor` without losing input/output schema, tags, examples,
      error modes, idempotency, read-only, destructive, or execution metadata.
- [ ] `TOOL-003` Preserve Codefly's two-phase summary/describe flow so Mind does
      not inject every heavy schema into every model turn.
- [ ] `TOOL-004` Route calls through Mind's canonical registry and executor;
      reject descriptor/route mismatches and duplicate canonical names.
- [ ] `TOOL-005` Evaluate the Mind allowlist and effect gate before requesting
      Codefly authorization.
- [ ] `TOOL-006` Request and attach audience-bound, short-lived, use-limited
      Codefly authorization for the exact tool request.
- [ ] `TOOL-007` Validate action/resource/principal/audience/caveats in the
      Toolbox process before touching the underlying system.
- [ ] `TOOL-008` Propagate session, task, objective, tool invocation, Codefly
      request, and trace identifiers end to end.
- [ ] `TOOL-009` Normalize errors without exposing secrets or provider details
      that would help an attacker.
- [ ] `MCP-001` Upgrade Mind's MCP adapter from `2024-11-05` to the selected
      supported revision, initially `2025-11-25`.
- [ ] `MCP-002` Preserve output schemas, structured content, annotations,
      pagination, resource links, and protocol error versus tool error.
- [ ] `MCP-003` Add Streamable HTTP and OAuth/resource-indicator support for
      external providers; retain stdio for local trusted processes.
- [ ] `MCP-004` Treat MCP annotations as untrusted hints; derive authority from
      Codefly/Mind configuration and policy.
- [ ] `TEST-TOOL-001` Test allow/deny at each policy layer independently.
- [ ] `TEST-TOOL-002` Test expired, replayed, revoked, wrong-audience,
      wrong-tenant, substituted-resource, and caveat-violation tokens.
- [ ] `TEST-TOOL-003` Fuzz descriptor and call-result decoding.
- [ ] `TEST-TOOL-004` Kill the Toolbox before, during, and after a call and
      prove deterministic retry/no-retry behavior.

Exit criteria:

- Mind discovers and calls a Codefly-hosted read-only fixture capability.
- Denial at either Codefly or Mind blocks the call.
- A credential never enters the descriptor, prompt, trace, result, or evidence.
- One-use authorization cannot be replayed after success, failure, or timeout.

## C2 — Secure PostgreSQL tooling vertical slice

Status: `BLOCKED` by C1
Required verification: V0-V4 initially; V6 before Warden/Mind AWS release
Deployment: local Postgres first; existing RDS binding only after local exit

### Binding separation

- [ ] `PG-001` Define `WorkloadDatabaseBinding` with reference-only endpoint,
      database, TLS, and workload credential lease metadata.
- [ ] `PG-002` Define `PostgresToolboxBinding` with toolbox identity, resource
      scope, role class, policy reference, and no connection URL.
- [ ] `PG-003` Keep password URL compatibility only in explicit local
      development mode; mark it unavailable to tool/LLM contexts.
- [ ] `PG-004` Define the provider contract by which local Postgres or AWS RDS
      supplies both bindings without changing the service contract.

### Read-only tool surface

- [ ] `PG-010` Implement `postgres.schema.list`.
- [ ] `PG-011` Implement `postgres.schema.describe` for allowed schemas,
      tables, views, columns, constraints, indexes, and RLS metadata.
- [ ] `PG-012` Expose schema as addressable read-only Toolbox resources without
      row samples or secret defaults.
- [ ] `PG-013` Implement a versioned named-query catalog with typed parameters
      and result schemas.
- [ ] `PG-014` Implement `postgres.query.named` using server-owned prepared
      statements/views, not caller SQL.
- [ ] `PG-015` Implement safe `postgres.query.explain` without `ANALYZE` and with
      an explicit cost ceiling.
- [ ] `PG-016` Implement `postgres.migration.status` as metadata-only.
- [ ] `PG-017` Classify schema objects/columns and redact or reject sensitive
      outputs.

### Database authority

- [ ] `PG-020` Create separate migration-owner, workload-runtime,
      schema-reader, tenant-reader, named-command, and privileged-worker roles.
- [ ] `PG-021` Ensure toolbox roles are not superusers, do not own application
      tables, cannot `SET ROLE` into stronger roles, and lack `BYPASSRLS`.
- [ ] `PG-022` Use `FORCE ROW LEVEL SECURITY` for tenant tables consumed by
      agent tools.
- [ ] `PG-023` Derive tenant/user/environment context from verified Codefly
      caveats and set it transaction-locally.
- [ ] `PG-024` Remove application-settable bypass flags from production policy.
- [ ] `PG-025` Audit and constrain `SECURITY DEFINER`, function execution,
      `search_path`, `PUBLIC`, `COPY`, `REFERENCES`, and `TRUNCATE` authority.

### Query budgets and audit

- [ ] `PG-030` Execute agent reads in a read-only transaction.
- [ ] `PG-031` Set statement, transaction, lock, and idle-transaction timeouts
      on the server/session.
- [ ] `PG-032` Enforce maximum rows, response bytes, time range, schemas,
      functions, query IDs, and estimated cost.
- [ ] `PG-033` Reject multi-statement input, locks, data-changing CTEs, `COPY`,
      DDL/DML, and unsafe/volatile functions on any future controlled-SQL path.
- [ ] `PG-034` Emit audit metadata containing query ID, parameter digest,
      tenant, role class, limit, duration, and row/byte count without SQL values
      or returned data.
- [ ] `PG-035` Add bounded connection pools and per-tenant/tool concurrency and
      rate limits.

### Verification

- [ ] `TEST-PG-001` Use real local Postgres through installed Codefly agents
      and `WithDependencies`; mocks alone are insufficient.
- [ ] `TEST-PG-002` Build a role/operation matrix covering schema, read,
      migration, worker, owner, and forbidden administration.
- [ ] `TEST-PG-003` Test two organizations and at least two tenants per
      organization against every exposed table/view/query.
- [ ] `TEST-PG-004` Test pool reuse and transaction failure for leaked tenant or
      role context.
- [ ] `TEST-PG-005` Test SQL injection in every parameter and identifier-like
      field.
- [ ] `TEST-PG-006` Test time, lock, cost, rows, bytes, cancellation, and
      connection exhaustion.
- [ ] `TEST-PG-007` Test revoked/expired/replayed authorization and substituted
      tenant, database, schema, query ID, and result limit.
- [ ] `TEST-PG-008` Test that secrets and row data do not enter logs, traces,
      errors, migration evidence, or model-visible artifacts.
- [ ] `TEST-PG-009` Add property/fuzz tests for catalog parameters, identifiers,
      canonicalization, and result truncation.
- [ ] `TEST-PG-010` In AWS dev, repeat IAM/TLS/RLS tests against RDS and RDS
      Proxy, including server-side timeout behavior.

Exit criteria:

- Mind can inspect permitted schema and execute named tenant-scoped reads with
  no database credential.
- Cross-tenant, stronger-role, arbitrary SQL, and unbounded query attempts fail.
- The same toolbox contract works against local Postgres and an existing AWS
  RDS binding.
- No general write tool exists at this gate.

## C3 — Telemetry and observability tooling vertical slice

Status: `BLOCKED` by C1
Required verification: V0-V5 initially; V6 before product release
Deployment: local collector/query fixture, then disposable cluster, then AWS dev

### Telemetry ingest

- [ ] `OBS-001` Define `TelemetrySinkBinding`: OTLP endpoint/protocol, TLS,
      credential reference, resource-attribute policy, and availability.
- [ ] `OBS-002` Instrument Codefly traces, metrics, and logs using standard OTEL
      signals; keep Mind's structured audit artifacts distinct but correlated.
- [ ] `OBS-003` Make TLS/auth required outside explicit local development and
      remove silent production stdout fallback.
- [ ] `OBS-004` Deploy a collector layer for batching, retry, memory limits,
      redaction, filtering, sampling, and provider export.
- [ ] `OBS-005` Stamp organization, environment, cloud context, application,
      service, release, artifact, Git revision, and Mind execution IDs at a
      trusted collector/gateway boundary.
- [ ] `OBS-006` Reject, replace, or quarantine untrusted application-supplied
      tenant identity attributes.

### Provider-neutral query contract

- [ ] `OBS-010` Define typed read operations for service listing, trace search,
      trace retrieval, log search/aggregation, metric query, SLO status, and
      release health.
- [ ] `OBS-011` Require organization/environment/service/release scope and
      enforce time-range, cardinality, series, row, and byte budgets.
- [ ] `OBS-012` Define provider-neutral result/error/pagination schemas without
      pretending every backend uses the same query language.
- [ ] `OBS-013` Keep observability administration—alert, dashboard, view, and
      notification mutations—in a separate future capability.

### SigNoz provider

- [ ] `OBS-020` Implement a SigNoz query adapter using a Viewer/service-account
      identity and no dashboard/alert/notification mutation authority.
- [ ] `OBS-021` If the official SigNoz MCP server is reused, mount an explicit
      read-only allowlist through Codefly Toolbox and normalize structured
      results into `observability.query`.
- [ ] `OBS-022` Do not expose raw provider credentials, unrestricted query
      builders, or provider-admin APIs to Mind.
- [ ] `OBS-023` Implement `observability.release.health` by joining telemetry,
      Codefly release state, and rollout analysis for one exact release.

### Verification

- [ ] `TEST-OBS-001` Send deterministic fixture traces, metrics, and logs
      through a real local collector.
- [ ] `TEST-OBS-002` Verify tenant/environment filtering before and after
      collector processing and in query results.
- [ ] `TEST-OBS-003` Inject secrets, tokens, SQL parameters, and sensitive
      attributes and prove redaction before export.
- [ ] `TEST-OBS-004` Test time/cardinality/result limits, pagination, partial
      results, backend timeout, and backend outage.
- [ ] `TEST-OBS-005` Test read-only provider identity against every mutating
      SigNoz operation and require denial.
- [ ] `TEST-OBS-006` Test wrong-tenant, wrong-environment, replayed, expired,
      and substituted-release authorization.
- [ ] `TEST-OBS-007` Deploy collector plus adapter in the disposable cluster
      and diagnose one deliberately unhealthy fixture release.
- [ ] `TEST-OBS-008` Repeat private endpoint, TLS, identity, tenant filter, and
      release correlation tests in AWS dev.

Exit criteria:

- Mind can answer why an exact release is unhealthy using bounded read-only
  traces, logs, metrics, and rollout state.
- OTLP ingest and telemetry query remain separate contracts.
- Tenant identity cannot be forged by application telemetry.
- No SigNoz mutation is reachable through the initial toolbox.

## C4 — Provider-neutral release core

Status: `BLOCKED` by C0
Required verification: V0-V5
Deployment: fake/local provider and disposable cluster only

- [ ] `REL-001` Define `ReleaseIntent` with application, scope, cloud context,
      source, immutable artifact digest, configuration/binding generations,
      strategy, gates, migration phases, deadline, and approvals.
- [ ] `REL-002` Define `DeliveryPlan` with renderer/provider versions, rendered
      digest, policy result, diff summary, Git target, controller target, and
      required effects.
- [ ] `REL-003` Define release states: draft, planned, approved, committed,
      reconciling, progressing, healthy, degraded, aborted, and rolled back.
- [ ] `REL-004` Define `Plan`, `Commit`, `Observe/Watch`, `Promote`, `Abort`, and
      `Rollback` provider operations.
- [ ] `REL-005` Bind approval and apply to the exact source, artifact,
      configuration, binding, policy, rendered, and plan digests.
- [ ] `REL-006` Persist idempotency, sequence, events, locks, leases/fences,
      deadlines, cancellation, attempts, and bounded history transactionally.
- [ ] `REL-007` Define rolling, canary, and blue-green intent independently of
      Argo resource fields.
- [ ] `REL-008` Define analysis gates with provider-neutral success/failure,
      inconclusive, interval, count, timeout, and promotion semantics.
- [ ] `REL-009` Define expand/contract migration phases, advisory locking,
      compatibility windows, and forward-fix policy.
- [ ] `REL-010` Bind image signature, provenance, SBOM, vulnerability policy,
      and admission results into the release plan.
- [ ] `REL-011` Implement a fake provider conformance suite.
- [ ] `REL-012` Adapt the current local Kubernetes renderer/apply path to the
      release contract without making it the production path.
- [ ] `TEST-REL-001` Golden-test deterministic manifests and plan digests.
- [ ] `TEST-REL-002` Property-test legal and illegal state transitions.
- [ ] `TEST-REL-003` Test duplicate commit, promote, abort, rollback, late
      completion, stale fence, lost watch, and server/worker restart.
- [ ] `TEST-REL-004` Test artifact/config/binding/policy/plan substitution.
- [ ] `TEST-REL-005` Test migration failure before workload promotion and prove
      committed schema is never automatically reversed.

Exit criteria:

- Fake GitOps and local Kubernetes providers execute the same release intent.
- The same plan is deterministic across clean repeated runs.
- Restart, duplicate delivery, cancellation, and stale completion converge to
  one valid auditable state.

## C5 — Argo CD and progressive delivery provider

Status: `BLOCKED` by C4
Required verification: V0-V6
Deployment: disposable cluster first, then AWS dev fixture

### GitOps provider

- [ ] `GIT-001` Implement a Git provider for a managed repository/path/branch
      with deterministic file ownership.
- [ ] `GIT-002` Create signed commits and optional pull requests containing no
      secrets and referencing the release/plan digest.
- [ ] `GIT-003` Detect concurrent edits, path ownership violations, stale base,
      non-fast-forward updates, and signature failure.
- [ ] `ARGO-001` Bootstrap Argo CD through IaC with pinned images/charts and
      private controller access.
- [ ] `ARGO-002` Replace wildcard AppProject sources and namespaced resource
      permissions with exact repositories, destinations, namespaces, and kinds.
- [ ] `ARGO-003` Model per-environment sync policy, sync windows, pruning,
      self-heal, deletion/finalizer, and orphan behavior.
- [ ] `ARGO-004` Map Argo sync, health, operation, drift, and error state into
      Codefly release events.
- [ ] `ARGO-005` Use Git revert/new desired state for release rollback; do not
      rely on an imperative rollback that conflicts with automatic sync.

### Progressive delivery

- [ ] `ROL-001` Render ordinary Kubernetes `Deployment` only for rolling
      strategy and Argo `Rollout` for canary/blue-green strategy; never let both
      controllers own one workload.
- [ ] `ROL-002` Map generic canary weights, pauses, manual gates, experiments,
      and analysis into Argo Rollouts.
- [ ] `ROL-003` Map blue/green active/preview services, pre-promotion analysis,
      post-promotion analysis, delay, and abort.
- [ ] `ROL-004` Integrate analysis with the neutral observability contract or a
      narrowly scoped metrics/web provider.
- [ ] `ROL-005` Implement Istio stable/canary routing first and configure Argo
      CD ignore rules for rollout-controller-owned traffic weights.
- [ ] `ROL-006` Keep traffic intent provider-neutral and add Gateway API only
      after the Istio path passes conformance and the selected plugin is pinned
      and verified.
- [ ] `ROL-007` Require separate policies for deploy, production promotion,
      abort, retry, and rollback effects.

### Verification

- [ ] `TEST-ARGO-001` Reconcile from a disposable Git remote into a new
      disposable cluster.
- [ ] `TEST-ARGO-002` Test unapproved repository, destination, namespace,
      cluster-scoped kind, and namespaced kind denials.
- [ ] `TEST-ARGO-003` Test drift/self-heal, controller restart, Git outage,
      invalid manifest, failed admission, and stale commit.
- [ ] `TEST-ROL-001` Test rolling, canary, blue/green, manual promote, automatic
      promote, abort, failed analysis, and recovery.
- [ ] `TEST-ROL-002` Verify traffic reaches only the intended stable/canary
      revision at every step.
- [ ] `TEST-ROL-003` Verify a failed canary cannot mutate stable configuration,
      secrets, bindings, or another tenant/application.
- [ ] `TEST-AWS-DEL-001` Repeat the fixture release through ECR, private EKS,
      workload identity, private DNS, Argo, Rollouts, Istio, and observability
      in the AWS dev context.

Exit criteria:

- An immutable fixture image becomes a signed Git change, reconciles through
  Argo CD, progresses through canary analysis, and promotes or aborts.
- Codefly observes the complete release without standing cluster-admin
  credentials.
- Git, controller, policy, artifact, telemetry, and release evidence share the
  same exact release identity.

## C6 — Warden AWS vertical slice

Status: `BLOCKED` by C2, C3, and C5
Required verification: V0-V7
Deployment: AWS dev, then optional ephemeral release candidate

- [ ] `WARDEN-001` Freeze clean source, Codefly agent pins, dependency graph,
      health contracts, migrations, and release strategy.
- [ ] `WARDEN-002` Plan all Warden services against one approved cloud context
      without provider or cluster credentials.
- [ ] `WARDEN-003` Resolve existing database and telemetry bindings.
- [ ] `WARDEN-004` Run checksum-bound migrations with the migration identity.
- [ ] `WARDEN-005` Deploy through GitOps and progressive delivery.
- [ ] `WARDEN-006` Exercise schema/read observability tools under Warden's
      platform scope and tenant boundaries.
- [ ] `WARDEN-007` Test cancel, failed migration, failed rollout, abort,
      independent rollback, and recovery.
- [ ] `WARDEN-008` Produce signed evidence binding every source, agent, plugin,
      context, policy, plan, migration, image, Git, controller, and test digest.

Exit criteria:

- One authenticated submission deploys and observes Warden in AWS dev.
- Warden can be aborted or rolled back without affecting Mind resources.
- All database, telemetry, network, identity, and tool boundaries pass positive
  and denial tests.

## C7 — Mind AWS vertical slice

Status: `BLOCKED` by C6
Required verification: V0-V7
Deployment: AWS dev, then optional ephemeral release candidate

- [ ] `MIND-001` Freeze clean source, Codefly agent pins, dependency graph,
      health contracts, migrations, tool catalog, and release strategy.
- [ ] `MIND-002` Plan trusted Mind services in the platform context and
      customer-code execution only in the isolated execution context.
- [ ] `MIND-003` Resolve database, telemetry, Warden API, and execution
      capabilities through explicit bindings.
- [ ] `MIND-004` Deploy all Mind services through GitOps and progressive
      delivery.
- [ ] `MIND-005` Use the native Codefly Postgres and observability toolboxes in
      an end-to-end objective without exposing credentials.
- [ ] `MIND-006` Prove one objective cannot widen its catalog, tenant,
      environment, database, query, time, row, release, or effect authority.
- [ ] `MIND-007` Test cancellation and recovery across Mind, Toolbox, Codefly,
      Postgres, observability, GitOps, and execution boundaries.
- [ ] `MIND-008` Test independent Mind rollback without changing Warden's
      release, database, telemetry, or identity state.
- [ ] `MIND-009` Produce signed cross-repository release evidence.

Exit criteria:

- One authenticated submission deploys Mind into its approved AWS contexts.
- A real Mind objective uses safe Codefly Postgres and observability tools under
  both policy layers.
- Cross-product communication occurs only through explicit authenticated APIs;
  data, identity, release, and tool authority remain independent.

## C8 — Joint production release gate

Status: `BLOCKED` by C7
Required verification: V0-V8
Deployment: release candidate, then production with explicit approval

- [ ] `PROD-001` Run Warden and Mind concurrently through deploy, cancellation,
      failed migration, failed canary, rollback, restart, and recovery.
- [ ] `PROD-002` Run cross-organization, cross-tenant, cross-environment,
      cross-context, cross-product, cross-database, cross-toolbox, and
      cross-release denial tests.
- [ ] `PROD-003` Run load and fairness tests for tool calls, queries, telemetry,
      release jobs, controller events, and audit export.
- [ ] `PROD-004` Restore databases and platform state from backups and verify
      RPO/RTO evidence.
- [ ] `PROD-005` Exercise break-glass, plugin revocation, token-key rotation,
      provider outage, Git outage, controller outage, and observability outage.
- [ ] `PROD-006` Complete external penetration testing and remediate release
      blockers.
- [ ] `PROD-007` Publish SLOs, alerts, dashboards, paging ownership, runbooks,
      kill switches, rollback procedure, migration forward-fix procedure, and
      customer communication procedure.
- [ ] `PROD-008` Generate and independently verify the signed release evidence
      bundle.
- [ ] `PROD-009` Bind production approval to the exact candidate evidence and
      plan digest.
- [ ] `PROD-010` Promote without rebuilding or re-rendering the candidate.
- [ ] `PROD-011` Run post-deploy smoke, tenant-isolation, telemetry, and rollback
      readiness checks.

Exit criteria:

- The signed release candidate is promoted unchanged.
- All critical SLOs and security signals are observable before customer traffic.
- Rollback and forward-fix paths have named operators and current evidence.
- No application, service plugin, Toolbox, or Mind objective has provider,
  cluster-admin, database-owner, or observability-admin authority.

## C9 — Deliberately deferred expansion

Status: `LATER`

- [ ] `LATER-001` Controlled arbitrary read-only SQL with a real PostgreSQL
      parser/AST, after named queries prove insufficient.
- [ ] `LATER-002` Named Postgres command tools with typed procedures,
      idempotency, row caps, and effect approval.
- [ ] `LATER-003` Observability administration tools for alerts and dashboards.
- [ ] `LATER-004` Flux delivery provider and Flagger compatibility.
- [ ] `LATER-005` Gateway API traffic provider after pinned plugin conformance.
- [ ] `LATER-006` OpAMP collector-fleet management with signed configuration,
      allowlisted packages, and non-overridable local restrictions.
- [ ] `LATER-007` GCP and Azure resource/delivery provider qualification.
- [ ] `LATER-008` Logical resource pools and fully on-demand physical
      infrastructure reconciliation.
- [ ] `LATER-009` Multi-region application and telemetry failover.

The following are not planned capabilities:

- unrestricted SQL or database administration for agents;
- raw provider credentials in service plugins;
- direct production `kubectl` from Codefly;
- automatic destructive schema rollback;
- trusting MCP annotations as authorization;
- multiple delivery controllers reconciling the same workload; or
- an agent bypassing plan, policy, approval, or evidence gates.

## Test command map

Commands are examples of the intended repeatable gates. Keep them in CI and
replace broad commands with narrower package runs only during local iteration.

### This infrastructure repository

```sh
npm run validate:local
```

This is the ordinary IaC development gate. `verify:all` is reserved for the
management-seed sealed fixed execution root on the dedicated native-Linux
qualifier. Real AWS preview/apply is separate and must use the rootless AWS
roadmap's reviewed-plan process.

Codefly CLI, core, plugin, Warden, and Mind qualification belongs to the
Codefly-owned pipeline after a separate infrastructure integration plan exists.

### Codefly

```sh
cd core && go test ./policy/... ./toolbox/...
cd ../service-postgres && go test ./...
cd ../cli && go test ./pkg/deployments/... ./pkg/orchestration/...
```

For real dependency-backed service integration, run from the relevant Codefly
service workspace using installed local agents:

```sh
codefly test service --suite integration --race --coverage
codefly test service --suite e2e --verbose
```

The default service test path starts declared dependencies. Service tests may
also use `sdk.WithDependencies()` directly when they need programmatic control,
unique naming scopes, timeouts, or deliberate dependency failure.

### Mind

```sh
make test-go
make test-server
make e2e
```

During Toolbox work, run targeted packages first, then the full gates:

```sh
cd modules/mind/services/mind/code
go test ./pkg/toolbind ./pkg/tools/... ./pkg/supervisor -count=1
```

### Disposable cluster

The final C3-C5 implementation must provide one non-interactive command that:

1. creates a uniquely named cluster;
2. installs pinned Argo CD, Argo Rollouts, Istio, Kyverno, collector, and test
   observability dependencies;
3. pushes or imports immutable fixture images;
4. runs all positive and denial scenarios;
5. exports evidence and controller diagnostics; and
6. deletes the cluster even after failure.

Until that command exists, C5 cannot be marked `DONE`.

## Evidence required at each promotion

Every gate produces a machine-readable manifest containing:

- repository URL, clean revision, and dirty-state result;
- Codefly CLI/server/core/plugin and Mind versions/digests;
- capability and schema versions/digests;
- organization/environment/cloud-context/application/release identities;
- source snapshot and dependency-lock digests;
- image, SBOM, provenance, signature, and vulnerability-policy results;
- policy bundle, authorization, approval, and plan digests;
- resource binding generations and reference identifiers, never secret values;
- database role/RLS/migration verification results;
- rendered manifests, Git commit, Argo application, rollout, and analysis IDs;
- telemetry correlation and redaction verification;
- positive, negative, chaos, restore, and rollback test results;
- timestamps, actor/workload identity, and verifier version; and
- an overall pass/fail decision with explicit waivers.

Waivers must be scoped, owned, time-limited, visible in the plan, and forbidden
for credential exposure, tenant isolation, unsigned artifacts, missing
authorization, or unreviewed production mutation.

## Immediate implementation queue

Execute these tasks first and keep the vertical slice continuously green:

1. `CAP-001` through `CAP-005`: capability advertisement and compatibility.
2. `AUTH-001` through `AUD-001`: scoped authority and audit envelope.
3. `TOOL-001` through `TOOL-009`: native Codefly Toolbox provider in Mind.
4. `TEST-TOOL-001` through `TEST-TOOL-004`: denial, replay, and crash evidence.
5. `PG-001` through `PG-004`: workload/toolbox binding separation.
6. `PG-010` through `PG-014`: schema and named-query read-only slice.
7. `PG-020` through `PG-035`: production-shaped roles, RLS, budgets, and audit.
8. `TEST-PG-001` through `TEST-PG-009`: real local hostile verification.
9. `OBS-001`, `OBS-004`, `OBS-010`, and `OBS-020`: smallest end-to-end
   observability query slice.
10. `REL-001` through `REL-005`: release intent and plan contract before Argo
    implementation begins.

The first demo is intentionally narrow:

> A Mind objective discovers `postgres.schema.describe` and one
> `postgres.query.named` tool from Codefly, receives authority scoped to one
> tenant and database, executes against real local Postgres, and produces a
> redacted audit record. Wrong-tenant, replay, expiry, row-limit, and timeout
> scenarios all fail.

That demo proves the security and capability spine. Observability and delivery
then reuse the same discovery, policy, authorization, audit, and evidence model
instead of inventing parallel mechanisms.

## Definition of complete

This roadmap is complete only when:

- workload secrets and agent tools use separate bindings;
- Mind consumes Codefly capabilities through its canonical tool registry;
- both policy layers and the Toolbox enforce exact scoped authority;
- safe Postgres schema/named-query tools pass real cross-tenant tests;
- provider-neutral observability queries diagnose an exact release without
  mutation or cross-tenant visibility;
- one provider-neutral release contract drives local and Argo delivery;
- Warden and Mind deploy independently through signed GitOps releases;
- canary/blue-green promotion, abort, application rollback, migration
  forward-fix, restart, restore, and denial paths are tested;
- the AWS dev and release-candidate gates pass with real IAM, EKS, ECR, RDS,
  networking, DNS, controllers, and telemetry; and
- production promotes the exact verified candidate with complete signed
  evidence and no ambient administrator credentials.
