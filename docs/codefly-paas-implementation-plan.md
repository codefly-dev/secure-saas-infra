# Codefly PaaS Implementation Plan

Status: proposed implementation plan
Scope: future changes to Codefly CLI, server, core protocol, plugins, provider
adapters, and product onboarding
Repository boundary: this plan is stored in `secure-saas-infra`; it does not
modify the Codefly, Warden, or Mind source trees

The decision-oriented delivery order lives in
[`codefly-bootstrap-paas-roadmap.md`](codefly-bootstrap-paas-roadmap.md). That
roadmap distinguishes mandatory seed/bootstrap IaC from the later Pulumi
Automation API infrastructure controller. This file remains the detailed
cross-repository implementation backlog.

The incremental capability, Postgres-tooling, observability, release-intent,
GitOps, progressive-delivery, test, and environment-promotion sequence lives in
[`codefly-capability-tooling-delivery-roadmap.md`](codefly-capability-tooling-delivery-roadmap.md).
That roadmap is the execution checklist for turning the Toolbox and delivery
research into verified Warden and Mind releases.

The self-contained implementation handoff for an agent modifying the Codefly
multi-repository workspace is
[`codefly-agent-implementation-roadmap.md`](codefly-agent-implementation-roadmap.md).

## Executive decision

Codefly should become a plugin-driven PaaS. Plugins own the desired state and
lifecycle semantics for their service type. They do not receive ambient cloud
credentials or unrestricted control-plane host access.

| Layer               | Owns                                                                                                                   | Must not own                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| CLI                 | Authentication, user intent, local UX, plan display, logs, cancellation                                                | Durable truth, cloud credentials, direct production mutation             |
| PaaS server         | Tenant authorization, policy, durable jobs, scheduling, state, locks, capabilities, audit, plugin dispatch             | Service-specific domain logic                                            |
| Service plugin      | Validation, desired state, build/sync/deploy plans, readiness, migrations                                              | Unrestricted provider credentials, host shell, cross-tenant state        |
| Resource broker     | Typed resource claims, idempotency, policy, provider selection                                                         | Application-specific logic                                               |
| Provider adapter    | Privileged cloud mutation for an approved typed claim                                                                  | User authentication, arbitrary plugin commands                           |
| Runtime worker      | Sandboxed execution of an approved job step                                                                            | Control-plane store access, scheduling authority, long-lived credentials |
| This IaC repository | Accounts, networks, clusters, identities, broker/runtime canvas, policies, generic contracts, provider implementations | Codefly product behavior                                                 |

The plugin initiates real work through `Deploy`. The privileged provider call is
performed by a constrained provider adapter behind the resource broker. This
keeps the plugin-native experience without making every service plugin a cloud
administrator.

## Delivery priority: application deployment first

Codefly has two related but independently deliverable planes:

| Plane                       | Near-term scope                                                                                                             | Long-term scope                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Application deployment      | Build, migrate, deploy, observe, promote, roll back, and destroy Warden/Mind inside selected pre-provisioned cloud contexts | Place components across multiple contexts and consume dynamically provisioned resources |
| Infrastructure provisioning | Resolve typed references and allocate logical resources from IaC-managed capacity                                           | Reconcile physical cloud resources on demand through brokered provider adapters         |

True on-demand infrastructure is a product goal, not the current critical path.
The first production slice deploys applications into cloud contexts created and
managed by this IaC repository. A context exposes only typed capabilities and
references for its account, region, network, runtime, registry, DNS, identity,
policy, and resource pools; it never exposes provider credentials.

The claim and broker contracts remain in place so this initial model can evolve
without redesign. At first, a claim may bind an existing database or allocate a
logical database and roles from pre-provisioned capacity. Later, the same claim
may trigger asynchronous physical provisioning. No near-term milestone should
be delayed solely to implement that later reconciler.

### North-star release

The first release has one outcome:

> Codefly builds, migrates, deploys, observes, and rolls back Warden and Mind in
> pre-provisioned AWS cloud contexts without giving either product cloud or
> cluster administrator credentials.

The operator creates and registers the contexts through IaC. A developer or CI
then selects a context and submits one Codefly deployment for either product.
Codefly returns a durable job identity, resolves only declared context
capabilities, builds immutable artifacts, runs bounded migrations, rolls out the
services, reports health, and records evidence. Warden and Mind can release and
roll back independently.

Terminology is precise:

- **application**: Warden or Mind as an independently releasable product;
- **platform scope**: the Codefly authorization and quota boundary for an
  application deployment; it is not a Warden/Mind SaaS customer tenant;
- **cloud context**: a credential-free catalog of approved runtime, network,
  registry, DNS, identity, policy, and managed-resource capabilities;
- **resource binding**: a reference to existing capacity available in a cloud
  context; and
- **resource claim**: the forward-compatible request that may initially resolve
  to an existing binding and may later trigger physical provisioning.

### Scope lock for the first release

Required:

- AWS only;
- pre-provisioned runtime, network, registry, DNS, identity, and database
  capacity;
- exact Warden and Mind source/module/service graphs;
- plan, deploy, status/watch, cancellation, migration, health, promotion,
  rollback, and release evidence;
- separate application, runtime, migration, and execution identities; and
- no remote control-plane host execution or ambient provider credentials.

Deferred without blocking the release:

- physical infrastructure provisioning from Codefly;
- GCP and Azure execution;
- a general plugin marketplace;
- arbitrary third-party application onboarding;
- automatic regional failover; and
- per-customer dedicated cloud infrastructure.

### Delivery board

| Gate | Outcome                                                       | Owning repositories                              | Status            |
| ---- | ------------------------------------------------------------- | ------------------------------------------------ | ----------------- |
| G0   | Exact, clean, pinned Warden/Mind product truth                | Warden, Mind, Codefly agents, IaC validation     | In progress       |
| G1   | Versioned, pre-provisioned AWS cloud contexts and bindings    | IaC                                              | In progress       |
| G2   | Durable Codefly application plan/deploy/watch/cancel/rollback | Codefly CLI/server/core                          | Not started       |
| G3   | Existing PostgreSQL binding and safe migration lifecycle      | PostgreSQL plugin, Codefly server, IaC contracts | Not started       |
| G4   | Warden end-to-end vertical slice                              | Warden, Codefly, IaC                             | Not started       |
| G5   | Mind multi-context end-to-end vertical slice                  | Mind, Codefly, IaC                               | Not started       |
| G6   | Joint security, recovery, and signed release gate             | All release repositories                         | Not started       |
| G7   | Physical infrastructure on demand                             | Broker/provider plugins and IaC                  | Deferred until G6 |

Work advances by closing gates in order. Later-gate design may be recorded, but
implementation must not delay the active gate unless an earlier contract would
otherwise become incompatible or unsafe.

## Why push work into plugins?

### Benefits

- Service knowledge stays with the service. PostgreSQL understands databases,
  extensions, migrations, readiness, connection publication, and upgrades.
- New capabilities ship as plugins instead of service-specific CLI/server
  branches.
- The same intent can target local Docker, AWS RDS/Aurora, GCP Cloud SQL, Azure
  Database for PostgreSQL, or another adapter.
- `Sync`, `Build`, `Deploy`, `Observe`, and `Destroy` become testable lifecycle
  contracts.
- Provider implementations can be versioned, policy checked, and replaced
  independently.

### Costs and risks

- Plugin protocol compatibility becomes a long-term product commitment.
- A compromised plugin is dangerous unless sandboxed and denied credentials,
  host execution, and cross-tenant access.
- Partial failure between plugin, broker, provider, and worker requires durable
  reconciliation; one successful RPC is not durable state.
- Distributed lifecycle logic needs structured events, correlation IDs,
  idempotency, and replay-safe recovery.
- Plugins need signing, provenance, revocation, admission policy, and conformance
  tests. Exact version pinning alone is insufficient.
- Cloud differences require capability discovery and explicit unsupported
  feature errors; a neutral API cannot hide every provider distinction.

### Rejected design: direct cloud access from service plugins

Do not mount AWS credentials into the PostgreSQL agent and let `Deploy` call RDS
directly. Plugin compromise would become account compromise, tenant isolation
would depend on plugin correctness, and central policy/idempotency/audit would
be bypassed. A provider adapter may itself be packaged as a plugin, but it runs
as a separately trusted broker worker with a constrained identity and typed
input.

## Target architecture

```text
developer / CI / Mind
          |
          | OIDC or workload identity, mTLS, tenant selection
          v
     Codefly CLI  ---------------- plan/log/status UX
          |
          | capability-bound ControlPlane API
          v
  Codefly PaaS API / gateway
          |
          +-- authorization + policy + immutable audit
          +-- durable state + idempotency + tenant locks
          +-- fair scheduler + cancellation + recovery
          |
          v
   tenant sandbox worker ---- runs signed service plugin
          |                         |
          | typed resource claim    | build/sync/deploy/observe result
          v                         |
     resource broker <--------------+
          |
          +-- aws-rds adapter
          +-- gcp-cloudsql adapter
          +-- azure-postgres adapter
          +-- kubernetes-postgres adapter
          |
          v
   provider resource + reference-only outputs
```

Every server-to-worker and worker-to-broker call carries actor, tenant, request,
job, operation, exact resource, source revision, artifact digest, desired-state
digest, capability ID, deadline, and trace context.

## Current Codefly baseline

The implementation builds on the local Codefly repositories:

- Builder already exposes `Sync` and `Deploy` RPCs.
- CLI orchestration has sync and deploy flows.
- Deploy can render manifests or apply them through a deployment manager.
- Agent processes are already managed gRPC services.
- A job-system design exists for one-shot and scheduled work.
- The daemon can run services or the Mind gateway.
- The gateway proxies plugin operations and directly performs filesystem, Git,
  command, and terminal operations.
- Non-loopback gateway binding currently requires a shared bearer token.

These are useful local-development foundations, not a production multi-tenant
server. Production must replace shared-token authorization, move host operations
into tenant sandboxes, and make lifecycle state durable.

### Infrastructure foundation completed in this repository

- [x] Publish a strict cloud-neutral `ManagedPostgres` intent and schema.
- [x] Bind the exact three Warden/Mind PostgreSQL services to independent tenant
      data boundaries and separate runtime/migration identities.
- [x] Produce deterministic intent/binding digests and reject destructive,
      dirty-state, credential-bearing, weak-auth, and cross-tenant input.
- [x] Compile the same intent into AWS broker claims and Codefly broker-only
      injection artifacts.
- [x] Render eight Kustomize-valid claim/contract artifacts without invoking or
      downloading agents. IaC renders no migration workload or migration
      admission policy.
- [x] Harden the concrete Aurora module to use an RDS-managed master credential
      and end-to-end IAM RDS Proxy without secret access.
- [x] Bind all new sources, contracts, and schemas into release evidence.
- [x] Add live K3s server validation for IaC-owned namespace and workload-token
      admission. Codefly owns migration allow/deny and execution tests.
- [x] Implement a strict provider-neutral resource-claim/state API with CAS,
      idempotency, capability redemption, generations, leases/fencing, bounded
      retry, drift, cancellation cleanup, and protected deletion.
- [x] Add a deterministic fake provider and hostile conformance suite; complete
      all three identical Codefly/AWS claims through it.
- [x] Remove VPC-CIDR database ingress in favor of distinct runtime, migration,
      proxy, and cluster SG boundaries.
- [x] Generate exact RDS-Proxy-resource/user-scoped runtime and migration
      `rds-db:connect` policies without wildcards or administrator privilege.

This foundation does not complete the unchecked Codefly tasks below. The
current PostgreSQL builder v0 agent cannot consume this contract; plugin v2,
transactional server persistence of the broker reducer, real provider
reconciliation/database grants, workload SG attachment, and real AWS lifecycle
tests remain implementation work in their owning repositories.

## Protocol boundaries

### Public ControlPlane API

Create `codefly/controlplane/v1` as the only remotely exposed platform API. Do
not expose raw Builder, Runtime, Code, terminal, or provider gRPC services.

Required services:

- `SessionService`: `WhoAmI`, `ListTenants`, `SelectTenant`, session exchange.
- `WorkspaceService`: register source, validate workspace, create/get immutable
  snapshots.
- `PlanService`: create, get, diff, and approve plans.
- `JobService`: submit, get, list, watch, cancel, and retry jobs.
- `DeploymentService`: get/list deployments, rollback, and destroy.
- `ArtifactService`: push, get, and retrieve provenance/SBOM/signatures.
- `ResourceService`: get/list/watch managed-resource claims.
- `AuditService`: get and verify evidence bundles.

API TODO:

- [ ] Version every request and response envelope.
- [ ] Require request ID and idempotency key on every mutation.
- [ ] Use explicit tenant and exact resource; never infer tenant from a path.
- [ ] Require deadlines and enforce server maximums.
- [ ] Return stable machine-readable reason codes.
- [ ] Make watch streams resumable with monotonic event IDs.
- [ ] Bound list, log, terminal, and stream payloads.
- [ ] Reject unknown fields at JSON/REST boundaries.
- [ ] Generate OpenAPI and gRPC descriptors from one source.

### Plugin protocol v2

Preserve Builder/Runtime v0 for local compatibility while adding a production
protocol that separates planning from execution.

Required plugin RPCs:

- `Describe`: identity, exact version/digest, protocol range, service kinds,
  capabilities, schemas, and required sandbox profile.
- `Validate`: validate service/dependency configuration without mutation.
- `SyncPlan`: deterministic source/config changes and desired-state digest.
- `BuildPlan`: inputs, outputs, sandbox, egress, secret references, and
  reproducibility requirements.
- `DeployPlan`: workloads, managed-resource claims, migration steps, readiness,
  rollback metadata, and output contracts.
- `Reconcile`: compare desired and observed state and emit idempotent steps.
- `Observe`: health, provider references, generation, drift, and redacted output.
- `DestroyPlan`: safe teardown, retention, and final-snapshot requirements.
- `ValidateUpgrade`: protocol, service, schema, engine, and provider checks.

Plugin execution TODO:

- [ ] Planning RPCs are pure: no provider mutation, undeclared network, secret
      material, or filesystem writes outside the mounted snapshot.
- [ ] Canonicalize and SHA-256 digest every plan.
- [ ] Require plans to declare every capability before execution.
- [ ] Bind approved plan signatures to tenant, source, plugin digest,
      environment, and expiry.
- [ ] Execute only signed approved plans.
- [ ] Make reconciliation level-triggered and idempotent.
- [ ] Deny plugin-authored arbitrary IAM, public endpoints, privileged pods,
      host mounts, and unbrokered egress.
- [ ] Return secret references, never plaintext values.
- [ ] Never give plugins control-plane store credentials.

### Resource broker protocol

Create `codefly/resources/v1` with `SubmitClaim`, `GetClaim`, `WatchClaim`,
`CancelClaim`, `DestroyClaim`, and `GetCapabilities`.

The claim envelope contains claim/tenant/environment/resource identity, API
version, desired-state digest, plugin identity/digest, source revision,
idempotency key, expected generation, deadline, exact capability, provider
constraints, typed desired state, and a reference-only output schema.

Broker TODO:

- [ ] Authenticate workers using mTLS workload identity.
- [ ] Re-run authorization rather than trust the worker decision.
- [ ] Validate resource schema and platform policy.
- [ ] Select an installed compatible provider adapter.
- [ ] Commit claim, capability redemption, and idempotency atomically.
- [ ] Fence concurrent reconcilers by claim generation.
- [ ] Persist observed state and provider resource IDs.
- [ ] Redact provider errors returned to unprivileged clients.
- [ ] Emit immutable allow, denial, mutation, and drift events.

## Lifecycle semantics

### Sync

`Sync` reconciles source-derived files and configuration. It does not mutate
production infrastructure.

1. Snapshot the declared source revision.
2. Run plugin `Validate`.
3. Run pure `SyncPlan` and calculate the desired-state digest.
4. Policy-check paths and operations.
5. Local CLI may apply the plan to the worktree after confirmation.
6. Remote PaaS applies only to an isolated snapshot or returns a patch/artifact.
7. Record before/after digests and evidence.

### Build

1. Plugin emits `BuildPlan`.
2. Server verifies source, dependencies, plugin digest, and policy.
3. Fair scheduler assigns an ephemeral tenant builder.
4. Builder receives a one-use artifact-push capability.
5. Build runs without host namespaces, socket, ambient credentials, or direct
   egress.
6. Output is digest-pinned, scanned, signed, and accompanied by provenance/SBOM.
7. Persist result and prove sandbox cleanup.

### Deploy

`Deploy` is the plugin-facing entrypoint for real platform work.

1. Plugin emits a `DeployPlan`; it does not mutate yet.
2. Server validates policy, calculates semantic diff, and records approval.
3. Submit managed-resource claims to the broker.
4. Provider adapters reconcile claims and return reference-only outputs.
5. Render workloads from approved artifact digests and output references.
6. Run migration/hooks as one-shot jobs with separate identities.
7. Pass readiness and policy gates.
8. Atomically promote the deployment generation.
9. On failure, clean up or roll back according to the approved plan.

### Cancel, rollback, destroy, recover

- Cancellation is a durable transition, not only context cancellation.
- Running work remains locked while `cancelling` until cleanup is proven.
- Rollback targets a previously promoted compatible digest/generation.
- Destroy requires a plan, retention decision, and provider policy.
- Database destroy requires elevated approval, final snapshot, retained backup,
  and evidence.
- After restart, recover jobs and reconcile worker leases before assignment.

## Server implementation

Create a dedicated `codefly-server`; do not expose the current local gateway as
the production server.

### API edge and identity

- [ ] OIDC authorization-code/device flow for humans.
- [ ] Federated workload identity for CI/internal services.
- [ ] mTLS between ingress, API, workers, broker, and adapters.
- [ ] Short-lived sessions; no static shared gateway token.
- [ ] Per-RPC tenant/resource authorization.
- [ ] Per-tenant request/rate/concurrency/deadline/stream limits.
- [ ] Immutable denial audit.
- [ ] Private-by-default endpoint.

### Durable state

Implement the neutral reducer semantics already defined in this repository:

- [ ] Serializable or conditional compare-and-swap revisions.
- [ ] Atomic snapshot/event/idempotency/capability-redemption commit.
- [ ] Per-tenant FIFO and deterministic fair scheduling.
- [ ] Global and tenant concurrency quotas.
- [ ] Resource locks with fencing tokens.
- [ ] Bounded retry preserving the original deadline.
- [ ] Cancellation cleanup acknowledgement.
- [ ] Deployment generations and bounded rollback history.
- [ ] Encrypted backup, restore testing, and regional recovery.
- [ ] Immutable event export with integrity verification.

Use a storage port so DynamoDB and serializable PostgreSQL implementations pass
the same conformance suite. Eventually consistent object storage alone is not a
safe live coordination store.

### Scheduler and workers

- [ ] Separate builder, deployer, plugin-plan, migration, provider, and audit
      pools.
- [ ] Schedule by sandbox profile and provider capability.
- [ ] One job per ephemeral sandbox; no shared writable workspace.
- [ ] Inject one-use capabilities and scoped workload identity only.
- [ ] Broker egress; deny direct Internet by default.
- [ ] Enforce CPU/memory/storage/process/output/lifetime limits.
- [ ] Authenticate heartbeat, completion, and cleanup evidence.
- [ ] Fence late workers after timeout or replacement.

### Plugin registry

- [ ] Content-address plugin executable/container digests.
- [ ] Require signatures, provenance, SBOM, and vulnerability policy.
- [ ] Maintain publisher trust roots and revocations.
- [ ] Pin plugin digest in every plan/job/deployment.
- [ ] Run non-root with read-only filesystem and no default service token.
- [ ] Separate planning and execution sandbox profiles.
- [ ] Deny undeclared network/filesystem/process/provider capability.
- [ ] Add compatibility, upgrade, quarantine, and revocation controls.

### Audit and observability

- [ ] Structured events include actor, tenant, request, operation, resource,
      authorization, source/artifact/plugin/plan digests, job/attempt, claim,
      deployment generation, timestamp, and trace.
- [ ] Sign batches or hash-chain events before immutable export.
- [ ] Redact at creation; never export raw secrets or SQL values.
- [ ] Measure queue fairness/age, job latency, cancellation, cleanup, plugin and
      provider reconciliation, deployment health, rollback, and recovery.
- [ ] Define subsystem SLOs and alerts.

## CLI implementation

### Authentication and contexts

- [ ] `codefly auth login --server`, `status`, `logout`, and refresh.
- [ ] OIDC device flow for terminal login.
- [ ] Named contexts with server, tenant, environment; no token in workspace
      YAML.
- [ ] OS keychain storage for refresh material.
- [ ] Explicit `--local` uses local agents only.
- [ ] `--remote` never falls back to host execution.

### Remote UX

- [ ] `codefly plan service|module|workspace --env ...`.
- [ ] Show plugin/workload/resource/migration/identity changes and denials.
- [ ] `codefly deploy ... --plan <digest> --idempotency-key ...`.
- [ ] Require confirmation or signed CI approval for production.
- [ ] `codefly jobs list|get|watch|cancel|retry`.
- [ ] `codefly deployments list|get|rollback|destroy`.
- [ ] `codefly resources list|get|watch`.
- [ ] `codefly evidence get|verify`.
- [ ] Stable JSON plus human-readable output.
- [ ] Resumable watches/logs and specific exit codes.

### Source safety and command migration

- [ ] Upload only declared paths; reject symlink/path traversal.
- [ ] Exclude `.git`, credentials, local state, and undeclared files.
- [ ] Use immutable content-addressed snapshots and show upload manifest.
- [ ] Bind plan/job to snapshot digest.
- [ ] Preserve current local workflows behind local mode.
- [ ] Route remote sync/build/deploy through ControlPlane API.
- [ ] Deprecate direct remote gateway file/Git/shell endpoints.
- [ ] Put remote terminal/command in an authorized tenant sandbox session.
- [ ] Never expose `sh -c` from the control-plane host.

## Core, protobuf, and SDK implementation

- [ ] Add `controlplane/v1`, `plugins/v2`, `resources/v1`, `jobs/v1`, and
      `evidence/v1` protobuf packages.
- [ ] Add shared identity, tenant, request, capability, deadline, digest,
      pagination, event cursor, status, and error details.
- [ ] Extend agent advertisement with protocol range, capabilities, schemas,
      sandbox profiles, and deterministic planning.
- [ ] Extend deployment context with tenant, snapshot, environment, approved
      plan, job identity, deadline, and reference-only configuration.
- [ ] Replace unstructured trust-boundary maps with allowlisted versioned typed
      resources.
- [ ] Add shared deterministic canonicalization/digest libraries.
- [ ] Add secret-reference types that cannot serialize values.
- [ ] Generate reproducible SDKs and publish compatibility/deprecation rules.
- [ ] Provide plugin SDK lifecycle plumbing, cancellation, deadlines, logs,
      tracing, redaction, claims, bounded workspace access, emulators, and
      conformance tests.
- [ ] Provide no raw provider SDK client in the service-plugin SDK.
- [ ] Add a malicious-plugin harness for network/filesystem/process/privilege
      and secret-access attempts.

## PostgreSQL and managed database reference

PostgreSQL is the first plugin-driven managed resource.

### Neutral service settings

Declare database name, compatible PostgreSQL major version, extensions,
local/managed runtime class, migration lineages, backup/RPO/RTO/restore needs,
capacity/SLO class, tenant isolation, and deletion/retention policy. Do not put
RDS IDs, AWS region, KMS ARN, password, or security-group ID in
`service.codefly.yaml`.

### PostgreSQL `SyncPlan`

- [ ] Validate identifiers, extension allowlist, filenames, ordering, and source
      ownership.
- [ ] Hash migrations and emit a lineage manifest.
- [ ] Reject modified checksums for published migrations.
- [ ] Detect destructive SQL and require a reviewed exception outside the
      default production path.
- [ ] Generate a `ManagedPostgres` claim and deterministic desired-state digest.
- [ ] Never connect to production during sync planning.

### PostgreSQL `DeployPlan`

- [ ] Request `ManagedPostgres` through the broker.
- [ ] Watch durable claim state instead of holding one RPC indefinitely.
- [ ] Receive endpoint/port/database/CA/runtime-identity/migration-identity
      references; receive no admin password.
- [ ] Create a one-shot migration job with separate identity/capability.
- [ ] Acquire an advisory lock scoped to database and lineage.
- [ ] Recheck desired-state and migration checksums.
- [ ] Use forward-only transactional production migrations.
- [ ] Fail closed on dirty state; never automatic `Drop`, `Force`, or global
      `Down` in production.
- [ ] Emit before/after version, checksums, duration, actor, plan, and claim
      generation evidence.
- [ ] Publish structured IAM/TLS configuration. Keep password URL compatibility
      only in explicit local development mode.

### AWS RDS/Aurora provider adapter

- [ ] Discover regional engine/version capabilities.
- [ ] Use private subnets and no public accessibility.
- [ ] Use customer-managed KMS with rotation and constrained grants.
- [ ] Satisfy neutral multi-AZ/capacity requirements.
- [ ] Require IAM database authentication and TLS.
- [ ] Use RDS Proxy with TLS and IAM where compatible.
- [ ] Use AWS-managed master secret bootstrap; never synthesize a password into
      Pulumi or Codefly state.
- [ ] Create separate least-privilege runtime and migration database roles.
- [ ] Restrict ingress to explicit workload/migration boundaries, not the whole
      VPC by default.
- [ ] Implement PITR, deletion protection, final snapshot, AWS Backup, restore
      tests, and regional recovery from claim requirements.
- [ ] Export safe monitoring/audit without SQL parameter leakage.
- [ ] Reconcile idempotently, import governed existing resources, detect drift,
      classify updates, and publish reference-only outputs.

Also implement local Docker, optional Kubernetes operator, GCP Cloud SQL, and
Azure PostgreSQL adapters against one provider conformance suite.

## Warden and Mind onboarding

Initial managed PostgreSQL bindings:

| Tenant | Codefly service              | Data boundary       |
| ------ | ---------------------------- | ------------------- |
| Warden | `warden-platform/saas/store` | `warden-saas-state` |
| Mind   | `mind-server/infra/postgres` | `mind-infra-state`  |
| Mind   | `mind-server/users/store`    | `mind-users-state`  |

TODO:

- [ ] Pin PostgreSQL plugin by signed digest, not only `0.0.103`.
- [ ] Add managed intent while preserving local Docker.
- [ ] Split runtime and migration identities.
- [ ] Convert consumers from password URLs to structured IAM/TLS config.
- [ ] Validate independent migration lineages.
- [ ] Render local and AWS plans from the same intent.
- [ ] Run cross-tenant denial, provision, migration, deploy, rollback, restore,
      and recovery tests.
- [ ] Bind exact Codefly/plugin/Warden/Mind/IaC/plan/artifact revisions and
      digests into release evidence.

## Testing program

### Unit and contract

- [ ] Strict parser/schema tests for every envelope.
- [ ] Cross-language golden canonicalization/digests.
- [ ] Authorization allow/deny matrix for every RPC/resource.
- [ ] Stale revision, idempotency, replay, cancellation, retry, deadline, lock,
      and rollback state tests.
- [ ] Plugin planning determinism and provider hostile-claim conformance.

### Integration

- [ ] CLI/server identity and tenant selection.
- [ ] Server/sandbox plugin planning and broker/provider dispatch.
- [ ] Worker/server crash, duplicate delivery, late completion, and partition.
- [ ] Plugin upgrade/protocol negotiation and artifact revocation/quarantine.
- [ ] Secret-reference redaction across logs/errors/traces/evidence.

### End-to-end, chaos, and security

- [ ] Deploy Warden/Mind using all declared dependencies and local agents only.
- [ ] Provision three claims in an ephemeral/test AWS account.
- [ ] Verify IAM/TLS migrations and workload connectivity.
- [ ] Prove all Warden/Mind job/resource/log/database/artifact/deployment crossing
      is denied.
- [ ] Cancel build, migration, provider reconciliation, and deployment.
- [ ] Roll back, restore backup, recover server/region, and sign evidence.
- [ ] Verify no sandbox has host socket/path/namespace, ambient credentials,
      direct egress, or cross-tenant mount.
- [ ] Fuzz decoders/path handling and test wildcard, audience, tenant, replay,
      expiry, and substituted-digest attacks.
- [ ] Kill workers at each lifecycle boundary and verify recovery.
- [ ] Complete external penetration test before public exposure.

## Ordered vertical-slice delivery

### Phase 0 — Freeze product truth and cloud-context contract

- [x] Model all six modules and 18 current Warden/Mind services.
- [x] Render the complete graph with installed local agents in isolated copies.
- [x] Publish strict `CloudContext`, capability, binding, placement, and status
      schemas with no credential-bearing fields.
- [x] Bind every component to an explicit context class and every dependency to
      an exact service or managed-resource reference.
- [ ] Reconcile current local agent pins, DNS inputs, environment normalization,
      and stale product module references in their owning repositories. IaC
      must not patch Codefly sources.
- Exit: clean, pinned sources produce one deterministic application/context plan
  per product with no temporary compatibility mutation.

### Phase 1 — Pre-provision the AWS contexts

- [ ] Produce a platform application context and an isolated execution context
      from this IaC repository.
- [ ] Register credential-free references for EKS runtime, ECR, private network,
      DNS, identities, policy profile, observability, and PostgreSQL capacity.
- [ ] Pre-provision the three Warden/Mind database bindings with distinct
      runtime/migration identities and source network boundaries.
- [ ] Prove context inventory, connectivity, IAM/TLS, backup, and denial paths
      without Codefly holding AWS credentials.
- Exit: a fixture workload can consume every required binding using only its
  scoped workload identity.

Implemented locally in the IaC graph:

- [x] Strict credential-free catalog, parser, status gate, schema, digest, and
      deterministic renderer.
- [x] Exact placement of all six components, three PostgreSQL bindings, and the
      delegated Mind customer-code execution runtime.
- [x] KMS-encrypted immutable ECR repositories for all 18 current services.
- [x] Contract-driven creation/output wiring for exactly three PostgreSQL
      databases with separate runtime/migration identities and SG boundaries.
- [x] Versioned Warden/Mind blueprint preset with explicit dev/staging/prod
      platform, execution, data, and egress CIDRs in all modular stack examples.
- [ ] Apply and promote the contexts using evidence from a dedicated AWS
      sandbox account.

### Phase 2 — Minimum durable Codefly application deployment

- [ ] Add versioned context selection plus plan/deploy/status/watch/cancel and
      rollback envelopes to Codefly.
- [ ] Persist deployment jobs, idempotency, revisions, events, locks, deadlines,
      cancellation, and bounded history transactionally.
- [ ] Authenticate every remote mutation and move any required command, file,
      build, and plugin execution off the control-plane host.
- [ ] Preserve explicit local mode in the Codefly-owned qualification pipeline;
      this IaC repository consumes only the resulting signed contract evidence.
- Exit: a signed fixture application survives duplicate requests and a server
  restart, deploys into a selected context, and rolls back without cloud or
  cluster administrator credentials.

### Phase 3 — PostgreSQL binding and migration path

- [ ] Make the PostgreSQL service plugin validate migrations and emit the strict
      `ManagedPostgres` requirement already defined here.
- [ ] Resolve that requirement from pre-provisioned context bindings; do not
      create or destroy RDS in this phase.
- [ ] Publish structured endpoint, CA, database, runtime identity, and migration
      identity references without a password URL.
- [ ] Run checksum-bound, advisory-locked, forward-only migrations as a separate
      one-shot identity before workload promotion.
- Exit: a fixture service deploys, migrates, redeploys idempotently, rejects a
  dirty/destructive lineage, and rolls back the application without rolling
  back committed schema history.

### Phase 4 — Warden vertical slice

- [ ] Plan, build, migrate, and deploy both Warden modules and all declared
      services into the platform application context.
- [ ] Verify internal dependencies, ingress, identities, database boundaries,
      health, cancellation, promotion, and rollback.
- [ ] Produce digest-bound evidence from clean Warden, Codefly, agent, IaC,
      plan, image, policy, and deployment revisions.
- Exit: one authenticated submission deploys Warden, reports health, and can
  independently cancel or roll back it without affecting Mind.

### Phase 5 — Mind vertical slice

- [ ] Plan, build, migrate, and deploy all four Mind modules and declared
      services.
- [ ] Place trusted control services in the platform application context and
      customer-code execution only in the isolated execution context.
- [ ] Verify Warden/Mind APIs as explicit authenticated dependencies with no
      shared database, identity, or implicit network authority.
- Exit: one authenticated submission deploys Mind across its approved contexts,
  reports health, and can independently cancel or roll back it without affecting
  Warden.

### Phase 6 — Joint release gate

- [ ] Exercise concurrent deployments, duplicate delivery, restart recovery,
      stale completion, cancellation, failed migration, failed rollout, and
      independent rollback.
- [ ] Run cross-application, cross-context, replay, wildcard, substituted-digest,
      host-access, ambient-credential, and direct-egress denial tests.
- [ ] Publish operator runbooks, SLOs, dashboards, kill switches, signed SBOM,
      provenance, and release evidence.
- Exit: both products pass the vertical-slice definition of done from clean,
  pinned sources in the same release candidate.

### Phase 7 — Physical infrastructure on demand (deferred)

- [ ] Allocate logical databases and roles from governed resource pools.
- [ ] Add asynchronous provider reconciliation, drift, capacity expansion,
      backup/restore lifecycle, and protected destruction.
- [ ] Reuse the same `CloudContext`, claim, binding, status, and evidence
      contracts; do not change the application deployment experience.
- Exit: a missing physical capability can be created safely and a paused
  deployment resumes after the claim becomes ready.

## Vertical-slice definition of done

- One authenticated Codefly submission can plan and deploy either Warden or Mind
  into explicitly selected, pre-provisioned AWS contexts.
- Both products use their exact clean source graph and pinned local agents.
- Deployment jobs are durable, idempotent, observable, cancellable, and
  independently reversible.
- Database bindings and migrations use distinct least-privilege identities,
  structured references, IAM/TLS, and no plaintext password URL.
- No remote operation executes on the control-plane host and no application or
  service plugin receives cloud or cluster administrator credentials.
- Warden and Mind have independent release, identity, data, network, health,
  cancellation, and rollback boundaries while explicit authenticated APIs may
  connect them.
- Secrets remain references and never enter source, plans, state, logs, traces,
  errors, artifacts, or evidence.
- Evidence binds source, Codefly, agents, context, plan, policy, artifacts,
  migrations, deployment, and verification digests.

## First authorized Codefly implementation slice

When Codefly source changes are explicitly authorized:

1. Add common request, application scope, context, digest, and capability
   envelopes.
2. Add read-only plan and context compatibility evaluation for a fixture
   application.
3. Add a durable application deployment job with status/watch/cancel and
   rollback state.
4. Resolve a fake and then existing `ManagedPostgres` binding without provider
   creation.
5. Route build, migration, and deployment through authorized workers rather
   than the control-plane host.
6. Prove deterministic plans, replay denial, restart recovery, migration safety,
   and independent rollback before onboarding Warden and Mind.
7. Defer AWS resource creation until after both product vertical slices pass.

This validates the application platform before privileged cloud mutation.
