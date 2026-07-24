# Codefly PaaS: Warden and Mind

> Deferred, non-executable design. Codefly, Warden, Mind, Kubernetes, and
> GitOps are outside the current management-seed IaC release. The
> `render:codefly*`, `kubectl`, and evidence commands below are target-state
> examples, not commands supported or qualified by the current `package.json`.

The complete proposed implementation plan for the Codefly CLI, production
server, plugin protocol, resource broker, provider adapters, PostgreSQL/RDS
reference flow, Warden/Mind rollout, and acceptance tests is in
[`codefly-paas-implementation-plan.md`](./codefly-paas-implementation-plan.md).

## Target

Codefly is a PaaS compiler and deployment control plane for two independently
operable products:

- **Warden**: SaaS administration, policy/approval surfaces, and the controlled
  signed-plugin registry.
- **Mind**: agent APIs, durable capability issuance/redemption, and isolated
  customer-code execution.

They share the neutral security kernel, not credentials or storage. Cloud
adapters provide infrastructure; the Codefly adapter injects a deployment
environment into the same application intent.

```text
PlatformBlueprint
  ├─ cloud-neutral network / workload / identity / data / evidence
  ├─ application: warden
  │    ├─ component: platform (independent identity/data)
  │    ├─ component: saas (independent identity/data)
  │    └─ explicit capability call to Mind
  └─ application: mind
       ├─ components: mind / execution / infra / users
       ├─ independent identity/data boundary per component
       └─ explicit capability call to Warden
             |
             v
      Codefly PaaS compiler
       ├─ local k3d environment
       └─ AWS EKS environment
```

## Implemented Here

- Generic `ApplicationDeployment` and dependency contracts in the neutral core.
- Generic component/module identities, data ownership, ingress, and explicit
  intra-product calls; the core has no Codefly, Kubernetes, or AWS types.
- Security policies that require:
  - short-lived, non-shared workload identities;
  - non-shared application data boundaries;
  - matching workload/data tenant scope;
  - minimum availability during disruption;
  - digest pinning, signature verification, provenance, and rollback;
  - explicit authenticated dependency audiences and actions;
  - deployment and authorization evidence.
- Security-graph nodes and edges for application placement, identity, data, and
  inter-application calls.
- Canonical `createWardenMindBlueprint()` intent.
- Deterministic Codefly compiler and artifact renderer with:
  - independent modules, namespaces, and service accounts;
  - local k3d or AWS EKS environment injection;
  - digest-pinned service images;
  - default-deny ingress and egress intent;
  - explicit internal dependency endpoints;
  - workload-identity and supply-chain requirements;
  - semantic application, identity, workload-plane, and blueprint-digest labels.
- Real `workspace.codefly.yaml`, `module.codefly.yaml`, and
  `service.codefly.yaml` output using exact pinned local agents.
- Cross-module Warden/Mind service dependencies and module interfaces.
- Namespace, service-account, default-deny/scoped-allow NetworkPolicy,
  PodDisruptionBudget, security-contract, and environment-overlay output.
- Overlay patches that enforce the compiled replica count, service account, and
  digest-pinned image on generated Codefly service deployments.
- Strict `paas.codefly.dev/v1alpha1` JSON Schema and compatibility gates for the
  Codefly CLI range, agent protocol, exact agents, and required PaaS features.
- Cross-repository release evidence containing the IaC revision, contract/schema
  hashes, security-critical source hashes, optional Codefly/Warden/Mind/
  SaaS-kernel revisions, and aggregate hashes for rendered deployment trees.
- The evidence manifest is hashed as a SLSA provenance subject and shipped with
  release artifacts and the SPDX SBOM.
- Local validation through the actual Codefly parser with `--local-agents`, plus
  Kubernetes rendering of both module security bases.
- Tests proving the topology is unchanged between local and AWS targets and that
  mutable images, hidden services, shared identities/data, and weak release
  posture fail closed.
- An exact two-workspace product compiler covering Warden `platform`/`saas` and
  Mind `mind`/`execution`/`infra`/`users`, with all 18 active services.
- Component-aware security overlays with independent namespaces and service
  accounts, default-deny connectivity, explicit caller identities, PDBs,
  digest-pinned workload patches, and fail-closed Kyverno verification for
  signatures, SLSA provenance, and SPDX attestations.
- An isolated real-product render gate that pins the desired contract in
  disposable copies, blocks external network access, uses local agents only,
  renders all 18 services, and Kustomize-validates six security bases plus 18
  self-contained service integrations.
- A strict, provider-neutral multi-tenant PaaS security contract covering
  authenticated endpoints, tenant quotas, seven separated identity roles,
  sandbox isolation, scheduling, software supply chain, durable deployment
  state, recovery, and immutable audit evidence.
- A Codefly control-plane injection compiler that turns that neutral contract
  into distinct system/builder/runtime/egress namespaces, tenant-derived
  service accounts, ResourceQuotas, default-deny and broker-only networking,
  runtime classes, and builder admission policy for Warden and Mind.
- A disposable-cluster admission gate that additionally server-validates all 18
  control-plane artifacts and proves the tenant builder is admitted only with
  its tenant identity and required microVM runtime class.

## Cloud-neutral PaaS security contract

The remote-control-plane security model is independent of Kubernetes, Codefly,
and AWS. Its versioned intent lives in
`contracts/codefly-paas-security-v1alpha1.json`, its strict published schema is
`schemas/paas-security-v1alpha1.schema.json`, and its parser and fail-closed
policy engine live in `src/core/paas.ts`.

The contract requires:

- authenticated, authorized, tenant-bound build, deploy, cancellation,
  rollback, and state operations with no direct host execution;
- distinct short-lived control-plane, builder, deployer, egress, registry,
  runtime, and audit identities;
- per-tenant quotas and queues with fair scheduling, cancellation, timeouts,
  and bounded global concurrency;
- ephemeral non-privileged builder sandboxes using microVM or dedicated-VM
  isolation, with no host namespaces, host paths, container socket, ambient
  cloud credentials, or direct egress;
- digest pinning, signature and provenance verification, SBOMs, immutable
  artifacts, durable encrypted state, idempotency keys, tenant locks, rollback,
  backup, restore tests, regional recovery, and immutable denial-aware audit.

The reference intent now declares five private capability-protected surfaces:
deployment/state, workspace files, command/terminal execution, registry, and
agent invocation. Together they govern build, deploy, cancel, rollback,
state-read, file-read/write, command, terminal, artifact push/pull, and agent
operations. Workspace, command, terminal, and agent operations are required to
target a tenant sandbox; `host` is an explicit denied request target.

### Request authorization

`src/core/paasAuthorization.ts` is a deterministic cloud-neutral authorization
engine. Its strict request envelope is published as
`schemas/paas-authorization-request-v1alpha1.schema.json`. A request is allowed
only when all applicable checks pass:

- the endpoint, operation, tenant, execution target, and authentication method
  match the declared intent;
- the actor tenant equals the requested tenant and the resource is exact, with
  no wildcard authority;
- mutating operations have an idempotency key, builds have a source revision,
  and deployment/rollback/registry artifact operations have a SHA-256 digest;
- a capability is cryptographically verified, issued by an explicitly trusted
  issuer, and exactly binds subject, tenant, audience, operation, and resource;
- the capability is currently valid, has at most a five-minute lifetime, has
  not been redeemed, and is one-use for mutations;
- RBAC endpoints, when used by another intent, have an exact unexpired subject,
  tenant, endpoint, operation, and resource grant.

Every allow or denial returns the required audit fields and stable reason codes.
The evaluator does not mutate state. A real control plane must verify signatures
before setting `cryptographicallyVerified` and atomically persist
`capabilityToRedeem` with the authorized mutation; a read-then-write sequence is
not sufficient replay protection under concurrency.

### Durable control state

`src/core/paasControlState.ts` defines the versioned
`security.deus.dev/paas-control-state/v1alpha1` snapshot and a pure transition
engine. The strict portable snapshot schema is
`schemas/paas-control-state-v1alpha1.schema.json`; the Codefly contract publishes
that API version for its state-store implementation.

The reducer provides:

- compare-and-swap revisions so stale writers fail rather than overwrite newer
  state;
- atomic enqueue, exact-payload idempotency, and one-use capability redemption;
- binding of the authorization decision timestamp, source revision, artifact
  digest, tenant, operation, resource, and idempotency key to the same state
  mutation, so an allowed decision cannot be replayed with substituted payload;
- FIFO queues per tenant with deterministic round-robin fairness, global and
  per-tenant concurrency limits, and per-resource locks;
- bounded retries that preserve the original deadline and release the lock only
  between attempts;
- authenticated cancellation, deadline sweeping, and a `cancelling` state that
  retains the resource lock until the correct worker supplies sandbox-cleanup
  evidence;
- digest-bound deployment promotion, bounded release history, and rollback only
  to a previously deployed digest;
- strict snapshot parsing and semantic invariant checks before every transition,
  plus deterministic state events for immutable audit export.

The transition engine is storage-neutral. Production Codefly must execute each
accepted transition as one serializable transaction or conditional write on the
declared revision, persist the returned snapshot and events atomically, and
authenticate builder/deployer acknowledgements. Merely writing the returned JSON
to an eventually consistent object is not a safe implementation.

## Managed PostgreSQL broker contract

PostgreSQL is the first typed managed resource crossing the plugin/broker
boundary. The cloud-neutral desired state is defined by
`security.deus.dev/managed-postgres/v1alpha1`; it contains tenant ownership,
engine compatibility, extensions, recovery objectives, capacity, runtime and
migration infrastructure identities, and reference-only connection
requirements. It deliberately contains no migration source, checksum, SQL,
execution phase, AWS account, region, ARN, subnet, security-group, password, or
provider credential.

The checked-in contract
`contracts/managed-postgres-v1alpha1.json` declares
`codefly.dev/postgres@0.0.103` as the required producer compatibility and binds
three independent data boundaries:

| Tenant | Codefly service              | Data boundary       |
| ------ | ---------------------------- | ------------------- |
| Warden | `warden-platform/saas/store` | `warden-saas-state` |
| Mind   | `mind-server/infra/postgres` | `mind-infra-state`  |
| Mind   | `mind-server/users/store`    | `mind-users-state`  |

The neutral parser fails closed on unknown fields, cross-tenant bindings,
shared runtime/migration identity, weak TLS/authentication, short recovery
retention, provider credentials, and exposed administrator credentials.
Deterministic intent and per-binding digests bind the environment, plan, claim,
access, and audit evidence. Migration behavior is owned and tested by Codefly.

### Executable resource-broker kernel

`src/core/resourceBroker.ts` implements the provider-neutral claim lifecycle
behind that contract. Both Codefly and AWS now compile the exact same strict
`ResourceClaim` envelope. The pure state machine provides:

- compare-and-swap revisions, exact idempotency, and atomic one-use capability
  redemption for claim apply, cancellation, and deletion;
- monotonically increasing desired-state generations;
- workload-identity-authenticated provider leases with expiring SHA-256 fencing
  tokens, bounded attempts, and late-worker denial;
- reference-only/safe-scalar provider outputs with secret-name, credential URL,
  unknown-field, and provider-credential rejection;
- retryable failure, drift invalidation, cancellation that retains the provider
  fence until cleanup evidence, and deletion requiring pre-bound approval and
  finalization evidence;
- strict durable-state and claim schemas, immutable transition events, a
  deterministic fake provider, and a reusable hostile conformance evaluator.

The fake provider completes all three Warden/Mind claims in tests and proves
that the Codefly and AWS claim envelopes are byte-for-byte semantically equal.
It is a conformance dependency, not a production provider. The Codefly server
must persist each accepted transition atomically in a serializable/conditional
store and authenticate real provider workers before this lifecycle is remotely
usable.

The AWS adapter consumes the intent and emits private Aurora PostgreSQL broker
claims with multi-AZ, CMK, IAM database authentication, end-to-end IAM RDS
Proxy, deletion protection, PITR/final snapshot, restore testing, and
reference-only outputs. This repository no longer renders Codefly PostgreSQL
artifacts or migration admission. The Codefly repository must consume the
checked contract through its own reviewed implementation.

The existing Pulumi Aurora module now uses an RDS-managed, CMK-encrypted master
credential and never synthesizes a password into Pulumi state. Its proxy uses
end-to-end IAM authentication and exact cluster/user-scoped `rds-db:connect`,
with no wildcard database user or Secrets Manager permission. Runtime,
migration, proxy, and cluster security groups are distinct; only explicit
SG-to-SG paths exist and no VPC CIDR is admitted.

The local PostgreSQL service still publishes password-shaped connection
secrets. It does not yet consume the structured IAM/TLS binding or refresh an
RDS IAM token per physical connection. Production application deployment
remains disabled until that separate Codefly plugin/SDK/server work is
implemented and qualified.

`src/adapters/codefly/paasControlPlane.ts` is the first provider injection. It
does not redefine the policy: it asserts the neutral intent and deterministically
compiles the Codefly/Kubernetes enforcement package. Render the checked-in
Warden/Mind contract with:

```sh
npm run render:codefly-control-plane -- \
  --intent contracts/codefly-paas-security-v1alpha1.json \
  --output ./generated/codefly-control-plane

kubectl kustomize ./generated/codefly-control-plane/paas
```

The renderer refuses to overwrite differing files unless `--force` is supplied.
Each tenant receives separate builder, runtime, and egress namespaces and
separate builder, deployer, runtime, and egress service accounts. A workload
implementing the egress broker must copy the generated
`security.deus.dev/paas-role: egress` label onto its Pods; creating the service
account alone does not label Pods.

This package is an enforceable deployment contract, not the complete PaaS
runtime. ResourceQuota and admission enforce the Kubernetes boundaries already
represented in the package. The Codefly daemon authorization layer, fair queue,
transactional state backend and workers, actual microVM runtime, egress broker,
registry, recovery automation, and signed audit pipeline must implement and
report the corresponding contract fields before CN-333 is done.

## Production Work Remaining

The repository now produces both typed plans and additive product security
artifacts. It does not yet make the remote Codefly daemon safe to expose, and it
does not silently rewrite product repositories with active uncommitted work.

### Existing product topology discovered locally

The original renderer remains a minimal reference topology. The product renderer
uses the exact graph below and writes additive artifacts; the reference output
must not be applied over either repository as if each product had one module:

- `warden-platform` already contains `platform` and `saas`. The governed gateway
  is the Rust `platform/warden` service using contract agent `0.0.12`.
- `mind-server` already contains `mind`, `execution`, `infra`, and `users`.
  Its primary `mind/mind` service is normalized in the disposable product copy
  to the exact current local `go-grpc` contract.
- Both repositories currently have active uncommitted work. This implementation
  intentionally did not mutate either worktree.

CN-335 records the future integration boundary. Live Codefly CLI, core, SDK,
plugin, Warden, and Mind builds or tests are deliberately not owned by this
repository. They require a separate reviewed Codefly infrastructure plan.

This repository owns provider-neutral infrastructure contracts, AWS adapters,
cluster and admission policy, and schemas for evidence supplied across that
boundary. It does not inspect, compile, rewrite, or execute adjacent Codefly,
Warden, or Mind worktrees. A future Codefly-owned qualification pipeline may
submit signed render and admission evidence to this repository's release gate.

Render a production plan with pinned images:

```sh
npm run render:codefly -- \
  --output ./generated/codefly \
  --environment aws-production \
  --cluster-kind eks \
  --registry 123456789012.dkr.ecr.us-east-1.amazonaws.com/deus \
  --registry-auth ecr \
  --ingress-namespace istio-ingress \
  --warden-api-image registry/warden-api@sha256:<64-hex> \
  --warden-frontend-image registry/warden-frontend@sha256:<64-hex> \
  --mind-api-image registry/mind-api@sha256:<64-hex>

npm run evidence:release -- \
  --output artifacts/security-contract-evidence.json \
  --rendered-codefly ./generated/codefly
```

The strict evidence command cross-checks the declared Codefly core, Warden, and
Mind revisions against the revisions used by the real render. It also rejects
dirty Codefly core, product, or locally rebuilt agent source repositories.
Admission
evidence is rejected unless it names the exact SHA-256 digest of the supplied
product-render report.

Render the exact two-workspace security package with a JSON object whose keys are
`deployment/component/service` and whose values are immutable image digests:

```sh
npm run render:codefly-products -- \
  --output ./generated/codefly-products \
  --environment production \
  --images ./release-images.json \
  --ingress-namespace istio-ingress \
  --ingress-service-account gateway \
  --image-issuer https://token.actions.githubusercontent.com \
  --image-subject 'https://github.com/deus/product/.github/workflows/release.yml@refs/heads/main'
```

Pass `--service-overlays ./service-overlays.json` only after Codefly has rendered
the product service manifests. That mapping must cover the same 18 canonical
keys and point to a Codefly tree copied below each generated service integration
directory; Kustomize load restrictions remain enabled. Workload image/identity
patches are activated only when the mapping is complete. The renderer writes to
its output directory and never changes Warden or Mind.

### 1. Complete cross-repository release integration

- Publish the plan schema for Codefly consumers and add migration fixtures when
  v1alpha2 is introduced.
- Pin IaC, Codefly, Warden, Mind, and SaaS-kernel source revisions into release
  evidence.
- Reconcile the remaining Warden/Mind product descriptor, DNS, and configuration
  drift without IaC compatibility shims.
- Add signed rendered-plan provenance and promotion between environments.

### 2. Build independent Warden and Mind modules

- Separate module roots, namespaces, databases/roles, buckets/keys, Vault paths,
  release channels, SLOs, rollback, and disaster-recovery procedures.
- Define versioned APIs between products. No shared database tables or implicit
  internal network reachability.
- Warden: signed registry, pinned artifact hashes, manifest compatibility,
  entitlement ceilings, CSP/egress limits, health, rollback, and kill switch.
- Mind: separate agent principals; short-lived, one-use, audience/subject/org/
  action/resource-bound capabilities; recent-MFA approvals for high-risk work;
  durable revocation, redemption, cancellation, timeout, and replay evidence.

### 3. Harden Codefly as a remote multi-tenant control plane

- Keep the new neutral PaaS intent and Codefly injection package as the
  mandatory contract for every remote control-plane implementation.
- Authenticate and authorize every daemon, builder, file, command, terminal,
  deployment, registry, and agent endpoint. Loopback assumptions are not a SaaS
  security boundary.
- Separate control-plane, deployment, registry, builder, and runtime identities.
- Run builds and customer code in ephemeral non-privileged tenant sandboxes with
  no shared writable host path, container socket, host PID/network namespace, or
  ambient cloud credential.
- Enforce per-tenant quotas, admission, egress, concurrency, cancellation,
  maximum lifetime, cleanup, and cost controls.
- Require source provenance, hermetic/reproducible builds where possible, SBOM,
  signing, deploy-time verification, and immutable artifact retention.
- Make deployment state durable and idempotent; implement locking, safe retry,
  rollback, regional recovery, and signed audit evidence.

### 4. Prove the complete system

- Run contract tests across pinned revisions of IaC, Codefly, Warden, Mind, and
  the SaaS kernel.
- Dependency-backed tests must cover cross-tenant RLS, capability replay,
  cross-org redemption, undeclared calls, unsigned plugin/image denial, secret
  isolation, rollback, backup restore, and regional recovery.
- Deploy Warden and Mind together, then prove either can be upgraded, rolled
  back, scaled, disabled, and restored without granting authority over the other.
- Archive a signed evidence manifest containing source revisions, blueprint and
  rendered-plan digests, images, signatures, SBOMs, policies, tests, and deployed
  environment identifiers.

The executable task breakdown and dependency order are CN-330 through CN-334 in
[cloud-neutral-backlog.md](cloud-neutral-backlog.md).
