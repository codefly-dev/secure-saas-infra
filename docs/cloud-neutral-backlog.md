# Cloud-Neutral Platform Implementation Backlog

This file is the execution backlog for the cloud-neutral security and tenancy
platform. Tasks are intentionally scoped so they can be implemented and reviewed
separately.

## Status Summary

The foundation is implemented and tested. The complete platform is not done.

Implemented today:

- cloud-neutral blueprint types;
- normalized security graph;
- structural, network, tenant, data, identity, and evidence policies;
- fail-closed adapter capability negotiation;
- AWS network translation and compilation;
- AWS network hub and single-account integration;
- strict IPv4 allocation and overlap validation;
- initial positive, hostile, graph, and adapter contract tests.
- strict Pulumi blueprint input parsing;
- workload-plane isolation policies;
- delegated entitlement analysis;
- transitive network reachability proofs;
- strict PaaS authorization and durable control-state reducers;
- provider-neutral resource claims, durable broker lifecycle, fencing, drift,
  cleanup, protected deletion, and provider conformance;
- one cloud-neutral `ManagedPostgres` intent compiled identically for Codefly
  and AWS, with three independent Warden/Mind claims;
- SG-to-SG database access and wildcard-free, cluster/user-scoped AWS database
  identity plans; and
- isolated local-agent rendering of all 18 Warden/Mind services plus live K3s
  validation of the security, PaaS, and managed-Postgres artifacts;
- strict planned/ready AWS cloud-context catalogs with complete application and
  managed-resource placement; and
- an immutable KMS-encrypted 18-service ECR registry plus contract-driven exact
  three-database Pulumi wiring.

The immediate critical path prioritizes application deployment; physical
infrastructure-on-demand is intentionally a later evolution:

```text
versioned CloudContext contract
  -> Codefly application plan/deploy within pre-provisioned contexts
  -> Warden and Mind build/migrate/deploy/rollback pilot
  -> authenticated transactional daemon integration
  -> clean, signed cross-repository release evidence

future: logical resource allocation from managed pools
  -> asynchronous provider reconciliation
  -> fully on-demand physical infrastructure
```

## Working Rules

Every task must preserve these rules:

1. `src/core` must not import Pulumi or a cloud SDK.
2. Provider-specific behavior belongs under `src/adapters/<provider>` or a
   provider-native component package.
3. Unsupported security intent must fail compilation. It must never be ignored.
4. Provider escape hatches may add stronger controls but may not weaken generic
   invariants.
5. Every new invariant requires at least one passing and one failing test.
6. Tenant isolation is an end-to-end property. Namespaces, tags, and storage
   prefixes alone are not isolation boundaries.
7. Native AWS IAM, GCP IAM, and Azure RBAC documents remain provider-specific.
   Only the entitlement graph is normalized.
8. No task is complete until `npm test` passes.

Task status values:

- `DONE`: implemented on the current worktree;
- `READY`: can start now;
- `BLOCKED`: dependency must land first;
- `LATER`: intentionally outside the current critical path.

## Completed Foundation

### CN-001 — Blueprint domain model

- Status: `DONE`
- Implementation: `src/core/model.ts`
- Includes trust zones, network domains, flows, tenants, data boundaries,
  identities, grants, evidence, posture, and capabilities.

### CN-002 — Security graph

- Status: `DONE`
- Implementation: `src/core/graph.ts`
- Includes placement, reachability, access, and evidence edges.

### CN-003 — Generic policy engine

- Status: `DONE`
- Implementation: `src/core/policy.ts`
- Includes structural, network, tenant, data, identity, and evidence policies.

### CN-004 — Adapter contract and capability negotiation

- Status: `DONE`
- Implementation: `src/core/adapter.ts`
- Compilation fails when a provider lacks a required capability.

### CN-005 — AWS network adapter

- Status: `DONE`
- Implementation: `src/adapters/aws/networkAdapter.ts`
- Existing AWS network configuration round-trips through neutral intent.

### CN-006 — AWS network stack integration

- Status: `DONE`
- Implementation: `src/stacks/networkHubStack.ts` and
  `src/stacks/workloadStack.ts`.

### CN-007 — Strict IPv4 validation

- Status: `DONE`
- Implementation: `src/cidr.ts`
- Rejects malformed, unaligned, overlapping, and out-of-parent networks.

### CN-008 — Initial contract and hostile tests

- Status: `DONE`
- Implementation: `tests/core.test.ts`, `tests/awsAdapter.test.ts`, and
  `tests/cidr.test.ts`.

## P0: Supported Blueprint Input

### CN-101 — Load `PlatformBlueprint` from Pulumi stack configuration

- Status: `DONE`
- Depends on: CN-001, CN-003
- Suggested files:
  - `src/core/schema.ts`
  - `src/blueprintConfig.ts`
  - `tests/blueprintConfig.test.ts`
  - `Pulumi.*.yaml.example`

Deliverables:

- Add a `secure-saas-infra:platformBlueprint` stack input.
- Parse it without importing Pulumi into `src/core`.
- Reject unknown fields instead of silently discarding them.
- Return all structural violations in one diagnostic where possible.
- Keep secrets out of the blueprint. The blueprint may contain secret
  references, never secret material.
- Preserve compatibility with current stack configuration during migration.

Acceptance criteria:

- A valid blueprint loads and evaluates before any resource registration.
- Invalid enum values, duplicate IDs, unknown references, and malformed CIDRs
  stop preview with actionable paths.
- Unknown schema versions fail closed.
- Existing stack examples still validate.
- Tests cover missing, valid, malformed, unknown-version, and unknown-field
  configurations.

### CN-102 — Blueprint schema versioning and migrations

- Status: `DONE`
- Depends on: CN-101
- Suggested files:
  - `src/core/migrations.ts`
  - `tests/blueprintMigrations.test.ts`

Deliverables:

- Define compatibility rules for `security.deus.dev/v1alpha1`.
- Add a migration interface for future versions.
- Separate lossless automatic migrations from changes requiring operator
  approval.
- Emit a migration report in preview output.

Acceptance criteria:

- Same-version input is unchanged.
- Unknown future versions are rejected.
- A migration never silently weakens posture or drops a security requirement.
- Migration tests use frozen before/after fixtures.

## P0: Workload Plane Intent

### CN-110 — Add cloud-neutral workload plane model

- Status: `DONE`
- Depends on: CN-001
- Suggested files:
  - `src/core/model.ts`
  - `src/core/policy.ts`
  - `tests/workloadPlane.test.ts`

Model at least:

- workload plane ID and trust zone;
- execution trust: trusted, semi-trusted, or untrusted;
- orchestration requirement: managed Kubernetes, serverless, microVM, or
  external sandbox;
- tenant scope;
- public control-plane prohibition;
- workload identity requirement;
- sandbox duration and credential-brokering requirements;
- required runtime isolation capability.

Acceptance criteria:

- Untrusted execution cannot share a hard boundary with the SaaS control plane.
- Untrusted execution requires brokered credentials and an explicit sandbox
  capability.
- Namespace-only isolation cannot satisfy a dedicated-boundary requirement.
- Tests cover EKS, E2B BYOC, microVM fallback, and an invalid regular-container
  execution plane.

### CN-111 — Compile AWS EKS and E2B from workload intent

- Status: `DONE`
- Depends on: CN-101, CN-110
- Suggested files:
  - `src/adapters/aws/workloadAdapter.ts`
  - `src/stacks/spokeClusterStack.ts`
  - `tests/awsWorkloadAdapter.test.ts`

Deliverables:

- Replace `createEks` as the primary decision input.
- Compile trusted platform planes to private EKS.
- Compile untrusted execution intent to E2B BYOC or an explicitly allowed
  microVM fallback.
- Capability-check private APIs, workload identity, network policy, secret
  encryption, control-plane logging, and runtime isolation.
- Preserve native AWS options in a typed provider extension block.

Acceptance criteria:

- The same workload intent produces a deterministic AWS plan.
- Unsupported runtime isolation fails before Pulumi resources are created.
- Execution intent cannot accidentally compile to ordinary containers.
- Existing EKS mock tests remain green and new negative tests prove fail-closed
  behavior.

### CN-112 — Route detached spokes through neutral intent

- Status: `DONE`
- Depends on: CN-101, CN-110
- Suggested files:
  - `src/adapters/aws/networkAdapter.ts`
  - `src/stacks/spokeClusterStack.ts`
  - `src/stacks/networkRoutingStack.ts`

Deliverables:

- Compile detached platform, execution, data, and shared-service spokes from
  trust zones and network domains.
- Make route-table intent explicit in the provider plan.
- Validate every stack reference against expected semantic outputs.
- Remove duplicated routing assumptions from stack entry points.

Acceptance criteria:

- Hub, spoke, and routing stacks use the same semantic IDs.
- Missing or mismatched stack outputs fail with a domain-level error.
- No workload spoke can compile a direct Internet or NAT path.
- Cross-account attachment and return-route tests pass.

## P0: Tenant Data and Encryption

### CN-120 — Compile artifact storage from `DataBoundary`

- Status: `DONE`
- Depends on: CN-001, CN-101
- Suggested files:
  - `src/adapters/aws/dataAdapter.ts`
  - `src/customerData.ts`
  - `tests/awsDataAdapter.test.ts`

Deliverables:

- Replace requirement-only booleans with executable data intent.
- Compile classification, tenant scope, retention, versioning, replication,
  deletion evidence, encryption, and audit requirements.
- Support pooled, dedicated-data, and dedicated-account storage plans.
- Generate explicit bucket/key ownership metadata for graph analysis.

Acceptance criteria:

- Regulated data cannot compile with a shared encryption key.
- Dedicated tenants receive distinct storage and key boundaries.
- Every confidential boundary has object-level audit coverage.
- Deletion evidence is a resource/workflow requirement, not only a tag.
- Tests prove cross-tenant read and write plans are rejected.

### CN-121 — Compile databases and backups from data intent

- Status: `DONE`
- Depends on: CN-120
- Suggested files:
  - `src/adapters/aws/databaseAdapter.ts`
  - `src/adapters/aws/backupAdapter.ts`
  - `src/database.ts`
  - `src/backup.ts`

Deliverables:

- Map data availability, retention, recovery, and isolation requirements to
  Aurora/RDS and AWS Backup plans.
- Model RPO, RTO, deletion protection, final snapshots, regional replication,
  and restore-test cadence.
- Attach every data boundary to an evidence sink.

Acceptance criteria:

- Production confidential data requires multi-AZ deployment and protected
  backups.
- Regulated data requires tenant-dedicated encryption and restore evidence.
- A backup plan without a tested restore requirement is rejected.
- Existing database and backup tests are retained as AWS contract tests.

## P0: Tenant Authorization

### CN-130 — Build provider-neutral entitlement analysis

- Status: `DONE`
- Depends on: CN-001, CN-002
- Suggested files:
  - `src/core/entitlements.ts`
  - `tests/entitlements.test.ts`

Deliverables:

- Normalize subject, tenant, resource, action, effect, and broker conditions.
- Compute effective allow/deny edges without pretending provider IAM semantics
  are identical.
- Detect wildcard grants, cross-tenant access, privilege-escalation edges, and
  missing tenant context.
- Represent reviewed platform-service exceptions explicitly.

Acceptance criteria:

- A tenant identity cannot acquire access to another tenant's data through a
  direct or inherited grant.
- Platform automation exceptions require an owner, reason, expiry, and audit
  requirement.
- Deny edges are visible in generated evidence.
- Tests cover direct, inherited, conditional, denied, and confused-deputy
  scenarios.

### CN-131 — Generate AWS IAM and resource policies

- Status: `DONE`
- Depends on: CN-120, CN-130
- Suggested files:
  - `src/adapters/aws/iamAdapter.ts`
  - `src/adapters/aws/policyDocuments.ts`
  - `tests/awsIamAdapter.test.ts`

Deliverables:

- Compile `IdentityGrant` into least-privilege IAM identity policies, role trust
  policies, KMS policies, S3 policies, and workload identity associations.
- Scope tenant access with resource ARNs, prefixes, principal tags, source
  identity, external IDs, and source account/ARN conditions as appropriate.
- Prohibit unmanaged wildcard policy fragments.

Acceptance criteria:

- Generated policies are deterministic and stable under key ordering.
- Tenant identities cannot list or access another tenant's prefix or key.
- Vendor trust requires role principals, external IDs, and bounded sessions.
- Privilege-escalation actions require explicit resource and condition scopes.
- Snapshot and semantic tests cover every generated statement.

### CN-132 — Validate generated AWS policies with IAM Access Analyzer

- Status: `BLOCKED`
- Depends on: CN-131
- Suggested files:
  - `src/adapters/aws/accessAnalyzer.ts`
  - `scripts/validate-iam-policies.mjs`

Deliverables:

- Run AWS IAM Access Analyzer policy validation during preview/CI where
  credentials are available.
- Classify errors, security warnings, suggestions, and unsupported checks.
- Fail production deployment on errors and configured security warnings.
- Archive findings with release evidence.

Acceptance criteria:

- Deliberately broad IAM, KMS, and S3 fixtures fail validation.
- Offline unit tests remain possible without AWS credentials.
- CI results identify the policy and exact finding location.

## P0: Pulumi Component Boundaries

### CN-140 — Convert AWS network resources to `ComponentResource`

- Status: `READY`
- Depends on: CN-005
- Suggested files:
  - `src/components/aws/networkHub.ts`
  - `src/components/aws/networkSpoke.ts`

Deliverables:

- Replace free resource-construction functions with named components.
- Accept explicit AWS providers and Pulumi resource options.
- Parent every child resource.
- Register semantic outputs.
- Define aliases for existing URNs to prevent destructive replacements.
- Apply protection to stateful/critical resources where appropriate.

Acceptance criteria:

- A preview against existing state shows no unintended replacement caused only
  by the refactor.
- Provider inheritance works for multi-account and multi-region deployments.
- Component outputs contain semantic IDs, not only raw cloud IDs.
- Mock tests verify parentage, providers, protection, and outputs.

### CN-141 — Convert stateful and security modules to components

- Status: `BLOCKED`
- Depends on: CN-120, CN-121, CN-131, CN-140

Convert:

- log archive;
- customer data;
- database;
- backup;
- EKS/workload plane;
- security tooling;
- ingress/WAF/DNS;
- shared services.

Acceptance criteria:

- Every component accepts explicit providers and options.
- Stateful resources have migration aliases and protection semantics.
- Cross-account dependencies use typed semantic outputs.
- No component imports mutable global configuration.

## P0: Isolation Proofs

### CN-200 — Add transitive network reachability analysis

- Status: `DONE`
- Depends on: CN-002
- Suggested files:
  - `src/core/reachability.ts`
  - `tests/reachability.test.ts`

Deliverables:

- Compute paths across direct flows, brokers, gateways, inspection zones, and
  external destinations.
- Record path purpose, authorization, protocol, and tenant scope.
- Detect bypass paths that are not obvious from a single edge.
- Prevent cycles from causing unbounded evaluation.

Acceptance criteria:

- The evaluator returns the exact path responsible for a violation.
- A hidden execution-to-data path through an intermediate workload is rejected.
- Internet paths prove traversal through the required inspection zone.
- Tests cover cycles, multiple paths, brokered paths, and disconnected graphs.

### CN-201 — Add transitive identity reachability analysis

- Status: `READY`
- Depends on: CN-130

Deliverables:

- Compute assume-role, impersonation, workload identity, key usage, and resource
  policy paths.
- Detect privilege escalation and confused-deputy paths.
- Join identity and network paths for high-risk access proofs.

Acceptance criteria:

- A principal cannot gain cross-tenant access through role chaining.
- Pass-role plus compute-creation escalation is detected.
- External vendor paths require the declared external ID and destination.
- Violations contain the full principal-to-resource path.

### CN-202 — Reference isolation blueprints

- Status: `DONE`
- Depends on: CN-101
- Suggested directory: `blueprints/reference/`

Create fixtures for:

- pooled SaaS tenants;
- dedicated data tier;
- dedicated network tier;
- dedicated AWS account tier;
- untrusted execution with E2B BYOC;
- fail-closed microVM fallback;
- intentionally hostile configurations.

Acceptance criteria:

- Valid fixtures compile with expected capabilities.
- Hostile fixtures fail with stable violation codes.
- Each isolation tier documents threat assumptions and residual risk.

### CN-203 — Mutation test suite

- Status: `BLOCKED`
- Depends on: CN-200, CN-201, CN-202

Mutations must include:

- remove inspection hop;
- expose a control-plane endpoint;
- share a regulated key;
- remove evidence coverage;
- add wildcard IAM access;
- swap tenant IDs;
- remove brokered credential condition;
- attach a direct Internet gateway;
- weaken retention or deletion protection.

Acceptance criteria:

- Every mutation causes at least one expected violation.
- The suite fails if a mutation survives policy evaluation.
- Violation-code snapshots are reviewed like an API contract.

### CN-204 — Isolation evidence report

- Status: `BLOCKED`
- Depends on: CN-200, CN-201
- Suggested files:
  - `src/core/evidenceReport.ts`
  - `scripts/render-security-evidence.mjs`

Deliverables:

- Emit JSON plus human-readable Markdown.
- Include blueprint digest, adapter version, capabilities, tenant placements,
  network paths, identity paths, data/key mappings, evidence sinks, exceptions,
  and violations.
- Sign or bind the report to the release provenance.

Acceptance criteria:

- Reports are deterministic for identical inputs.
- Secrets never appear in reports.
- Every production tenant and confidential data boundary is covered.
- CI publishes the report as a retained artifact.

## P0: Pulumi Policy Pack Integrity

### CN-220 — Replace policy source-text tests

- Status: `DONE`
- Depends on: none
- Implementation:
  - `policy/index.ts`
  - `tests/policy.test.ts`
  - `tests/policyFixtures.test.ts`

Deliverables:

- Export policy evaluators as testable functions.
- Replace regular-expression assertions over `policy/index.ts`.
- Add compliant, hostile, malformed, and bypass fixtures.
- Keep the `PolicyPack` registration layer thin.

Acceptance criteria:

- Tests execute the same functions registered by the Policy Pack.
- Removing a check causes its hostile fixture to pass and the test to fail.
- IAM parsing tests cover strings, arrays, malformed JSON, `NotAction`, and
  conditional wildcard actions.

The exported callbacks are the exact objects passed to `PolicyPack`.
Registration occurs only when the policy entrypoint is executed as the main
program, so unit tests execute callbacks without starting the Pulumi policy
RPC service.

### CN-221 — Add stack relationship policies

- Status: `DONE`
- Depends on: CN-220
- Implementation:
  - `policy/stackRules.ts`
  - `tests/policyStackFixtures.test.ts`

Prove at stack scope:

- every VPC has flow and DNS query logging;
- every S3 bucket has public-access blocking, versioning where required, and
  customer-managed encryption;
- every Network Firewall has FLOW and ALERT logs;
- every confidential data resource reaches an immutable evidence sink;
- every workload VPC default route follows approved egress;
- no Internet/NAT gateway is accepted based only on its name.

Acceptance criteria:

- A missing companion resource fails the stack policy.
- Relationship checks use URNs, IDs, tags, or semantic outputs—not string naming
  conventions alone.
- Preview fixtures test both complete and incomplete resource graphs.

Relationships use Pulumi `propertyDependencies` and exact URNs. Confidential
resources bind the evidence-sink ID already proven immutable by the
cloud-neutral blueprint compiler. The gateway rule also replaces the former
resource-name heuristic with the `NetworkRole=central-egress` boundary and a
dependency walk from NAT gateway to subnet to VPC.

## P1: Provider Contract and GCP

### CN-300 — Shared adapter conformance suite

- Status: `DONE`
- Depends on: CN-101, CN-110, CN-120, CN-130, CN-202
- Suggested directory: `tests/contracts/`

Deliverables:

- Define blueprints every adapter must compile.
- Define blueprints every adapter must reject.
- Define normalized plan assertions without requiring identical cloud resource
  shapes.
- Version the provider contract.

Acceptance criteria:

- AWS passes the suite before GCP work starts.
- Capability differences produce explicit rejection or documented stronger
  mappings.
- No adapter-specific field appears in the core contract fixtures.

### CN-310 — GCP network and workload adapter

- Status: `BLOCKED`
- Depends on: CN-300
- Suggested directory: `src/adapters/gcp/`

Initial scope:

- projects/folders as isolation boundaries;
- global VPC plus regional subnets;
- hierarchical firewall policy;
- Cloud NAT or approved proxy egress;
- private GKE control plane;
- Workload Identity Federation;
- Cloud KMS;
- immutable audit export.

Acceptance criteria:

- GCP passes the shared conformance suite.
- Global VPC semantics do not leak into the neutral model.
- Unsupported AWS-specific intent fails with a capability explanation.
- No GCP deployment grants primitive owner/editor roles.

### CN-311 — Core abstraction correction after GCP

- Status: `BLOCKED`
- Depends on: CN-310

Deliverables:

- Catalogue every AWS assumption exposed by the GCP adapter.
- Rename or split abstractions whose semantics were too AWS-specific.
- Migrate v1alpha1 fixtures through the schema migration mechanism.

Acceptance criteria:

- Changes improve both adapters rather than adding provider conditionals to the
  core.
- AWS and GCP pass the same conformance suite after migration.

## P1: Azure Adapter

### CN-320 — Azure network, identity, and workload adapter

- Status: `BLOCKED`
- Depends on: CN-311
- Suggested directory: `src/adapters/azure/`

Initial scope:

- management groups/subscriptions as boundaries;
- VNet, hub/spoke, Azure Firewall, and Private Link;
- private AKS;
- workload identity;
- Key Vault/managed HSM capability mapping;
- Azure Policy and immutable evidence export.

Acceptance criteria:

- Azure passes the shared conformance suite.
- RBAC, deny assignments, and Azure Policy stay provider-native.
- Unsupported dedicated-boundary requirements fail explicitly.

## P0: Codefly PaaS and Product Deployments

Codefly is a first-class PaaS compiler target. It consumes the same neutral
workload, identity, tenant, data, network, and evidence intent as the cloud
adapters; it does not weaken or duplicate those contracts. The first product
topology contains two independent deployments: `warden` and `mind`.

The locked first release is application deployment, not infrastructure
provisioning: Codefly must build, migrate, deploy, observe, cancel, and roll back
both products inside pre-provisioned AWS cloud contexts. Physical resources
remain IaC-managed. Claims initially resolve existing bindings so the later
on-demand provider path does not force an application-protocol redesign.

### CN-330 — Model provider-neutral application deployments

- Status: `DONE`
- Depends on: CN-101, CN-110, CN-120, CN-130
- Suggested files:
  - `src/core/model.ts`
  - `src/core/schema.ts`
  - `src/core/policy.ts`
  - `tests/applicationDeployments.test.ts`

Deliverables:

- Model an application deployment independently from Kubernetes, Codefly, or a
  cloud provider: workload plane, service identity, tenant scope, data
  boundaries, ingress exposure, dependencies, availability, and release policy.
- Model `warden` and `mind` as separate deployment/security principals with no
  implicit shared credentials, database roles, buckets, keys, or admin tokens.
- Make every inter-deployment call an explicit authenticated flow with audience,
  action, and resource bounds.
- Express Mind agent principals and Warden plugin authority as bounded delegated
  identities rather than ordinary end-user sessions.

Acceptance criteria:

- A blueprint can place Warden and Mind on different workload planes/accounts
  without changing product code.
- Missing service identity, data ownership, evidence, or dependency flow fails
  before provider compilation.
- Mind cannot inherit Warden administrator authority, and Warden cannot redeem a
  Mind agent capability unless an explicit delegation permits it.

### CN-331 — Build the Codefly PaaS adapter

- Status: `DONE`
- Depends on: CN-300, CN-330
- Suggested directory: `src/adapters/codefly/`

Deliverables:

- Compile neutral application deployments into Codefly workspace, module,
  environment, service, dependency, endpoint, and deployment intent.
- Keep Codefly builder/agent invocation local and use installed local agents.
- Map workload planes to Codefly deployment environments and cloud-adapter
  outputs without embedding AWS primitives in the Codefly plan.
- Generate deterministic render-only artifacts suitable for GitOps review.
- Reject undeclared dependencies, public internal endpoints, ambient production
  credentials, mutable image references, and cross-tenant secret injection.

Acceptance criteria:

- The same Warden/Mind application blueprint renders for local k3d and AWS EKS
  targets by changing provider extensions only.
- `codefly --local-agents` validates and tests the generated modules with all
  declared dependencies.
- Rendered resources carry semantic deployment, tenant, identity, data-boundary,
  and blueprint-digest metadata.

### CN-332 — Create independent Warden and Mind deployment packages

- Status: `IN PROGRESS`
- Depends on: CN-331, CN-335

Deliverables:

- Produce separate Codefly application/release boundaries, namespaces, service
  accounts, network policies, secret references, database roles, release
  channels, and rollback boundaries for Warden and Mind.
- Warden: signed plugin registry, manifest/hash verification, permission and
  entitlement ceilings, egress/CSP allowlists, health, rollback, and kill switch.
- Mind: short-lived workload/agent identities; audience-, subject-, org-, action-,
  and resource-bound one-use capabilities; durable approval and redemption
  evidence; isolated customer-code execution.
- Define explicit Warden-to-Mind and Mind-to-Warden APIs, with deny-by-default
  connectivity and no database-level coupling.

Acceptance criteria:

- Either product deploys, rolls back, scales, and fails independently.
- Compromise of one deployment identity does not grant the other's data-plane or
  deployment authority.
- Capability replay, cross-org redemption, unsigned plugin activation, and
  undeclared service calls fail in dependency-backed tests.

### CN-335 — Reconcile the existing multi-module product workspaces

- Status: `IN PROGRESS`
- Depends on: CN-331
- Observed local topology:
  - Warden workspace `warden-platform`: modules `platform` and `saas`; primary
    governed gateway `platform/warden` uses the pinned Rust agent `0.0.12`.
  - Mind workspace `mind-server`: modules `mind`, `execution`, `infra`, and
    `users`; primary `mind/mind` currently uses the forbidden `latest` agent pin.

Deliverables:

- Import and validate existing workspace/module/service descriptors instead of
  replacing them with the single-module reference renderer.
- Extend application intent with neutral component/module identities, data
  ownership, availability, ingress, and dependency mappings.
- Preserve all declared internal services and dependencies while generating
  security overlays around them.
- Treat Warden and Mind as two independent Codefly workspaces/releases; compile
  cross-product calls as authenticated external/private contracts rather than
  same-workspace module dependencies.
- Replace every `latest` agent declaration with a reviewed installed version and
  pin both product revisions in release evidence.

Acceptance criteria:

- The imported graph exactly covers Warden `platform`/`saas` and Mind
  `mind`/`execution`/`infra`/`users` without invented or omitted services.
- `codefly --local-agents show dependencies` succeeds for every production
  service in both workspaces.
- Security overlays render against real service output and enforce distinct
  workspace namespaces, service accounts, image digests, NetworkPolicies, PDBs,
  and evidence labels.
- Updating either product topology produces an actionable semantic diff.

Implemented in this repository:

- The neutral application model now owns component identities, data boundaries,
  ingress, availability, and both intra-product and cross-product dependency
  contracts.
- The exact product compiler covers six modules and all 18 active services with
  exact installed agent versions; missing modules, services, or exact pins fail
  closed.
- The read-only local validator successfully resolves every active service with
  `codefly --local-agents`; it never downloads agents or mutates either product
  repository.
- The additive product renderer emits six independent namespace/service-account
  boundaries, default-deny and declared-caller NetworkPolicies, Istio workload
  identity authorization, PDBs, exact image patches, fail-closed Kyverno
  signature/SLSA/SPDX verification, and digest-bound security evidence.
- Service-output composition is explicit: every one of the 18 services must
  have both a digest-pinned image and a self-contained mapped Kustomize output
  before workload patches are activated.
- The isolated real-product gate renders all 18 desired pinned services and
  validates six security bases plus 18 service integrations using local agents
  with external network access blocked.
- Current local core/agent source revisions, working-tree digests, dirty state,
  and executed agent binary digests are captured in strict-schema render evidence.
- Release evidence verifies the exact 18-service set and current local agent
  versions, then cross-checks Codefly core/Warden/Mind source revisions;
  production mode rejects dirty render sources.
- A disposable pinned K3s gate server-validates all six security bases and 18
  composed service integrations plus 18 PaaS control-plane artifacts with the
  GitOps-pinned Istio and Kyverno versions. Two positive admission paths and six
  denial paths pass, and strict release evidence binds the admission result to
  the exact render report.

Remaining before `DONE`:

- Apply the ten reviewed agent pin updates in the actively modified Warden/Mind
  worktrees, then make the product audit strict.
- In Codefly, set `automountServiceAccountToken: false` on every migration Job,
  then reconcile missing local DNS contracts and split environment
  configurations in their owning repositories. IaC does not render migration
  Jobs, carry compatibility patches, or retain historical-agent fallbacks.
- Pin the final Warden and Mind revisions in signed cross-repository release
  evidence.

### CN-333 — Operate Codefly as a multi-tenant PaaS control plane

- Status: `IN PROGRESS`
- Depends on: CN-332, CN-335
- Detailed execution plan:
  [`codefly-paas-implementation-plan.md`](./codefly-paas-implementation-plan.md)
- Capability/tooling/delivery execution and verification plan:
  [`codefly-capability-tooling-delivery-roadmap.md`](./codefly-capability-tooling-delivery-roadmap.md)

Vertical-slice priority:

- define and select credential-free pre-provisioned AWS cloud contexts;
- durably plan/deploy/watch/cancel/roll back applications in those contexts;
- resolve PostgreSQL from existing context bindings and run separate migrations;
- deploy Warden, then Mind, then pass their joint release gate; and
- defer physical infrastructure provisioning until this path is complete.

Deliverables:

- Separate Codefly control-plane, builder, deployment, registry, and runtime
  identities; remove unauthenticated command execution from any remotely exposed
  daemon surface.
- Add per-tenant build/execution isolation, quotas, admission, provenance,
  signature verification, artifact retention, and egress control.
- Add durable deployment state, idempotency, concurrency control, cancellation,
  rollback, and immutable audit evidence.
- Define SLOs and runbooks for build, deploy, runtime, identity, registry, and
  dependency failures.

Post-MVP expansion adds disaster recovery, regional failover, logical resource
pools, and physical provider reconciliation without changing the application
deployment contract.

Acceptance criteria:

- No PaaS endpoint can turn an unauthenticated request into host command
  execution, file mutation, secret access, or deployment.
- Builders and customer workloads use ephemeral, non-privileged, tenant-isolated
  sandboxes with no shared writable host paths or ambient cloud credentials.
- A dependency-backed end-to-end test deploys Warden and Mind, verifies tenant
  and application denial paths, performs independent rollback, and archives
  signed evidence.

Implemented in this repository:

- A strict `security.deus.dev/paas-security/v1alpha1` cloud-neutral model,
  parser, JSON Schema, and fail-closed policy evaluator cover endpoints,
  tenants/quotas, identities, builder/runtime sandboxes, scheduling, supply
  chain, deployment state/recovery, and immutable audit.
- The reference contract defines independent Warden and Mind tenant boundaries
  and seven non-reused roles: control-plane, builder, deployer, egress,
  registry, runtime, and audit.
- Host execution, missing authentication/authorization/tenant binding, shared
  or long-lived identities, weak sandboxing, ambient credentials, direct
  egress, missing quotas/cancellation/timeouts, mutable or unverified supply
  chain, unsafe state/recovery, and weak audit all fail before provider
  compilation.
- Five governed remote endpoint classes now cover deployment/state, workspace
  files, command/terminal execution, registry, and agent invocation. All 12
  operations are explicitly declared, and file/command/terminal/agent requests
  must target a tenant sandbox.
- A strict versioned request parser/schema and pure authorization evaluator
  enforce authentication strength, tenant binding, exact endpoint/operation/
  resource authority, trusted capability issuer, signature-verification input,
  subject/audience binding, five-minute TTL, one-use mutation, replay state,
  idempotency, source revision, artifact digest, and host-execution denial.
- Authorization decisions produce stable denial codes and complete allow/deny
  audit records. Exact, expiring RBAC grants are supported for intents that
  select RBAC instead of capabilities.
- A versioned, strict-schema durable control-state reducer provides
  compare-and-swap revisions, atomic capability redemption/idempotent enqueue,
  per-tenant FIFO queues and deterministic round-robin fairness, global/tenant
  concurrency, resource locks, bounded retries, cancellation and deadline
  cleanup, deployment promotion, bounded history, and digest-safe rollback.
- State mutations bind the authorization decision time and complete governed
  payload, preventing a valid decision for one source revision or artifact from
  authorizing a substituted job.
- Running or expired work retains its resource lock while cancellation is in
  progress. Only the expected tenant worker role can acknowledge cleanup, and
  missing cleanup evidence fails closed. Every transition emits deterministic
  events for the immutable audit adapter.
- The Codefly adapter emits 18 deterministic control-plane artifacts: a system
  boundary; three namespaces and four tenant-derived service accounts per
  tenant; ResourceQuotas; default-deny, DNS, and broker-only NetworkPolicies;
  microVM/dedicated-VM RuntimeClasses; published contracts; and a Kyverno
  builder sandbox policy.
- The checked-in Warden/Mind contract has an operator CLI and Kustomize-valid
  output. It never invokes or downloads an agent.
- Disposable pinned K3s server validation covers the complete package. A
  tenant-bound microVM builder passes; missing tenant identity and missing
  microVM isolation are denied. The resulting report is strict-schema release
  evidence bound to the exact real-product render.
- Unit and hostile tests exercise the neutral policy, strict parser/schema,
  compiler separation, quotas, brokered networking, digest metadata, and
  rendered Kustomize package.
- A strict managed-Postgres infrastructure contract binds all three Warden/Mind
  PostgreSQL services to their exact tenant, data boundary, runtime identity,
  migration access identity, pinned plugin, and recovery posture. Migration
  execution semantics remain Codefly-owned.
- The AWS compiler emits three private Aurora broker claims; the Codefly
  seam emits broker-only reference configuration and eight Kustomize-valid
  claim/contract artifacts while honestly requiring plugin protocol v2. It
  emits no migration workload or admission policy.
- The concrete Aurora module no longer creates a password value in Pulumi state:
  RDS manages the CMK-encrypted master secret, and RDS Proxy uses end-to-end IAM
  with a cluster-scoped `rds-db:connect` role.
- Disposable K3s validates only IaC-owned namespace, ServiceAccount-token, and
  identity-projection policy. PostgreSQL migration admission/execution tests
  belong to Codefly.
- A provider-neutral resource-broker reducer now enforces CAS revisions, exact
  idempotency, one-use capabilities, generations, expiring provider leases,
  fencing, bounded retry, drift, cleanup-evidenced cancellation, protected
  deletion, and secretless outputs. A deterministic fake provider runs all
  three Codefly/AWS-identical claims through the conformance lifecycle.
- Aurora ingress is SG-to-SG only: separate runtime and migration sources reach
  the proxy, and only the proxy reaches the cluster. Exact runtime/migration
  database users receive independently materialized, wildcard-free,
  Proxy-resource/user-scoped `rds-db:connect` policies.

Remaining before `DONE`:

- Integrate the contract into the actual Codefly daemon so every remote file,
  command, terminal, build, deploy, registry, and agent operation is
  authenticated, authorized, tenant-bound, and incapable of host execution.
- Connect the daemon's real cryptographic verifier to the neutral capability
  input and atomically commit one-use capability redemption with each mutation;
  never trust a caller-supplied verification boolean or non-atomic replay set.
- Connect the neutral reducer to a serializable durable store using conditional
  revision writes, atomically persist snapshots/events/redemptions, authenticate
  worker completion and cleanup acknowledgements, and recover the scheduler
  after process or regional failure.
- Operate the actual microVM/dedicated-VM builder controller and labeled egress
  broker; prove there is no host path, socket, namespace, credential, or direct
  Internet escape.
- Implement the immutable registry, provenance/SBOM/signing pipeline, encrypted
  state store, signed audit sink, backups, restore tests, and regional recovery.
- Run dependency-backed Warden/Mind build, deploy, tenant-denial, cancellation,
  rollback, restore, and failover tests against those real dependencies.
- Define and exercise SLOs and runbooks for authentication, builders,
  scheduling, deployment state, registry, runtime, egress, and recovery.
- Implement PostgreSQL plugin binding/migration, persist deployment and broker
  reducers transactionally in the Codefly server, resolve the three existing
  AWS database bindings, attach generated source security groups to the correct
  workload ENIs/pods, and run real migrate/deploy/rollback tests.
- Deferred: implement physical AWS reconciliation, capacity expansion,
  protected destruction, and provision/restore testing after the application
  vertical slice passes.

### CN-334 — Cross-repository contract and release gates

- Status: `IN PROGRESS`
- Depends on: CN-331, CN-332

Deliverables:

- Version the neutral-to-Codefly plan schema and publish compatibility rules.
- Add contract tests spanning this repository and the local Codefly workspace.
- Verify descriptor/API/network-policy parity, rendered deployment schema,
  provenance, SBOM, signatures, and backward-compatible migrations.
- Pin tested revisions of IaC, Codefly, Warden, Mind, and the SaaS kernel in the
  release evidence manifest.

Acceptance criteria:

- An incompatible Codefly or blueprint change fails before deployment with an
  actionable semantic diff.
- Clean-checkout and all-dependency tests cover both deployments and their
  declared service graph.
- Release evidence identifies exactly which source, plan digest, artifacts,
  policies, and dependency versions were deployed.

Implemented increment:

- Release evidence hashes the neutral managed-Postgres source, AWS and Codefly
  seam adapters, strict intent/plan schemas, checked-in three-service contract,
  concrete RDS module, and renderer. Disposable-cluster evidence covers only
  IaC-owned identity/token admission and explicitly excludes application
  migration execution.

## P1: Deployment Verification

### CN-400 — Pulumi preview fixtures

- Status: `READY`
- Depends on: CN-220

Deliverables:

- Minimal compliant and hostile Pulumi programs.
- Preview tests with the real Policy Pack.
- Golden summaries of semantic resources and violations.

Acceptance criteria:

- No cloud deployment is required for preview fixtures.
- Hostile previews fail for the intended policy codes.
- Fixture outputs are stable and reviewable.

### CN-401 — Ephemeral AWS integration environment

- Status: `BLOCKED`
- Depends on: CN-111, CN-112, CN-120, CN-131, CN-140

Deliverables:

- Disposable organization/account or sandbox-account deployment path.
- Automated deployment, verification, evidence collection, and teardown.
- Strict budget and maximum-lifetime controls.

Acceptance criteria:

- Teardown succeeds after both passing and failed tests.
- Leaked resources trigger alerts and an automated cleanup attempt.
- Test credentials are short-lived and environment-scoped.

### CN-402 — AWS deny-path tests

- Status: `BLOCKED`
- Depends on: CN-401, CN-200, CN-201

Test at least:

- execution cannot reach control-plane data directly;
- disallowed egress domain fails;
- tenant A cannot read/list/write tenant B data;
- public EKS/API access is absent;
- unsigned or incorrectly signed image admission fails;
- audit events arrive in immutable storage;
- backup restore succeeds in isolation;
- break-glass use emits an alert.

Acceptance criteria:

- Tests verify denial empirically, not only by inspecting plans.
- Every result is attached to the isolation evidence report.

### CN-403 — Property-based model testing

- Status: `READY`
- Depends on: CN-101

Generate:

- valid and invalid CIDR plans;
- random tenant placements;
- access graphs with cycles and inheritance;
- random control removals;
- provider capability combinations.

Acceptance criteria:

- Generated tests are deterministic from recorded seeds.
- Failures print a minimized reproduction blueprint.
- At least CIDR containment, cross-tenant isolation, and capability fail-closed
  properties are covered.

### CN-404 — Dependency security gate

- Status: `DONE`
- Depends on: none

Deliverables:

- Fail CI on new high or critical production dependency advisories.
- Track accepted moderate advisories with owner, justification, expiry, and
  compensating controls.
- Monitor the Pulumi/OpenTelemetry advisory chain for a compatible resolution.
- Produce an SBOM for the released IaC artifact.

Acceptance criteria:

- The current 14 moderate transitive findings are documented, not silently
  ignored.
- A synthetic high-severity finding fails CI.
- Exception expiry is machine-enforced.

## P2: Productization

### CN-500 — Package the core and provider adapters

- Status: `LATER`
- Depends on: CN-311

Deliverables:

- Separate packages for core, provider contracts, AWS, GCP, and Azure.
- Semantic versioning and changelogs.
- Package provenance and SBOMs.
- Supported-version compatibility matrix.

### CN-501 — Generate diagrams and control mappings

- Status: `LATER`
- Depends on: CN-204

Generate from the security graph:

- trust-zone diagrams;
- tenant placement diagrams;
- network and identity path diagrams;
- threat-model deltas;
- NIST, SOC 2, CIS, and internal control mappings.

Acceptance criteria:

- Generated documentation identifies its blueprint digest.
- Diagrams and evidence cannot drift from deployed intent.

### CN-502 — Tenant cost, quota, and lifecycle policies

- Status: `LATER`
- Depends on: CN-120, CN-130

Deliverables:

- Cost attribution requirements per isolation tier.
- Quotas and anomaly thresholds.
- Tenant onboarding, suspension, export, and deletion workflows.
- Evidence that deleted tenants have no remaining active access paths.

## Suggested Execution Order

Critical path:

1. CN-101
2. CN-110 and CN-130 in parallel
3. CN-120 and CN-140 in parallel
4. CN-111, CN-112, and CN-131
5. CN-121 and CN-132
6. CN-200 and CN-201
7. CN-202, CN-203, and CN-204
8. CN-220 and CN-221 can run alongside steps 1–5
9. CN-300, then CN-310 and CN-311
10. CN-320

Verification track:

1. CN-404 can start immediately.
2. CN-400 can start after CN-220.
3. CN-403 can start after CN-101.
4. CN-401 and CN-402 start after the AWS vertical slice is complete.

Codefly PaaS track:

1. Freeze CN-335's exact Warden/Mind product truth and remove temporary drift.
2. Publish and pre-provision the AWS `CloudContext` contracts and bindings.
3. Add CN-333's minimum durable application plan/deploy/watch/cancel/rollback
   path without provider provisioning.
4. Resolve existing PostgreSQL bindings and prove the migration path.
5. Complete Warden as the first vertical slice, then Mind across application and
   isolated-execution contexts.
6. Run the joint denial/restart/cancel/rollback gate and complete CN-332.
7. Use CN-334 to pin clean cross-repository release evidence.
8. Only then implement physical infrastructure-on-demand reconciliation.

## Milestones and Exit Criteria

### Milestone A — Neutral kernel usable by AWS

Required tasks:

- CN-101, CN-110, CN-111, CN-112, CN-120, CN-121, CN-130, CN-131, CN-132,
  CN-140, CN-200, CN-201, CN-202, CN-220, CN-221.

Exit criteria:

- Production AWS stacks compile from the blueprint.
- Existing requirement-only booleans are no longer the source of security
  truth.
- Tenant isolation paths and generated policies are executable and tested.
- No high or critical dependency advisories are accepted silently.

### Milestone B — AWS isolation evidence

Required tasks:

- CN-203, CN-204, CN-400, CN-401, CN-402, CN-403, CN-404.

Exit criteria:

- Isolation is tested both statically and empirically.
- Each release includes a signed security evidence report.
- Restore, break-glass, audit delivery, and denial paths are exercised.

### Milestone C — Proven cloud-neutral contract

Required tasks:

- CN-300, CN-310, CN-311.

Exit criteria:

- AWS and GCP pass the same semantic conformance suite.
- The core contains no accidental AWS resource semantics.
- Unsupported intent fails with explicit capability diagnostics.

### Milestone D — Three-cloud adapter set

Required tasks:

- CN-320 and the Azure-specific integration fixtures.

Exit criteria:

- AWS, GCP, and Azure compile the shared reference blueprints.
- Provider-native identity and policy behavior remains explicit.
- Cross-cloud evidence uses the same normalized security graph.

### Milestone E — Codefly PaaS with Warden and Mind

Required tasks:

- CN-330, CN-331, CN-332, CN-333, CN-334, CN-335.

Exit criteria:

- One authenticated Codefly submission can build, migrate, deploy, observe,
  cancel, and independently roll back either Warden or Mind in explicitly
  selected, pre-provisioned AWS cloud contexts.
- Codefly resolves credential-free context capabilities and existing managed
  resource bindings; physical infrastructure provisioning is not required.
- The remote Codefly control plane has no unauthenticated command, file, secret,
  builder, terminal, registry, or deployment mutation surface.
- Cross-scope, cross-product, replay, supply-chain, migration, cancellation, and
  rollback tests run with real declared dependencies and produce signed release
  evidence.

### Milestone F — Codefly infrastructure on demand

Required only after Milestone E:

- logical managed-resource pools;
- asynchronous provider reconciliation and drift detection;
- capacity expansion, backup/restore lifecycle, and protected destruction; and
- ephemeral AWS provision/migrate/restore/destroy evidence.

Exit criteria:

- The same claim used by Milestone E can create missing physical capacity and
  resume a paused application deployment without exposing provider credentials.

## Definition of Fully Done

The cloud-neutral initiative is fully done only when:

- all production infrastructure is derived from versioned blueprint intent;
- AWS, GCP, and Azure adapters pass the shared conformance contract;
- pooled and dedicated tenant tiers have static and deployed isolation proofs;
- identity, network, data, encryption, audit, backup, and cost boundaries are
  connected in one graph;
- every unsupported capability fails before resource creation;
- releases contain signed plans, SBOMs, policy results, and isolation evidence;
- disaster recovery and deny-path tests run on a documented cadence;
- no critical security property exists only as a config boolean, tag, or prose
  requirement.

Until those conditions hold, the kernel is usable and valuable, but the complete
cloud-neutral multi-tenant platform remains in progress.
