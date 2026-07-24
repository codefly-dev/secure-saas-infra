# Rootless AWS Infrastructure Execution Roadmap

Status: active execution roadmap
Decision date: 2026-07-15
Primary repository: `secure-saas-infra`
North star: a future platform host may authorize typed infrastructure intent,
while isolated Pulumi workers reconcile cloud resources with temporary,
least-privilege credentials. Application-facing consumers never receive
provider credentials.

Current execution boundary: this repository implements and tests IaC only.
CLI, server, plugin, product, and cross-repository qualification are deferred
until a separate reviewed integration plan explicitly reopens them.

This file records the active IaC security boundaries, dependencies, detailed
tasks, evidence, and real-AWS gates. Platform/PaaS documents are historical
design context only until the integration boundary above is explicitly
reopened.

## Decisions

| ID      | Decision                                                                                                                                                                           | Status                                              |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| DEC-001 | Use AWS Organizations-managed landing-zone controls for the first bootstrap. Keep the owner explicit so a future Control Tower adapter imports rather than competes for resources. | Accepted                                            |
| DEC-002 | Require a central PDP, manifest ceiling, and signed scoped authorization at the future platform-host boundary without coupling the IaC protocol to that implementation.            | Accepted                                            |
| DEC-003 | Keep AWS and Pulumi credentials out of application and infrastructure-request plugins.                                                                                             | Accepted                                            |
| DEC-004 | Run Pulumi only in isolated infrastructure workers controlled by an infrastructure broker/controller.                                                                              | Accepted                                            |
| DEC-005 | Keep organization/account bootstrap human-authorized and outside application automation. No controller assumes the management-account bootstrap role.                              | Accepted                                            |
| DEC-006 | Initially use Pulumi Cloud with OIDC for state, locking, history, RBAC, and short-lived backend authentication. Preserve a backend interface for a later self-managed backend.     | Proposed; requires Pulumi organization confirmation |
| DEC-007 | Provision `dev` first. Create governed production accounts, but admit no production workload or provider reconciliation until production gates pass.                               | Accepted                                            |
| DEC-008 | `staging` remains a disabled module until migration, recovery, or release evidence makes persistent preproduction necessary.                                                       | Accepted                                            |

Control Tower uses AWS Organizations underneath. `organizations` versus
`control-tower` therefore means **which system owns the landing-zone resources
and controls**, not whether Organizations exists. Pulumi must never update a
Control Tower-owned resource as if Pulumi were its controller of record.

## Non-negotiable invariants

- Root has no access key and is never used by a script, automation controller,
  Pulumi, CI, or an application-facing consumer.
- The steady state uses temporary credentials exclusively.
- The management account contains no product workload or infrastructure worker.
- Platform authorization may permit a request; it does not itself grant AWS
  authority.
- Every physical resource and every Pulumi stack has exactly one controller of
  record.
- Every infrastructure mutation binds the principal, organization, tenant,
  environment, CloudContext, claim, generation, desired-state digest, reviewed
  plan digest, deadline, idempotency key, and audit trace.
- Provider output is reference-only. No cloud credential, kubeconfig, database
  administrator secret, or Pulumi backend credential is a resource binding.
- Production mutation requires separation of duties. Protected deletion
  requires two distinct approvers and explicit finalization evidence.
- Authorization, state, policy, or audit unavailability fails closed.
- A preview is not authority to apply. An apply is not authority to destroy.

## Authority model

An infrastructure request is allowed only when every layer allows it:

```text
authenticated principal
  AND organization/tenant membership
  AND platform role grant
  AND plugin manifest ceiling
  AND exact short-lived capability
  AND environment/release policy
  AND reviewed plan-digest binding
  AND approval/separation-of-duties policy
  AND controller lease/fence/idempotency state
  AND AWS SCP/RCP boundary
  AND IAM role policy/permissions boundary/session policy
```

No individual layer is treated as sufficient authority.

## Repository ownership

| Repository/component                  | Owns                                                                                                                    | Must not own                                                                               |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `secure-saas-infra`                   | Generic contracts, AWS landing-zone adapter, bootstrap stacks, role plans, policy packs, evidence and conformance tests | Codefly server persistence, plugin implementations, application releases                   |
| Codefly core/server                   | Authentication, principals, PDP, grants, capabilities, durable jobs, broker state, approval records, audit              | Raw provider credentials in API processes, provider-specific resource construction         |
| Codefly CLI                           | Login, intent submission, plan display, approval UX, status/watch/cancel                                                | Durable truth, implicit tenant selection, production credentials, direct provider mutation |
| Application plugin                    | Application validation, build/deploy intent, typed resource claims, binding consumption, migrations                     | AWS SDK/Pulumi, physical RDS creation, cloud credentials, management-account access        |
| Infrastructure-request plugin/adapter | Typed broker RPC, request/response translation                                                                          | Pulumi CLI, AWS SDK, kubeconfig, provider credentials, host sockets                        |
| Infrastructure controller             | Authorization re-check, durable operation state, locks, fencing, provider dispatch, sanitized output                    | Application source/build behavior, organization bootstrap                                  |
| Pulumi worker/provider component      | Deterministic plan and authorized provider reconciliation                                                               | User authentication, tenant grants, approval policy, application orchestration             |

## Delivery gates

### R0 — Contract and ownership freeze

AWS required: no
Mutation allowed: no

- [x] `R0-001` Define the cloud-neutral model, resource claim/binding, and
      broker. Application/PaaS contracts are deferred outside the active
      published registry.
- [x] `R0-002` Separate application plugin behavior from physical provider
      reconciliation.
- [x] `R0-003` Record Pulumi as the implementation engine behind a typed
      platform API.
- [x] `R0-004` Model bootstrap state separately from application deployment
      state and claim-owned infrastructure state.
- [x] `R0-005` Define the infrastructure controller operations: `Plan`,
      `Reconcile`, `Observe`, `Cancel`, and protected `Delete`.
- [x] `R0-006` Define exact infrastructure authorization and stack-ownership
      metadata in `src/core/infrastructureController.ts`.
- [x] `R0-007` Publish a strict JSON schema and compatibility fixture for the
      normalized internal controller authorization request.
- [x] `R0-008` Define the public RPC request/response envelopes, monotonic
      operation events, and resumable watch cursors. The trusted host—not the
      plugin—must load the manifest/grant and verify the signed token before
      constructing the internal authorization request.
- [x] `R0-009` Define stable machine-readable error/reason codes across gRPC,
      REST, CLI, and audit records.
- [x] `R0-010` Define version-negotiation and deprecation rules for controller
      and provider protocols.
- [x] `R0-011` Remove cross-repository compatibility execution from the IaC
      gate. Dirty local sources remain valid only for local evidence, never
      promotion.

Acceptance:

- Unknown fields and wildcard tenant/resource authority are rejected.
- Every mutation is digest-bound, deadline-bound, idempotent, and one-use.
- Production reconcile and all deletion paths enforce separation of duties.
- Contract tests require no external platform process, AWS account, network, or Pulumi
  backend.

### R1 — Rootless operator bootstrap

AWS required: only for the final read-only checks
Mutation allowed: no

- [x] `R1-001` Add a non-mutating bootstrap doctor that checks local tools,
      onboarding decisions, account emails, credential mode, caller identity,
      and Pulumi login only when explicitly requested.
- [x] `R1-002` Make doctor operation offline by default; an AWS call requires
      `--check-aws-session` or `--strict`.
- [x] `R1-003` Pin Node, npm, Pulumi, AWS CLI, Git, and the management-seed AWS
      provider plugin in reviewed manifests; qualification also seals their
      executable/install digests.
- [x] `R1-004` Install Pulumi locally without downloading external agents or
      executing an unreviewed remote shell script.
- [ ] `R1-005` Create the real `onboarding.local.json` outside version control.
- [ ] `R1-006` Set `landingZoneOwner=organizations`, real management account ID,
      Pulumi organization/backend, GitHub organization, and email domain.
- [ ] `R1-007` Generate and manually verify every globally unique AWS account
      email and its monitored recovery route.
- [ ] `R1-008` Secure management-account root with multiple MFA devices, no
      access keys, monitored recovery, and multi-person access.
- [ ] `R1-009` Enable organization IAM Identity Center and connect the workforce
      identity source.
- [ ] `R1-010` Create group-based permission sets for audit, read-only preview,
      nonproduction administration, and the exceptional bootstrap lane.
- [ ] `R1-011` Configure AWS CLI SSO and prove automatic temporary credential
      refresh.
- [ ] `R1-012` Reject root, IAM-user long-lived keys, wrong account, expired
      sessions, and ambiguous default profiles in strict doctor mode.
- [ ] `R1-013` Capture a credential-free bootstrap readiness report.

Acceptance:

- `npm run bootstrap:doctor` performs no cloud call and no write.
- Strict mode identifies an assumed/federated principal in the exact management
  account and rejects a root ARN.
- No secret value appears in stdout, JSON output, logs, Git, Pulumi config, or
  evidence.

### R2 — AWS role and guardrail plan

AWS required: no for rendering; yes for policy validation/simulation
Mutation allowed: no

- [x] `R2-001` Define a credential-free `AwsBootstrapAccessPlan` contract.
- [x] `R2-002` Render separate human-only management seed preview and
      seed-create policies. Preview is read-only; apply explicitly denies
      organization/account/guardrail and delegated-security destruction.
- [x] `R2-003` Render per-account `InfrastructurePlan` roles.
- [x] `R2-004` Render separate `InfrastructureApplyNonProd` and
      `InfrastructureApplyProd` capability-lane roles. Each action set is a
      distinct role because one combined exact-action policy exceeds AWS's
      [6,144-character managed-policy limit](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html);
      the compiler refuses to hide that limit behind `service:*`.
- [ ] `R2-005` Keep destructive authority out of ordinary apply roles; render a
      separately approved deletion session policy.
- [x] `R2-006` Attach permissions boundaries to every role able to create or
      pass IAM roles.
- [ ] `R2-007` Restrict OIDC trust to the exact issuer, audience, organization,
      project/controller, service account, and environment.
- [x] `R2-008` Deny role chaining into management, organization bootstrap,
      billing, root-session, or account-closure authority.
- [ ] `R2-009` Require resource ownership tags and request tags wherever AWS
      supports them; document create APIs that cannot be resource-scoped.
- [ ] `R2-010` Render SCP/RCP and permissions-boundary interaction tests.
- [ ] `R2-011` Run IAM Access Analyzer policy validation in a real sandbox.
- [ ] `R2-012` Run positive and negative IAM simulations for every controller
      action.

Acceptance:

- Application automation has no trust path into `OrganizationSeedPreview` or
  `OrganizationSeedApply`.
- Dev authority cannot mutate prod; plan authority cannot mutate; apply cannot
  close accounts or disable security/audit controls.
- A role created by Pulumi cannot exceed the permissions boundary.

Implemented evidence:

- `src/adapters/aws/bootstrapAccess.ts` strictly parses and compiles the
  credential-free plan. It emits one observation role and one mutation role per
  capability lane, exact role principals and external IDs, no wildcard Allow
  actions, explicit high-risk denies, and a hard AWS managed-policy size gate.
- The contract's `management.accessInstallerRoleArn` is a separate,
  human-federated management-account identity used only to install those scoped
  member-account roles. It is neither `OrganizationSeedPreview` nor
  `OrganizationSeedApply`, is not trusted by the infrastructure controller, and
  has no organization/account-vending authority by contract.
- `src/awsBootstrapAccess.ts` materializes protected/retained IAM roles, inline
  policies, and permissions boundaries. No plan or mutation role trusts the
  controller until its own member-account role and EKS Pod Identity association
  are independently materialized and verified.
- `scripts/render-aws-bootstrap-access.mjs` renders either desired or compiled
  review artifacts without network access. The schema, reference contract, and
  release evidence are version-bound.
- `scripts/bootstrap.mjs` currently admits only the management `seed` wave for
  real preview/apply. The modeled access wave has no broad-role compatibility
  flag and remains blocked until real account outputs and exact scoped provider
  bindings are available. Application automation never receives the member
  handoff or management bootstrap role.
  Policy-checked Pulumi previews save exact update plans and a commit-bound
  SHA-256 manifest; apply requires the reviewed manifest digest and passes each
  plan back through Pulumi's update-plan constraint.

Remaining R2 boundaries are intentional: the management Identity Center
permission set, controller-host EKS Pod Identity trust, request-tag conditions,
SCP/RCP interaction, Access Analyzer validation, and real IAM simulation still
need implementation or a real AWS sandbox.

### R3 — Pulumi backend and local execution

AWS required: no for mocks/local state; yes for real preview
Mutation allowed: no

- [ ] `R3-001` Confirm Pulumi organization and initial Pulumi Cloud backend.
- [ ] `R3-002` Register the isolated controller workload as a Pulumi Cloud OIDC issuer and request
      short-lived Pulumi access tokens; store no organization token in a pod.
- [ ] `R3-003` Pin Pulumi, Node, package lock, providers, policy pack, and
      controller versions.
- [ ] `R3-004` Define stack identity as organization/project/environment/
      context/claim, never a user-selected free-form string.
- [ ] `R3-005` Implement an Automation API workspace factory with a clean,
      ephemeral working directory.
- [ ] `R3-006` Bind stack tags and ownership metadata to tenant, claim,
      generation, and desired-state digest.
- [ ] `R3-007` Enforce one writer with backend lock plus controller lease/fence.
- [ ] `R3-008` Store provider secrets only through dynamic identity; sanitize
      environment, logs, diagnostics, and outputs.
- [ ] `R3-009` Execute policy packs for every preview and update.
- [ ] `R3-010` Preserve the reviewed preview artifact and require the exact
      digest for reconciliation.
- [ ] `R3-011` Add deterministic Pulumi mocks and provider contract tests.
- [ ] `R3-012` Test process crash, timeout, cancellation, lock loss, stale fence,
      retry, and partial provider failure.

Acceptance:

- Local tests prove plans without AWS.
- A worker cannot continue after losing its lease or fence.
- Reconciliation refuses a plan whose desired state, policy result, provider
  version, or plan digest changed.

### R4 — Landing-zone preview and bootstrap apply

AWS required: yes
Mutation allowed: only after explicit user authorization

- [ ] `R4-001` Run strict doctor and save the redacted report.
- [ ] `R4-002` Discover existing organization, OUs, accounts, delegated
      administrators, trusted access, IAM Identity Center, and root credential
      posture without mutation.
- [ ] `R4-003` Compare discovery with desired ownership and fail on a Control
      Tower/Pulumi ownership collision.
- [ ] `R4-004` Create concrete stack configuration with no placeholder.
- [ ] `R4-005` Preview management and identity stacks with policy packs.
- [ ] `R4-006` Review account-vending emails, names, parent OUs, role names,
      service access, delegated administrators, and SCP attachments.
- [ ] `R4-007` Record preview digest, tool/provider versions, caller ARN,
      management account ID, policy results, cost estimate, and expiry.
- [ ] `R4-008` Obtain explicit authorization for the first mutation.
- [ ] `R4-009` Apply only the reviewed management/identity plan.
- [ ] `R4-010` Wait for accounts to become active and verify bootstrap role
      assumption before any downstream stack.
- [ ] `R4-011` Render the real account-ID-bound access plan, preview every
      `access-{account}` stack, and validate each policy with IAM Access
      Analyzer before mutation.
- [ ] `R4-012` Explicitly authorize the one-time member handoff, install the
      protected capability-lane roles/boundaries, simulate positive and
      negative actions, and record the resulting role/output digests.
- [ ] `R4-013` Enable centralized root access management, remove member-account
      root credentials, and delegate root management to the security account.
- [ ] `R4-014` Verify CloudTrail records only the expected federated/assumed
      sessions and no root activity.

Rollback/stop conditions:

- Stop on unexpected existing resources, email conflict, wrong management
  account, root caller, Control Tower ownership, policy failure, cost-limit
  failure, or plan-digest change.
- AWS account creation and organization changes are not treated as casually
  reversible. Do not automate organization-level destroy.

### R5 — Dev platform and execution context

AWS required: yes
Mutation allowed: explicit nonproduction approval

- [ ] `R5-001` Apply logging, security tooling, network, shared services, and
      dev platform/execution accounts in dependency order.
- [ ] `R5-002` Keep EKS APIs private and operator access temporary.
- [ ] `R5-003` Install EKS Pod Identity and create a dedicated infrastructure
      worker service account.
- [ ] `R5-004` Establish cross-account target roles with temporary credentials.
- [ ] `R5-005` Deploy immutable registry, audit sink, policy enforcement,
      secrets references, broker, queue, and worker isolation.
- [ ] `R5-006` Deny instance metadata credentials, host network/PID/path,
      container sockets, privileged mode, and undeclared egress.
- [ ] `R5-007` Prove network default deny and only broker-to-worker/provider
      paths.
- [ ] `R5-008` Prove worker identity cannot access management or prod.
- [ ] `R5-009` Run backup/restore and audit delivery exercises.
- [ ] `R5-010` Promote dev CloudContexts to `ready` only with digest-bound
      evidence.

### R6 — Deferred future platform authorization and broker integration

AWS required: no for contract/server tests; dev for end-to-end
Repository: external platform repository after a separate integration plan

- [ ] `R6-001` Add public `PlanInfrastructure`, `ReconcileInfrastructure`,
      `ObserveInfrastructure`, `CancelInfrastructure`, and protected
      `DeleteInfrastructure` RPCs.
- [ ] `R6-002` Require explicit organization, tenant, environment, context,
      claim, generation, desired-state digest, request ID, idempotency key, and
      deadline.
- [ ] `R6-003` Map authenticated users/services/agents to the existing unified
      Codefly principal model.
- [ ] `R6-004` Store grants centrally and wrap the SaaS PDP with the manifest
      ceiling.
- [ ] `R6-005` Set `CODEFLY_PDP_REQUIRE_MANIFEST=true` in every production
      server and worker.
- [ ] `R6-006` Use Ed25519 v2 scoped authorizations with key IDs, rotation,
      audience, exact action/resource, TTL, and replay enforcement.
- [ ] `R6-007` Disable legacy HMAC authorization after migration.
- [ ] `R6-008` Keep shadow PDP limited to observation/burn-in; never use it as
      production enforcement.
- [ ] `R6-009` Persist decisions, reason codes, delegation chain, capability ID,
      approvals, and plan digest in immutable audit.
- [ ] `R6-010` Require step-up and a distinct approver for production
      reconciliation.
- [ ] `R6-011` Require two distinct approvers, retention/final-snapshot policy,
      and finalization evidence for deletion.
- [ ] `R6-012` Fail closed when PDP, grant store, signing key, replay store,
      operation store, or audit sink is unavailable.

### R7 — Thin infrastructure-request adapter

AWS required: no
Repository: Codefly/plugin repository after R6

- [ ] `R7-001` Create a thin infrastructure-request adapter, distinct from an
      application plugin and provider component.
- [ ] `R7-002` Declare only broker-facing permission actions and tenant/context
      resource prefixes in its install-time manifest.
- [ ] `R7-003` Permit network only to the mTLS broker endpoint.
- [ ] `R7-004` Deny provider credentials, Pulumi backend access, filesystem
      outside an ephemeral request directory, Unix sockets, host execution, and
      direct Kubernetes access.
- [ ] `R7-005` Make planning deterministic and mutation impossible inside the
      adapter process.
- [ ] `R7-006` Add compatibility tests proving manifest action/resource names
      match this repository's contract.

### R8 — ManagedPostgres vertical slice

AWS required: dev after mocks pass

- [ ] `R8-001` Keep the application Postgres plugin cloud-neutral.
- [ ] `R8-002` Emit a `ManagedPostgres` claim describing semantics, not RDS
      classes, subnets, security groups, ARNs, or passwords.
- [ ] `R8-003` Implement the AWS provider component behind the infrastructure
      controller.
- [ ] `R8-004` Start by allocating a logical database from bootstrap-owned
      Aurora capacity.
- [ ] `R8-005` Return endpoint, port, database, CA, runtime identity, and
      migration identity references only.
- [ ] `R8-006` Create separate runtime and migration roles; runtime cannot DDL
      and migration cannot administer the cluster.
- [ ] `R8-007` Run checksum-bound, advisory-locked, forward-only migrations.
- [ ] `R8-008` Prove duplicate reconcile, restart, drift, cancellation, backup,
      restore, deletion protection, and finalization.
- [ ] `R8-009` Add dedicated RDS/Aurora child stacks only after pooled logical
      allocation is reliable.

### R9 — Application deployment and product onboarding

AWS required: dev, then preprod/prod after gates

- [ ] `R9-001` Deploy a signed fixture application against existing bindings.
- [ ] `R9-002` Prove deploy/status/watch/cancel/promote/rollback independently
      from physical infrastructure reconciliation.
- [ ] `R9-003` Deploy Warden as an independent tenant/release.
- [ ] `R9-004` Deploy Mind as an independent tenant/release.
- [ ] `R9-005` Keep product identities, data, networks, jobs, claims, releases,
      and rollback authority separate.
- [ ] `R9-006` Prove explicit authenticated cross-product APIs are the only
      allowed cross-product path.
- [ ] `R9-007` Enable persistent preprod before public production if migration,
      integration, or recovery evidence cannot be proven safely in dev.
- [ ] `R9-008` Promote the exact signed artifact digest; never rebuild for prod.

### R10 — Production readiness

- [ ] `R10-001` Complete threat model, architecture decision records, and data
      flow review.
- [ ] `R10-002` Complete external penetration test and remediate high/critical
      findings.
- [ ] `R10-003` Exercise signing-key rotation, identity-provider outage, PDP
      outage, backend outage, worker compromise, and audit outage.
- [ ] `R10-004` Exercise disaster recovery with measured RPO/RTO.
- [ ] `R10-005` Exercise break glass with time limit, two-person control,
      immutable audit, automatic revocation, and post-incident review.
- [ ] `R10-006` Prove tenant deletion, retention, legal hold, and evidence
      lifecycle.
- [ ] `R10-007` Establish SLOs, error budgets, capacity, quotas, cost limits,
      paging, and on-call ownership.
- [ ] `R10-008` Admit production only when every mandatory evidence item is
      present and digest-bound.

### R11 — Multi-cloud expansion

Wait until the AWS provider passes recovery, drift, and deletion tests.

- [ ] `R11-001` Extract provider conformance tests from the proven AWS
      implementation.
- [ ] `R11-002` Implement GCP workload identity, project boundaries, provider
      component, and equivalent audit/recovery semantics.
- [ ] `R11-003` Correct generic contracts that accidentally encode AWS
      behavior.
- [ ] `R11-004` Implement Azure only after AWS and GCP pass the same suite.
- [ ] `R11-005` Keep provider-specific extensions explicit; do not weaken the
      generic model to the lowest common denominator.

## Hostile test matrix

Every applicable layer must test these denials:

- unknown field, unsupported API version, malformed ID, wildcard authority;
- wrong organization, tenant, environment, context, claim, or generation;
- missing OIDC/mTLS, untrusted issuer, wrong audience, wrong subject;
- unsigned, expired, not-yet-valid, overlong, reusable, or replayed capability;
- plugin manifest omission or a manifest broader than its sandbox purpose;
- role grant missing action/resource or expired grant;
- desired-state digest or reviewed plan digest mismatch;
- plan expired, policy checks failed, provider/controller version changed;
- production actor approving their own change;
- deletion without two distinct approvers and finalization requirements;
- duplicate idempotency key with a different payload;
- stale lease/fence, concurrent writer, worker restart, timeout, cancellation;
- provider output containing a credential or unsafe unredacted value;
- dev-to-prod, tenant-to-tenant, product-to-product, or workload-to-management
  access;
- IAM privilege escalation through `PassRole`, role creation, trust update,
  permissions-boundary removal, resource policy, or role chaining;
- failure or partition of PDP, database, replay store, audit sink, backend,
  provider, or cloud API.

## Evidence required per gate

- exact source revision and clean-tree status;
- dependency lock, SBOM, vulnerability result, signatures, and provenance;
- contract/schema versions and compatibility matrix;
- tool, Pulumi, provider, policy-pack, controller, and plugin versions;
- caller principal, account, role session, capability ID, and delegation chain;
- desired-state and plan digests;
- policy results, approvals, idempotency record, lease, and fence;
- Pulumi preview/update result and sanitized output digest;
- CloudTrail/audit event references;
- positive and negative test results;
- backup/restore, recovery, and deletion/finalization evidence where applicable.

## Immediate implementation queue

Execute in this order:

1. Finish public RPC envelopes/reason codes in `R0-008` through `R0-010` while
   keeping those tests offline.
2. Fill the real onboarding decisions, stable federated bootstrap role, and
   Pulumi organization/backend in `R1`.
3. Finish the management permission set, controller Pod Identity trust,
   request-tag enforcement, and SCP/RCP interaction tests in `R2`.
4. Split compound infrastructure stacks by capability lane so normal Pulumi
   and Codefly execution never need the temporary broad member role.
5. Install/pin Pulumi and finish local Automation API mocks in `R3`.
6. Stop and request explicit authorization before `R4-009`, the first AWS
   mutation.
7. Install and simulate scoped member roles at `R4-011`/`R4-012`; remove the
   temporary compatibility flag after lane migration.
8. Build dev foundations and workload identity in `R5`.
9. Change Codefly only after the controller and authorization contract is
   stable, beginning with `R6` and `R7`.
10. Prove `ManagedPostgres`, then fixture deployment, Warden, and Mind.

## Inputs still required from the operator

- real AWS management account ID;
- globally unique and monitored account email addresses;
- Pulumi organization name and confirmation of Pulumi Cloud versus a
  self-managed backend;
- workforce identity provider and initial platform/security groups;
- real DNS zones and GitHub organization;
- explicit authorization immediately before any `pulumi up` or other AWS
  mutation.
