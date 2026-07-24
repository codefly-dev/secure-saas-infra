# Codefly Bootstrap and Pulumi PaaS Roadmap

Status: active roadmap
Decision date: 2026-07-15
North star: Codefly deploys applications through cloud-neutral contracts and
uses Pulumi as its infrastructure execution engine without mixing application
plugins, provider privilege, or bootstrap ownership.

The task-level security, dependency, evidence, and real-AWS gates are tracked
in
[`rootless-aws-codefly-execution-roadmap.md`](rootless-aws-codefly-execution-roadmap.md).

## Executive decision

Codefly needs infrastructure as code at two different lifecycle levels:

1. **Bootstrap IaC is required now.** It creates the accounts, trust, state,
   networks, runtime, data, and observability that Codefly itself requires in
   order to exist.
2. **PaaS-managed infrastructure comes later.** Once Codefly is running, a
   higher-level infrastructure controller may use Pulumi Automation API to
   fulfill typed application resource claims.

These levels must not own the same resource. The PaaS cannot be the initial
owner of the credentials, state backend, policy boundary, or control-plane
runtime on which it depends.

## Bootstrap organizations and environments

“Organization” exists at three separate layers and must not be overloaded:

| Layer                | Initial value                              | Purpose                                                                                     |
| -------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| AWS Organization     | Company/root AWS organization              | Account governance, billing, SCPs, delegated security, and landing-zone controls            |
| Pulumi organization  | Operator-owned infrastructure organization | Projects, stacks, state, policy, ESC environments, and deployment authorization             |
| Codefly organization | `deus` initially                           | Application tenancy, members, teams, environments, quotas, releases, and resource ownership |

Codefly also needs a **system realm** for its own control-plane resources. The
system realm is not a customer organization and must not be creatable,
transferable, or administrable through ordinary organization APIs.

Bootstrap the first Codefly organization through one idempotent, audited seed
operation:

- exact organization ID and slug;
- exact initial owner OIDC subject and issuer;
- no default password, shared bearer token, or permanent API key;
- initial teams and least-privilege roles;
- environment definitions and release policies;
- CloudContext references, never AWS credentials; and
- a digest of the seed declaration so re-execution is a no-op or explicit
  reconciliation, not duplicate creation.

### Initial environment decision

Create environment support as a modular data model from day one, but initially
operate only development and production:

| Environment           | Provision now                                                        | AWS isolation                                                    | Purpose                                                                                                        |
| --------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `dev`                 | Yes                                                                  | Dedicated platform and execution accounts                        | Continuous integration, local-agent compatibility, shared development, destructive testing with synthetic data |
| `staging` / `preprod` | Declare disabled                                                     | Future dedicated platform and execution accounts                 | Production-like rehearsal when release and migration risk justify a persistent environment                     |
| `prod`                | Create governed accounts now; deploy workloads only after gates pass | Dedicated platform and execution accounts with stricter controls | Customer production                                                                                            |

Skipping a permanently running staging environment is acceptable initially if:

- production and non-production never share accounts, data, Pulumi state,
  network paths, identities, or context bindings;
- ephemeral integration environments run in the non-production boundary;
- the exact immutable artifact digest is promoted rather than rebuilt;
- production has stricter approval, policy, backup, and evidence requirements;
  and
- a production-like preprod environment is added before public production if
  database migrations, external integrations, or recovery exercises cannot be
  proven safely in development.

For this platform, database migrations and multi-service Warden/Mind releases
make preprod advisable before public customer production. It does not need to
block the initial dev bootstrap.

An environment is a policy and isolation object, not a free-form label. It
binds:

- an environment class (`nonproduction`, `preproduction`, or `production`);
- allowed CloudContext IDs and AWS accounts;
- data classification and synthetic/production data policy;
- source-ref and artifact-promotion rules;
- quotas, regions, retention, backup, and recovery policy;
- approval and separation-of-duties requirements; and
- environment-specific evidence requirements.

### Lean AWS account topology

The lean secure starting topology is:

```text
AWS management account             # organization-only; no workloads
Security OU
  security-tooling / audit
  log-archive
Infrastructure OU
  network
  shared-services                  # may remain minimal initially
Workloads / NonProd OU
  platform-dev
  execution-dev
Workloads / PreProd OU                 # declared; account creation disabled
  platform-staging
  execution-staging
Workloads / Prod OU
  platform-prod
  execution-prod
```

Enable the paired preprod definitions later from the same module. Do not create
environment-specific forks of the IaC program.

AWS recommends keeping workloads out of the management account, organizing OUs
by common controls, separating production from non-production, and centralizing
audit logs. Current AWS Control Tower landing zones can establish central audit
and log-archive accounts, while its controls-only option may fit an already
established AWS Organization. Relevant current guidance:

- [AWS Organizations multi-account best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices.html)
- [AWS OU best practices](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_ous_best_practices.html)
- [AWS recommended OUs and accounts](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/recommended-ous-and-accounts.html)
- [AWS Control Tower landing-zone behavior](https://docs.aws.amazon.com/controltower/latest/userguide/how-control-tower-works.html)
- [AWS Control Tower landing zone 4.0](https://docs.aws.amazon.com/controltower/latest/userguide/landing-zone-v4-migration-guide.html)

### Pulumi organization practice

- Decide the state backend before the first real stack. Existing ESC imports
  require the Pulumi Cloud backend.
- Use separate stacks for account/environment/component boundaries; never use
  one mutable “all environments” stack.
- Compose common configuration into environment-specific configuration.
- Use OIDC-issued short-lived AWS sessions; never save static AWS access keys in
  Pulumi configuration or CI.
- Scope deployment-role trust to exact Pulumi organization, project, stack, and
  operation claims where supported.
- Apply permissions boundaries to roles that can create or pass IAM roles.
- Pin production ESC imports to a reviewed revision or release tag rather than
  implicitly consuming the latest revision.
- Keep development and production state, secrets, roles, and update approvals
  separate even when they use the same Pulumi project code.

Current Pulumi guidance:

- [Pulumi ESC environments](https://www.pulumi.com/docs/esc/concepts/environments/)
- [Pulumi AWS OIDC for deployments](https://www.pulumi.com/docs/deployments/guides/oidc/aws/)

```text
operator / protected CI
        |
        | Pulumi CLI
        v
seed + Codefly bootstrap IaC
        |
        +-- accounts, network, EKS, registry, KMS, audit
        +-- Codefly control plane, broker, workers, durable state
        +-- platform and isolated execution CloudContexts
        |
        v
running Codefly PaaS
        |
        +-- application plugins -> release lifecycle
        +-- resource broker -> claims and bindings
        |
        v
infrastructure controller (later)
        |
        | Pulumi Automation API + provider components
        v
application-scoped AWS / GCP / Azure resources
```

## Separation of concerns

| Boundary                  | Owns                                                                                                                                          | Must not own                                                                |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Seed IaC                  | Organization, accounts, Pulumi state, root KMS keys, OIDC, break-glass, audit roots                                                           | Application releases or application schema                                  |
| Codefly bootstrap IaC     | Codefly runtime, durable control state, broker workers, base clusters, registry, networking, observability, pre-provisioned resource capacity | General application behavior                                                |
| Application plugin        | Source synchronization, build intent, service configuration, migrations, deployment shape, readiness                                          | Cloud SDKs, Pulumi programs, provider credentials, physical cloud resources |
| Codefly PaaS server       | Authentication, tenant authorization, durable jobs, context selection, locks, policy, claims, bindings, audit                                 | Provider-specific resource construction                                     |
| Infrastructure controller | Authorized claim reconciliation, Pulumi workspace/stack lifecycle, drift, provider dispatch, reference-only outputs                           | Application source, builds, migrations, releases                            |
| Pulumi provider component | AWS/GCP/Azure implementation of a typed resource                                                                                              | PaaS authentication or application orchestration                            |

Use distinct terminology:

- **application plugin** for the existing Codefly service agents;
- **infrastructure controller** for the privileged PaaS subsystem;
- **provider component** or **infrastructure driver** for an AWS, GCP, or Azure
  Pulumi implementation.

Do not call all three simply “plugins.” Their trust and lifecycle models are
different.

## Resource and state ownership

Every physical resource has exactly one controller of record.

| Resource class                                         | Initial owner               | Possible future owner          |
| ------------------------------------------------------ | --------------------------- | ------------------------------ |
| AWS organization and accounts                          | Seed Pulumi stacks          | Seed Pulumi stacks             |
| Network hub, inspection, Transit Gateway               | Bootstrap Pulumi stacks     | Bootstrap Pulumi stacks        |
| Codefly platform and execution contexts                | Bootstrap Pulumi stacks     | Bootstrap Pulumi stacks        |
| Codefly API, broker, workers, and durable state        | Bootstrap Pulumi/GitOps     | Bootstrap Pulumi/GitOps        |
| Shared registry, DNS zones, audit roots, backup vaults | Bootstrap Pulumi stacks     | Bootstrap Pulumi stacks        |
| Pre-provisioned Aurora capacity                        | Bootstrap Pulumi stacks     | Bootstrap Pulumi stacks        |
| Logical database and scoped roles inside a pool        | Resource broker binding     | Infrastructure controller      |
| Dedicated application database cluster                 | Not in release one          | Claim-owned Pulumi child stack |
| Application release and Kubernetes objects             | Codefly deployment state    | Codefly deployment state       |
| Application schema history                             | PostgreSQL migration ledger | PostgreSQL migration ledger    |

Pulumi state is internal infrastructure state. Applications receive sanitized
`ResourceBinding` values such as endpoint, CA, database, and identity
references. They never receive a Pulumi backend token, stack credentials,
provider credentials, kubeconfig, or master database password.

## Stable abstraction boundary

The application-facing API describes required semantics, not cloud resources:

```yaml
kind: ManagedPostgres
spec:
  engine: postgresql
  majorVersion: "16"
  availability: multi-zone
  authentication: workload-identity
  isolation: dedicated-database
  recovery:
    rpoMinutes: 60
    retentionDays: 35
```

The resource broker selects a compatible provider implementation. Capability
negotiation must fail explicitly when a provider cannot satisfy the requested
semantics. Provider extension blocks may expose genuinely provider-specific
features, but generic intent must not contain subnet IDs, security-group IDs,
KMS ARNs, RDS class names, or provider credentials.

## Ordered delivery gates

### G0 — Freeze contracts and ownership

Status: in progress

Do now:

- [x] Define strict `CloudContext`, `ResourceClaim`, `ResourceBinding`, broker
      state, PaaS security, and `ManagedPostgres` contracts.
- [x] Separate application plugin behavior from privileged provider mutation.
- [x] Record Pulumi as the infrastructure execution engine, not the
      application-facing API.
- [x] Enforce the single-controller ownership rule.
- [x] Define the minimal infrastructure-controller RPC: `Plan`, `Reconcile`,
      `Observe`, `Cancel`, and protected `Delete`.
- [x] Define Pulumi stack ownership metadata: claim ID, tenant, context,
      generation, desired-state digest, controller version, and expiry policy.
- [x] Remove IaC-owned Codefly compatibility patches and cross-repository build
      runners; IaC validates only its provider-neutral contracts and adapters.

Exit: the contracts can support both an existing binding and future physical
provisioning without changing application plugins.

### G1 — Bootstrap real AWS foundations

Status: active

Do now in this IaC repository:

- [x] Select AWS Organizations-managed landing-zone ownership for the initial
      implementation and encode the choice in onboarding; keep Control Tower
      as an explicit alternate owner and never let both own the same controls.
- [ ] Keep the AWS management account workload-free and delegate supported
      security services to member accounts.
- [x] Establish Security, Infrastructure, NonProd, PreProd, and Prod OU
      definitions with inherited workload controls and strict parent ordering.
- [x] Create dev and prod platform/execution account definitions; keep the
      preprod module declared but disabled.
- [x] Compile separate platform and execution AWS CloudContexts from one
      provider-neutral Warden/Mind blueprint.
- [x] Require separate AWS account boundaries for platform and execution.
- [x] Define immutable KMS-encrypted ECR repositories for all 18 services.
- [x] Define exactly three contract-bound PostgreSQL databases with separate
      runtime and migration identities and network boundaries.
- [x] Keep generated contexts in `planned` state until real verification.
- [ ] Install the Pulumi CLI using the operator-approved local installation
      method; do not download Codefly agents.
- [ ] Select and initialize the Pulumi organization/backend, then create
      versioned common, dev, and prod ESC configuration using short-lived OIDC
      sessions.
- [ ] Create concrete non-example Pulumi stack files and remove every account,
      role, organization, DNS, and email placeholder.
- [ ] Establish short-lived AWS access to dedicated network, platform sandbox,
      and execution sandbox accounts.
- [ ] Add hard budgets, maximum test lifetime, and teardown ownership before
      the first mutation.
- [ ] Run policy-checked previews in the documented stack order.
- [ ] Obtain explicit authorization before the first `pulumi up`.
- [ ] Apply network, routing, platform, and execution sandbox stacks.
- [ ] Materialize exact workload and migration identities, database grants, and
      workload network attachments; references alone are not readiness.
- [ ] Verify ECR, private EKS access, inspected egress, IAM/TLS database access,
      backup/restore, audit delivery, and cross-boundary denial.
- [ ] Promote CloudContexts from `planned` to `ready` only with digest-bound
      evidence.

Exit: a fixture workload consumes every required binding through scoped
identity and network paths without provider or cluster administrator
credentials.

### G2 — Bootstrap the Codefly control plane

Status: active (contract published; reconciliation pending)

Defined now in this bootstrap IaC repository:

- [x] Define the Codefly system realm separately from ordinary
      organizations.
- [x] Publish the first Codefly organization (`deus`) as an idempotent,
      digest-bound, auditable bootstrap declaration.
- [x] Create modular `dev` and `prod` environment records and a disabled
      `preprod` template; bind only credential-free CloudContext IDs.
- [x] Add a strict parser, JSON schema, deterministic offline renderer, hostile
      tests, and release-evidence hashing for the seed contract.

Do immediately after the AWS context is usable and the Codefly bootstrap RPC
exists:

- [ ] Reconcile the declaration transactionally to seed the protected system
      realm and first organization; never let bootstrap IaC call ordinary
      organization APIs for the system realm.
- [ ] Authenticate the initial owner through an exact OIDC identity and require
      step-up/break-glass procedure for organization recovery.
- [ ] Define the minimum production Codefly topology: API/gateway, durable job
      store, resource broker, scheduler, worker pools, audit sink, and status
      stream.
- [ ] Decide and document the durable-state technology and recovery model.
- [ ] Provision the control-plane database/queue through bootstrap IaC; Codefly
      must not depend on itself to create its first durable state.
- [ ] Create separate workload identities for API, scheduler, broker, builder,
      deployer, migration, and execution workers.
- [ ] Deploy the initial control plane with protected CI and GitOps/Pulumi.
- [ ] Disable remote host command/file/terminal execution in production mode.
- [ ] Prove restart recovery, duplicate request handling, bounded retry,
      cancellation, fencing, and immutable audit delivery.

Exit: Codefly survives restart and can accept authenticated application jobs,
but it still resolves only pre-provisioned infrastructure bindings.

### G3 — Application deployment before infrastructure creation

Status: not started

Do next:

- [ ] Add context selection and compatibility planning to the CLI and server.
- [ ] Implement durable plan/deploy/status/watch/cancel/promote/rollback jobs.
- [ ] Build immutable images, publish digests, verify signatures/provenance, and
      deploy through scoped workers.
- [ ] Preserve installed-local-agent development mode.
- [ ] Resolve resource claims only from existing CloudContext bindings.
- [ ] Deploy a signed fixture application before onboarding Warden or Mind.

Exit: Codefly deploys and rolls back an application inside a selected AWS
context without creating physical infrastructure.

### G4 — PostgreSQL logical lifecycle

Status: not started

Do next:

- [ ] Keep the current PostgreSQL application plugin cloud-neutral.
- [ ] Make it emit and consume `ManagedPostgres` claims/bindings.
- [ ] Do not put AWS SDK or Pulumi access into the PostgreSQL application
      plugin.
- [ ] Bootstrap exact runtime and migration database roles through a privileged
      database bootstrap worker without returning the master credential.
- [ ] Run checksum-bound, advisory-locked, forward-only migrations with the
      migration identity.
- [ ] Use the runtime identity for application connections and deny DDL/admin
      operations.
- [ ] Roll application releases back independently from committed schema
      history.

Exit: a fixture service migrates and deploys idempotently against a
pre-provisioned AWS binding with no password URL or provider credential.

### G5 — Warden, then Mind vertical slices

Status: not started

Do next:

- [ ] Deploy Warden as one independently releasable application.
- [ ] Verify all Warden modules, services, dependencies, databases, health,
      cancellation, promotion, and rollback.
- [ ] Deploy Mind as a separate application after Warden passes.
- [ ] Keep Mind control services in the platform context and delegate only
      customer-code execution to the isolated execution context.
- [ ] Verify Warden and Mind cannot read, mutate, cancel, or roll back each
      other except through explicit authenticated APIs.

Exit: both products deploy on demand into existing AWS contexts and have
independent operational boundaries.

### G6 — Minimum Pulumi infrastructure controller

Status: wait until G5

Build only after application deployment is proven:

- [ ] Implement the infrastructure controller around Pulumi Automation API.
- [ ] Keep provider credentials only in isolated infrastructure workers.
- [ ] Start with one resource kind: `ManagedPostgres`.
- [ ] Support `Plan`, policy evaluation, asynchronous `Reconcile`, `Observe`,
      drift, cancellation, and approval-bound deletion.
- [ ] Create one claim-owned child stack or another explicitly isolated state
      boundary; never place application claims in the bootstrap stack.
- [ ] Bind Pulumi operations to tenant, context, claim generation, capability,
      desired-state digest, deadline, and audit trace.
- [ ] Return only reference-safe outputs to the broker.
- [ ] First allocate a logical database from pre-provisioned capacity.
- [ ] Add dedicated Aurora/RDS creation only after logical allocation and
      cleanup are reliable.

Exit: a missing `ManagedPostgres` binding can be fulfilled safely and a paused
application deployment resumes when it becomes ready.

### G7 — Multi-cloud provider expansion

Status: wait until the AWS controller passes recovery and deletion testing

- [ ] Extract the validated AWS semantic assumptions into provider conformance
      tests.
- [ ] Implement a GCP provider component against the same resource contracts.
- [ ] Fix abstractions that accidentally encode AWS semantics.
- [ ] Add Azure only after AWS and GCP pass the same conformance suite.
- [ ] Keep provider-specific extensions explicit instead of weakening generic
      guarantees to a lowest common denominator.

Exit: the same application intent is fulfilled by at least two providers with
equivalent tenancy, identity, recovery, evidence, and deletion semantics.

## Explicitly deferred

Do not spend critical-path time on these before the Warden and Mind vertical
slices pass:

- general physical infrastructure provisioning from every application plugin;
- GCP or Azure implementation;
- a universal abstraction for every cloud resource;
- a public infrastructure-provider marketplace;
- automatic AWS account vending per application or tenant;
- dedicated VPC or cluster per SaaS customer;
- arbitrary third-party application onboarding;
- automatic multi-region failover;
- Codefly self-management of its seed IAM, state backend, audit root, or
  break-glass path; and
- migration of bootstrap-owned physical resources into PaaS-owned stacks.

## Immediate work queue

Work in this order:

1. Decide the AWS landing-zone owner and Pulumi backend/organization, then
   bootstrap the lean AWS account/OU structure.
2. Bring up dev platform/execution first; create governed empty prod accounts,
   but do not deploy production workloads yet.
3. Finish real AWS previews, workload identity/network materialization, and dev
   sandbox verification.
4. Bootstrap the Codefly system realm, first organization, and modular
   dev/prod/preprod environment records through protected IaC/GitOps.
5. Implement application plan/deploy/watch/cancel/rollback against existing
   bindings.
6. Complete the PostgreSQL logical binding and migration lifecycle.
7. Deploy Warden, then Mind, add preprod if required by the release evidence,
   and only then authorize production workloads.
8. Build the Pulumi Automation API infrastructure controller.
9. Add GCP and Azure after the AWS controller passes conformance, recovery,
   drift, and deletion tests.

This ordering bootstraps Codefly safely, proves the PaaS experience early, and
preserves a clean path to high-level multi-cloud infrastructure without making
application plugins cloud-aware.
