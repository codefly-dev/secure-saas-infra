# IaC Validation-First Execution TODO

Status: active execution backlog
Last updated: 2026-07-24
Repository: `secure-saas-infra`
Immediate objective: qualify the AWS Organizations management seed before its
first real preview. Later account-foundation, network, EKS/RDS, and edge waves
remain IaC work, but are not admitted into this seed release. GitOps and other
in-cluster delivery are a separate platform backlog.

This is the active TODO for this IaC repository only. It does not authorize
testing or modifying an external application platform, CLI, server, plugin,
Mind, or Warden repository. Future platform integration remains design context
until a separate implementation plan explicitly reopens it. Every security
claim here must be enforced by the rendered infrastructure, tested on its
denial path, and represented by evidence whose inputs cannot be silently
substituted.

Related documents:

- [Cloud-neutral platform backlog](cloud-neutral-backlog.md)
- [Rootless AWS infrastructure execution roadmap](rootless-aws-codefly-execution-roadmap.md)

The platform-integration roadmaps elsewhere in `docs/` are deferred reference
material, not executable work for the current IaC scope.

## Authoritative current checkpoint — 2026-07-24

The management-seed code has reached the pre-AWS boundary, but production
qualification is not complete. The exact-tree adversarial disposition, tagged
two-architecture release, installed native signer/runtime lifecycle, and real
backend/account choices remain open below. No Codefly, Mind, Warden, CLI,
server, application-plugin, or in-cluster platform source is part of this
checkpoint. This checkpoint does not claim that the later VPC, EKS, RDS,
ingress, backup, or security waves are complete.

Completed in this local-only pass:

- [x] Replace Policy Pack source-string assertions with exact callback
      execution for secure, hostile, malformed, and bypass fixtures.
- [x] Add Pulumi stack relationship callbacks using exact property-dependency
      URNs for VPC logging, S3 companions, Network Firewall logging,
      confidential evidence IDs, private-spoke TGW defaults, and
      central-egress-only Internet/NAT gateways.
- [x] Implement a two-stage bootstrap. Credential-free qualification binds a
      clean source tree, ignored account configuration, compiled program,
      pinned tools, sealed dependencies/policy/provider runtime, five cloud-IaC
      gates, adversarial review, SBOM, and release evidence into a
      detached-signature candidate. Preview/apply require that candidate and
      distinct exact management roles. In-cluster evidence is excluded by the
      boundary in `docs/iac-platform-boundary.md`.
- [x] Remove all implicit onboarding/build/config mutation from the
      credentialed phase. Preview/apply are admitted only through the non-Node
      environment guard and apply only reviewed saved Pulumi plans.
- [x] Make adversarial review process evidence a strict, seven-day contract
      bound to the exact Git revision, file bytes, and modes, with exact
      architecture, security, and validation routing labels. The labels and
      self-authored timestamp are not cryptographic reviewer authentication;
      the independent Ed25519 candidate signature remains the authorization
      boundary.
- [x] Render a deterministic, content-addressed, schema-checked CloudFormation
      handoff for the fixed management preview/apply roles. Each role trusts a
      different exact same-account federated principal and carries its checked
      policy both inline and as a maximum-permissions boundary.
- [x] Remove the mutable-checkout stage-zero root seam. A separately isolated
      release job now packages the minimal launcher/runtime-installer kit
      without npm dependencies or Pulumi and gives that kit its own SLSA
      provenance. The host consumes only a root-owned copy verified against the
      exact repository, tag, reviewed commit, and extracted checksums.
- [x] Replace opaque signer input hashes with one confidential, strict review
      bundle containing the exact ignored configuration and all
      non-reproducible candidate evidence. The independent verifier recomputes
      source, build, launcher, evidence, SBOM, access template, complete runtime
      closure, and root-owned provenance before a signing decision.
- [x] Remove `/usr/bin` and `/bin` from the credentialed process `PATH`; only
      candidate-bound runtime directories remain. Implement layered execution
      confinement: a root-managed one-shot systemd service applies
      `NoExecPaths=/` with exact candidate/native `ExecPaths`, denies namespace
      and mount/memfd creation, and then the unprivileged launcher installs an inner
      Landlock `EXECUTE | READ_FILE` policy over the hashed ELF closure.
      Writable home/output paths remain no-exec. Real installed-unit and
      explicit-loader acceptance on native hosts remains pending below.
- [x] Replace inherited raw AWS/Pulumi secrets with strict anonymous-pipe
      envelopes and a native authenticated loopback credential broker. Enforce
      Yama ptrace isolation before credential handling and keep raw secrets out
      of Node's initial environment.
- [x] Authenticate the independent signer's complete clean checkout with a
      host-kit-bound source manifest before npm, package scripts, dependencies,
      or repository JavaScript execute.
- [x] Split signer execution into an online preparation service that has no
      bundle/configuration and a second root-managed, read-only,
      private-network review service. A root-held transaction lock serializes
      both phases. The preparation cgroup is collected, the dedicated locked
      non-login signer UID must have no remaining process, the reconstructed
      checkout is exactly inventoried and changed to root-owned/read-only, and
      only then does the root parent copy the root-only bundle into a fully
      sealed anonymous memfd for the review phase.
- [x] Configure native Linux `amd64` and `arm64` host-kit builds, SLSA subjects,
      inner Landlock denial tests, and checksum-bound provider-download smoke
      jobs. No tag has executed those release jobs yet. The full installed
      systemd-plus-Landlock lifecycle remains a native-host gate.
- [x] Enforce the JavaScript/TypeScript source import closure against the
      positive management-seed inventory. Relative imports, fixed execution
      imports, and declared generated outputs must resolve exactly; ungoverned,
      ambiguous, escaping, or non-literal dynamic loads fail qualification.
- [x] Collapse offline doctor, runtime, and Pulumi topology validation onto one
      exact greenfield management-seed model: seven ordered OUs, ten account
      definitions with staging disabled only as a pair, eight active accounts,
      three parent guardrail targets, six standalone trusted-service owners,
      RAM as its own owner, and only `SERVICE_CONTROL_POLICY` plus native
      `S3_POLICY`. Existing-organization mode now fails closed.
- [x] Replace self-derived IAM validation with fixed preview/apply action
      inventories and hostile injected-action tests. Permit only the
      `organizations:MoveAccount` operation required to place newly vended
      accounts into their reviewed OUs; retain explicit destruction and
      post-seed-maintenance denies. Bound account creation to three lanes.
- [x] Replace whole-checkout sealing with a positive execution inventory.
      Require zero qualification-UID processes; prune Git, test/support output,
      every non-seed tracked file, unsigned payloads, and confidential signing
      material; reject special/extra/escaping/oversized trees; copy onto fresh
      `root:deus-runtime` 0440/0550 inodes; and clean failed staging roots.
- [x] Consume and unlink both copies of the confidential signing bundle, add a
      post-review signer-process check, remove Unix sockets from the credential
      runtime, and fail closed on string-only or malformed dependency-audit
      findings and metadata count drift.
- [x] Add native host-kit archive preflight before root extraction. The exact
      member/type/mode/owner/time/size/checksum/release inventory rejects
      traversal, duplicates, links, special files, and trailing compressed
      content. Add `go vet` to G0.
- [x] Split ordinary source CI from the evidence-only promotion workflow.
      Source PRs run the full source/test/audit/SBOM gate without pretending a
      disposition already approves their head; a separate non-merge child that
      changes only the disposition may become taggable after rerunning
      `validate:source`, but its evidence remains explicitly unqualified. Only
      the sealed fixed-root Linux qualifier may later run `verify:all` and emit
      production local-gate evidence.
- [x] Replace the impossible pre-Organization Identity Center assumption with
      one exact same-account `DeusBootstrap` SAML provider and four distinct
      `/deus/bootstrap-source/` roles. Target-role trust, source-role trust,
      and source policies are exact and live-attested; initial federation is
      explicitly an external first-authority prerequisite.
- [x] Split the management seed into `organization-only` and `full` candidate
      waves. The full wave is blocked until Service Quotas in `us-east-1`
      admits exactly nine accounts and live Organizations state has no foreign
      member, open invitation, or concurrent account creation.
- [x] Make `full` preview-only and reject `full` apply before any AWS
      observation until a separately qualified member-access wave can
      immediately retire every `DeusOrganizationBootstrap` role.
- [x] Bind the complete prepared Pulumi backend configuration to the exact
      signed ignored management configuration; alternate keys or values fail
      before provider execution.
- [x] Bind capacity/state evidence to the candidate, management account, and
      configuration, freeze it into the saved-plan manifest, and repeat it
      immediately before and after Pulumi, including failure paths.
- [x] Add an independent Organizations state transition observer. It requires
      `AWSOrganizationsNotInUseException` before the first preview/apply,
      proves the exact Organization/root/policy-type/management-only baseline
      after Organization creation, and rejects foreign OUs, policies,
      attachments, service access, delegated administrators, account work, or
      invitations before the full preview.
- [x] Require exact live retirement of the JIT provisioner: SAML-only trust,
      zero policies, three retirement tags, and one sole-version deny-all
      permissions boundary. Upstream IdP deactivation remains external.
- [x] Replace the impossible same-session self-retirement sequence with a
      fourth independently governed SAML retirement role, an exact capped
      policy, a governed boundary -> sole-policy-delete -> retired-tag
      operation, exact monotonic resume states, a live read-back, and a
      content-addressed retirement receipt.
- [x] Add bounded Organizations post-apply convergence retries and a separate
      read-only recovery mode bound to the same signed candidate, frozen plan
      manifest, exact plan bytes, reviewed standalone state, source revision,
      preview caller, and exact converged baseline. Recovery invokes neither
      Pulumi nor any AWS mutating operation.
- [x] Replace logical-name-only graph checking with exact resource type,
      critical property, tag, dependency, and property-dependency checks plus
      exact input-key inventories and hostile type/property/extra-input/graph
      substitutions, including the admitted one-resource wave.
- [x] Narrow the AWS apply role and its boundary to Organization creation,
      exact policy-type enablement, exact service-linked-role creation, and
      reads. Future accounts/OUs/policies/service-access/RAM authority requires
      a new role and qualification.
- [x] Restrict the qualified access contract to commercial AWS; GovCloud and
      China require separately qualified partition variants.
- [x] Bind every generated execution path to a signed path/type/size/mode/hash
      inventory, admit the real pinned provider size under bounded 2 GiB/8 GiB
      limits, copy into fresh root-owned inodes, and completely revalidate the
      copy before publication.
- [x] Replace the signer's in-place ownership freeze with a bounded fresh-inode
      snapshot and post-copy byte/type/target validation, so old writable file
      descriptors cannot mutate the review tree.
- [x] Harden release provenance: exact tag checkout, live pre/post publication
      tag peeling, protected-main reachability, deterministic tar/gzip
      container metadata (the timestamped evidence payload is not claimed
      byte-reproducible), immutable-release post-publication enforcement,
      provider version probe, native verification of each produced host kit,
      real `codefly-dev/platform-security` CODEOWNERS target, and protected-base
      binding for the evidence-only child.
- [x] Add exact `node --check` and `sh -n` syntax inventories with hostile
      parser tests. No governed JavaScript or executable shell source can avoid
      a syntax parser in G0.
- [x] Revalidate the ordinary-checkout source gate after the July 24 dependency
      advisory refresh. Upgrade transitive `fast-uri` to patched `3.1.4`, keep
      zero dependency exceptions, and make repeated native-launcher builds
      replace only their exact direct regular-file artifact without an
      interactive overwrite prompt.
- [x] Make the offline doctor report the complete pre-AWS release boundary:
      independent Ed25519 trust, exact clean worktree, resolved authenticated
      review dispositions, and native Linux qualification capability. Missing
      fixture-only release files remain warnings, while present invalid or
      unconfigured trust/review state fails closed.
- [ ] Re-record all three dispositions only after exact-tree re-review. The
      checked-in dispositions remain deliberately unresolved;
      `approvedForAwsMutation` always remains `false`.

Local validation that can run on the dirty implementation worktree:

- [x] TypeScript typecheck and policy build pass.
- [x] Seventeen strict management-seed evidence schemas compile. Platform and
      post-seed contracts are explicitly quarantined from this qualification.
- [x] All 96 positively inventoried management-seed unit/hostile tests pass.
      Quarantined post-seed and platform tests are not compiled or executed.
- [x] Native Go unit tests pass on Darwin; the Linux fresh-snapshot, exact-seal,
      host-kit, and budget subsets pass in a local glibc container. Full
      Landlock execution correctly fails in the local VM/container because its
      kernel does not expose Landlock; native Ubuntu systemd/Landlock evidence
      remains an external host gate.
- [x] Dependency audit reports zero advisories and zero exceptions; the SPDX
      2.3 management-seed SBOM contains all 219 package-lock paths with exact
      multiplicity, stable path-derived IDs, and a verified dependency
      relationship graph.
- [x] Docker, K3s, Kubernetes, Helm, Argo CD, Codefly, Mind, and Warden are not
      invoked by management-seed qualification.

Local operator steps still required before AWS:

- [x] Install Pulumi CLI `3.253.0` through the existing `mise` tool manager and
      verify its signed/checksummed distribution. Shells without the `mise`
      activation hook must prefix bootstrap commands with `mise exec --`.
- [x] Freeze first-bootstrap tool authentication at host-kit-authenticated exact
      digest pins for Go/Node/Pulumi and AWS-team PGP verification for AWS CLI.
      Node release-key and Pulumi Sigstore-bundle verification remain explicit
      post-bootstrap supply-chain hardening; this release makes no stronger
      claim.
- [x] Keep the first bootstrap as a manual reviewed-release signing ceremony.
      Before unattended or multi-operator signing, move confidential bundle
      parsing into an independently versioned signer trust domain that is not
      candidate release code. Candidate verifier output is confidential and
      can never authorize signature issuance by exit status alone.
- [ ] Provision the independent Ed25519 bootstrap qualification key on a
      different identity/host or non-exportable signing service and commit only
      `security/bootstrap-qualification-trust.json`.
- [ ] Obtain final architecture, security, and validation GO dispositions for
      the exact source tree; each disposition remains non-authorizing for AWS
      mutation and expires after seven days. The JSON records read-only process
      labels, not authenticated reviewer identity; retain externally
      authenticated repository approvals or signed attestations separately.
- [ ] Review and commit this worktree, including the public trust root. The
      clean-source gate intentionally cannot issue qualification evidence for
      uncommitted code.
- [ ] Create the exact reviewed release tag. Let the native `amd64` and `arm64`
      release jobs build both separately provenanced host kits; do not build a
      privileged kit from a mutable local checkout.
- [ ] Copy the architecture-matched host kit into a root-owned staging
      directory and verify its SLSA repository/tag/revision identity plus
      native exact-archive preflight before any root extraction, then verify
      extracted checksums before any kit file runs with `sudo`. Use only that
      authenticated kit to install the pinned root-owned runtime and native
      launcher.
- [ ] On an independent fixed-path Linux signer builder, reproduce the exact
      source, build, launcher, Node/Pulumi/AWS CLI/provider/dependency closure,
      install the digest-bound signer sudo policy, run the native two-phase
      `signing-review-service` against the root-created sealed anonymous memfd,
      complete
      human account/email/role/backend review, and return only the detached
      signature. Native acceptance must prove the online phase cannot read the
      bundle, its detached descendants are gone before review, and the review
      phase has a read-only checkout and private network.
- [x] Select the Pulumi organization/backend and recovery procedure.
      Pulumi Cloud organization `toussaint-antoine-gmail-com`, project
      `secure-saas-infra`, and the empty `management` stack are initialized and
      bound by `security/pulumi-cloud-backend.json` plus
      `docs/pulumi-cloud-recovery.md`. Self-managed backends remain blocked
      until backend selection and authentication are candidate-bound.
- [ ] Run seed onboarding with the real management account ID, globally unique
      account emails, fixed distinct empty pre-bounded management preview/apply
      target roles, their two immutable managed boundaries, the two exact
      preview/apply SAML source roles, the distinct JIT SAML provisioner, the
      fixed independently governed retirement SAML role and deny-all boundary,
      `saml-provider/DeusBootstrap`, its exact metadata SHA-256, and exact empty
      provider tags. For a truly new account, execute the documented
      two-person, console-only root ceremony with multiple hardware MFA devices,
      no root access key/API/CLI use, exact reviewed inventory, immediate
      federation verification and sign-out, and retained audit evidence.
      Member account IDs do not exist until the real full seed update returns
      them.
- [ ] Render and review the access bundle locally; in the real management
      account, use the signed-candidate-bound provisioner launcher to prepare
      and inspect a capability-free, RolePolicy-only CloudFormation change set
      for its exact two retained inline role policies, then separately confirm
      execution. Change-set
      preparation is the first AWS control-plane mutation; execution is the
      first IAM mutation. Neither is performed by local qualification.
- [ ] End the provisioner session, assume only the exact independent retirement
      role, and run the governed retirement mode against the executed receipt.
      It attaches the pre-created deny-all boundary, deletes the sole exact
      active grant, sets exact retired tags, and live-verifies each monotonic
      prefix in that order.
      Then deactivate the provisioner at the upstream IdP and retain both the
      machine receipt and external evidence.
- [ ] Initialize and configure the management backend stack without AWS
      credentials, run credential-free qualification with its isolated-home
      launcher, transfer the payload to the independent signer, and finalize
      only the returned detached signature.
- [ ] Run the complete credential-free Linux lifecycle—authenticated kit
      install, prepare, qualify, finalize, seal, and native no-op/help
      execution—and retain the root-ownership/inode/runtime evidence.
- [ ] On both native architectures, execute the real provider smoke jobs and
      retain the installed `resource-aws@7.27.0` archive/extraction evidence.
- [ ] On dedicated native `amd64` and `arm64` Linux hosts with unified cgroup v2,
      run the real root-managed transient service. Prove the locked non-login
      `deus-runtime` UID has no supplementary groups or peers; inherited stdin
      remains an anonymous pipe; all systemd sandbox properties are accepted;
      writable home/output ELFs, direct absolute execution, explicit-loader
      execution, namespace/mount/memfd escape, Git/npm/shell/downloaders, and
      cross-broker tokens are denied; and the exact Pulumi `3.253.0`
      language-host, policy-analyzer, AWS CLI, and provider process tree works.
      Collect observation only from a root-owned domain that `deus-runtime`
      cannot mutate. Diagnostic evidence does not authorize AWS mutation.
- [ ] Validate both generated sudoers policies with native `visudo`; prove
      modern sudo preserves the runtime credential pipe under the scoped
      `!use_pty` default; prove the root-frozen content-addressed plan-review
      export is readable by operators while the mutable runtime plan directory
      is not, and prove the root runtime service rejects apply unless that
      complete frozen export revalidates.
- [ ] Replace production Git revision placeholders with reviewed signed commit
      SHAs. Generated database handoff directories remain empty until provider
      outputs exist; do not treat them as ready.

The next operation that needs real AWS is the separately audited initial
management-account SAML federation if it does not already exist. The first
repository-governed mutation then provisions the two bounded target roles from
the reviewed access template. After that one-time IAM mutation, the next AWS
operation is a read-only, policy-checked `organization-only` preview using
`--phases seed`; its reviewed apply creates only the Organization. A newly
qualified `full` candidate performs only a live capacity/drift-bound preview;
full apply remains machine-blocked until scoped member access and immediate
account-vending-role retirement are qualified. Every later wave is
machine-blocked before cloud access until seed
outputs and scoped provider bindings exist.
Before that preview, run the strict doctor and confirm
`aws sts get-caller-identity`. The preview saves plans and a digest; it does not
authorize apply. AWS apply and all EKS Auto Mode, Access Entry, Pod Identity,
Pod security-group, ApplicationNetworkPolicy, RDS IAM Proxy/TLS,
backup/restore, CloudTrail, and Access Analyzer claims remain explicitly
untested until the real environment.

## Historical checkpoint — 2026-07-18 (superseded)

This section supersedes older snapshots and task counts later in this living
document. Exact counts are refreshed after the final local gate run.

Completed in the current IaC-only slice:

- [x] ManagedPostgres materialization rejects MySQL, wrong PostgreSQL
      major/version/port, missing end-to-end IAM Proxy, missing regional
      recovery target, insufficient retention, and unsupported extensions
      before creating Pulumi resources.
- [x] AWS database recovery intent names the implemented mechanism truthfully:
      `regionalRecoveryCopy` via cross-region AWS Backup, not an Aurora regional
      read replica.
- [x] Runtime and migration use exact Proxy-user `rds-db:connect` policies,
      separate SG-to-SG paths, separate restricted namespaces, cluster-bound
      Pod Identity trust, and persistent exact Pod Identity associations.
- [x] Secrets Manager uses a dedicated endpoint security group with only the
      exact bootstrap SG ingress/egress path; no VPC-CIDR shortcut remains.
- [x] RDS Proxy requires TLS and end-to-end IAM, has source-account/source-ARN
      confused-deputy conditions, and depends on its exact role policy.
- [x] The access binding digest covers effective trust/permission JSON,
      association state, network, namespace, ServiceAccount, admission,
      `ApplicationNetworkPolicy`, Auto Mode NodeClass/NodePool, and scheduling.
- [x] Application, infrastructure-controller, and bootstrap projections are
      separate. Cluster-scoped manifests are not application-facing.
- [x] `PostgresAccessProfile v1alpha1` is a checked credential-free contract
      with strict Schema/parser differential tests and complete AWS IAM
      connection metadata.
- [x] Runtime, migration, and bootstrap handoffs emit separate restricted
      namespaces plus fail-closed Kyverno identity/scheduling binding.
- [x] Bootstrap has an exact role/policy/network plan but no standing Pod
      Identity association; activation is explicitly just-in-time and blocked
      pending an authorized controller operation.
- [x] All bindings remain pending until the cluster bundle, exclusive deployer
      authority, and PostgreSQL bootstrap evidence are observed. Rendered YAML
      is never treated as readiness.
- [x] Local K3s evidence explicitly proves token/admission behavior only and
      explicitly excludes EKS Auto Mode, Pod Identity runtime, Pod security
      groups, AWS network policy, STS, and RDS Proxy.

Latest local results for this worktree:

- 95/95 management-seed unit and hostile tests pass.
- 17 strict published schemas compile; the governed checked contracts pass both
  schema and semantic validation.
- Management qualification invokes no Codefly, Docker, Helm, kubectl, K3s,
  Kubernetes, Argo CD, or GitOps validation.
- Dependency audit reports zero advisories and zero exceptions. The SPDX 2.3
  SBOM contains 219 packages and 405 relationships.
- Darwin/arm64 local validation passes Go vet and native launcher tests, but it
  is validation-only. Production qualification still requires the sealed fixed
  execution root on native Linux/amd64 or Linux/arm64.
- No AWS call or AWS mutation has been performed. Source-release evidence may
  be produced in ordinary CI, but it is explicitly unqualified and contains no
  local-gate artifact.

Completed in the current database-access hardening pass:

- [x] Split application runtime outputs from migration/deploy-control outputs.
- [x] Make `PostgresAccessProfile v1alpha1` immutable at
      `pending-infrastructure`, content-address its exact specification, and
      reject forged readiness, database-name/user, and workload-bundle
      substitutions.
- [x] Publish a checked, content-addressed
      `AwsDatabaseInfrastructureHandoff v1alpha1`; recursively reject credential
      material and bind every opaque provider manifest bundle by digest.
- [x] Add cluster-wide database NodePool reservation, controller-owner shape,
      allowed workload-kind policy, and `snatPolicy: Disabled`; keep real EKS
      routing/admission proof explicitly pending.
- [x] Add signed, expiring, revocable, replay-protected
      `PostgresAccessObservationEvidence v1alpha1`. It binds the profile,
      handoff, every resource observation, deployment authority, evidence
      lineage, and PostgreSQL bootstrap proof, then produces a separate ready
      decision without mutating the pending profile.
- [x] Split relational provisioning from the object-storage `data` lane into a
      dedicated rootless `database` lane. RDS creates require exact ownership
      request tags; later mutations require existing ownership tags and exact
      account/region scope. The lane retains prefixed-role `iam:PassRole` and
      `iam:PassedToService` constraints.
- [x] Bind every database-created IAM role to a deterministic
      `${resourceNamePrefix}-database-*` name and a separately provisioned
      delegated-role permissions boundary. The human apply boundary stays
      mutation-only; the delegated ceiling contains only RDS monitoring logs,
      `rds-db:connect`, exact RDS-managed secret reads, and Secrets
      Manager-mediated KMS decrypt. Exact inline policies reduce that ceiling
      per role.
- [x] Remove Kubernetes/GitOps validation from AWS bootstrap qualification.
      Temporary extraction-only checks are explicitly named
      `platform:validate:gitops` and `platform:validate:k3s`.
- [x] Join authenticated CloudContext placement and PostgreSQL observation
      decisions into one runtime deployment admission decision. The join
      requires exact selected-binding coverage, runtime-only access, unchanged
      in-process verifier results, current TTLs, and a digest binding both
      decisions; serialized, forged, missing, extra, and expired decisions fail.
- [x] Use one recursive credential-free JSON guard for the PostgreSQL profile,
      infrastructure handoff, and observation envelope. It normalizes hostile
      key spelling, rejects Kubernetes Secrets, control/non-ASCII values, PEM,
      AWS access keys, JWT, DSN/userinfo, Bearer/Basic, GitHub token, and
      base64/base64url-encoded credential canaries while preserving the exact
      intentional `credentials: null` sentinel.

Remaining local work before AWS:

- [ ] `AUTH-DB-001`: bind the real infrastructure/deployment controller
      ServiceAccount and exact Git source/path to each database namespace;
      allow only `Deployment` for runtime and `Job` for migration/bootstrap,
      deny direct Pods and binding/scheduler/NodePool/NodeClass mutation, and
      prove the RBAC/admission denial matrix. The current owner-reference rule
      validates shape only; it does not authenticate the creating actor. The
      handoff records this as `pending-identity-binding`.
- [ ] `GIT-DB-001`: implement the controller-owned application path that may
      apply the dynamic Namespace, ClusterPolicy, `ApplicationNetworkPolicy`,
      NodeClass, and NodePool bundle. Existing tenant delivery projects must
      not receive these cluster-scoped permissions.
- [ ] `PG-V2-001`: design a backward-compatible ManagedPostgres v1alpha2 that
      separates `applicationId` from platform tenant/end-customer tenant,
      separates generic service ownership from Codefly topology/version, and
      expresses service-level read-only/read-write entitlements. Do not silently
      change the frozen v1alpha1 wire contract.
- [x] `EVD-DB-001`: define signed observed-state evidence with exact digest
      equality, lineage, expiry, revocation, replay protection, deployment
      authority, and bootstrap proof. Real evidence issuance remains an AWS-dev
      runtime task; local fixtures are not observations.
- [ ] Refresh all documentation, run the three adversarial resolution reviews,
      and execute the complete local validation/audit/SBOM/evidence gate.

First honest AWS boundary after those local items:

- [ ] Policy-checked Pulumi preview under the exact expected account and
      short-lived read-only management preview role. Preview still requires an
      explicit operator warning and real AWS configuration; apply uses a
      distinct seed-create role.
- [ ] Reviewed dev apply, then observed EKS NodeClass/NodePool/network-policy,
      Pod ENI/SG, Pod Identity/STS, IAM RDS Proxy/TLS, denial, CloudTrail, backup,
      restore, and cleanup probes.

No Codefly source, tests, processes, or agents are used by this execution loop.
No AWS call or mutation has been made.

## Decisions frozen by this backlog

1. The active published contract registry contains IaC-owned contracts only.
   Application-platform contracts are not compiled, rendered, or tested here.
2. This repository owns the generic public infrastructure-controller protocol
   and the normalized internal authorization request. A future platform host
   may consume them, but it does not define their cloud-provider behavior.
3. Public infrastructure requests carry ordinary typed intent and a reference
   to transport-bound authorization context. Callers cannot supply grants,
   verification verdicts, policy results, provider credentials, or backend
   access.
4. A URI is not proof. `ready` must eventually require content-addressed,
   subject-bound, generation-bound, expiring, authenticated evidence.
5. A schema or plan claiming `pass: true` is not sufficient evidence. The
   release gate must bind raw verifier outputs, verifier identity, exact inputs,
   and immutable digests.
6. Application-facing consumers never receive AWS, Pulumi, Kubernetes
   administrator, or authorization-signing credentials.
7. Physical resource lifecycle has one canonical desired claim and one
   observed provider state; provider outputs are reference-only.
8. Application identity, platform tenant, resource owner, and end-customer RLS
   tenant are different concepts and must never be substituted for one another.
9. Local emulation and Moto can test API shapes and failures, but they cannot
   prove EKS workload identity, Pod security groups, RDS IAM/Proxy behavior, or
   AWS network enforcement.
10. No real AWS mutation occurs without a saved, reviewed Pulumi plan, the
    expected account identity, short-lived authority, and an explicit warning
    to the operator immediately before apply.

## Scope boundary

### IaC work that can proceed now

- Execute and differentially test the schemas and parsers already owned here.
- Freeze and harden the infrastructure-controller and resource-provider seams.
- Maintain stable protocol reason codes, negotiation, deprecation, monotonic
  events, and signed resumable watch cursors.
- Define typed reference resolution and authenticated infrastructure
  observation envelopes.
- Make deployment admission evaluate only the selected dependency closure.
- Attach exact Kubernetes identities to exact cloud roles and network paths.
- Harden Argo CD bootstrap, AppProjects, admission, workload profiles,
  observability infrastructure, and disposable-cluster verification.
- Build rootless AWS bootstrap/preview/apply gates.

### Deferred external-platform integration

- CLI/server/plugin RPC implementation and persistence.
- Application deployment, product rendering, and application-plugin tests.
- Agent-facing database or observability tools.
- Public application release/delivery contracts.
- Cross-repository compatibility or live process qualification.

The unblock condition is an explicit, reviewed integration plan with ownership,
versioning, transport identity, compatibility, downgrade, and repository-local
test responsibilities. Until then this repository performs no such testing.

## Status and severity

Task status:

- `DONE`: implementation, denial tests, documentation, and required evidence
  are present and the listed gate passes.
- `IN PROGRESS`: implementation has started but at least one acceptance
  criterion remains.
- `READY`: prerequisites are present.
- `BLOCKED`: a named external or prior task is missing.
- `LATER`: deliberately outside the next executable sequence.

Severity:

- `P0`: can expose credentials, cross a tenant boundary, authorize an invalid
  deployment, or make release evidence untrustworthy.
- `P1`: blocks reliable local/cluster qualification or creates material drift.
- `P2`: improves operability, performance, or maintainability after the trust
  boundary is sound.

No P0 may be waived with documentation alone.

## Definition of done

A task may move to `DONE` only when all applicable items are true:

- The owner and trust boundary are documented.
- The contract is closed by default and versioned.
- Positive, boundary, and denial tests exist.
- Negative tests assert an exact stable reason or policy/rule, not merely any
  failure.
- The denial path proves zero side effects where mutation is possible.
- Unknown fields, unsupported versions, stale generations, and substituted
  identities/digests fail closed.
- Secrets are absent from plans, rendered files, logs, traces, errors, and
  evidence.
- Output is deterministic under a fixed `SOURCE_DATE_EPOCH` where time is not
  the subject under test.
- Relevant real dependencies/controllers are exercised rather than mocked.
- Machine-readable evidence records source revision, input digests, tool
  versions, outcomes, and diagnostics.
- The adversarial review protocol below has no unresolved blocker.

## Verification ladder

Every task names its highest required level. All lower applicable levels remain
mandatory.

| Level | Gate                      | Required proof                                                                                            | AWS                   |
| ----- | ------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------- |
| G0    | Test-system credibility   | Reproducible install, format check, strict schema compilation, machine-readable results, dependency audit | No                    |
| G1    | Contract/model            | Parser/schema differential corpus, properties, mutations, deterministic digest, stable denial codes       | No                    |
| G2    | Render/admission static   | Golden render, server-side schema validation, credential/wildcard/token/image/field-ownership scans       | No                    |
| G3    | Deferred external process | Real producer/consumer process, cancellation/restart/replay, no copied expected fixture                   | No                    |
| G4    | Real local dependencies   | Local Postgres/collector/Git, RLS/roles, connection reuse, limits, failure injection                      | No                    |
| G5    | Disposable cluster        | Real resources/controllers, runtime RBAC/network/admission/reconciliation/rollback, guaranteed teardown   | No                    |
| G6    | AWS dev preview           | Correct account/role, policy-checked preview, Access Analyzer, saved immutable plan digest                | Read-only preview     |
| G7    | AWS dev apply             | Exact reviewed plan, EKS/RDS/IAM/network runtime probes, restore and recovery evidence                    | Reviewed dev mutation |
| G8    | Promotion candidate       | Clean pinned repositories and exact signed candidate promoted without rebuild/re-render                   | Explicit approval     |

Rules:

- Every pull request runs G0-G1.
- Contract, policy, renderer, or security-manifest changes also run G2.
- Cross-repository capability changes run G3.
- Postgres and observability runtime changes run G4.
- Kubernetes, GitOps, admission, and rollout changes run G5.
- G6 begins only after all applicable G0-G5 gates pass.
- G7 never rebuilds or re-renders the G6 candidate.
- Moto is supplemental at G1/G2 and never substitutes for G7.

## Adversarial review protocol

Every milestone that changes a trust boundary requires three independent
reviews:

1. **Architecture critic:** attacks ownership, versioning, lifecycle,
   compatibility, duplicated truth, and failure containment.
2. **Security critic:** attacks identity substitution, credential exposure,
   confused-deputy paths, tenant crossing, admission bypass, network escape,
   evidence forgery, and supply chain.
3. **Validation critic:** attacks mocks, false-positive tests, missing negative
   cases, optional CI gates, nondeterminism, flaky cleanup, and unproven runtime
   claims.

Review rules:

- Critics receive the intended invariant and exact changed paths, but not a
  request to approve the design.
- Findings are ranked `blocker`, `high`, `medium`, or `low` and include an
  executable denial test.
- The author may resolve a blocker only with code plus a reproducing regression
  test, or by removing the unsupported claim/feature.
- A second critic verifies the blocker resolution.
- Unresolved blockers are recorded in release evidence and make promotion
  fail; they are not converted into warnings.

## Immediate execution queue

| Order | ID       | Task                                                               | Severity | Gate | Status            |
| ----: | -------- | ------------------------------------------------------------------ | -------- | ---- | ----------------- |
|     1 | CTRL-001 | Publish the generic infrastructure-controller protocol             | P0       | G1   | DONE              |
|     2 | BOOT-001 | Keep rootless AWS bootstrap generic and human-rooted               | P0       | G1   | DONE              |
|     3 | VAL-001  | Execute every published JSON Schema and checked contract           | P0       | G0   | IN PROGRESS       |
|     4 | VAL-003  | Make validation outputs and strict gates mandatory in CI/evidence  | P0       | G2   | IN PROGRESS       |
|     5 | SEC-001  | Disable application Kubernetes API token automount                 | P0       | G2   | MOVED TO PLATFORM |
|     6 | VAL-002  | Add parser/schema differential and generated mutation corpus       | P0       | G1   | IN PROGRESS       |
|     7 | REF-001  | Add typed reference registry and digest-bound resolution           | P0       | G1   | IN PROGRESS       |
|     8 | EVD-001  | Add authenticated dependency observation envelope                  | P0       | G1   | IN PROGRESS       |
|     9 | ID-001   | Bind exact Kubernetes subject to exact cloud role/network boundary | P0       | G5   | MOVED TO PLATFORM |
|    10 | GIT-001  | Replace Argo `default` project with least-privilege AppProjects    | P0       | G5   | MOVED TO PLATFORM |
|    11 | K8S-001  | Build hardened neutral data-tool workload profile                  | P0       | G5   | MOVED TO PLATFORM |
|    12 | CLU-001  | Upgrade disposable cluster from dry-run to runtime proof           | P0       | G5   | MOVED TO PLATFORM |
|    13 | AWS-001  | Qualify rootless AWS dev preview                                   | P0       | AWS  | BLOCKED by setup  |

Historical local verification snapshot (2026-07-16; superseded by the
authoritative 2026-07-18 checkpoint above):

- `npm run verify:all` passes all 235 tests plus TypeScript, policy build,
  contract/schema, GitOps, dependency, SBOM, and release-evidence gates.
- The active registry contains four checked contracts and nine strict schemas.
- The SPDX 2.3 SBOM contains 235 packages; the dependency gate reports no high
  or critical findings and one reviewed moderate underlying advisory.
- Release evidence hashes 304 build inputs and explicitly records
  `externalApplicationRuntimeTested: false` and `awsMutationPerformed: false`.
- The worktree is intentionally dirty during implementation, so the generated
  evidence is locally useful but not promotable. Promotion still requires a
  clean reviewed revision and the remaining environment gates.

## Completed current slice — generic controller and rootless AWS seam

- [x] Public operation request/response envelopes reject caller-supplied
      grants, credentials, and authorization/policy verdicts.
- [x] Version negotiation selects the server's supported preference, fails
      closed on missing versions/features, and publishes deprecation metadata.
- [x] Stable reason codes declare retry semantics.
- [x] Operation events are monotonic, terminal-aware, subject-bound, and
      SHA-256 chained.
- [x] Resumable watch cursors are HMAC-authenticated, canonical-encoding
      checked, expiring, and bound to organization, tenant, and operation.
- [x] The checked protocol fixture is generated from implementation and
      contains no provider credentials or provider-specific construction.
- [x] AWS bootstrap root/handoff/management access remains human-only; no
      account grants direct controller plan or apply authority before its
      independently verified runtime identity exists.
- [x] Build/test output is cleaned before compilation so deleted tests cannot
      remain active as stale JavaScript.
- [x] Release evidence revalidates and re-hashes the exact repository schema
      and contract inventory before binding it.

## Phase A — Test-system credibility

### VAL-001 — Execute every published JSON Schema and checked contract

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G0
- Files:
  - `scripts/validate-contract-schemas.mjs`
  - `tests/contractSchemaValidation.test.ts`
  - `artifacts/contract-schema-validation.json`

Implemented in the current slice:

- AJV Draft 2020-12 strict compilation for all 14 published IaC schemas.
- Format validation through `ajv-formats`.
- Validation of nine checked IaC contract documents against their mapped
  schemas.
- Deterministic report time under `SOURCE_DATE_EPOCH`.
- SHA-256 binding of every schema and contract in the report.
- Rejection of symlinked schema inputs.
- Negative tests for an unknown field, a credential-bearing reference, a
  missing isolation field, and a symlink substitution.
- Explicit owner/validation-mode inventory for every published schema and
  checked contract; an unowned addition fails the gate.
- Repair of strict-schema defects surfaced by the compiler.

Remaining TODO:

- [x] Verify every published schema is mapped either to a positive fixture or
      an explicit `schema-only` registry entry with an owner.
- [x] Validate the report itself against a closed evidence schema.
- [x] Add exact stable error codes in addition to AJV diagnostics.
- [x] Reject duplicate CLI flags and output paths that are symlinks.
- [x] Add the validator, schema registry, governing workflow/policy inputs, and
      report digest to release evidence.
- [x] Upload the report in CI.

Acceptance:

- A broken `$ref`, strict type error, invalid format, unknown property, or
  contract/schema version mismatch fails `npm test`.
- An unmapped new contract/schema fails until explicitly registered.
- The same fixed inputs under `SOURCE_DATE_EPOCH=0` produce byte-identical
  evidence.

### VAL-002 — Parser/schema differential and mutation corpus

- Status: `IN PROGRESS`
- Severity: `P0`
- Depends on: VAL-001
- Required gate: G1

TODO:

Implemented in the current slice:

- The frozen `CloudContext v1alpha1` fixture runs through both AJV and the
  handwritten parser.
- The first differential corpus covers missing/future versions, unknown root
  and nested fields, missing isolation posture, unsupported provider,
  credential-bearing references, and a credential value in resource output.
- Canonical catalog digest invariance is verified under recursive object-key
  reordering.

Remaining TODO:

- [x] Create one registry containing schema ID, positive fixture, handwritten
      parser, canonicalizer, and owning module.
- [x] Feed every fixture to both AJV and the parser and require that the
      handwritten parser is never weaker than the schema; parser-only semantic
      rules are declared in the registry.
- [x] Delete every required field individually at every object depth.
- [x] Add an unknown field at every object depth.
- [ ] Mutate every `const`, enum, version, identity, generation, digest,
      reference scheme, and tenant/application/data-boundary tuple.
- [x] Generate `const`, enum, pattern/format, minimum/maximum, `minItems`, and
      `uniqueItems` schema-rejection mutations.
- [ ] Complete valid-shape semantic identity, generation, digest, reference,
      and tenant/application/data-boundary mutations for every contract.
- [x] Test schema-declared min/max values and just-outside boundaries.
- [x] Test arrays where schema uniqueness is required.
- [ ] Complete semantic duplicate-ID tests not expressible by JSON Schema.
- [x] Test credential-bearing URI userinfo, NUL, non-ASCII, JWT, PEM, AWS keys,
      DSNs, bearer/basic tokens, and encoded credential canaries across every
      PostgreSQL contract projection.
- [ ] Complete traversal, wildcard, URI query/fragment, and semantic Unicode
      confusable cases across every checked contract.
- [x] Prove canonical digest invariance under object-key reordering.
- [ ] Declare whether each array is an ordered sequence or semantic set and
      test the corresponding digest behavior.
- [ ] Add property/fuzz seeds for the identity, reference, version, and status
      decision functions.
- [ ] Require exact reason codes and zero mutation side effects on rejection.

Acceptance:

- No schema/parser disagreement survives in the corpus.
- Unknown/future/downgraded versions fail closed unless an explicit migration
  exists.
- Security decision functions reach 100% branch coverage; the contract package
  reaches at least 90% branch coverage.
- No mutation affecting tenant, authority, version, digest, or reference
  sensitivity survives.

### VAL-003 — Mandatory CI and trustworthy evidence

- Status: `IN PROGRESS`
- Severity: `P0`
- Depends on: VAL-001
- Required gate: G2 initially, G5 before AWS

TODO:

- [x] Add non-mutating `format:check` and run it before compilation.
- [x] Split fast G0/G1, render G2, cross-repository G3, dependency G4, and
      cluster G5 commands while keeping one strict aggregate command.
- [ ] Publish JUnit/JSON results with tool versions and input digests.
- [x] Make contract-schema validation mandatory in CI and upload its report.
- [x] Keep external application rendering and platform qualification outside
      this repository until an explicit integration plan assigns it.
- [x] Remove disposable-cluster and GitOps validation from cloud-IaC
      qualification; move their ownership and mandatory gates to the future
      platform repository.
- [x] Keep dirty local evidence visibly non-promotable and provide a
      `--require-clean` promotion gate.
- [x] Hash `package.json`, policy sources, the evidence generator, CI workflows,
      release workflows, schema registry, and validator in evidence.
- [x] Replace hard-coded evidence inventories/counts with declared registries
      and semantic expected sets.
- [x] Revalidate the contract report and compare every reported digest to the
      repository before release evidence accepts it.
- [x] Verify the SPDX package inventory exactly against `package-lock.json`.
- [x] Re-run the trusted disposable-cluster verifier before release evidence
      accepts a cluster report.
- [x] Add hostile local verification for source, scope, checks, denial
      metadata, input/image pins, cleanup, report digest, contract report, and
      SBOM substitution.
- [ ] Define and verify a signed `EvidenceEnvelope`; do not trust caller-supplied
      `pass: true`.
- [x] Export diagnostics and always tear down disposable resources in `finally`.

Acceptance:

- Omitting a required report makes the relevant CI/release job fail.
- Tampering a report, verifier identity, source revision, schema, policy, plan,
  image, Git commit, cluster UID, or report digest fails evidence verification.
- A failed verifier cannot use cached success as fallback.

### VAL-004 — Dependency and supply-chain hygiene

- Status: `IN PROGRESS`
- Severity: `P1`
- Required gate: G0

TODO:

- [ ] Review all `npm audit` findings; classify direct/transitive exposure and
      record any time-bound exception with owner and compensating control.
- [ ] Pin validation dependencies deliberately and prevent unrelated lockfile
      upgrades in feature changes.
- [ ] Generate an SBOM after the exact clean install used for testing.
- [ ] Verify package integrity/provenance in CI.
- [ ] Add a positive signed-image admission fixture that actually starts.
- [ ] Corrupt signature, provenance, and SBOM independently and assert the exact
      denying Kyverno rule—not registry/DNS failure.

## Phase B — Make the existing cloud-context seam truthful

### CTX-001 — Freeze `CloudContext v1alpha1`

- Status: `READY`
- Severity: `P0`
- Required gate: G1

TODO:

- [ ] Preserve the current valid fixture byte-for-byte as a compatibility
      fixture.
- [ ] Add a digest fixture and test it in both TypeScript and JSON Schema paths.
- [ ] Reject new required fields under `v1alpha1`.
- [ ] Document current semantics and known limitations: global readiness,
      aggregate identity capability, opaque references, and Postgres-only
      resource binding.
- [ ] Reserve a new API revision only after Codefly publishes its golden
      capability fixture.
- [ ] Require explicit migration and downgrade-rejection tests for the future
      revision.

Acceptance:

- Existing `v1alpha1` bytes continue to parse and hash identically.
- Future changes cannot silently reinterpret or strengthen required fields
  without a version change.

### REF-001 — Typed reference registry and resolution

- Status: `IN PROGRESS`
- Severity: `P0`
- Depends on: CTX-001
- Required gate: G1

Define an infrastructure-owned resolver registry for each permitted reference
scheme. Each entry must declare:

- owner and resolver implementation ID/version;
- accepted caller/subject;
- typed output schema and confidentiality class;
- workload-projectable versus control-plane-only result;
- provider resource UID, generation/version, and expected digest behavior;
- timeout, unavailable, stale, revoked, and not-found semantics; and
- audit/evidence requirements.

TODO:

- [x] Add a typed companion request without changing `CloudContext v1alpha1`
      bytes or required fields.
- [x] Permit only registered schemes; unknown schemes fail closed before any
      resolver is called.
- [x] Add local fake resolvers for complete deterministic tests.
- [x] Bind request and resolution to organization, tenant, application,
      component, context, dependency, purpose, confidentiality, projection,
      output type, generation, provider UID/version, and digests.
- [x] Distinguish explicitly allowed public metadata from confidential
      references; no resolver can serialize resolved values or accept provider
      credentials.
- [ ] Invalidate production readiness when the underlying value or provider generation
      changes.
- [x] Ensure the current evidence path contains workload-projectable references
      or typed public
      metadata, never Pulumi state/AWS credentials.
- [ ] Add production resolver implementations with timeout, not-found,
      unavailable, and revocation semantics; do not ship the test resolver.

Denial matrix:

- [x] Wrong scheme, owner, subject, tenant, environment, resource, field,
      generation, type, sensitivity, or digest.
- [x] Mutable resolution after observation is rejected by signed request and
      output digests.
- [ ] Credential value disguised as `dsn`, `apiKey`, `authorization`, encoded
      text, or an arbitrary benign field name.
- [ ] Resolver timeout/restart/revocation with no cached-allow fallback.

### EVD-001 — Authenticated dependency observation

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G1

The infrastructure observation envelope must bind:

- catalog and dependency ID/digest;
- organization, platform tenant, application, environment, account, region,
  and cluster UID;
- desired and observed generation;
- provider resource UID/version and resolved-output digest;
- verifier identity/version and policy/schema digests;
- issued-at, expiry, unique run/nonce, and previous evidence linkage; and
- signature/provenance reference.

TODO:

- [x] Add closed schema, strict parser, canonical digest, signer/verifier seam,
      and deterministic fixtures.
- [x] Make evidence content-addressed and require an expected digest at
      redemption.
- [x] Sign the exact canonical envelope with Ed25519 and trust an exact
      verifier ID/version/key scoped to organization, tenant, and environment.
- [x] Bind policy, resolver-registry, desired catalog, placement, dependency
      closure, typed resolution, subject, generation, expiry, nonce, and
      previous observation link.
- [x] Require an atomic replay-store redemption after every other check passes.
- [ ] Separate `planned`, `observed`, `verified`, `degraded`, and `revoked`.
- [x] Reject future-dated, expired, wrong-subject, wrong-generation,
      wrong-output, unknown-verifier, replayed, and tampered evidence.
- [ ] Integrate a production trust registry, durable multi-replica replay store,
      revocation distribution, and authenticated immutable evidence storage.
- [ ] Add explicit account, region, and cluster-UID claims when the production
      observer contract has authoritative values for them.

### CTX-002 — Selected dependency-closure admission

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G1

TODO:

- [x] Resolve one application/component placement to its exact runtime,
      identity, network, registry, DNS, resource, and observability dependencies.
- [ ] Mark each dependency `required`, `promotion-required`, or
      `optional/degraded`.
- [x] Evaluate only the selected closure, not every context/binding in the
      catalog.
- [x] Bind the admission result to placement, dependency-set digest, evidence
      digests, generation, and expiry.
- [ ] Add promotion-required and optional/degraded dependency semantics; the
      current companion contract treats the derived closure as required.
- [x] Add tests where an unused degraded dependency does not block.
- [ ] Add a test where a
      selected required degraded dependency does block.
- [x] Add substitution tests for consumer, context, capability, binding,
      generation, and evidence.
- [x] Require every selected ManagedPostgres binding to contribute an exact,
      authenticated runtime-readiness decision to the final IaC deployment
      admission join.
- [ ] Wire the companion decision into the future Codefly deployment admission
      RPC; the legacy Codefly v1 plan remains byte-compatible and global.

## Phase C — Identity, database, and network enforcement

### SEC-001 — Disable Kubernetes API credentials for application workloads

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G2

Implemented in the current slice:

- Application overlay rendering sets
  `automountServiceAccountToken: false` instead of `true`.
- A YAML-AST scanner rejects omitted, `true`, `null`, and string `"false"`
  automount values, projected ServiceAccount tokens, duplicate keys/identities,
  aliases, unknown PodSpec-shaped CRDs, and unsafe ServiceAccounts.
- The scanner covers Pod, ReplicationController, Deployment, StatefulSet,
  DaemonSet, ReplicaSet, Job, CronJob, Argo Rollout, multi-document streams,
  and nested Kubernetes Lists.
- Exact resource/issue exceptions require approver, reason, and future expiry;
  duplicate, invalid, stale, and unused exceptions fail closed.
- Every real local-agent service render is parsed and scanned. The versioned
  scan result binds the exact rendered bytes and is embedded in product-render
  and release evidence.

Remaining TODO:

- [x] Add a manifest-level scanner covering every current workload renderer.
- [x] Implement an exact, expiring reviewed exception mechanism; keep the
      production exception list empty until a controller has a proved need.
- [x] Add Kyverno denial for explicit token automount and unauthorized token
      projection outside the allowlist.
- [x] Prove denial in disposable K3s and prove fixture Pods cannot call the
      Kubernetes API at runtime.
- [ ] Prove AWS workload identity still functions through its dedicated
      projection mechanism without granting the general Kubernetes API token.

### ID-001 — Exact workload identity binding

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G5

Define an IaC-owned `WorkloadIdentityBinding` containing exact organization,
platform tenant, application, environment, cloud context/generation,
namespace, ServiceAccount, SPIFFE/OIDC subject, audience, cloud role, allowed
resource identities, network-boundary/Pod-SG reference, session duration, and
content-addressed verification evidence.

Invariants:

- One subject, one tenant, one environment, and one cloud role per binding.
- `administrator: false` and `shared: false` are mandatory.
- Cross-tenant role reuse and wildcard subjects fail.
- Placement selects one binding, never an aggregate identity allowlist.

TODO:

- [x] Add a versioned exact selectable binding companion without changing the
      frozen aggregate `CloudContext v1alpha1` bytes.
- [x] Validate OIDC subject semantics against owned namespace/ServiceAccount.
- [x] Materialize KSA -> cloud role -> resource -> Pod security-group mapping.
- [x] Add wrong namespace, ServiceAccount, SPIFFE subject, role, audience,
      tenant, environment, and resource substitution tests.
- [ ] Run runtime identity probes in a disposable cluster and AWS dev.

### PG-001 — One infrastructure Postgres truth

- Status: `BLOCKED by EVD-001`
- Severity: `P0`
- Required gate: G4 locally, G7 on AWS

TODO:

- [ ] Make one canonical `ManagedPostgres` desired resource produce one broker
      claim.
- [ ] Derive workload binding from an `available`, verified observed claim;
      stop reconstructing stack-output names in multiple adapters.
- [ ] Require exact typed outputs and observed generation/digest.
- [ ] Separate runtime, migration, schema-reader, and future Toolbox-reader
      identities, database users, and network boundaries.
- [ ] Distinguish application/resource ownership from request-scoped
      end-customer RLS tenant.
- [ ] Attach runtime and migration security groups to actual Pod ENIs/nodes via
      exact supported EKS mechanism; exported unattached SG IDs are not proof.

Codefly-owned handoff, not implementation work in this repository:

- Reconcile PostgreSQL roles, `rds_iam`, ownership, `BYPASSRLS`, inheritance,
  `SET ROLE`, RLS policies, and default privileges.
- Negotiate the installed PostgreSQL plugin capability before a binding becomes
  consumable.
- Own migration SQL, checksums, locks, ordering, execution, and release gates.

Denial matrix:

- [ ] Runtime identity attempts migration/admin/owner behavior.
- [ ] Migration IAM/Pod identity attempts runtime or bootstrap capabilities.
- [ ] Shared database user or cloud role across tenant bindings.
- [ ] Cross-tenant reads under connection-pool reuse.
- [ ] Owner, superuser, `BYPASSRLS`, `CREATEROLE`, `CREATEDB`, replication, or
      stronger `SET ROLE` on reader identities.

### PG-002 — Application migration execution

- Status: `MOVED TO CODEFLY`
- Severity: `P0`
- Required gate: Codefly application-delivery gates plus AWS G7

IaC creates only the distinct migration identity and network lane. Codefly owns
the Job/controller shape, approvals, checksums, image/source binding, replay and
deadline policy, execution, and release ordering. No SQL migration admission
policy or migration Job is rendered or tested in this repository.

## Phase D — GitOps and cluster substrate

### GIT-001 — Least-privilege Argo CD ownership

- Status: `IN PROGRESS`
- Severity: `P0`
- Required gate: G5

TODO:

- [x] Create separate bootstrap, platform-operator, security, and
      tenant-delivery AppProjects.
- [x] Restrict exact source repositories, destinations, namespaces, cluster
      kinds, namespaced kinds, and project roles.
- [x] Remove deployment authority from the `default` AppProject.
- [x] Prevent tenant delivery from managing Namespace, RBAC, CRDs, admission,
      Argo, Istio control-plane, or secret-operator resources.
- [x] Configure OIDC and explicit project RBAC; disable the local admin account
      after bootstrap.
- [x] Remove ambient global `readonly` access unless explicitly justified.
- [ ] Require immutable production commit SHA or a verified signed release tag;
      never a mutable `main` revision.
- [ ] Eliminate remaining repository/provenance placeholders from anything
      deployable. The Argo baseline repository now uses the real origin.
- [ ] Define field ownership between Codefly, Argo CD, Rollouts, and Istio.

Denial matrix:

- [x] Wrong repository, AppProject, and resource kind fail the semantic GitOps
      gate.
- [ ] Complete commit/ref, destination cluster, namespace, and managed-path
      denial cases.
- [x] Tenant attempts cluster-scoped authority and forbidden resource kinds.
- [ ] Production mutable branch.
- [ ] Field-ownership conflict and unauthorized drift/self-heal.

### K8S-001 — Hardened neutral data-tool workload profile

- Status: `BLOCKED by ID-001`
- Severity: `P0`
- Required gate: G5

This is infrastructure substrate, not yet a Codefly Toolbox public contract.

TODO:

- [ ] Use a dedicated namespace/profile and exact ServiceAccount per binding or
      an equivalently strong boundary.
- [ ] Disable Kubernetes API token automount and all secret read/list/watch.
- [ ] Apply restricted Pod Security, RuntimeDefault seccomp, non-root,
      read-only root filesystem, dropped capabilities, no privilege escalation,
      immutable digest, quotas, bounded concurrency, and deadlines.
- [ ] Apply default-deny ingress/egress with exact DNS, authorization, database,
      and audit destinations only.
- [ ] Deny Kubernetes API, IMDS, internet, other tenant/binding, migration
      endpoint, raw unmediated database, and observability mutation endpoints.
- [ ] Put principal/turn authority on each authenticated request/audit record,
      not static pod labels.
- [ ] Do not reuse the current `agent-broker`, `agent-egress`, or exempt
      `observability` namespaces as-is.

### OBS-001 — Observability infrastructure split

- Status: `READY for substrate; BLOCKED for public Codefly contract`
- Severity: `P1`
- Required gate: G5

TODO now:

- [ ] Split immutable audit, OTLP ingest, and read-only query infrastructure.
- [ ] Harden collector workloads without namespace-wide admission exemptions.
- [ ] Add default-deny networking and exact collector/query identities.
- [ ] Define TLS/auth, trusted attribute stamping, redaction, memory limits,
      retry, backpressure, sampling, rate, payload, and cardinality policies.
- [ ] Test forged tenant/environment/release attributes and secret canaries with
      a real collector.

Wait for Codefly:

- [ ] Consume the Codefly-owned telemetry sink fixture/schema.
- [ ] Consume the separately Codefly-owned observability-query contract.
- [ ] Keep SigNoz administration absent from the read-only query binding.

### CLU-001 — Disposable-cluster runtime qualification

- Status: `READY`
- Severity: `P0`
- Required gate: G5

TODO:

- [ ] Create a unique disposable cluster and Git remote per run.
- [ ] Pin controller charts/images and record provenance/digests.
- [ ] Install CRDs before server-side schema/admission validation.
- [ ] Start a correctly signed fixture workload and require Ready.
- [ ] Assert exact Kyverno policy/rule for each invalid fixture.
- [ ] Run `kubectl auth can-i` denial matrices for each ServiceAccount.
- [ ] Probe allowed and forbidden network paths from real Pods.
- [ ] Prove DNS allowance is not arbitrary egress.
- [ ] Reconcile with Argo CD and exercise forbidden repo/namespace/kind,
      drift, outage, restart, deletion, and recovery.
- [ ] Add Rollouts/Istio canary success, failure, abort, and stable recovery.
- [ ] Restart policy/controllers and rerun denials.
- [ ] Export diagnostics and delete cluster/Git/dependencies in `finally` after
      both passing and deliberately failing tests.

Do not claim Kata/microVM isolation merely because a `RuntimeClass` object was
admitted. That requires a compatible runtime host and a real executed workload.

## Deferred appendix — external platform integration

This appendix is retained only as future design context. It is not part of the
active IaC execution queue and does not authorize external repository tests or
changes.

### CFD-001 — Import, never duplicate, the Codefly capability fixture

- Status: `BLOCKED by Codefly golden fixture`
- Severity: `P0`
- Required gate: G3

TODO:

- [ ] Pin exact Codefly schema/protobuf digest and source revision.
- [ ] Test current, previous-compatible, unsupported-newer, and downgrade cases
      through Codefly and IaC parsers.
- [ ] Reject schema-digest, protocol, transport, identity, and version
      substitution.
- [ ] Add a future cloud-context revision or companion projection; preserve
      `v1alpha1` unchanged.
- [ ] Model resource owner separately from multiple exact authorized consumers.

### CFD-002 — First narrow Postgres data-tool integration

- Status: `BLOCKED by CFD-001, PG-001, K8S-001`
- Severity: `P0`
- Required gate: G4-G5

First proof:

```text
Codefly capability fixture
  -> IaC provider projection
  -> verified Postgres resource binding
  -> hardened neutral workload profile
  -> selected dependency admission
  -> real local Postgres
  -> hostile denial evidence
```

Authorization blockers owned in Codefly, not fixed here:

- [ ] Replace plugin-visible HMAC signing secret with Ed25519 public-key-only
      verification in the plugin process.
- [ ] Keep private signing material out of plugin environment, arguments,
      files, memory, logs, and sandbox-readable host paths.
- [ ] Solve maximum-use/revocation across restart and replicas using atomic
      host redemption, durable shared redemption, or unique cryptographic
      spawn/session binding.
- [ ] Race one token across two real processes and retry after restart; exactly
      one effect may occur.

IaC integration TODO after those blockers close:

- [ ] Bind exact Codefly process/session, workload identity, Postgres binding,
      policy digest, tenant context source, limits, and audit sink.
- [ ] Run cross-process replay, wrong-toolbox, wrong-resource, wrong-tenant,
      expiry, cancellation, crash, and cleanup tests.
- [ ] Prove no database credential reaches model-visible output.

### CFD-003 — Telemetry and delivery projections

- Status: `LATER; BLOCKED by successful CFD-002`
- Severity: `P1`
- Required gate: G5

Sequence:

1. Integrate the Codefly-owned telemetry sink contract.
2. Integrate the separate read-only observability query contract.
3. Integrate the Codefly-owned delivery-target/release contract.
4. Prove each independently before composing them.

Do not begin all three in parallel; the first Postgres seam must establish the
versioning, identity, evidence, and cross-repository conformance pattern.

## Phase F — AWS qualification

### AWS-001 — Rootless dev preview

- Status: `BLOCKED by real AWS/operator inputs, an independently reviewed
release, and AWS session`
- Severity: `P0`
- Required gate: G6

Prerequisites:

- [x] Install and pin Pulumi CLI compatible with the repository SDK. Local and
      CI qualification use Pulumi CLI `3.253.0` with SDK `3.253.0`.
- [x] Select Pulumi organization/backend and document state recovery. The
      selected empty Pulumi Cloud management stack and recovery contract are
      recorded in `security/pulumi-cloud-backend.json` and
      `docs/pulumi-cloud-recovery.md`.
- [ ] Supply real management/workload account IDs and globally unique account
      emails through secret-safe operator input.
- [ ] Configure short-lived, narrowly scoped bootstrap/preview roles; no root
      access keys and no standing administrator plugin credentials.
- [ ] Verify `aws sts get-caller-identity` matches the expected account/role.
- [x] Execute policy callbacks with malicious fixtures, not source-string tests.
- [ ] Run IAM Access Analyzer on generated policies.
- [ ] Save the policy-checked preview/plan and SHA-256 digest.
- [ ] Review all create/update/replace/delete operations and expected cost/risk.

Go/no-go:

- All applicable G0-G5 evidence is current and bound to the exact revision.
- No unresolved adversarial blocker exists.
- No unexpected deletion/replacement, public endpoint, wildcard trust, shared
  tenant role, or administrator authority appears.
- The operator receives a clear warning before any mutation.

### AWS-002 — Dev apply and runtime proof

- Status: `BLOCKED by AWS-001 approval`
- Severity: `P0`
- Required gate: G7

TODO:

- [ ] Apply the exact reviewed saved plan; do not re-preview and implicitly
      accept a different plan.
- [ ] Verify EKS private endpoint, workload identity, Pod security groups,
      network policy, DNS, ECR, and controller identity.
- [ ] Verify RDS IAM/Proxy TLS, exact runtime/migration role separation, and
      private connectivity.
- [ ] Prove cross-tenant, cross-account, wrong-role, Kubernetes API, IMDS, and
      internet denial.
- [ ] Exercise backup/restore, controller restart, failed canary, rollback, and
      cleanup.
- [ ] Record CloudTrail/config/runtime evidence and bind it to the plan digest.

Deployment sequence:

1. Infrastructure fixture only.
2. Small signed fixture application.
3. Warden with independent rollback gate.
4. Mind only after Warden and cross-product denial tests pass.

## Historical adversarial blockers (superseded by 2026-07-19 checkpoint)

These findings are release blockers until their tasks above close:

1. Rendered application token automount is now scanned from final YAML and the
   current render path requires an empty exception list. Kyverno denial and
   runtime proof that application Pods cannot call the API remain SEC-001.
2. Argo Applications are assigned to exact AppProjects and local-admin/ambient
   readonly access is disabled, but production can still follow mutable
   revisions/placeholders and field ownership is not production-qualified.
3. Database runtime/migration security groups are declared but are not attached
   to the actual Kubernetes workload network path.
4. Cloud identity capability selection is aggregate rather than an exact
   logical identity -> Kubernetes subject -> cloud role binding.
5. The legacy cloud-context/Codefly v1 readiness path still accepts syntactic
   evidence references and evaluates catalog-global health. The new IaC
   companion path joins typed, Ed25519-authenticated selected-closure and exact
   PostgreSQL readiness decisions, but production resolvers/trust/replay
   storage and future Codefly RPC integration remain.
6. Managed Postgres is reconstructed in several overlapping models rather than
   derived from one observed broker claim.
7. The observability namespace is exempt from important admission policies and
   lacks a safe network boundary for query tools.
8. The strongest local/cluster validators are mandatory in CI and release, but
   the release envelope still does not cryptographically bind unit, typecheck,
   policy, GitOps, dependency-audit, or adversarial-review result artifacts.
9. Codefly's integrated authorization path exposes an HMAC signing secret to
   the plugin, and replay state does not survive restart/replication. IaC must
   not integrate that v1 path.

## Historical commands for the 2026-07-18 slice

Fast contract gate:

```sh
npm run validate:contracts
npx tsc -p tsconfig.test.json
node --test dist-test/tests/contractSchemaValidation.test.js
```

Repository gate before handing off:

```sh
npm run verify:all
```

At that historical checkpoint, `verify:all` was the strict clean-source
cloud-IaC aggregate but was not production qualification. The current command
is intentionally stricter: it succeeds only from the sealed fixed execution
root on native Linux and emits production local-gate evidence while still
making no AWS call and claiming no AWS runtime result.

## Historical next slices (superseded)

### Slice 1 — Finish validation foundation (`IN PROGRESS`)

- Complete VAL-001 report schema/registry/evidence integration.
- Implement VAL-002 first differential corpus for `CloudContext v1alpha1`.
- [x] Finish SEC-001 full-render token scan.

Exit: schema and parser agree; any token-enabled application manifest fails.

### Slice 2 — Truthful reference and readiness seam (`IN PROGRESS`)

- [x] Add the infrastructure-owned companion types without changing v1alpha1.
- [x] Implement typed reference requests, Ed25519 observations, replay
      redemption, and selected dependency closure.
- [ ] Integrate production resolvers and trust/revocation/replay persistence.
      External deployment admission remains deferred.

Exit: one existing dependency becomes ready only through verified observed
state; any identity/generation/output/evidence substitution fails; an unrelated
degraded dependency does not block.

### Slice 3 — Enforced identity/Postgres/GitOps substrate

- Implement ID-001 and attach database network boundaries.
- Materialize the IaC-owned Pod Identity and database network bindings; keep
  migration execution in Codefly.
- Implement GIT-001 exact AppProjects.
- Extend CLU-001 to real runtime probes.

Exit: the exact allowed identity/token/GitOps paths work in a disposable
cluster; AWS-only identity/network paths have explicit G7 probes; every
enumerated local escape fails for its intended reason.

Only after all applicable G0-G5 gates pass should AWS-001 begin. External
platform integration is not a prerequisite for proving the IaC model and is
not part of this execution queue.

## Historical validation checkpoint (superseded)

Recorded on 2026-07-16 for the current worktree:

| Check                                          | Result       | Meaning                                                                                             |
| ---------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------- |
| Strict schema/contract validation              | PASS         | Eight owned IaC schemas compiled; three checked contracts and the validation report validated       |
| Targeted controller/bootstrap/evidence tests   | PASS         | Protocol, rootless access, hostile schema, cursor, event, and report-substitution cases pass        |
| Full `npm test`                                | PASS         | Clean output build, policy build, contracts, GitOps render, and 213 IaC tests                       |
| Clean-install `npm run verify:all`             | PASS         | Installed 238 packages (239 audited); tests, audit, 235-package SBOM, and 294-input evidence passed |
| `npm run security:audit`                       | PASS         | One underlying moderate advisory is covered by one reviewed exception; no high/critical finding     |
| External platform/plugin/product qualification | OUT OF SCOPE | Deferred until a separate reviewed integration plan                                                 |
| Scoped changed-file Prettier check             | PASS         | Current controller, schema, evidence, test, and roadmap changes are formatted                       |
| Disposable-cluster runtime proof               | NOT RUN      | Current suite is not yet sufficient for G5 claims                                                   |
| AWS preview/apply                              | NOT RUN      | Deliberately blocked; no AWS credentials, calls, or mutations used                                  |

These results qualify the current changes for local G0/G1 confidence only. They
do not qualify an external platform integration, cluster runtime, AWS apply, or
production promotion.
