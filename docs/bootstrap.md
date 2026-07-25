# One-command Bootstrap

`scripts/bootstrap.mjs` orchestrates the landing zone, but it is deliberately a
two-stage process. Local qualification first freezes a clean source revision,
configuration, compiled program, toolchain, adversarial review, five cloud-IaC
gate results, and SBOM into one immutable candidate.
Only that candidate may enter the short-lived AWS preview/apply phase. Root,
IAM-user, wrong-account, wrong-role, stale-review, and changed-input paths fail
closed.

## Prerequisites (humans-only)

These external decisions are required for the management seed:

| Step                              | One-time action                                                                                                                                                         |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Create the AWS management account | Sign up at aws.amazon.com; secure root with hardware MFA.                                                                                                               |
| Bootstrap account federation      | Establish `saml-provider/DeusBootstrap` and four locked source roles—preview, organization-only apply, JIT provisioner, and independent provisioner retirement—through a separately audited initial administrator session.            |
| Pinned toolchain                  | Install Node/npm/Pulumi from `.tool-versions` and AWS CLI/Git from `security/bootstrap-host-toolchain.json`.                                                            |
| Trusted execution snapshot        | Install the native launcher and complete pinned Node/Pulumi/AWS CLI trust domain, then qualify and root-seal the fixed execution root; see the management-seed runbook. |
| Pulumi auth                       | Select Pulumi Cloud, authenticate, initialize only the management stack, and configure it before qualification.                                                         |
| Repository controls              | Protect the source/evidence review topology, tags, environment, and immutable releases before publishing a candidate.                                                  |

Tailscale, E2B, DNS delegation, GitHub governance IaC, and initialization of
non-management Pulumi stacks are later-wave dependencies, not prerequisites
for this first Organization-only seed.

## Onboarding config

```sh
cp onboarding.config.example.json onboarding.local.json
# Edit: githubOrg, pulumiOrg, accountEmailDomain, etc.
```

The onboarding file also makes the ownership and bootstrap identity explicit:

- `landingZoneOwner`: currently only `organizations`; `control-tower` fails
  qualification until its discovery/import adapter exists.
- `pulumiBackend`: currently only `pulumi-cloud`, with
  `pulumiBackendUrl=https://api.pulumi.com`. Self-managed backend selection is
  rejected until a signed credentialed backend channel is implemented. The
  exact selected organization, only admitted stack, state export, and recovery
  procedure are defined in
  [pulumi-cloud-recovery.md](pulumi-cloud-recovery.md).
- `managementPreviewRoleArn`: the exact human-only preview target role. The
  independent access foundation pre-creates it empty with its immutable
  preview boundary; the governed installer adds only
  `security/aws-management-seed-preview-policy.json`.
- `managementApplyRoleArn`: a distinct human-only Organization-create role
  pre-created empty with its immutable apply boundary. The governed installer
  adds only `security/aws-management-seed-apply-policy.json`. It cannot create
  accounts, OUs, policies, attachments, service access, RAM sharing, or tags.
  Neither role may trust
  Codefly, an application workload, an IAM user, or root.
- `managementPreviewTrustedPrincipalArn` and
  `managementApplyTrustedPrincipalArn`: two distinct, existing, same-account
  pre-organization SAML source roles under `/deus/bootstrap-source/`. Each receives
  only `sts:AssumeRole` for its corresponding fixed target role.
- `managementBootstrapSamlProviderArn`: the exact same-account
  `saml-provider/DeusBootstrap` provider. Both source-role trusts are attested
  byte-semantically as the one exact SAML-only trust; AWS/service principals
  and alternate audiences fail closed.
- `managementBootstrapSamlMetadataSha256`: the lowercase SHA-256 of the exact
  UTF-8 `SAMLMetadataDocument` returned by `iam:GetSAMLProvider`. The digest is
  bound into the access bundle and live-attested together with an exact empty
  provider-tag inventory, `Allowed` assertion-encryption mode, and no SAML
  provider private keys, so changing the IdP issuer, signing certificates, or
  provider encryption state behind the stable provider ARN fails closed.
- `managementProvisionerPrincipalArn`: the third exact SAML source role. Its
  upstream IdP authorization and exact generated one-policy capability exist only
  long enough to install and verify the two target-role inline policies. It
  cannot create a role or managed policy. Before seed
  preview it must have zero policies, the exact pre-created deny-all retirement
  boundary, and the exact governed retirement tags; this AWS-side state is
  live-attested. A fourth fixed `ManagementSeedRetirement` SAML role has only
  the generated authority to attach that provisioner's one exact deny-all
  boundary, delete its sole exact inline grant, apply the retired tags last,
  and read back each resumable monotonic state. Upstream IdP assignment removal
  remains external evidence.

Render and independently verify the target roles and permissions boundaries
before qualification. The exact commands and first-AWS change-set boundary are
in [management-seed-runbook.md](management-seed-runbook.md). No AWS role is
created by the renderer.

Before any preview, run the offline, non-mutating readiness doctor:

```sh
npm run bootstrap:doctor
```

It checks the local toolchain, onboarding decisions, example values, unique
account emails, and accidental long-lived AWS key environments. It performs no
AWS or Pulumi backend request unless explicitly asked. After AWS SSO and Pulumi
login are configured, strict mode adds read-only identity checks:

```sh
npm run bootstrap:doctor -- --strict
```

Strict mode calls only identity/readiness endpoints, verifies the exact
management account, and rejects root and IAM-user callers. It never mutates
AWS or Pulumi state.

## Prepare and qualify without AWS credentials

Qualification rejects AWS credential/profile variables, Pulumi access-token
variables, and GitHub token variables. Do not assume the management role yet.
The preparation phase is allowed to authenticate to the chosen Pulumi state
backend, but it must not have an AWS session and must not run a provider
preview.

1. Install the exact `.tool-versions` and host-toolchain manifest versions,
   then run
   `env -i HOME="$HOME" LANG=C PATH="$PATH" mise exec -- ./scripts/prepare-bootstrap-plugins`.
   The plugin command downloads only the
   exact AWS provider version; qualification seals its installed tree digest.
2. Run onboarding to create ignored, account-specific `Pulumi.*.yaml` files.
3. Initialize only the management backend stack. Its executable config must
   bind `stackKind=management`, `deploymentMode=organization`,
   `environment=management`, `seedWave=organization-only`, exactly one
   `aws:allowedAccountIds` equal to the
   management account, no AWS provider assume-role/profile keys, and no ESC
   imports. Later stack initialization remains blocked.

AWS Organizations still creates one administrative account-vending role in
each new member account. This repository requires the explicit
`DeusOrganizationBootstrap` name, never the generic default name. It is a
transient human bootstrap seam, is not trusted by Codefly or any controller,
and must be retired after the future scoped member-access installation is
verified. No current post-seed execution wave is admitted through it.

4. Provision the Ed25519 qualification key on a separate trusted OS identity,
   host, HSM/KMS-backed signer, or protected signing service. The qualification
   and AWS execution hosts must never be able to read or address the private
   key. Commit only the generated public trust root.

5. Commit all repository changes, including the public trust root. Never add
   the private key. Account-specific stack files and onboarding
   input remain ignored, but the tracked source must be clean.
6. On the dedicated Linux qualification account described in
   [management-seed-runbook.md](management-seed-runbook.md), remove all cloud
   credential environment variables and qualify the fixed execution root:

```sh
cd /usr/local/lib/deus-bootstrap/execution
env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY \
  -u AWS_SESSION_TOKEN -u PULUMI_ACCESS_TOKEN -u PULUMI_CONFIG_PASSPHRASE \
  -u GITHUB_TOKEN -u GH_TOKEN -u NPM_TOKEN -u NODE_AUTH_TOKEN -u SSH_AUTH_SOCK \
  -u NODE_OPTIONS -u NODE_PATH \
  ./scripts/credential-free-qualification --config onboarding.local.json

# Transfer only artifacts/bootstrap-signing-review-bundle.json through a
# confidential authenticated channel. The signer independently fetches and
# rebuilds the reviewed commit, verifies every embedded input, reproduces the
# complete runtime closure, and returns only a raw 64-byte Ed25519 signature.

npm run bootstrap:finalize -- \
  --signature /trusted-transfer/bootstrap-candidate.sig
```

The command runs exactly these gates: clean install, static/type/build/contract
checks, all unit and policy callback fixtures, dependency audit, and SPDX SBOM
generation. It writes ignored
artifacts including:

- `artifacts/local-gate-evidence.json`;
- `artifacts/security-contract-evidence.json`;
- `artifacts/secure-saas-infra.spdx.json`; and
- `artifacts/bootstrap-candidate.unsigned.json`;
- `artifacts/bootstrap-candidate.payload`; and
- `artifacts/bootstrap-signing-review-bundle.json`; and
- `artifacts/bootstrap-candidate.json`.

Any source, configuration, build, dependency, policy build, executable, Pulumi
plugin, or evidence change invalidates the candidate. The candidate is
Ed25519-authenticated by the pinned independent signer. It is source
qualification, not invocation authorization: the seven-day adversarial review,
exact short-lived AWS role, and reviewed plan digest govern each invocation.
The governed bootstrap path does not invoke Docker, Helm, kubectl, K3s, or
GitOps. Those belong to the in-cluster platform layer described in
[iac-platform-boundary.md](iac-platform-boundary.md).

Repository shell entrypoints refuse credentialed use. A human operator creates
an envelope on an anonymous pipe and sends it to the native root-only
`runtime-service` entrypoint. That entrypoint starts one fixed transient systemd
unit under a locked, non-login, peer-free runtime UID. The unprivileged launcher
constructs a fresh allowlisted environment, starts scoped authenticated
loopback brokers, and imports code only from the root-sealed fixed execution
snapshot. Raw AWS and Pulumi secrets are never inherited by Node from the
operator shell.
Repository IaC code never invokes Git or npm in the credentialed phase and
neither is candidate-listed as a credentialed executable. On Linux, systemd
first applies `NoExecPaths=/` with only the candidate-bound executable and
native mapping closure restored through exact `ExecPaths`; writable home,
plan, and output paths remain non-executable. Namespace creation and mount
and `memfd_create` syscalls are denied. The launcher then installs an inner mandatory Landlock
`EXECUTE | READ_FILE` ruleset before starting Node. The kernel denies Git, npm,
host shells, downloaders, unapproved loader targets, and every other executable
even when addressed by absolute path. Landlock is not claimed to make every
readable file unreadable. Unsupported systemd sandbox features, cgroup v2, or
Landlock fail closed. Pulumi can discover plugins only from the exact sealed
candidate-bound home.

## Preview and apply with the exact AWS role

The bootstrap models six waves. By default a dry run shows all six for the
target environment(s):

```sh
# Print the dev orchestration order only. This performs no Pulumi preview.
npm run bootstrap -- --environment dev

# Print the modeled environment order. Prod and staging are excluded.
npm run bootstrap -- --environment all

# Credentialed preview/apply must use the anonymous-pipe credential-envelope
# to root-managed runtime-service protocol. See management-seed-runbook.md.
# Direct credential-bearing child invocation fails closed.

# Preview production only after its release gates pass.
npm run bootstrap -- --environment prod --enable-production --dry-run

# Print the future foundation order. Credentialed foundation execution is blocked.
npm run bootstrap -- --environment all --phases foundation --dry-run

# Show the plan without executing.
npm run bootstrap -- --environment all --dry-run

# Only after both staging accounts are enabled in the management configuration.
npm run bootstrap -- --environment staging --enable-preprod --dry-run
```

The default and `--dry-run` modes print dependency order only. They do not
require a candidate and never contact AWS. Real preview/apply are admitted only
through the native anonymous-pipe commands in the management-seed runbook.
Preview runs the policy pack and saves Pulumi update plans under the ignored
`artifacts/pulumi-plans` directory; it does not mutate AWS. Preview and apply
both require the qualified candidate, a clean Git worktree, the exact
configured assumed-role ARN, and the candidate-bound commit. Apply mode
requires the saved plan manifest's SHA-256 digest and passes each reviewed plan
back through Pulumi's
[`--plan` update constraint](https://www.pulumi.com/docs/iac/guides/basics/update-plans/).
Preview/apply also require
`--confirm-management-account-id` to match both
`onboarding.local.json` and `aws sts get-caller-identity`; root identities are
rejected. The candidate and its gate/release evidence are revalidated
before and after Pulumi operations. `dev` is the default planning environment;
credentialed execution currently admits only the management `seed` phase.
Production and staging flags affect future plan composition only and do not
admit those waves into the qualified runtime.

The access installer is a distinct, JIT human-only transition that must finish
before seed preview. The wrapper rejects real preview/apply for every wave
except `seed`; it exposes no
flag that accepts `OrganizationAccountAccessRole` or bypasses scoped provider
binding. After the seed update, export the real account IDs, materialize and
review the account-access contract, and implement exact preview/apply provider
bindings before admitting `access` or any member-account wave. Codefly never
assumes the organization bootstrap or member handoff role.

## Phases

| Phase        | Stacks                                                                                                                                                                             |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seed`       | `management`; `organization-only` creates only the Organization and enables two policy types. `full` is preview-only and apply-blocked.                                                |
| `foundation` | `github-governance`, `identity`, `log-archive`, `organization-audit`, `security-tooling`, `shared-services`, `dns`, `network`, `detection`, `compliance`, `macie`, `cost-controls` |
| `access`     | `access-{account}` for foundational and selected environment accounts; creates plan plus capability-lane apply roles and their permissions boundaries                              |
| `shared`     | `backup-{env}` per environment                                                                                                                                                     |
| `workload`   | `platform-{env}`, `execution-{env}` per environment, plus `network-routing`                                                                                                        |
| `edge`       | `waf-{env}`, verified platform-owned internal-NLB handoff, then `ingress-{env}`                                                                                                    |

Phases run in order; within each phase, stacks deploy sequentially in the
declared order.

## Cross-account assume-role

`management` is the only currently executable stack and runs against the exact
management-account bootstrap session. Only `seedWave: organization-only` is
admitted for apply. `seedWave: full` remains available for a policy-checked,
capacity-bound preview but apply is machine-blocked until the member-access
installation can immediately retire every `DeusOrganizationBootstrap` role.
The modeled `access-*` stacks would use
the organization-created member role once to create protected scoped roles,
but that transition is deliberately not executable yet. The compiled roles
have exact principal trust, external IDs, separate plan/apply authority,
per-lane permissions boundaries, and no direct delete/detach/revoke/shutdown
actions. No apply role trusts the infrastructure controller.

The compound stacks still need decomposition so each Pulumi worker uses only
one capability lane. There is no temporary broad-role exception: preview and
apply fail before cloud access for those waves until the provider binding is
implemented and reviewed.

Relational resources are no longer part of the generic `data` capability. The
access compiler emits a dedicated `database` apply role and two different
boundaries:

- the apply-role boundary permits reviewed RDS/KMS/security-group mutations but
  no database login, secret read, decrypt, or service log write;
- the delegated-role boundary is installed by the human account-access stack
  and is the mandatory ceiling for every monitoring, Proxy, Pod Identity, and
  just-in-time bootstrap role created by the database stack.

Platform stack examples load the same checked access plan with
`awsBootstrapAccessPlanPath` and select their exact account using
`awsBootstrapAccessAccountName`. Replace the reference account IDs before any
real preview. The compiler fails closed if the selected account lacks the
`database` lane or a rendered role is not name- and boundary-constrained.

The cloud program publishes EKS access and handoff outputs but does not use
them to reconcile Kubernetes resources. Argo CD activation and all subsequent
cluster API access belong to the platform layer.

## What the currently admitted seed can show

1. AWS Organizations ownership, OUs, organization guardrails, and the selected
   member-account requests/outputs.
2. A source-, configuration-, runtime-, role-, and plan-bound evidence trail
   for the exact seed preview/update.

Identity, audit, networking, EKS, RDS, backup, and edge remain later cloud
waves. Kubernetes/Argo CD state is not an IaC wave in this repository.

## Manual follow-ups (post-bootstrap)

The bootstrap leaves a short list of operational steps that _must_ be
human-performed:

- Drop Tailscale OAuth values into the placeholder Secrets Manager
  secrets (`shared-services` stack created the slots).
- Drop E2B BYOC vendor principal ARN + external ID into
  `Pulumi.execution-prod.yaml`, then re-run that stack.
- Point your registrar's NS records at the Route 53 zone if the apex is
  external.
- Create `@codefly-dev/platform-security`, grant it repository access, and
  verify GitHub recognizes it as the CODEOWNERS target before protection is
  relied upon.

## Destruction and recovery

There is no qualified destroy path. The current role explicitly denies
deletion, detach, removal, update, and organization-leave actions. Teardown,
retained-resource cleanup, role revocation, and organization deletion require
a separately designed and reviewed incident/change procedure; raw
`pulumi destroy` is not an acceptable fallback.
