# Governed Deployment Runbook

This is the authoritative greenfield deployment order. Raw Pulumi
preview/update commands and direct GitOps bootstrap applies are not supported:
they bypass the clean-source candidate, exact AWS role, Policy Pack, saved-plan,
and evidence checks enforced by `scripts/bootstrap.mjs`.

No command in the preparation and qualification stages may contact an AWS
provider. Stop before the preview stage until the real account values, Pulumi
backend, and short-lived management preview/apply roles are ready.

## 1. Human-owned prerequisites

Complete these outside the repository:

- create and secure the AWS management account with multiple hardware MFA
  devices. If it has no federation authority, use only the two-person,
  console-only [greenfield root ceremony](management-seed-runbook.md#truly-greenfield-account-one-governed-root-console-ceremony);
- select AWS Organizations as the landing-zone owner for this release;
  Control Tower is rejected until a separate discovery/import adapter exists;
- select the upstream IdP and export the exact UTF-8 SAML metadata bytes that
  will be reviewed, hashed, and later uploaded as `DeusBootstrap`; do not
  create the provider or roles before the bundle and signed candidate exist;
- choose one Pulumi organization/backend;
- reserve globally unique account email addresses;
- approve the planned distinct preview, apply, JIT provisioner, and retirement
  SAML identities. Their exact trusts, policies, paths, tags, and boundaries
  come only from the subsequently reviewed bundle.

Outside that one greenfield ceremony, do not use AWS root. Never use an IAM
user, long-lived access key, or unrelated same-account role.

## 2. Credential-free repository preparation

Install exactly the versions in `.tool-versions` and
`security/bootstrap-host-toolchain.json`, then create the ignored local
configuration:

```sh
cp onboarding.config.example.json onboarding.local.json
cp Pulumi.management.yaml.example Pulumi.management.yaml
# Replace every example account, email, backend, role, and principal value.
npm run bootstrap:doctor -- --config onboarding.local.json
env -i HOME="$HOME" LANG=C PATH="$PATH" \
  mise exec -- ./scripts/prepare-bootstrap-plugins
npm run bootstrap:access-bundle -- \
  --config onboarding.local.json \
  --output artifacts/management-seed-access-bundle.json \
  --template-output artifacts/management-seed-access.template.json
npm run bootstrap:verify-access-bundle -- \
  --config onboarding.local.json \
  --bundle artifacts/management-seed-access-bundle.json \
  --template artifacts/management-seed-access.template.json
```

Review the generated changes. The input must define the real landing-zone
owner, backend URL, management account ID, exact preview/apply role ARNs,
three distinct configured pre-organization SAML source role ARNs, the fixed
fourth `ManagementSeedRetirement` role derived by the bundle, fixed access
region, account emails, and Pulumi organization. `managementAccessRegion` must equal the
management stack's `aws:region`; the access stack name is fixed to
`deus-management-seed-access`.

Log in to the selected Pulumi backend and initialize only the management stack
as fixed by the
[Pulumi Cloud recovery procedure](pulumi-cloud-recovery.md). This is backend
preparation only. Do not assume an AWS role and do not invoke a provider
preview. Copy `Pulumi.management.yaml.example` to its ignored
non-example name and replace every placeholder. The stack must bind the exact
management account and may not import an ESC environment or configure AWS
provider indirection. Member-stack preparation remains intentionally blocked.
The management config names the unavoidable AWS Organizations account-vending
role `DeusOrganizationBootstrap`; it is transient, human-only, and not an
authorized path for any current controller or post-seed wave.

Only the management seed stack is executable in this release. Every later
account-foundation, network, compute/data, and edge wave remains blocked until
the seed returns real account outputs and earns a separate qualification.

Run the strict offline checks, review and commit all tracked changes, and verify
that the worktree is clean:

```sh
npm run validate:local
git status --short
```

## 3. Credential-free qualification

Qualification rejects AWS, Pulumi-token, and GitHub-token environment
credentials. It runs the exact clean install, static/contract, unit/Policy Pack,
dependency, and SBOM gates. It binds the
source, generated configuration, compiled program, tool versions, adversarial
review, dependencies, compiled policy, executables, provider plugin, and gate
evidence into a source-bound qualification request. Repository code never sees
the independently controlled Ed25519 private key.

Create the key once on a different trusted identity/host, HSM/KMS-backed
signer, or protected signing service, then commit only the public trust root.
The qualification and AWS execution hosts must never receive the private key.

```sh
cd /usr/local/lib/deus-bootstrap/execution
env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY \
  -u AWS_SESSION_TOKEN -u PULUMI_ACCESS_TOKEN -u PULUMI_CONFIG_PASSPHRASE \
  -u GITHUB_TOKEN -u GH_TOKEN -u NPM_TOKEN -u NODE_AUTH_TOKEN -u SSH_AUTH_SOCK \
  -u NODE_OPTIONS -u NODE_PATH \
  ./scripts/credential-free-qualification --config onboarding.local.json

# Transfer the payload to the independent signer, verify its candidate digest
# there, and return only the raw 64-byte signature.

npm run bootstrap:finalize -- \
  --signature /trusted-transfer/bootstrap-candidate.sig
```

Expected outputs are ignored local artifacts:

- `artifacts/bootstrap-candidate.unsigned.json` and detached payload;
- `artifacts/bootstrap-candidate.json` after detached signature verification;
- `artifacts/local-gate-evidence.json`;
- `artifacts/security-contract-evidence.json`;
- `artifacts/contract-schema-validation.json`; and
- `artifacts/secure-saas-infra.spdx.json`.

Any source, configuration, build, evidence, executable, dependency, policy, or
provider-plugin change invalidates the candidate. Review freshness and the
short-lived role session govern invocation time.

No in-cluster or GitOps report participates in AWS bootstrap qualification.
Those validations belong to the platform layer and begin only after a verified
cloud-to-platform handoff.

## 4. One-time management access provisioning

Using the signed candidate and its exact reviewed bundle, perform the
console-only greenfield root ceremony—or the equivalent independently governed
existing-federation procedure—exactly as documented in
[management-seed-runbook.md](management-seed-runbook.md). Create only the
provider, four source roles, two empty bounded target roles, and three
boundaries in that allowlist. Sign out, assume the JIT provisioner through the
new federation after activating its exact upstream IdP assignment just in time,
and run governed `--observe-foundation`; it permits only the exact STS/IAM read
inventory and emits a receipt with both mutation flags false.

The
first repository-governed cloud-control action after the external root ceremony
and federated foundation observation is a reviewed CloudFormation change set.
Create it from `artifacts/management-seed-access.template.json` with the exact
`managementProvisionerPrincipalArn` after its upstream IdP authorization and
exact generated single policy are activated just in time. The four source
roles, two empty target roles, and three immutable managed boundaries are
independently governed prerequisites. The preview/apply source roles have only
their rendered one-target assume-role grants. Creating the change set mutates
CloudFormation control-plane state only. Executing it is the first
repository-governed IAM mutation and must contain only two inline role-policy
`Add` changes in the bundle's exact account, partition, region, and fixed stack
name. Use
no CloudFormation capability acknowledgement: the exact template contains only
`AWS::IAM::RolePolicy`, which is not in CloudFormation's capability-required
resource list. Stop if `ValidateTemplate` or the described change set reports
any capability, replacement, deletion, unexpected
resource, or nonempty/drifted foundation. Verify the deployed target-role trust,
inline policies, boundary default versions, and source-to-target assumption;
then end that session and run governed `--retire` through the independent
retirement role. It attaches the exact pre-created deny-all boundary, deletes
the sole active grant, sets the three governed retirement tags last, verifies
each resumable monotonic state, and emits a retirement receipt. Remove the upstream IdP
assignment and record that external retirement before any seed
preview. Live preview/apply attestation refuses any AWS-side drift from that
inert state.

Use only the native credential-envelope-to-root-managed-`runtime-service
access-provisioner` anonymous-pipe protocol in
[management-seed-runbook.md](management-seed-runbook.md), with a separate
reviewed `--prepare` and `--execute` invocation. The launcher requires the
signed candidate and reviewed bundle digest, rejects proxy/custom-CA/profile
indirection, passes the verified template bytes directly to AWS, accepts only
the exact two-add change set, and emits prepared/executed receipts. Raw
CloudFormation create/execute commands are not a governed substitute.

## 5. First read-only AWS preview

After the target roles exist, assume only the exact `managementPreviewRoleArn`
from `onboarding.local.json`. The first narrow preview should select only the
management stack and use the checked-in read-only preview policy:

Use the complete credential-envelope-to-`runtime-service bootstrap` Bash
pipeline in [management-seed-runbook.md](management-seed-runbook.md); a direct
credential-bearing child invocation outside the fixed service fails closed.

Replace the example account ID with the real confirmed ID. The wrapper verifies
the exact STS assumed-role ARN, candidate, source, configuration, evidence,
toolchain, stack existence, and Policy Pack before saving a plan. Preview may
read AWS and the Pulumi backend; it must not mutate AWS.

Review the complete diff, `artifacts/pulumi-plans/manifest.json`, each saved
plan, and the printed manifest SHA-256. A failed or unexpected preview ends the
run; do not weaken a policy to make it pass.

## 6. Explicit update from the reviewed plan

An update is a separate, human-authorized action under the distinct
`managementApplyRoleArn`. It must use the same qualified candidate, the exact
reviewed manifest digest, and the apply-role credential-envelope pipeline in
[management-seed-runbook.md](management-seed-runbook.md).

Do not run this command until the preview is approved. Pulumi receives the
saved update plan through an inherited verified file descriptor; an atomic
pathname replacement cannot change the inode Pulumi reads. A changed manifest, candidate, source,
configuration, build, evidence file, toolchain, account, or role fails closed.

## 7. Phase order

Advance only after the prior phase has a reviewed preview, authorized update,
and post-update evidence.

| Phase        | Purpose                                                    | Initial order                                                                                                                                              |
| ------------ | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seed`       | Organization-only bootstrap                                | Management; real apply creates only the Organization and enables the two reviewed policy types. The future full topology is preview-only.                   |
| `foundation` | Identity, audit, shared controls, DNS, and central network | GitHub governance; identity; log archive; organization audit; security tooling; shared services; DNS; network; detection; compliance; Macie; cost controls |
| `access`     | Install bounded capability-lane roles in member accounts   | One `access-<account>` stack per selected account                                                                                                          |
| `shared`     | Environment backup controls                                | `backup-<env>`                                                                                                                                             |
| `workload`   | Private EKS workload accounts and transit routing          | `platform-<env>`; `execution-<env>`; `network-routing`                                                                                                     |
| `edge`       | Public cloud edge                                          | `waf-<env>`; verified platform-owned internal-NLB handoff; `ingress-<env>`                                                                                 |

All non-seed waves currently fail closed before cloud access. There is no
`OrganizationAccountAccessRole` acknowledgement or broad-role compatibility
flag. After the seed update, real account outputs must be converted into a
reviewed access contract and each Pulumi worker must bind one exact bounded
plan/apply role before the corresponding wave can be enabled.

## 7. Cloud-to-platform handoff

Cloud IaC stops after publishing the exact cluster endpoint/CA, EKS access,
Pod Identity/IAM, network, DNS, certificate, and load-balancer prerequisite
outputs. The separately owned platform layer must authenticate and verify that
handoff before it reconciles any Kubernetes object. This repository does not
install Argo CD Applications, Helm releases, Kyverno, Istio, namespaces,
operators, or application workloads. See
[iac-platform-boundary.md](iac-platform-boundary.md).

Database migrations remain application code. Infrastructure provisions RDS,
Proxy, IAM auth, network reachability, backup, and access contracts; it does not
execute schema migrations.

## 8. Evidence and stop conditions

For every preview/update retain:

- source revision and candidate digest;
- local gate, release, contract, audit, and SBOM evidence;
- Pulumi organization/project/stack and exact tool versions;
- STS account plus approved assumed-role identity;
- saved-plan manifest and digest;
- complete preview/update result; and
- post-deployment AWS runtime checks for the cloud resources in that wave.

Stop immediately on a dirty worktree, unverified or source-mismatched candidate,
stale adversarial review, changed configuration, unexpected account/role, raw
Pulumi invocation, policy warning, missing saved plan, unreviewed manifest
digest, broad member-account authority, or failed runtime evidence. Re-prepare
and re-qualify instead of bypassing the gate.

The detailed two-stage mechanics and current escape-hatch debt are documented
in [bootstrap.md](bootstrap.md). Incident response remains governed by
[incident-response.md](incident-response.md).
