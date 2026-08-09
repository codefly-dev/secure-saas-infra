# Secure SaaS Infrastructure

This repository is the starting implementation for a secure SaaS platform that hosts client code.

> **Current governed release:** AWS Organizations management seed only. This
> is the first cloud-infrastructure wave, not the final infrastructure scope.
> VPC/routing, EKS, RDS, ingress/load-balancer prerequisites, identity,
> observability, backup, and security-service stacks remain planned cloud IaC
> waves. Kubernetes API objects, Helm/Argo reconciliation, operators, and
> application migrations belong to the separate platform-delivery layer. See
> [the cloud IaC boundary](docs/iac-platform-boundary.md) and
> [the management-seed runbook](docs/management-seed-runbook.md).

The baseline uses:

- Pulumi TypeScript for AWS infrastructure.
- A cloud-neutral security/tenancy kernel plus provider adapters.
- A generic, strict infrastructure-controller protocol with version
  negotiation, stable reason codes, digest-chained operation events, and
  authenticated resumable watch cursors. See
  [docs/infrastructure-controller-protocol.md](docs/infrastructure-controller-protocol.md).
- A centralized inspection and egress VPC pattern.
- Private-only workload VPCs connected through AWS Transit Gateway.
- EKS Auto Mode for platform and execution clusters.
- Tailscale private access instead of bastion hosts.
- IAM Identity Center for workforce access.
- GitHub Actions OIDC for CI/CD access without long-lived AWS keys.
- Pulumi-managed GitHub repository governance for rulesets, Actions
  restrictions, protected environments, Dependabot security updates, and
  vulnerability alerts.
- VPC endpoints for AWS service access.
- Credential-free cloud-to-platform handoff contracts; in-cluster desired state
  is owned separately.
- Vault-ready secrets architecture.
- E2B BYOC-ready execution specification for customer-code sandboxes.
- Optional E2B BYOC vendor-access role scaffold with external ID and
  least-privilege policy validation.
- Tenant-prefix-enforced customer artifact bucket and confused-deputy-hardened
  CloudTrail bucket/KMS policies (`aws:SourceArn` + `aws:SourceAccount`).
- Optional CloudTrail S3 data event capture for the customer artifact and
  Vault backup buckets.
- Expanded SCPs: deny IAM users/access keys, deny disabling KMS rotation,
  deny disabling EBS default encryption, deny mutating organization CloudTrail
  trails.
- Config-time validators for production firewall posture, private-EKS scoped
  IAM Identity Center `eks.accessGrants`, shared-services KMS coverage, and `microvm-runtimeclass`
  isolation boundary.
- AWS Backup organization plan: multi-region KMS replicas, vault lock,
  cross-region copy, tag-based selection. See [docs/disaster-recovery.md](docs/disaster-recovery.md).
- Aurora baseline (PostgreSQL or MySQL) with IAM auth, CMK, deletion
  protection, RDS-managed master credentials outside Pulumi state, end-to-end
  IAM RDS Proxy, and audit logging. See [docs/database.md](docs/database.md).
- Executable cloud-neutral resource broker with CAS/idempotency, capability
  redemption, provider fencing, drift/cancellation/deletion lifecycle, a fake
  provider conformance suite, explicit database access SGs, and wildcard-free
  runtime/migration RDS Proxy IAM plans.
- EKS Pod Identity compilation with exact namespace/ServiceAccount association,
  `pods.eks.amazonaws.com` trust, source-organization/session-tag constraints,
  and no IRSA role annotation. The PostgreSQL boundary uses dynamic per-
  connection IAM tokens and publishes no credential; see
  [docs/postgres-codefly-aws-auth-boundary.md](docs/postgres-codefly-aws-auth-boundary.md).
- WAF model-gateway rate limiting. See [docs/waf.md](docs/waf.md).
- Public WAFv2 Web ACL with managed rule sets, bot control, and a strict
  model-gateway rate limit. See [docs/waf.md](docs/waf.md).
- EventBridge detection rules + SNS fan-out for GuardDuty, IAM, KMS,
  CloudTrail, Config, and Security Hub events.
- AWS Config conformance pack for CIS AWS Foundations + EKS hardening, and an
  optional Audit Manager assessment. See [docs/compliance.md](docs/compliance.md).
- Per-tenant AWS Budgets and Cost Anomaly Detection. See [docs/cost-controls.md](docs/cost-controls.md).
- Macie classification jobs over the customer artifact and Vault backup
  buckets.
- VPC-level Route 53 Resolver query logs in every workload VPC.
- SLSA Level 3 release workflow using `slsa-framework/slsa-github-generator`.
- Public ingress hub: CloudFront + WAFv2 + ACM (TLS 1.3) + VPC Origin to a
  platform-owned internal-NLB handoff. No public IP in any VPC. See
  [docs/ingress.md](docs/ingress.md).
- DNS module: Route 53 root zone + per-environment delegated subdomain zones
  (`dev.<root>`, `staging.<root>`, `prod.<root>`) with public-zone query
  logging.
- AWS Organizations standalone trusted access for the exact six seed
  principals: CloudTrail, both AWS Config principals, GuardDuty, Security Hub,
  and Inspector. AWS RAM sharing has its own exclusive Pulumi owner. Other
  integrations are deferred to separately qualified post-seed waves.
- Governed bootstrap currently admits only the
  organization/account seed. Later cloud waves remain fail-closed until real
  account outputs and exact bounded provider roles exist.

## Management-seed bootstrap

```sh
cp onboarding.config.example.json onboarding.local.json
# Replace every example with the real backend, account, and role decision.
cp Pulumi.management.yaml.example Pulumi.management.yaml
# Replace every example account email and management account ID.

npm run bootstrap:doctor
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

# Only after the reviewed preview-role policy exists and root is signed out:
npm run validate:aws-account -- \
  --root-activity-cutoff '<ROOT_CEREMONY_CUTOFF_UTC>' \
  --json
```

From an ordinary checkout, stop there and follow the exact
[management-seed runbook](docs/management-seed-runbook.md). Credential-free
qualification is allowed only from
`/usr/local/lib/deus-bootstrap/execution` after the authenticated release host
kit has prepared that fixed root on a dedicated native-Linux qualifier. It
cannot mutate AWS. After a clean commit, three GO reviews, independent signing,
and configuration of the real Pulumi backend, the irreducible cloud
prerequisite is the separately audited `DeusBootstrap` SAML federation. The
governed observation mode then proves the exact empty foundation without a
mutation. Preparing the reviewed RolePolicy-only CloudFormation change set is
the first repository-governed cloud-control mutation; executing its exact two
inline-policy additions is the first IAM mutation. That template requires no
CloudFormation capability acknowledgement. The next cloud action is a
policy-checked seed preview through the native anonymous-pipe credential
protocol. Follow the exact
[management-seed runbook](docs/management-seed-runbook.md). All non-seed waves
currently fail closed before configuration or AWS access.

## First Deployment Flow

The raw Pulumi preview/update path is intentionally unsupported. The governed
flow prevents a preview or update from bypassing the clean-source, exact-role,
policy, saved-plan, evidence, and account checks.

1. Copy `onboarding.config.example.json` to the ignored
   `onboarding.local.json` and fill the real
   ownership/backend/account/role values. Copy
   `Pulumi.management.yaml.example` to the ignored
   `Pulumi.management.yaml` and fill the exact seed configuration.
2. Log in to the selected Pulumi backend and initialize only the management
   stack. Stack initialization is preparation only; it must not run an AWS
   provider action. The selected backend, encrypted export procedure, and
   restore boundary are fixed in the
   [Pulumi Cloud recovery runbook](docs/pulumi-cloud-recovery.md).
3. Run `npm run bootstrap:doctor` offline. Provision the Ed25519
   qualification key on a different OS identity/host, HSM/KMS-backed signer,
   or protected signing service, then commit only its public trust root.
4. Bind the SHA-256 of the exact reviewed UTF-8 SAML metadata bytes and locally
   render and verify the deterministic access bundle with
   `npm run bootstrap:access-bundle` and
   `npm run bootstrap:verify-access-bundle`. The preview/apply source roles
   will receive only their corresponding capped assume-role policy; the JIT
   provisioner and independent retirement roles will receive only their
   rendered exact policies. The target roles are specified with no inline or
   attached policy and their matching precreated boundaries. Install the exact
   AWS provider plugin with
   `env -i HOME="$HOME" LANG=C PATH="$PATH" mise exec -- ./scripts/prepare-bootstrap-plugins`.
   After authenticating and installing the release host kit, prepare the fixed
   execution root exactly as documented in the management-seed runbook. Remove
   cloud credentials and run `credential-free-qualification` only inside that
   root. It emits an unsigned request and detached signing payload; no
   private-key path enters repository code.
5. Transfer the payload to the independent signer and return only its detached
   signature. Never sign on the qualification or AWS execution host. Then run
   `npm run bootstrap:finalize -- --signature <raw-signature>` to
   verify it against the committed public root and create the candidate.
6. Using only the signed candidate's bundle, establish the exact same-account
   `DeusBootstrap` SAML provider, four `/deus/bootstrap-source/` roles, two
   empty target roles, and three immutable managed boundaries through the
   independently governed initial account-federation procedure. The runbook
   defines the only permitted console-only root ceremony for a truly greenfield
   account. Never create a root access key or IAM user. After signing out,
   activate the exact `managementProvisionerPrincipalArn` assignment at the
   upstream IdP just in time and assume its short-lived session. Governed
   `--observe-foundation` compares the AWS-returned metadata with the reviewed
   digest and verifies empty provider tags/private-key inventory, `Allowed`
   assertion-encryption mode, and every exact role/boundary. From that same or
   a renewed short-lived session, run
   the native credential-envelope-to-root-managed-`runtime-service` pipeline
   documented in the runbook to create and verify the fixed-region
   CloudFormation change set. It must contain only the two fixed inline role
   policies for the already bounded target roles and report no CloudFormation
   capabilities. After separate review, run the same
   pipe protocol with `--execute` and its exact confirmation; it re-verifies
   the change set and performs post-create IAM attestation. Then immediately
   end that session and use the distinct generated-policy
   `ManagementSeedRetirement` SAML role with governed `--retire`. It first
   attaches the pre-created deny-all boundary, then deletes the sole active
   inline grant, and only then applies the exact retired tags. Every exact
   intermediate prefix is resumable and emits a bound retirement receipt.
   Remove the upstream IdP assignment and retain that external evidence.
   Seed preview refuses any AWS-side drift from that inert state.
7. Keep `seedWave: organization-only` for the first candidate and apply only
   the reviewed Organization plan. A newly qualified `seedWave: full`
   candidate may produce a read-only plan only; apply remains machine-blocked
   until a qualified member-access wave immediately replaces and retires every
   `DeusOrganizationBootstrap` account-vending role. Its live gate requires
   effective quota for nine accounts and rejects external
   account/invitation drift.
8. On a fresh execution host/operator identity, pass one short-lived AWS
   session and Pulumi token through separate anonymous pipes into the fixed
   root-managed systemd service. Its locked, non-login runtime identity gives
   Node only scoped authenticated loopback broker capabilities and creates
   policy-checked saved plans. Review every diff and manifest digest.
9. For update, assume the distinct `managementApplyRoleArn`; `--apply` uses
   the same source-bound candidate and immutable reviewed plan descriptor.

See [the management-seed runbook](docs/management-seed-runbook.md) for exact
commands. Never invoke a raw provider preview/update as a substitute for the
governed wrapper.

Governed qualification covers cloud IaC, not resources reconciled inside
Kubernetes. See
[the cloud-IaC/platform boundary](docs/iac-platform-boundary.md).

## Current Scope

This is the IaC foundation, not an application platform implementation. This
repository does not currently test or modify an external CLI, server, plugin,
Mind, or Warden repository. It creates the infrastructure and security baseline
that later, explicitly planned integration layers may consume:

- Network-services egress VPC.
- Transit Gateway and route tables.
- Private account-specific platform and execution VPCs.
- Cross-account Transit Gateway attachment routing.
- Optional AWS Network Firewall insertion point.
- EKS clusters with private API endpoints and Auto Mode.
- Cloud-side private-access prerequisites and explicit EKS access entries.
- A versioned handoff boundary for the separately owned in-cluster platform.

See
[docs/rootless-aws-codefly-execution-roadmap.md](docs/rootless-aws-codefly-execution-roadmap.md)
for the dependency-ordered rootless AWS implementation backlog, real-AWS gates,
hostile test matrix, and required evidence.
See
[docs/iac-validation-first-execution-todo.md](docs/iac-validation-first-execution-todo.md)
for the active IaC implementation queue, strict validation ladder,
adversarial-review blockers, and exact AWS go/no-go gates.
See
[docs/pre-aws-readiness-todo.md](docs/pre-aws-readiness-todo.md)
for the short dependency-ordered operator checklist to complete before creating
the AWS management account.
See
[docs/pre-aws-readiness-roadmap.md](docs/pre-aws-readiness-roadmap.md)
for the dependency-ordered map of tracked issues to that checklist's stages, from
the current state to the first governed management-seed apply.
See
[docs/infrastructure-controller-protocol.md](docs/infrastructure-controller-protocol.md)
for the implemented public/internal controller trust boundary and protocol
verification rules.
See [docs/cloud-neutral-kernel.md](docs/cloud-neutral-kernel.md) for the cloud-neutral security and tenancy architecture, implemented capabilities, and prioritized TODO list.

See [docs/accounts.md](docs/accounts.md) for the multi-account stack model.
See [docs/onboarding.md](docs/onboarding.md) for the local onboarding helper.
See [docs/identity.md](docs/identity.md) for the AWS Identity Center and GitHub OIDC model.
See [docs/deploy-runbook.md](docs/deploy-runbook.md) for the ordered deploy checklist.
See [docs/mind-server-security.md](docs/mind-server-security.md) for the Mind server customer-code security baseline.
See [docs/e2b-byoc.md](docs/e2b-byoc.md) for the E2B BYOC execution specification.
See [docs/github-security.md](docs/github-security.md) for required GitHub repository controls.
See [docs/incident-response.md](docs/incident-response.md) for customer-code incident runbooks.
See [docs/customer-data.md](docs/customer-data.md) for tenant-scoped artifact storage requirements.
See [docs/disaster-recovery.md](docs/disaster-recovery.md) for backup, restore, and DR posture.
See [docs/database.md](docs/database.md) for the Aurora baseline.
See [docs/agentic-ai.md](docs/agentic-ai.md) for the agent broker contract.
See [docs/runtime-security.md](docs/runtime-security.md) for Falco runtime detection.
See [docs/compliance.md](docs/compliance.md) for the Config conformance pack and SOC 2 evidence.
See [docs/cost-controls.md](docs/cost-controls.md) for per-tenant budgets and cost anomaly detection.
See [docs/waf.md](docs/waf.md) for public-ingress WAF posture.
See [docs/ingress.md](docs/ingress.md) for the CloudFront + VPC Origin + Istio ingress architecture.
