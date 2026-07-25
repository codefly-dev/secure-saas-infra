# Implementation Roadmap

> **Status boundary:** only the AWS Organizations management seed is currently
> in the positive build/test/release inventory. The later account foundation,
> network, EKS/RDS, and edge sections below are cloud-infrastructure roadmap
> work, not qualified runtime claims. In-cluster Kubernetes/Argo/Helm work is
> separately owned platform delivery and must not enter the IaC release.

## Current IaC-only execution boundary — 2026-07-21

Only the AWS Organizations management seed is executable in the positive
qualification scope. Local gates bind the exact source/build/runtime closure,
independent review disposition, access bundle, dependency audit, SPDX
inventory, Policy Pack, candidate signing request, and immutable Pulumi plan
manifest. The exact graph policy checks every admitted logical identity against
its resource type, exact input-key inventory, critical properties, tags,
dependency set, and property dependencies. No Codefly, Kubernetes, Helm, Argo CD, GitOps, application, VPC,
EKS, or RDS code is executed by these gates.

The pre-Organization access contract uses one exact commercial-AWS SAML
provider and four distinct source roles: preview, Organization-only apply,
just-in-time provisioner, and independently governed provisioner retirement.
The active provisioner and retirement authority each have one exact generated
policy. The governed retirement runner binds the executed access receipt and
performs deny-all boundary -> sole-policy deletion -> retired tag, resuming
only from an exact monotonic prefix before exact live read-back. Seed
preview/apply refuses to start unless the provisioner is live
verified as inert under its exact deny-all retirement boundary with zero
policies and exact retirement tags. Upstream IdP assignment removal is an
external first-authority responsibility.

`seedWave: organization-only` is the only admitted apply and its AWS role can
create only the protected Organization and enable the two reviewed policy
types. The plan manifest binds the absent-Organization precondition; apply
then proves the exact Organization/root/management-only baseline and absence
of foreign Organizations state. `seedWave: full` is preview-only: its live account,
invitation, pending-creation, and quota observation is bound to the candidate,
management account, configuration, and reviewed plan manifest, then repeated
immediately before and after Pulumi. Full apply remains machine-blocked until a
separately qualified member-access wave can replace and immediately retire
every broad `DeusOrganizationBootstrap` account-vending role.

Remaining qualification and real-environment prerequisites:

- commit the exact tree and obtain three fresh adversarial dispositions;
- create a protected evidence-only child, protected tag, and GitHub immutable
  release;
- configure only the Ed25519 public trust root here while the private signer
  remains independently controlled;
- build and verify native `amd64` and `arm64` host kits, then prove the
  installed systemd/Landlock/sudo/runtime lifecycle on native Linux;
- retain the selected Pulumi Cloud organization, recovery procedure, and
  already initialized empty management stack; provide the real management
  account ID plus globally unique account emails;
- establish the separately audited SAML provider/four source roles, two empty
  pre-bounded target roles, and three immutable managed boundaries; execute the
  exact two-inline-policy access change set; and retire the provisioner; and
- run the first governed read-only `organization-only` preview. Any apply requires
  a separately reviewed saved plan and explicit operator confirmation.

The cloud-neutral, database, network, EKS, and other material later in this
document is roadmap context only. In-cluster delivery is owned by the platform
layer; see [iac-platform-boundary.md](iac-platform-boundary.md).

## Phase 1: Foundation

- Create AWS landing zone and accounts. The Pulumi account-vending scaffold exists.
- Deploy the centralized egress network. The hub stack scaffold exists.
- Deploy private platform and execution EKS clusters. The account-specific spoke stack modules exist.
- Associate and route cross-account Transit Gateway attachments. The network-routing stack exists.
- Replace bastion access with Tailscale operator/admin access.
- Enable account-level audit, detection, and logging. The log-archive, organization-audit, security-tooling, and shared-services stacks exist.
- Configure workforce and CI/CD identity. IAM Identity Center permission sets/account assignments and GitHub Actions OIDC role scaffolding now exist.
- Publish the versioned cloud-to-platform handoff; the platform repository owns
  Argo CD and all in-cluster desired state.

## Phase 2: Security Hardening

- Wire AWS Network Firewall rule groups to a production allowlist process. The
  firewall scaffold now logs FLOW and ALERT events; the remaining work is
  change-controlled allowlist operations and deployed deny-path tests.
- Add VPC endpoint policies for S3, ECR, STS, KMS, and Secrets Manager. The
  baseline now attaches explicit action-scoped policies to all workload AWS
  service endpoints, including CloudWatch, SSM, EKS, EKS Pod Identity, EC2, and
  Elastic Load Balancing. Policies now scope to same-account principals and use
  same-account resource conditions when AWS exposes `aws:ResourceAccount`.
- Add Pulumi policy checks for public ingress, public EKS APIs, unencrypted
  storage, VPC endpoint policy defaults, VPC Flow Logs, and Network Firewall
  logging. The mandatory Policy Pack now covers public EKS APIs,
  Kubernetes secret encryption, public ingress, direct internet gateways outside
  egress, audit bucket Object Lock, KMS rotation, organization CloudTrail
  posture, explicit VPC endpoint policies, all-traffic VPC Flow Logs, and
  Network Firewall FLOW plus ALERT logging. It also rejects broad IAM identity
  policies (including IAM Identity Center permission set inline policies),
  high-risk managed admin policies, wildcard Allow actions, and unbounded
  privilege-escalation actions. The policy pack now also requires one-year
  CloudWatch log retention, customer-managed KMS for Secrets Manager and S3
  encryption, SSE-C rejection for S3 buckets, no IAM users/access keys, and
  IMDSv2 on EC2 instances.
- Tighten config-time validators: production-like network-hub/single-account
  stacks must enable Network Firewall, private EKS clusters must declare
  scoped IAM Identity Center `eks.accessGrants`, shared-services must keep customer-managed KMS for the Vault
  backup bucket and Tailscale secrets, and the in-cluster microVM execution
  provider is held to the same dedicated-account/private-LB/central-egress
  boundary as E2B BYOC.
- Tighten organization SCPs: deny IAM user/access-key creation, deny disabling
  KMS rotation or key deletion scheduling, deny disabling EBS default
  encryption, and deny mutations on organization CloudTrail trails.
- Capture S3 object-level events in the organization CloudTrail through the
  new `logArchive.s3DataEventBucketArns` and
  `organizationAudit.s3DataEventBucketArns` config fields. Set them to the
  customer artifact and Vault backup bucket ARNs before admitting customer
  code.
- Harden the CloudTrail bucket policy and KMS key with both `aws:SourceArn`
  and `aws:SourceAccount` conditions. The organization-audit stack reads the
  trail name and source account from log-archive's outputs and refuses to run
  if they do not match the local stack.
- Enforce tenant prefix on the customer artifact bucket through a bucket
  policy `Deny` for `s3:PutObject`, `s3:DeleteObject`, and
  `s3:DeleteObjectVersion` outside `tenant/*/job/*/artifact/*` and
  `tenant/*/job/*/manifest/*`.
- Enable GuardDuty, Security Hub, AWS Config, CloudTrail organization trails, and immutable log archive.
- Add image signing, SBOM, provenance, and admission verification. The baseline
  now enforces Sigstore keyless image signatures, SLSA provenance, and SPDX SBOM
  attestations for application pods.

## Phase 3: Secrets and Identity

- Deploy or integrate Vault in a dedicated account.
- Configure Kubernetes auth per cluster.
- Connect IAM Identity Center to the real external IdP and SCIM source.
- Enforce GitHub branch rules, CODEOWNERS, required checks, protected environments, secret scanning, and code scanning. The repo now includes CODEOWNERS, Dependabot config, a PR security checklist, a pinned CI workflow, and a `github-governance` Pulumi stack for repository rulesets, Actions restrictions, Dependabot security updates, vulnerability alerts, and protected environments; remaining work is replacing org placeholders and exporting evidence.
- Use dynamic credentials for databases, object storage brokers, and execution services.
- Rotate all static bootstrap credentials.
- Add break-glass access with alerting.
- Move Tailscale operator credentials to Vault-backed rotation or workload identity federation.

## Phase 4: Client Code Execution

- Use E2B BYOC as the preferred production execution path in dedicated
  execution AWS accounts. Use fully self-hosted E2B only when the BYOC
  control-plane relationship is not acceptable for a tenant.
- Keep any in-cluster microVM path as a fail-closed fallback owned and verified
  by the platform repository, not by cloud IaC.
- Deny direct metadata service access.
- Enforce CPU, memory, disk, network, and wall-clock quotas.
- Add per-job identity and audit logs.
- Route all outbound traffic through the egress VPC.

## Phase 5: Tenant Isolation

- Define tenant tiers.
- Add per-tenant KMS keys for higher tiers. The execution artifact store now has
  a KMS-backed shared baseline and requires dedicated KMS for enterprise tiers;
  remaining work is automated tenant-specific store/key creation.
- Add dedicated execution accounts or clusters for enterprise tenants.
- Add tenant-aware authorization tests.
- Automate customer deletion, export, and retention workflows. The repo now
  defines deletion/export manifest requirements in [customer-data.md](customer-data.md).

## Phase 6: Production Readiness

- Run restore drills (quarterly cadence). See [disaster-recovery.md](disaster-recovery.md).
  AWS Backup organization plan with multi-region KMS replicas and vault lock
  is now deployed via the `backup` stack.
- Aurora baseline now ships in `src/database.ts` with IAM auth, CMK, deletion
  protection, RDS Proxy, and audit logging. See [database.md](database.md).
- Platform-owned admission, Vault, Falco, and agent namespaces consume only the
  verified cloud handoff; their deployment and validation are not IaC work.
- WAFv2 Web ACL with managed rule sets, bot control, and a strict
  model-gateway rate limit. See [waf.md](waf.md).
- EventBridge detection rules + SNS fan-out for GuardDuty, IAM, KMS,
  CloudTrail, Config, and Security Hub events.
- AWS Config conformance pack for CIS AWS Foundations + EKS hardening, and
  optional Audit Manager assessment. See [compliance.md](compliance.md).
- Per-tenant AWS Budgets and Cost Anomaly Detection. See
  [cost-controls.md](cost-controls.md).
- Macie sensitive-data discovery jobs over customer artifact and Vault
  backup buckets.
- Route 53 Resolver query logs in every workload VPC for DNS-layer forensics.
- SLSA Level 3 release workflow using
  `slsa-framework/slsa-github-generator`.
- Public ingress hub: CloudFront + WAFv2 + ACM + CloudFront VPC Origin to an
  internal NLB. No public IP in any VPC; the "hub" lives at the AWS edge,
  not in a VPC. See [ingress.md](ingress.md).
- ExternalDNS reconciles Route 53 from in-cluster Gateway API resources.
- Argo Rollouts ships canary + blue-green progressive delivery.

Remaining work for production:

- Run sandbox escape tabletop exercises.
- Run the customer-code incident runbooks in [incident-response.md](incident-response.md).
- Run red-team testing.
- Load test egress, firewall, and execution services.
- Wire Falco events into the SIEM via Security Hub custom findings.
- Build the per-tenant tag policy for FinOps and the broker service for
  agentic AI tool-call orchestration.
