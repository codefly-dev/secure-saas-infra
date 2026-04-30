# Implementation Roadmap

## Phase 1: Foundation

- Create AWS landing zone and accounts. The Pulumi account-vending scaffold exists.
- Deploy the centralized egress network. The hub stack scaffold exists.
- Deploy private platform and execution EKS clusters. The account-specific spoke stack modules exist.
- Associate and route cross-account Transit Gateway attachments. The network-routing stack exists.
- Replace bastion access with Tailscale operator/admin access.
- Enable account-level audit, detection, and logging. The log-archive, organization-audit, security-tooling, and shared-services stacks exist.
- Configure workforce and CI/CD identity. IAM Identity Center permission sets/account assignments and GitHub Actions OIDC role scaffolding now exist.
- Bootstrap GitOps security baseline. Argo CD apps now cover Istio ambient mode, cert-manager, Gateway API CRDs, metrics-server, kube-prometheus-stack, Vault Secrets Operator, Tailscale Operator, Kyverno, namespaces, NetworkPolicies, and mesh security defaults.

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
  `adminRoleArns`, shared-services must keep customer-managed KMS for the Vault
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
- Keep the in-cluster microVM path as a fail-closed fallback. The execution
  GitOps baseline now declares the `deus-microvm` RuntimeClass, requires
  per-job audit metadata and resource limits, and applies namespace quotas; the
  remaining work is installing and validating the backing runtime on labeled
  execution nodes.
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
- Agent broker / agent egress namespaces are reserved with Kyverno and
  NetworkPolicy guardrails. See [agentic-ai.md](agentic-ai.md). The broker
  service itself is application code; the IaC reserves the trust boundary.
- Vault deployed via Argo CD with AWS KMS auto-unseal and Raft storage.
- Falco DaemonSet (modern eBPF) wired through Argo CD for syscall-level
  runtime detection. See [runtime-security.md](runtime-security.md).
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

Remaining work for production:

- Run sandbox escape tabletop exercises.
- Run the customer-code incident runbooks in [incident-response.md](incident-response.md).
- Run red-team testing.
- Load test egress, firewall, and execution services.
- Wire Falco events into the SIEM via Security Hub custom findings.
- Build the per-tenant tag policy for FinOps and the broker service for
  agentic AI tool-call orchestration.
