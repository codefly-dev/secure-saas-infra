# Mind Server Security Baseline

Mind server handles customer source code. Treat customer code, prompts, execution
artifacts, logs, and derived indexes as confidential customer data. The security
model is closer to a private code-hosting and execution platform than a normal
SaaS control plane.

## Required Posture

Production must run in a private-by-default mode:

- No public workload VPC egress except through the centralized inspection VPC.
- No public Kubernetes API endpoints.
- No direct human access to execution workloads except audited break-glass.
- No customer code execution in the SaaS control-plane trust boundary.
- No long-lived cloud credentials in GitHub, clusters, or job environments.
- No unpinned or unsigned production images.
- No IAM users or IAM access keys in infrastructure stacks.
- No general-purpose container runtime as the final isolation boundary for
  arbitrary customer code.

Use the `execution` account or cluster as the orchestration boundary. The
preferred production path is E2B BYOC in a dedicated execution AWS account with
private sandbox ingress and centralized inspected egress. Fully self-hosted E2B
is the fallback for tenants that cannot accept the E2B BYOC control-plane
relationship. See [e2b-byoc.md](e2b-byoc.md) for the execution specification.
Kubernetes namespaces and regular containers are defense-in-depth only, not hard
tenant boundaries.

The GitOps baseline now fails closed for the in-cluster execution path: Pods in
the `execution` namespace must request the `deus-microvm` RuntimeClass, disable
service account token automount, and declare CPU, memory, and ephemeral-storage
limits. The `deus-microvm` RuntimeClass maps to a Kata Cloud Hypervisor handler
and selects nodes labeled `deus.dev/sandbox-runtime=microvm`. Workloads will not
run until those nodes and the runtime handler are installed.

## Standards To Track

These are the standards and frameworks that should drive requirements, tests,
evidence, and customer-facing security posture.

| Area                  | Standard                                                                                                                                                                                                                                                                                                                             | How we use it                                                                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Security program      | [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)                                                                                                                                                                                                                                                | Executive-level taxonomy for Govern, Identify, Protect, Detect, Respond, and Recover outcomes.                                                     |
| Control catalog       | [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)                                                                                                                                                                                                                                                          | Control IDs for evidence, policy-as-code coverage, and future FedRAMP-style mappings.                                                              |
| Customer assurance    | [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)                                                                                                                                                                                                             | Minimum scope should be Security, Availability, and Confidentiality. Add Privacy if customer code or logs can include personal data.               |
| ISMS                  | [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)                                                                                                                                                                                                                                                                             | Risk management system, governance, policies, audit cadence, supplier management, and continual improvement.                                       |
| Cloud controls        | [CSA Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix)                                                                                                                                                                                                                                        | Cloud-specific shared-responsibility controls and customer questionnaire mapping.                                                                  |
| AWS hardening         | [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)                                                                                                                                                                                                                                            | AWS account, IAM, logging, network, and storage configuration baselines.                                                                           |
| EKS hardening         | [CIS Amazon EKS Benchmark](https://aws.amazon.com/blogs/containers/introducing-cis-amazon-eks-benchmark/) and [AWS EKS Security Best Practices](https://docs.aws.amazon.com/eks/latest/best-practices/security.html)                                                                                                                 | Cluster logging, IAM/RBAC, pod security, network security, runtime security, detective controls, image security.                                   |
| Kubernetes hardening  | [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and [NSA/CISA Kubernetes Hardening Guidance](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/)                                                       | Enforce restricted pod posture, network separation, least privilege, vulnerability scanning, and log auditing.                                     |
| Container risk        | [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)                                                                                                                                                                                                                                                                       | Container-specific threat model and compensating controls; supports the decision that containers alone are not enough for arbitrary customer code. |
| Software supply chain | [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final), [SLSA](https://openssf.org/projects/slsa/), [Sigstore](https://docs.sigstore.dev/)                                                                                                                                                                              | Secure SDLC, provenance, signed artifacts, SBOMs, hardened builders, and deployment-time verification.                                             |
| CI/CD risk            | [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)                                                                                                                                                                                                                                      | Pipeline identity, artifact integrity, dependency-chain abuse, credential hygiene, and CI/CD logging.                                              |
| GitHub-style mode     | [GitHub Enterprise hardening](https://docs.github.com/en/enterprise-server@3.20/admin/configuring-settings/hardening-security-for-your-enterprise), [GitHub Actions OIDC for AWS](https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services) | Private access, separation for user-supplied content, protected repo flows, and OIDC instead of static deploy keys.                                |
| Federal readiness     | [FedRAMP Rev. 5 continuous monitoring guidance](https://www.fedramp.gov/docs/rev5/playbook/csp/continuous-monitoring/vulnerability-scanning/)                                                                                                                                                                                        | Not required unless we sell to U.S. federal customers, but useful for image hardening, scanning cadence, inventory, and POA&M discipline.          |

## Control Requirements

### Customer Code Isolation

- Customer code must execute only in execution accounts or dedicated enterprise
  tenant accounts.
- The control plane may schedule jobs, but it must not mount or execute customer
  repositories directly.
- Use per-job or per-tenant identities with minimum AWS and Kubernetes
  permissions.
- Enforce CPU, memory, process, file, disk, network, and wall-clock limits.
- Deny instance metadata access from job sandboxes unless an explicit brokered
  identity flow exists.
- Destroy job filesystems by default. Persist only approved artifacts into
  encrypted, tenant-scoped storage.
- Use the [customer-data.md](customer-data.md) artifact-store contract for
  prefixes, deletion manifests, export manifests, and enterprise KMS tiers.
- For enterprise tenants, support dedicated execution accounts, dedicated KMS
  keys, and dedicated egress policy.

### Network And Egress

- Workload VPCs must have no Internet Gateway and no NAT Gateway.
- All internet egress must pass through the centralized egress VPC and AWS
  Network Firewall or an approved application-layer egress proxy.
- Workload VPCs must use explicit VPC endpoint policies for AWS service access.
  Endpoint policies are defense-in-depth and do not replace IAM identity
  policies, resource policies, or tenant authorization checks.
- Endpoint policies must scope calls to same-account principals and, where AWS
  exposes the global key, same-account resources.
- Production egress allowlists must be change-controlled. Customer code should
  request temporary egress grants through a broker, not by editing broad firewall
  allowlists.
- Tailscale is for operator/admin access only. It must never become the normal
  outbound path for customer code.
- Execution-plane Tailscale access must stay break-glass only.

### Kubernetes

- Keep EKS endpoint public access disabled.
- Keep Kubernetes secret envelope encryption enabled with customer-managed KMS.
- Keep control-plane logs enabled for API, audit, authenticator, controller
  manager, and scheduler.
- Enforce Pod Security `restricted` for application namespaces.
- Enforce default-deny NetworkPolicies and Istio default-deny AuthorizationPolicy.
- Pin images by digest and require signed provenance before production deploy.
- Admit application images only when Sigstore verification succeeds for a GitHub
  Actions keyless signing identity and matching SLSA provenance attestation.
- Require an SPDX SBOM attestation for admitted application images.
- Do not grant cluster-admin to normal developer groups. Use audited break-glass
  for emergency execution access.

### Secrets And Credentials

- Use GitHub OIDC or workload identity federation for CI/CD. Do not store static
  cloud deploy keys.
- Use IAM Identity Center for humans. Do not create IAM users or long-lived IAM
  access keys.
- Use Vault or cloud-native dynamic credentials for database, object storage, and
  execution-service access.
- Bootstrap secrets must be rotated into managed secret paths after deployment.
- Customer code must not receive platform secrets. When a job needs an external
  credential, issue a scoped, time-bound brokered token.

### Supply Chain

- Build images in hardened, isolated builders.
- Generate SBOMs for production images.
- Sign images and attest build provenance.
- Enforce digest-pinned images and deployment-time signature verification.
- Scan source dependencies, images, IaC, and Kubernetes manifests before merge
  and before deploy.
- Mirror or proxy high-risk package ecosystems when customer code execution needs
  package installation.

### Detection, Logging, And Forensics

- Centralize CloudTrail, EKS audit logs, VPC flow logs, Network Firewall logs,
  Kubernetes audit events, admission-denial events, and sandbox lifecycle events.
- Retain audit logs in immutable storage.
- Keep CloudWatch security-evidence log groups for at least 365 days before
  archive forwarding or lifecycle transition.
- Alert on execution-plane admin access, egress denials, policy bypass attempts,
  sandbox escape indicators, unexpected metadata access, and unsigned image
  admission.
- Maintain enough job metadata to reconstruct who ran what, when, from which
  source revision, under which identity, with which egress grants.

## Current Implementation Review

Already present in this repository:

- Multi-account model separating management, security tooling, log archive,
  network, shared services, platform, and execution accounts.
- Private spoke VPCs with no direct IGW/NAT and default egress routed through
  Transit Gateway to a central egress VPC.
- Optional AWS Network Firewall domain allowlist with FLOW and ALERT logging.
- VPC Flow Logs for centralized egress and workload spoke VPCs.
- Explicit VPC endpoint policies for AWS service endpoints, including S3, ECR,
  STS, KMS, Secrets Manager, CloudWatch Logs, CloudWatch Metrics, SSM, EKS, EKS
  Pod Identity, EC2, and Elastic Load Balancing. Policies are scoped with
  `aws:PrincipalAccount` and `aws:ResourceAccount` where available.
- Private EKS API endpoints by default.
- EKS secret envelope encryption with KMS.
- EKS control-plane logging.
- EKS Access Entries instead of `aws-auth`.
- VPC CNI network policy in strict mode.
- GitOps baseline for namespaces, default-deny NetworkPolicies, Istio strict
  mTLS, Istio default-deny AuthorizationPolicies, Kyverno restricted pod posture,
  host namespace denial, RuntimeDefault seccomp, and image digest enforcement.
- Execution namespace admission requires the `deus-microvm` RuntimeClass,
  disabled service account token automount, resource limits, and per-job audit
  metadata.
- Execution namespace quota and limit ranges cap pod count, CPU, memory, and
  ephemeral-storage blast radius.
- Execution stack config validates the E2B BYOC security specification:
  dedicated account boundary, private load balancers, centralized egress,
  24-hour maximum sandbox lifetime, audit metadata, and brokered credentials.
- Optional E2B BYOC vendor-access role scaffold requires IAM role principals,
  external ID, one-hour maximum sessions, and reviewed least-privilege policies.
- Execution stacks create an encrypted customer artifact store with
  tenant-scoped prefix, deletion-manifest, export-manifest, lifecycle, and KMS
  requirements. See [customer-data.md](customer-data.md).
- Kyverno verifies application image signatures, SLSA provenance, and SPDX SBOM
  attestations through Sigstore keyless identities issued by GitHub Actions.
- GitHub Actions OIDC roles scoped to explicit repository refs or environments.
- Immutable audit log archive with Object Lock and KMS encryption.
- Organization-level GuardDuty, Security Hub, Inspector, and AWS Config
  scaffolding.
- Tailscale pattern that reserves execution access for break-glass.
- Mandatory Pulumi policies for private EKS APIs, Kubernetes secret encryption,
  public ingress denial, centralized egress, Object Lock, KMS rotation, and
  organization CloudTrail posture.
- Mandatory Pulumi policies that require explicit VPC endpoint policies,
  all-traffic VPC Flow Logs, and Network Firewall FLOW plus ALERT logging.
- Mandatory Pulumi policies that require CloudWatch Log Group retention of at
  least 365 days, customer-managed KMS for Secrets Manager and S3 bucket
  encryption, SSE-C rejection for S3 buckets, no IAM users or long-lived access
  keys, and IMDSv2 for EC2 instances.
- Mandatory Pulumi policies that inspect IAM Identity Center permission set
  inline policies for wildcard actions, `NotAction` Allow statements, and
  unbounded privilege-escalation actions.
- Tenant prefix enforcement on the customer artifact bucket: object writes
  outside `tenant/<id>/job/<id>/artifact/*` and `tenant/<id>/job/<id>/manifest/*`
  are denied by the bucket policy in addition to broker checks.
- CloudTrail bucket policy and KMS key require both `aws:SourceArn` and
  `aws:SourceAccount` to defeat confused-deputy access from other accounts.
- Optional CloudTrail S3 data event capture wired through `logArchive` and
  `organizationAudit` config (`s3DataEventBucketArns`).
- Expanded SCP guardrails: deny IAM user/access-key creation, deny disabling
  KMS rotation or scheduling deletion, deny disabling EBS default encryption,
  and deny mutations on organization CloudTrail trails.
- GitHub governance artifacts for CODEOWNERS, Dependabot, and pull request
  security review. See [github-security.md](github-security.md).
- Customer-code incident runbooks. See
  [incident-response.md](incident-response.md).

Important gaps before production customer-code handling:

1. Deploy and validate E2B BYOC in a dedicated execution AWS account, including
   vendor access role review, private sandbox ingress, and centralized egress.
   If using the in-cluster fallback, install and continuously validate the
   actual sandbox node runtime behind `deus-microvm`.
2. Add policy tests or integration tests that prove non-allowlisted egress is
   denied through the deployed firewall path.
3. Extend the customer-data artifact-store contract to derived indexes and
   application authorization tests.
4. Add metadata-service denial or brokered IMDS controls for execution jobs at
   the node/runtime layer. Kubernetes network policy already defaults to deny,
   but sandbox networking must also block metadata access.
5. Add explicit image hardening and scanning cadence aligned with CIS/FedRAMP
   expectations.
6. Apply and export evidence for GitHub organization/repository rulesets in the
   actual GitHub organization. The repo now documents the required settings, but
   the settings still have to be enforced outside Pulumi.
7. Run tabletop exercises against the incident runbooks for customer code
   exposure, sandbox escape, suspicious egress, leaked deploy credentials, and
   tenant deletion/export.

## Production Gate

Do not declare Mind server production-ready for customer code until these gates
pass:

- Untrusted code runs through E2B BYOC or a fully self-hosted equivalent in a
  dedicated execution account. Any in-cluster fallback is admitted only with the
  `deus-microvm` RuntimeClass and the backing microVM runtime installed and
  tested.
- All production deploy artifacts are signed, attested, scanned, and admitted by
  policy.
- Every production execution path has default-deny egress plus an auditable grant
  flow.
- Customer data has tenant-scoped storage, retention, deletion, and export
  controls.
- Security telemetry is centralized, immutable, and alerting on execution-plane
  bypass attempts.
- A SOC 2-ready evidence map exists for Security, Availability, and
  Confidentiality.
- A tabletop exercise has covered sandbox escape and customer code disclosure.
