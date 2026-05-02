# Secure SaaS Infrastructure

This repository is the starting implementation for a secure SaaS platform that hosts client code.

The baseline uses:

- Pulumi TypeScript for AWS infrastructure.
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
- GitOps-ready Kubernetes security baseline manifests.
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
- Config-time validators for production firewall posture, private-EKS
  `adminRoleArns`, shared-services KMS coverage, and `microvm-runtimeclass`
  isolation boundary.
- AWS Backup organization plan: multi-region KMS replicas, vault lock,
  cross-region copy, tag-based selection. See [docs/disaster-recovery.md](docs/disaster-recovery.md).
- Aurora baseline (PostgreSQL or MySQL) with IAM auth, CMK, deletion
  protection, RDS Proxy, audit logging. See [docs/database.md](docs/database.md).
- Agent broker / agent egress namespaces, Kyverno audit metadata enforcement,
  WAF model-gateway rate limit. See [docs/agentic-ai.md](docs/agentic-ai.md).
- Public WAFv2 Web ACL with managed rule sets, bot control, and a strict
  model-gateway rate limit. See [docs/waf.md](docs/waf.md).
- EventBridge detection rules + SNS fan-out for GuardDuty, IAM, KMS,
  CloudTrail, Config, and Security Hub events.
- AWS Config conformance pack for CIS AWS Foundations + EKS hardening, and an
  optional Audit Manager assessment. See [docs/compliance.md](docs/compliance.md).
- Per-tenant AWS Budgets and Cost Anomaly Detection. See [docs/cost-controls.md](docs/cost-controls.md).
- Macie classification jobs over the customer artifact and Vault backup
  buckets.
- Vault Helm release (Raft + AWS KMS auto-unseal) and Falco DaemonSet (modern
  eBPF) wired through Argo CD. See [docs/runtime-security.md](docs/runtime-security.md).
- VPC-level Route 53 Resolver query logs in every workload VPC.
- SLSA Level 3 release workflow using `slsa-framework/slsa-github-generator`.
- Public ingress hub: CloudFront + WAFv2 + ACM (TLS 1.3) + VPC Origin to an
  internal NLB → Istio ambient → backends. No public IP in any VPC. See
  [docs/ingress.md](docs/ingress.md).
- ExternalDNS reconciles Route 53 from in-cluster `Service`/`Ingress`/Gateway
  API resources; Argo Rollouts ships canary + blue-green progressive
  delivery.
- DNS module: Route 53 root zone + per-environment delegated subdomain zones
  (`dev.<root>`, `staging.<root>`, `prod.<root>`) with public-zone query
  logging.
- Argo CD installed via Pulumi (`@pulumi/kubernetes` Helm release) — replaces
  the manual `kubectl apply -k` bootstrap; Argo CD then self-syncs every
  platform application from the repo.
- AWS Organizations service-access enabled at the org level for AWS Backup,
  IAM Access Analyzer, IAM Identity Center, AWS RAM, AWS Firewall Manager,
  and CloudFormation StackSets so dependent stacks deploy without console
  clicks.
- Single-command bootstrap (`npm run bootstrap`) provisions org + accounts +
  identity + log archive + organization audit + security tooling + shared
  services + DNS + network + detection + compliance + macie + cost-controls
  + per-env workload + per-env edge in one orchestrated run with
  cross-account assume-role wired automatically.

## One-command Bootstrap

```sh
cp onboarding.config.example.json onboarding.local.json
# Edit onboarding.local.json: githubOrg, pulumiOrg, accountEmailDomain, etc.

GITHUB_TOKEN=ghp_xxx npm run bootstrap -- --environment all
```

`scripts/bootstrap.mjs` walks four phases — foundation, shared, workload,
edge — and provisions the entire landing zone end-to-end. See
[docs/bootstrap.md](docs/bootstrap.md) for the human-only prerequisites
(create the AWS root account, enable IAM Identity Center, create the
Tailscale OAuth client) and the per-phase stack list.

## First Deployment Flow

1. Install dependencies:

   ```sh
   npm install
   ```

2. Run the local safety preflight:

   ```sh
   npm run preflight
   ```

3. Generate local onboarding files:

   ```sh
   cp onboarding.config.example.json onboarding.local.json
   npm run onboard -- --config onboarding.local.json --write
   npm run preflight:strict
   npm run verify:onboarding -- --config onboarding.local.json
   ```

   See [docs/onboarding.md](docs/onboarding.md) for all supported flags.

4. Apply repository governance before AWS account vending:

   ```sh
   pulumi stack init github-governance
   cp Pulumi.github-governance.yaml.example Pulumi.github-governance.yaml
   pulumi preview --stack github-governance
   pulumi up --stack github-governance
   ```

   Set `GITHUB_TOKEN` to a GitHub token that can administer the repository.
   Replace `your-github-org` in `Pulumi.github-governance.yaml` and
   `.github/CODEOWNERS` first.

5. Create the management/account-vending stack:

   ```sh
   pulumi stack init management
   cp Pulumi.management.yaml.example Pulumi.management.yaml
   ```

   Edit all account email addresses before previewing.

6. Preview the account plan from the AWS Organizations management account:

   ```sh
   pulumi preview --stack management
   ```

7. Configure identity after the member accounts are active:

   ```sh
   pulumi stack init identity
   cp Pulumi.identity.yaml.example Pulumi.identity.yaml
   pulumi stack init github-oidc
   cp Pulumi.github-oidc.yaml.example Pulumi.github-oidc.yaml
   ```

8. Create the network-account stack after the `network` AWS account exists:

   ```sh
   pulumi stack init network
   cp Pulumi.network.yaml.example Pulumi.network.yaml
   ```

9. Create the log archive and organization audit stacks:

   ```sh
   pulumi stack init log-archive
   cp Pulumi.log-archive.yaml.example Pulumi.log-archive.yaml
   pulumi stack init organization-audit
   cp Pulumi.organization-audit.yaml.example Pulumi.organization-audit.yaml
   ```

10. Create security tooling and shared services:

```sh
pulumi stack init security-tooling
cp Pulumi.security-tooling.yaml.example Pulumi.security-tooling.yaml
pulumi stack init shared-services
cp Pulumi.shared-services.yaml.example Pulumi.shared-services.yaml
```

11. Create the account-specific platform and execution stacks after the Transit Gateway is shared:

```sh
pulumi stack init platform-dev
cp Pulumi.platform-dev.yaml.example Pulumi.platform-dev.yaml
pulumi stack init execution-dev
cp Pulumi.execution-dev.yaml.example Pulumi.execution-dev.yaml
```

Edit `secure-saas-infra:spoke.networkStackRef` in each file so it points to your real `network` stack.

12. Run the network routing stack in the network account after spoke stacks export their attachment IDs:

```sh
pulumi stack init network-routing
cp Pulumi.network-routing.yaml.example Pulumi.network-routing.yaml
```

13. Use the single-account dev stack only for fast local iteration or a proof of concept:

```sh
pulumi stack init dev
cp Pulumi.dev.yaml.example Pulumi.dev.yaml
```

14. Edit stack files for the target AWS account, region, CIDR plan, Pulumi stack references, account IDs, and admin role ARNs.

15. Preview:

```sh
pulumi preview --policy-pack ./policy --stack <stack-name>
```

16. Deploy:

```sh
npm run up
```

## Current Scope

This is the foundation slice, not the whole product. It creates the network and cluster security baseline that later layers depend on:

- Network-services egress VPC.
- Transit Gateway and route tables.
- Private account-specific platform and execution VPCs.
- Cross-account Transit Gateway attachment routing.
- Optional AWS Network Firewall insertion point.
- EKS clusters with private API endpoints and Auto Mode.
- Tailscale operator/admin access baseline.
- GitOps manifests for default-deny and restricted pod posture.

See [docs/roadmap.md](docs/roadmap.md) for the next implementation phases.
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
