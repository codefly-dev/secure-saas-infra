# Deploy Runbook

This is the intended greenfield order. Run `npm test` before starting and `pulumi preview --policy-pack ./policy` before every `pulumi up`.

## 0. Prepare

1. Run `npm run preflight`.
2. Copy `onboarding.config.example.json` to `onboarding.local.json` and run `npm run onboard -- --config onboarding.local.json --write`.
3. Replace `your-github-org` in `Pulumi.github-governance.yaml` and `.github/CODEOWNERS` if you did not use the onboarding helper.
4. Replace every `aws+...@example.com` email in `Pulumi.management.yaml`.
5. Replace `111111111111` with the real management account ID in `Pulumi.log-archive.yaml`.
6. Replace every `your-pulumi-org/secure-saas-infra/...` stack reference.
7. Enable IAM Identity Center for the organization.
8. Replace GitHub owner/repo and deployer policy ARNs in `Pulumi.github-oidc.yaml`.
9. Add EKS admin role ARNs to platform and execution stack files.
10. Confirm CIDRs do not overlap.
11. Run `npm run preflight:strict` and `npm run verify:onboarding -- --config onboarding.local.json` after real stack files exist.

## 1. GitHub Governance

Run before account vending. This stack does not need AWS credentials.

```sh
pulumi stack init github-governance
cp Pulumi.github-governance.yaml.example Pulumi.github-governance.yaml
pulumi preview --stack github-governance
pulumi up --stack github-governance
```

Set `GITHUB_TOKEN` to a GitHub token that can administer the target repository.
The stack enables repository vulnerability alerts, Dependabot security updates,
Actions SHA pinning, selected Actions allowlists, a `main` ruleset, a push
ruleset for secret-like files and oversized files, and protected deployment
environments. Organization settings are optional and disabled by default because
they affect future repositories.

## 2. Management Account

```sh
pulumi stack init management
cp Pulumi.management.yaml.example Pulumi.management.yaml
pulumi preview --stack management
pulumi up --stack management
```

Wait until all member accounts are `ACTIVE`.

The management stack also delegates GuardDuty, Security Hub, Inspector, and AWS Config organization administration to `security-tooling`.

## 3. Identity

Run in the management account after IAM Identity Center is enabled.

```sh
pulumi stack init identity
cp Pulumi.identity.yaml.example Pulumi.identity.yaml
pulumi preview --stack identity
pulumi up --stack identity
```

This creates group-based IAM Identity Center permission sets and account assignments. If groups come from an external IdP, set `create: false` or provide `groupId` values in the stack config.

## 4. GitHub OIDC

Run in each AWS account where GitHub Actions needs preview or deploy access.

```sh
pulumi stack init github-oidc
cp Pulumi.github-oidc.yaml.example Pulumi.github-oidc.yaml
pulumi preview --stack github-oidc
pulumi up --stack github-oidc
```

Use GitHub protected environments for deploy roles, especially production. The AWS trust policy is scoped to explicit refs or environments, and the `github-governance` stack applies the repository-side rules and environment gates.

## 5. Log Archive

Run in the `log-archive` account.

```sh
pulumi stack init log-archive
cp Pulumi.log-archive.yaml.example Pulumi.log-archive.yaml
pulumi preview --stack log-archive
pulumi up --stack log-archive
```

## 6. Organization Audit

Run in the management account after the log archive stack exists.

```sh
pulumi stack init organization-audit
cp Pulumi.organization-audit.yaml.example Pulumi.organization-audit.yaml
pulumi preview --stack organization-audit
pulumi up --stack organization-audit
```

## 7. Security And Shared Services

Run each stack in its matching account.

```sh
pulumi stack init security-tooling
cp Pulumi.security-tooling.yaml.example Pulumi.security-tooling.yaml
pulumi preview --stack security-tooling
pulumi up --stack security-tooling

pulumi stack init shared-services
cp Pulumi.shared-services.yaml.example Pulumi.shared-services.yaml
pulumi preview --stack shared-services
pulumi up --stack shared-services
```

After `shared-services`, put the real Tailscale OAuth values into the created Secrets Manager secrets.

## 8. Network

Run in the `network` account.

```sh
pulumi stack init network
cp Pulumi.network.yaml.example Pulumi.network.yaml
pulumi preview --stack network
pulumi up --stack network
```

## 9. Platform And Execution

Run each stack in its matching workload account.

```sh
pulumi stack init platform-dev
cp Pulumi.platform-dev.yaml.example Pulumi.platform-dev.yaml
pulumi preview --stack platform-dev
pulumi up --stack platform-dev

pulumi stack init execution-dev
cp Pulumi.execution-dev.yaml.example Pulumi.execution-dev.yaml
pulumi preview --stack execution-dev
pulumi up --stack execution-dev
```

Repeat for staging and production when ready.

## 10. Network Routing

Run in the `network` account after the spoke stacks exist.

```sh
pulumi stack init network-routing
cp Pulumi.network-routing.yaml.example Pulumi.network-routing.yaml
pulumi preview --stack network-routing
pulumi up --stack network-routing
```

## 11. GitOps Bootstrap

Render first:

```sh
npm run validate:gitops
```

Then bootstrap Argo CD applications from the matching overlay. `gitops/bootstrap/argocd` defaults to dev; staging and production have explicit overlays.

```sh
kubectl apply -k gitops/bootstrap/argocd
kubectl apply -k gitops/bootstrap/argocd/overlays/staging
kubectl apply -k gitops/bootstrap/argocd/overlays/production
```

This installs cert-manager, Gateway API CRDs, Istio ambient mode, Kyverno, metrics-server, kube-prometheus-stack, Vault Secrets Operator, Tailscale Operator, namespaces, network policies, and mesh security defaults.

For production customer-code execution, deploy E2B BYOC in the dedicated
execution AWS account before admitting jobs. Use
[e2b-byoc.md](e2b-byoc.md) to review the vendor role, private load balancer,
centralized egress path, runtime log storage, and broker audit contract.
If E2B onboarding requires a vendor IAM role, set
`secure-saas-infra:e2bByocAccess.createVendorRole: true` only after replacing
vendor principal ARNs, external ID, and account-local least-privilege policy
ARNs.

Execution stacks also create the customer artifact store described in
[customer-data.md](customer-data.md). Before admitting customer-code jobs,
confirm the broker writes only tenant-scoped prefixes and emits deletion/export
manifests.

For the in-cluster fallback, install or select nodes with the `kata-clh`
runtime handler and label them `deus.dev/sandbox-runtime=microvm` before
admitting customer-code jobs. The baseline creates the `deus-microvm`
RuntimeClass, requires execution audit metadata, and Kyverno denies execution
pods that do not request it.

Before application deploys, configure CI to sign images keylessly with GitHub
Actions OIDC and publish SLSA provenance plus SPDX SBOM attestations. Unsigned
or unattested application images are denied by Kyverno.

## Policy Gate

The local Policy Pack in `policy/` blocks the highest-risk mistakes during preview:

- public EKS API endpoints;
- missing EKS secrets encryption;
- public security group ingress;
- Internet or NAT gateways outside the egress VPC;
- audit/backup buckets without Object Lock;
- KMS keys without rotation;
- organization CloudTrail without multi-region logging and log validation;
- VPC endpoints without explicit endpoint policies or with full-access policies;
- VPC endpoint policies that omit same-account principal scoping;
- VPC Flow Logs that do not capture all traffic;
- AWS Network Firewall logging that omits FLOW or ALERT logs;
- broad IAM identity policies, high-risk managed admin policies, wildcard
  Allow actions, and unbounded privilege-escalation actions, including IAM
  Identity Center permission set inline policies;
- CloudWatch Log Groups with less than 365 days retention;
- Secrets Manager secrets without customer-managed KMS;
- S3 bucket encryption that is not customer-managed KMS or that permits SSE-C;
- IAM users and long-lived IAM access keys;
- EC2 instances that do not require IMDSv2.

The `validateConfig` step also rejects unsafe stack-config combinations before
the Pulumi resources run:

- `network-hub` and `single-account` stacks must enable AWS Network Firewall
  in production-like environments (`production`, `prod`, `prd`, `staging`,
  any `*-prod` or `*-staging`);
- `platform`, `execution`, and `single-account` stacks with private EKS
  endpoints must declare at least one `adminRoleArns` entry;
- `shared-services` stacks cannot create the Vault backup bucket or the
  Tailscale bootstrap secrets without also creating the customer-managed Vault
  KMS key;
- the `microvm-runtimeclass` execution sandbox provider is held to the same
  isolation boundary as `e2b-byoc` (dedicated account, private load balancer,
  centralized egress);
- the `organization-audit` trail name must match the log-archive stack's
  `organizationTrailName` and the audit stack must run in the same account
  the log-archive bucket policy trusts.

## GitHub Gate

Before production, apply the `github-governance` stack and keep evidence for
rulesets, CODEOWNERS enforcement, required checks, protected environments, secret
scanning, push protection, Dependabot, code scanning, and OIDC deploy-role trust
policies. Use [github-security.md](github-security.md) for the evidence list and
manual checks that Pulumi cannot read back in this repo.

## 12. Backup, Detection, Compliance, Cost Controls, Macie, WAF

After workload stacks deploy, run the security-side stacks. Each runs in the
matching AWS account.

```sh
pulumi stack init backup
cp Pulumi.backup.yaml.example Pulumi.backup.yaml
pulumi up --stack backup

pulumi stack init detection
cp Pulumi.detection.yaml.example Pulumi.detection.yaml
pulumi up --stack detection

pulumi stack init compliance
cp Pulumi.compliance.yaml.example Pulumi.compliance.yaml
pulumi up --stack compliance

pulumi stack init cost-controls
cp Pulumi.cost-controls.yaml.example Pulumi.cost-controls.yaml
pulumi up --stack cost-controls

pulumi stack init macie
cp Pulumi.macie.yaml.example Pulumi.macie.yaml
pulumi up --stack macie

pulumi stack init waf
cp Pulumi.waf.yaml.example Pulumi.waf.yaml
pulumi up --stack waf
```

The `backup` stack runs in each workload account where you want
cross-region recovery (`platform-prod`, `execution-prod`, `shared-services`).
The `detection`, `compliance`, and `macie` stacks run in `security-tooling`.
The `cost-controls` stack runs in `management`. The `waf` stack runs in the
account that owns the public ingress (typically `platform-prod`).

## 13. Vault and Falco

Both run via Argo CD; sync them after the cluster bootstraps:

```sh
kubectl get applications -n argocd vault falco
```

Vault uses AWS KMS auto-unseal keyed against
`alias/deus-shared-services-vault-auto-unseal`. Provide the unseal IAM role
to the Vault `ServiceAccount` via Pod Identity before initial unseal.

## Incident Gate

Before production, run tabletop exercises for the runbooks in
[incident-response.md](incident-response.md), especially customer code exposure,
sandbox escape, suspicious egress, leaked deploy credentials, and tenant
deletion/export failure.
