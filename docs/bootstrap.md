# One-command Bootstrap

`scripts/bootstrap.mjs` deploys the entire landing zone — AWS Organizations,
member accounts, IAM Identity Center wiring, network hub, security tooling,
log archive, per-env workload accounts, edge ingress — from a single Pulumi
run, given an AWS Organizations management account root credential.

## Prerequisites (humans-only)

These steps cannot be automated and must happen before bootstrap:

| Step | One-time action |
|---|---|
| Create the AWS management account | Sign up at aws.amazon.com; secure root with hardware MFA. |
| Enable IAM Identity Center | One UI click in the management account. AWS exposes no API. |
| GitHub admin token | Issue a token with `repo` and `admin:org` scopes; export as `GITHUB_TOKEN`. |
| Pulumi auth | `pulumi login` against your backend (Pulumi Cloud or self-hosted S3). |
| Tailscale OAuth client | Create at `login.tailscale.com`; values plug into Secrets Manager after `shared-services` runs. |
| E2B BYOC vendor onboarding | Get vendor principal ARN + external ID from E2B; plug into `Pulumi.execution-prod.yaml` after the stack initializes. |
| Domain registrar delegation | If your apex domain is at an external registrar, point its NS records at the Route 53 zone created by the `dns` stack. |
| GitHub Team plan | Required for branch protection / rulesets on private repos (~$4/user/month). |

## Onboarding config

```sh
cp onboarding.config.example.json onboarding.local.json
# Edit: githubOrg, pulumiOrg, accountEmailDomain, etc.
```

## Run it

The bootstrap walks four phases. By default it runs all four for the target environment(s):

```sh
# Provision dev only.
GITHUB_TOKEN=ghp_xxx npm run bootstrap -- --environment dev

# Provision dev + staging + prod (sequential).
GITHUB_TOKEN=ghp_xxx npm run bootstrap -- --environment all

# Provision only the foundation (org, identity, log-archive, audit, etc.).
GITHUB_TOKEN=ghp_xxx npm run bootstrap -- --environment all --phases foundation

# Skip ahead to a specific stack on a known-good plan.
npm run bootstrap -- --environment prod --from-stack ingress-prod

# Show the plan without executing.
npm run bootstrap -- --environment all --dry-run
```

## Phases

| Phase | Stacks |
|---|---|
| `foundation` | `github-governance`, `management`, `identity`, `log-archive`, `organization-audit`, `security-tooling`, `shared-services`, `dns`, `network`, `detection`, `compliance`, `macie`, `cost-controls` |
| `shared` | `backup-{env}` per environment |
| `workload` | `platform-{env}`, `execution-{env}` per environment, plus `network-routing` |
| `edge` | `waf-{env}`, `ingress-{env}`, `argocd-platform-{env}`, `argocd-execution-{env}` |

Phases run in order; within each phase, stacks deploy sequentially in the
declared order.

## Cross-account assume-role

`management` is the only stack that runs against the management account
credentials directly. Every other stack gets its `aws:assumeRole.roleArn`
configured by the bootstrap script using the `organizationAccountIds`
output of the management stack — the orchestrator assumes
`OrganizationAccountAccessRole` (the default member-account role) into
the right account for each stack. No manual stack file edits needed.

For the `argocd-*` stacks: after the cluster's IAM trust is set up via
EKS Access Entries (handled by the `platform-{env}` stack with the role
that's running the bootstrap), the Argo CD Pulumi stack uses
`aws eks get-token` exec auth to talk to the cluster's private API
endpoint. **Run bootstrap from a machine on the Tailscale tailnet** so
the private endpoint is reachable.

## What you can show after bootstrap

1. AWS Organizations with 9 member accounts under `Security`,
   `Infrastructure`, `Workloads`, and `Execution` OUs, each with the
   seven SCPs attached.
2. IAM Identity Center groups + permission sets + account assignments.
3. Log archive bucket with Object Lock + organization CloudTrail
   forwarding into it (`aws:SourceArn` + `aws:SourceAccount`).
4. Centralized inspected egress through AWS Network Firewall, with
   FLOW + ALERT logs.
5. Private EKS Auto Mode clusters in each platform / execution account.
6. Aurora cluster with IAM auth + RDS Proxy (wired via the `database`
   config in the platform stack).
7. AWS Backup org plan with multi-region KMS replicas, vault lock,
   cross-region copy.
8. CloudFront + WAFv2 + ACM + VPC Origin → internal NLB → Istio ambient
   for public ingress.
9. Argo CD running inside each cluster, pulling the GitOps baseline
   (Istio, Kyverno, Falco, Vault, Tailscale operator, ExternalDNS,
   Argo Rollouts, etc.).

## Manual follow-ups (post-bootstrap)

The bootstrap leaves a short list of operational steps that *must* be
human-performed:

- `vault operator init` against the Vault Helm release; distribute the
  Shamir-split unseal keys.
- Drop Tailscale OAuth values into the placeholder Secrets Manager
  secrets (`shared-services` stack created the slots).
- Drop E2B BYOC vendor principal ARN + external ID into
  `Pulumi.execution-prod.yaml`, then re-run that stack.
- Point your registrar's NS records at the Route 53 zone if the apex is
  external.
- Open a PR to update CODEOWNERS to point at the real
  `@your-org/platform-security` team.

## Reset

To tear down a single env:

```sh
pulumi destroy --stack ingress-dev
pulumi destroy --stack waf-dev
# ... in reverse dependency order
```

To tear down everything: drive the same plan in reverse. There is no
`bootstrap --destroy` because organization-level destroy is destructive
in ways that tooling should not make easy. Manual is correct.
