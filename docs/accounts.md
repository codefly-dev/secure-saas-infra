# AWS Accounts And Pulumi Stacks

The baseline now separates account vending from workload deployment.

## Account Model

The management account owns AWS Organizations. It vends these member accounts:

- `security-tooling`
- `log-archive`
- `network`
- `shared-services`
- `platform-dev`
- `platform-staging`
- `platform-prod`
- `execution-dev`
- `execution-staging`
- `execution-prod`

The management account itself is not created by Pulumi. It is the account from which the organization stack runs.

## Stack Files

Use these example files as Pulumi stack templates:

- `Pulumi.management.yaml.example`: creates OUs, accounts, RAM organization sharing, baseline SCPs, and security delegated administrator registration.
- `Pulumi.log-archive.yaml.example`: creates immutable audit log S3 storage with Object Lock, KMS encryption, lifecycle, and CloudTrail bucket policy.
- `Pulumi.organization-audit.yaml.example`: runs in the management account to create the organization CloudTrail writing to the log archive bucket.
- `Pulumi.identity.yaml.example`: creates IAM Identity Center groups, permission sets, and group-to-account assignments.
- `Pulumi.github-governance.yaml.example`: manages GitHub repository rulesets, Actions restrictions, Dependabot security updates, vulnerability alerts, and protected deployment environments.
- `Pulumi.github-oidc.yaml.example`: creates GitHub Actions OIDC roles in whichever target AWS account needs CI/CD access.
- `Pulumi.security-tooling.yaml.example`: enables organization-level GuardDuty, Security Hub, Inspector, and AWS Config aggregation.
- `Pulumi.shared-services.yaml.example`: bootstraps Vault KMS auto-unseal, Vault backup storage, and Tailscale OAuth secret placeholders.
- `Pulumi.network.yaml.example`: creates the central egress/network account hub and shares the Transit Gateway with the organization.
- `Pulumi.network-routing.yaml.example`: runs in the network account after spoke stacks are created and associates/routes cross-account Transit Gateway attachments.
- `Pulumi.dev.yaml.example`: deploys a single-account dev baseline for fast iteration.
- `Pulumi.platform-*.yaml.example` and `Pulumi.execution-*.yaml.example`: create private spoke VPCs, attach to the shared Transit Gateway, and deploy private EKS Auto Mode clusters.
- `Pulumi.security-tooling.yaml.example`, `Pulumi.log-archive.yaml.example`, and `Pulumi.shared-services.yaml.example`: account-level security baselines.
- `Pulumi.backup.yaml.example`: AWS Backup multi-region KMS, locked vaults, and a cross-region copy plan.
- `Pulumi.detection.yaml.example`: EventBridge detection rules + SNS fan-out for GuardDuty, IAM, KMS, CloudTrail, Config, and Security Hub events.
- `Pulumi.compliance.yaml.example`: AWS Config CIS conformance pack + optional Audit Manager assessment.
- `Pulumi.cost-controls.yaml.example`: per-tenant AWS Budgets and Cost Anomaly Detection.
- `Pulumi.macie.yaml.example`: Macie account + scheduled classification jobs over the customer artifact and Vault backup buckets.
- `Pulumi.waf.yaml.example`: WAFv2 Web ACL for the public ingress with managed rule sets, bot control, and a strict model-gateway rate limit.

## Environments

The repo includes Pulumi ESC environment templates under `environments/`:

- `dev`
- `staging`
- `production`

The platform and execution stack examples import these environments so common settings such as region, EKS version, private API posture, and security-service defaults stay centralized.

## Deployment Order

1. Run the `github-governance` stack with a GitHub admin token.
2. Run the management stack from the AWS management account. For a greenfield setup, leave `createOrganization: true`; for an existing AWS Organization, set it to `false`.
3. Wait for all member accounts to reach `ACTIVE`.
4. Enable IAM Identity Center for the organization, then run the `identity` stack from the management account.
5. Run `github-oidc` in each account where GitHub Actions needs preview or deploy access.
6. Run the `log-archive` stack in the log archive account.
7. Run `organization-audit` from the management account after editing its `logArchiveStackRef`.
8. Run `security-tooling` in the security tooling account.
9. Run `shared-services` in the shared services account.
10. Run the network hub stack in the `network` account.
11. Run each `platform-*` and `execution-*` stack in its matching workload account.
12. Run the `network-routing` stack back in the `network` account to accept, associate, and route the cross-account attachments.
13. Use the `dev` stack only when you need a single-account baseline for fast iteration.

## Guardrails

The management stack creates conservative SCPs for member OUs:

- deny member accounts from leaving the organization;
- deny disabling core audit and detection services;
- deny loosening S3 account public access block settings;
- deny IAM user creation, IAM access key creation, and IAM login profile changes;
- deny disabling KMS key rotation or scheduling deletion of customer-managed keys;
- deny disabling EBS default encryption;
- deny mutating organization CloudTrail trails (`DeleteTrail`, `StopLogging`,
  `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`).

SCPs are attached to `Security`, `Infrastructure`, `Workloads`, and `Execution` OUs by default.

## Required Manual Inputs

Before deploying `Pulumi.management.yaml.example`, replace every `aws+...@example.com` value with a globally unique AWS account email address.

Before deploying `Pulumi.identity.yaml.example`, enable IAM Identity Center in the management account and decide whether groups will be created by Pulumi or synchronized from an external IdP.

Before deploying `Pulumi.github-governance.yaml.example`, replace GitHub owner values, replace `.github/CODEOWNERS` owners with a real team, and export `GITHUB_TOKEN` with repository administration access.

Before deploying `Pulumi.github-oidc.yaml.example`, replace GitHub owner/repo values and use account-local deployment policy ARNs.

Before deploying workload stacks, replace empty `adminRoleArns` with the IAM Identity Center or break-glass admin roles that should receive EKS Access Entries.
