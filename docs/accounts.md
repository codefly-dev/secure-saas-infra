# AWS Accounts And Pulumi Stacks

The baseline now separates account vending from workload deployment.

## Account Model

The management account owns AWS Organizations. The initial active topology
vends these member accounts:

- `security-tooling`
- `log-archive`
- `network`
- `shared-services`
- `platform-dev`
- `platform-prod`
- `execution-dev`
- `execution-prod`

The `platform-staging` and `execution-staging` definitions remain in the
management configuration with `create: false`. They are validated as a pair in
the `PreProd` OU but are not admitted by the first qualified management seed.
The eight active members plus the management account require capacity for nine
accounts. AWS documents a default of ten but warns that new accounts and
Organizations can receive less. Therefore the first wave creates only the
Organization; a separately qualified full wave observes the effective quota in
`us-east-1` and fails before Pulumi unless capacity is at least nine. Enabling
both staging members would require eleven total accounts and remains rejected.

Environment accounts live under nested `Workloads/NonProd`,
`Workloads/PreProd`, and `Workloads/Prod` OUs. Platform and execution remain
separate AWS accounts inside each environment boundary.

The management account itself is not created by Pulumi. It is the account from which the organization stack runs.

## Stack Files

Use these example files as Pulumi stack templates:

- `Pulumi.management.yaml.example`: creates the exact greenfield OUs and
  account baseline, RAM organization sharing, six standalone trusted-service
  access resources, one consolidated baseline SCP, one Suspended deny-all SCP,
  and the native S3 Block Public Access policy. Delegated administrators are
  deliberately deferred.
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

The only currently admitted AWS mutation is the reviewed
`seedWave: organization-only` management apply. It creates the Organization and
nothing else. This seed is greenfield-only and requires
`createOrganization: true`; existing Organizations require a separately
designed discovery/import adapter.

The next safe sequence is intentionally split:

1. Preview and apply the independently qualified `organization-only` plan.
2. Re-qualify `seedWave: full` and run its read-only preview. The candidate-,
   account-, and configuration-bound capacity/state attestation is frozen in
   the plan manifest and repeated before and after Pulumi.
3. Implement and qualify the member-access installation that replaces and
   immediately retires every broad `DeusOrganizationBootstrap` account-vending
   role.
4. Only then enable full account vending apply and later account-foundation,
   identity, audit, network, workload, database, backup, and edge waves.

GitHub governance and all later stacks are modeled backlog, not current
bootstrap commands. They require their own authority, provider binding,
reviewed plan, and runtime evidence.

## Guardrails

The management stack creates conservative SCPs for member OUs:

- deny member accounts from leaving the organization;
- deny disabling core audit and detection services;
- enforce all four S3 Block Public Access settings with the native
  Organizations `S3_POLICY` type;
- deny IAM user creation, IAM access key creation, and IAM login profile changes;
- deny disabling KMS key rotation or scheduling deletion of customer-managed keys;
- deny disabling EBS default encryption;
- deny mutating organization CloudTrail trails (`DeleteTrail`, `StopLogging`,
  `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`).

SCPs are attached to `Security`, `Infrastructure`, and the parent `Workloads`
OU by default. The workload controls are inherited by its `NonProd`, `PreProd`,
and `Prod` children.

## Required Manual Inputs

Before deploying `Pulumi.management.yaml.example`, replace every active
`aws+...@aws.example.com` value with a globally unique AWS account email address.
Leave both staging definitions disabled. Their placeholder addresses may be
replaced now, but this seed rejects `create: true`; the active nine-account
capacity contract does not admit eleven accounts.

Before deploying `Pulumi.identity.yaml.example`, enable IAM Identity Center in the management account and decide whether groups will be created by Pulumi or synchronized from an external IdP.

Before enabling protected promotion, create the
`codefly-dev/platform-security` GitHub team, grant it repository access, and
verify GitHub recognizes it as the CODEOWNER. Repository-rule mutation is
outside the active management seed.

Before deploying `Pulumi.github-oidc.yaml.example`, replace GitHub owner/repo values and use account-local deployment policy ARNs.

Before deploying workload stacks, assign the named IAM Identity Center
permission sets to each workload account. `eks.accessGrants` resolves those
generated roles and creates EKS Access Entries; resolution fails unless exactly
one role exists.
