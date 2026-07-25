# Disaster Recovery

This is the recovery posture for the secure SaaS baseline. Treat backups as a
production system: deployed by Pulumi, monitored, alerted, and exercised.

## Targets

| Tier          | RPO       | RTO     | Notes                                                              |
| ------------- | --------- | ------- | ------------------------------------------------------------------ |
| Audit logs    | 0         | n/a     | Immutable Object Lock + multi-region replica.                      |
| Customer code | 1 hour    | 4 hours | Continuous backup + cross-region copy.                             |
| Customer data | 5 minutes | 1 hour  | RDS PITR + AWS Backup continuous backup; cross-region copy.        |
| Control plane | 24 hours  | 4 hours | Daily AWS Backup with 365 day retention.                           |
| Pulumi state  | 1 hour    | 1 hour  | Pulumi Cloud or S3 backend with versioning + replication separate. |

These targets are **commitments** to customers; they drive backup frequency,
copy actions, and the quarterly restore drill.

## AWS Backup

The `backup` Pulumi stack creates:

- a multi-region primary KMS key with rotation enabled and a replica key in
  the configured DR region;
- a primary AWS Backup vault and a cross-region replica vault, both with vault
  lock in COMPLIANCE-equivalent mode (`min/max retention` + cooling-off
  `changeableForDays`);
- a daily backup plan with a `copyAction` to the replica vault, continuous
  backup enabled, cold-storage transition, and tag-based selection
  (`Backup=required`).

The mandatory Pulumi policy pack rejects:

- AWS Backup vaults without a customer-managed KMS key arn or with `forceDestroy`;
- AWS Backup plan rules without a `copyActions` block or with
  `lifecycle.deleteAfter < 35`.

## RDS / Aurora

`database` config defaults enforce:

- storage encryption with a customer-managed KMS key;
- IAM database authentication;
- deletion protection;
- backup retention >= 14 days (35 days in the platform-prod example);
- Performance Insights with 731-day retention;
- audit logging (`pgaudit` for Postgres; `server_audit_logging` for MySQL).

Aurora point-in-time recovery is on by default. Cross-region snapshot copy is
delegated to AWS Backup so a single mechanism covers RDS, EBS, EFS, DynamoDB,
and Vault Raft volumes.

## Pulumi state

The selected management-seed backend is Pulumi Cloud, in
`toussaint-antoine-gmail-com/secure-saas-infra/management`, with Pulumi
Cloud service encryption. Its exact normal export, identity recovery,
same-backend restore, deleted-stack recovery, migration boundary, and drill are
defined in [pulumi-cloud-recovery.md](pulumi-cloud-recovery.md).

The Pulumi state backend must remain outside the account and region of the
production workloads. Supported designs are:

- Use Pulumi Cloud (managed); or
- Self-host the S3 backend in a dedicated account with versioning, MFA delete,
  Object Lock, and cross-region replication into the log-archive account.

Pulumi state in a workload account is a single point of failure during account
compromise. Do not deploy workload stacks with a backend co-located in the
workload account. The current seed admits Pulumi Cloud only; the S3 design
requires a separately qualified backend migration.

## Vault

Vault Raft data and audit volumes are tagged `Backup=required` so AWS Backup
covers them. Vault auto-unseal is keyed against the multi-region KMS replica;
losing the primary region preserves access to the unseal key.

The Vault auto-unseal KMS key, the customer artifact KMS key, and the Aurora
KMS key should each have multi-region replicas in the DR region before
go-live. Single-region keys mean unrecoverable backups if the primary region
loses metadata for the key.

## Account-loss playbook

Treat AWS Organizations management compromise as the worst case:

1. Pulumi state is in a separate org-isolated backend (Pulumi Cloud or another
   AWS Organizations account). Compromise of the management account does not
   mutate stack state.
2. Audit logs are in the `log-archive` account with Object Lock + KMS
   `aws:SourceAccount` conditions and SCP `deny-cloudtrail-mutations`. They
   survive management account compromise.
3. The customer artifact bucket should have S3 cross-region cross-account
   replication into a recovery account (configure
   `customerData.replicationRegion` and `replicationAccountId` once the
   recovery account exists).
4. Backup vaults in the DR region are sufficient to rebuild the workload
   accounts; the management account is rebuilt by re-running
   `Pulumi.management.yaml` against a fresh AWS Organization.

## Restore drills

Quarterly drill, owned by the platform team:

1. Pick a tier (control plane, customer data, audit) on a rotating schedule.
2. Spin up an isolated drill account from the management account.
3. Restore the most recent recovery point into the drill account.
4. Boot the application stack, run the smoke tests, and check artifact and
   audit-log integrity.
5. Capture restore time, RPO realised, and any surprises.
6. Tear down the drill account.

Drill output is part of the SOC 2 evidence package and feeds the next sprint's
backlog.

## Alerts

- AWS Backup job failures route through the `detection` SNS topic.
- Vault lock change windows are alerted via the
  `cloudtrail-mutations` EventBridge rule.
- KMS rotation disable / scheduled deletion is alerted via the
  `kms-rotation-disabled` EventBridge rule.
