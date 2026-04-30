# Database Baseline

The `database` module deploys an Aurora cluster (PostgreSQL or MySQL) with the
secure-by-default posture required for customer-data workloads.

## Posture

- Private subnet placement only; no `publiclyAccessible` instances.
- Storage encryption with a per-cluster customer-managed KMS key (rotation +
  30-day deletion window). Enforced by Pulumi policy
  `rds-clusters-private-and-protected`.
- IAM database authentication enabled. Bootstrap master password lives in
  Secrets Manager with KMS encryption; rotate it through Vault dynamic
  credentials after first deploy.
- Deletion protection on by default. The mandatory policy pack rejects
  `deletionProtection: false`.
- Backup retention >= 14 days (35 in the platform-prod example), copy-tagged
  for AWS Backup, and PITR enabled by default through Aurora.
- Multi-AZ via at least two cluster instances. The validator rejects
  `instanceCount < 2`.
- Performance Insights with KMS encryption and 731-day retention so forensics
  go back two years.
- CloudWatch logs export: `postgresql` for Aurora PostgreSQL, audit + error +
  general + slow-query for Aurora MySQL.
- A parameter group that turns on `pgaudit`, forces SSL, and logs DDL/slow
  statements (or `server_audit_logging` for MySQL).
- Optional RDS Proxy with `requireTls`, IAM auth required, and reviewed
  least-privilege secrets policy. Mandatory policy pack rejects RDS Proxies
  without TLS.

## Stack config

`Pulumi.platform-prod.yaml.example` now includes:

```yaml
secure-saas-infra:database:
  name: control-plane
  engine: aurora-postgresql
  engineVersion: "16.4"
  engineMajorVersion: "16"
  databaseName: deus
  masterUsername: deus_admin
  port: 5432
  instanceClass: db.r6g.large
  instanceCount: 2
  backupRetentionDays: 35
  deletionProtection: true
  createProxy: true
```

`validateDatabaseConfig` rejects `engine` values outside
`aurora-postgresql`/`aurora-mysql`, `deletionProtection: false`,
`backupRetentionDays < 14`, `instanceCount < 2`, and out-of-range `port`.

## Operating

- The bootstrap master password in Secrets Manager is a placeholder. Rotate
  to Vault-issued dynamic credentials before opening the cluster to
  application traffic.
- Use the RDS Proxy endpoint for application connections so credential
  rotation is transparent and connection pooling is enforced.
- Tag the cluster with `Backup=required`; AWS Backup picks it up via the
  selection from the `backup` stack.
- Monitor `RDSDeletionProtection` and `RDSStorageEncrypted` Config rules from
  the compliance conformance pack.
