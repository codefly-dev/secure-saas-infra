# Customer Data Boundary

Customer source, execution artifacts, derived indexes, logs, and export bundles
must be treated as tenant-scoped confidential data.

## Artifact Store

Execution stacks create a customer artifact store by default. The store is for
approved outputs from the brokered execution path, not for platform deploy
artifacts or logs.

The scaffold creates:

- customer-managed KMS key with rotation and a 30-day deletion window;
- private S3 bucket with public access blocked;
- versioning enabled;
- default KMS encryption with SSE-C blocked;
- TLS-only bucket policy;
- lifecycle expiration for current and noncurrent versions;
- tags that identify tenant-prefix, deletion-manifest, and export-manifest
  requirements.

Default stack config:

```yaml
secure-saas-infra:customerData:
  createArtifactStore: true
  artifactRetentionDays: 90
  noncurrentVersionExpirationDays: 30
  requireTenantScopedPrefixes: true
  requireDeletionManifests: true
  requireExportManifests: true
  enterpriseDedicatedKmsRequired: true
```

The config validator rejects execution stacks that disable the artifact store,
omit tenant-scoped prefixes, omit deletion or export manifests, or disable
dedicated KMS requirements for enterprise tenant tiers.

## Prefix Contract

The broker must write customer artifacts under immutable tenant and job prefixes:

```text
tenant/<tenant-id>/job/<job-id>/artifact/<artifact-name>
tenant/<tenant-id>/job/<job-id>/manifest/deletion.json
tenant/<tenant-id>/job/<job-id>/manifest/export.json
```

The broker must not accept tenant IDs, job IDs, or object keys directly from
customer code. Customer code can write only to a sandbox-local filesystem; the
broker decides which artifacts are persisted.

The artifact bucket policy denies `s3:PutObject`, `s3:DeleteObject`, and
`s3:DeleteObjectVersion` for any key that is not under
`tenant/*/job/*/artifact/*` or `tenant/*/job/*/manifest/*`. A broker bug that
tries to write a top-level key, a tenant-only key, or a job-only key is
rejected by S3 in addition to broker-side checks.

## Deletion Manifest

A deletion manifest should include:

- tenant ID;
- job IDs and source revisions covered;
- object keys and versions deleted or retained;
- derived indexes deleted;
- snapshots or templates affected;
- retention exception reason when an object is retained;
- timestamp, actor, and approval record.

## Export Manifest

An export manifest should include:

- tenant ID;
- requested export scope;
- object keys and versions included;
- derived indexes included;
- source revisions included;
- integrity hashes;
- requester, approver, timestamp, and delivery channel.

## Enterprise Tenant Tier

For enterprise tenants, use dedicated execution accounts or dedicated artifact
stores with tenant-specific KMS keys and egress policies. The shared artifact
store is acceptable only for lower-risk tiers where tenant isolation is enforced
by the broker, IAM, S3 prefixes, and audit evidence.
