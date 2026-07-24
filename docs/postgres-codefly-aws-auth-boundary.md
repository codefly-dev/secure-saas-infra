# PostgreSQL, Codefly, and AWS IAM: Ownership and Authentication Boundary

Status: architecture decision and implementation contract, 2026-07-16.

## Decision

Database migrations are application delivery code. Codefly's PostgreSQL service
owns migration discovery, checksums, ordering, locking, execution, failure
handling, and release evidence. This IaC repository does not render or execute a
migration Job and does not interpret SQL.

IaC owns the infrastructure that makes a separately authorized Codefly
migration worker possible: the managed database, private network paths, KMS,
RDS Proxy, EKS workload identities, exact `rds-db:connect` policies, and
reference-only outputs.

The word `migration` may therefore appear in IaC only as an infrastructure
access class: a distinct IAM role, Kubernetes ServiceAccount association,
database-login name, and source security group. It never means migration code
or a migration runner in this repository.

## Ownership

| Concern                                                                     | Owner                                     |
| --------------------------------------------------------------------------- | ----------------------------------------- |
| Aurora/RDS lifecycle, encryption, backups, Proxy, private endpoints         | IaC                                       |
| EKS Pod Identity role and namespace/ServiceAccount association              | IaC                                       |
| Exact IAM permission to connect as one PostgreSQL login                     | IaC                                       |
| Runtime, migration, and bootstrap source security groups                    | IaC                                       |
| RDS-managed master secret and KMS policy                                    | IaC                                       |
| PostgreSQL login creation, role membership, grants, default privileges, RLS | Codefly PostgreSQL service                |
| Migration source, checksum ledger, advisory lock, execution, forward-fix    | Codefly PostgreSQL service                |
| Release ordering around migrations and application rollout                  | Codefly deploy layer                      |
| Dynamic IAM token generation at physical connection creation                | Codefly SDK/database library              |
| Tenant context and authorization supplied to a transaction                  | Application plus Codefly database library |

## Why the current password-shaped SDK contract cannot represent AWS IAM

The local PostgreSQL service currently publishes secret owner, read-only, and
read-write connection strings. That is appropriate for an isolated local
Docker/Nix database, but it must not be copied to AWS:

- an RDS IAM authentication token is a SigV4 value with a 15-minute lifetime;
- the token is bound to the endpoint, Region, and database user;
- a pool can open a new physical connection after the originally returned token
  expired; and
- placing a token in a Codefly configuration, environment variable, Kubernetes
  Secret, log, or Pulumi state turns a dynamic credential into a stale secret.

Therefore `Secret("postgres", "read-write-connection")` remains a local or
password-provider compatibility API. For an AWS IAM binding it must return an
explicit “dynamic authentication; use the PostgreSQL client API” error. It must
never mint and return a token as a long-lived configuration value.

## Current AWS access profile and future provider-neutral binding

The application layer should receive a structured, credential-free binding.
The checked IaC seam currently implemented here is explicitly AWS-specific:
[`PostgresAccessProfile v1alpha1`](../contracts/postgres-access-profile-v1alpha1.json),
validated by both a strict JSON Schema and a handwritten semantic parser. The
contract is content-addressed and can only represent
`pending-infrastructure`; a forged ready state or mutation with a stale digest
is rejected. A future provider-neutral envelope may discriminate AWS IAM,
password-reference, and other dynamic strategies without pretending the AWS
role, RDS Proxy, and Pod Identity fields are generic. The example below is
conceptual—the checked contract also
contains the exact role, namespace, ServiceAccount, Pod Identity association,
security group, scheduling requirements, content digests, and readiness
blockers.

```json
{
  "apiVersion": "resources.codefly.dev/postgres-binding/v1alpha1",
  "bindingId": "tenant-a-main",
  "endpointRef": "broker://tenant-a-main/proxy-endpoint",
  "port": 5432,
  "database": "tenant_a",
  "tls": {
    "mode": "verify-full",
    "caBundleRef": "broker://tenant-a-main/ca-bundle"
  },
  "access": {
    "class": "runtime-read-write",
    "databaseUser": "tenant_a_runtime_rw",
    "workloadIdentityRef": "identity://tenant-a-runtime-rw",
    "networkBoundaryRef": "network://tenant-a-runtime-rw-db",
    "authentication": {
      "kind": "aws-rds-iam",
      "region": "us-east-1",
      "target": "rds-proxy",
      "resourceIdRef": "broker://tenant-a-main/proxy-resource-id"
    }
  }
}
```

The binding contains references and non-secret values only. A local provider
can use `authentication.kind = password-reference` with a secret reference; an
AWS provider uses `aws-rds-iam`; future providers can add their own dynamic
authentication strategy without changing PostgreSQL migration semantics.

The access classes are:

- `runtime-read-only`;
- `runtime-read-write`;
- `migration`; and
- `bootstrap`, which is control-plane-only and is never published to an
  application or toolbox.

Each class has a different database login and should normally have a different
Kubernetes ServiceAccount, EKS Pod Identity association, IAM role, and source
security group. A role gets only the exact `rds-db:connect` ARN for its login.

On EKS Auto Mode, the source group is attached through a dedicated
`NodeClass`/`NodePool` for that access class. Auto Mode does not support the VPC
CNI `SecurityGroupPolicy` resource. IaC publishes the NodeClass, NodePool, and
the exact selector/toleration that the Codefly workload must use. Reusing a
NodeClass across runtime, migration, or bootstrap would collapse their network
boundary and is forbidden.

IaC emits the cluster-scoped resources only in
`databaseInfrastructureHandoffs`, owned by `external-iac` and consumable only by
the infrastructure controller. Application-facing access profiles do not
contain the cluster-scoped manifests. A handoff is content-addressed and remains
`pending-application` until the exact Namespace, ServiceAccount, admission
policy, network policy, NodeClass, NodePool, and Pod Identity association are
observed by a future evidence flow. Runtime, migration, and bootstrap use three
different restricted
namespaces. The fail-closed Kyverno rule binds an admitted Pod to the exact
ServiceAccount, labels, annotations/digest, selector, toleration, and token
automount posture. It also reserves the dedicated NodePool selector
cluster-wide, constrains owner/controller shape, and rejects incompatible
workload kinds. Exclusive deployment actor RBAC is still an explicit blocker;
the emitted policy does not claim to prove it.

## AWS runtime flow

1. The Pod runs as an exact Kubernetes ServiceAccount.
2. EKS Pod Identity maps that namespace/ServiceAccount to an IAM role. EKS Auto
   Mode already includes the Pod Identity Agent.
3. The AWS SDK default credential chain obtains short-lived role credentials
   from the Pod Identity Agent. No AWS key is supplied by Codefly.
4. The Codefly PostgreSQL client resolves the credential-free binding and calls
   the AWS RDS auth token builder for the exact endpoint, Region, and database
   user.
5. The token is assigned as the password immediately before a new physical
   PostgreSQL connection is opened. It is not cached as application
   configuration. Existing authenticated connections are unaffected when the
   15-minute token-generation window ends.
6. TLS uses `verify-full`, the provider CA bundle, and the exact RDS or Proxy
   hostname.
7. IAM permits connection to exactly one database login. PostgreSQL grants and
   RLS determine what SQL that login can execute.

For Go/pgx, the intended Codefly SDK surface is conceptually:

```go
binding, err := codefly.For(ctx).Postgres("postgres").ReadWrite()
pool, err := binding.OpenPGX(ctx)
```

`OpenPGX` installs a per-connection hook that generates a fresh token before
each physical connection. Equivalent provider hooks are required for other
language SDKs. A raw `Token(ctx)` escape hatch may exist for CLI tools, but its
return type must be redacted, non-serializable, and clearly short-lived.

## Initial database bootstrap without root

AWS account root is never involved. Kubernetes cluster-admin is never involved.
The RDS master login is not an AWS root identity, but it is still privileged and
must be isolated.

1. IaC creates Aurora with IAM database authentication enabled and
   `manageMasterUserPassword = true`. RDS generates and rotates the master
   password in Secrets Manager under a customer-managed KMS key. Pulumi never
   receives the password value.
2. IaC creates one dedicated bootstrap IAM role with the minimum
   `secretsmanager:GetSecretValue` and KMS decrypt path for that exact master
   secret, plus the bootstrap source security group. It does **not** create a
   standing bootstrap Pod Identity association. No runtime or migration
   identity receives this permission.
3. The Codefly PostgreSQL deploy/bootstrap RPC retrieves the secret in memory,
   connects over TLS, and transactionally reconciles:
   - NOLOGIN owner/capability roles;
   - separate IAM LOGIN roles for read-only, read-write, and migration;
   - `GRANT rds_iam` to those login roles;
   - `PASSWORD NULL`, no superuser, no `BYPASSRLS`, no role/database creation
     for runtime logins;
   - schema ownership, grants, default privileges, extensions, and RLS; and
   - a bootstrap schema/version marker bound to the infrastructure binding
     digest.
4. Normal migrations subsequently connect as the IAM migration login, assume
   only the application owner role, and never retrieve the master secret.
5. A separately authorized infrastructure operation creates the exact
   bootstrap Pod Identity association just in time, applies the digest-bound
   Job lane, observes audit/bootstrap evidence, and removes the association.
   Every bootstrap-secret retrieval and role session is audited; the credential
   is never printed or exported.

Keeping the isolated role/policy plan available supports deterministic grant
reconciliation and disaster recovery without leaving it assumable. Just-in-time
association creation/removal and evidence are required before the first secure
AWS deployment; until that controller path exists, bootstrap readiness stays
blocked.

Aurora Data API can avoid returning the master password to the worker for a
narrow SQL bootstrap path, but it is Aurora-specific and is not a general
replacement for transactional migration tooling. It is an optional provider
optimization, not the baseline contract.

## PostgreSQL role shape

Use login identities only for authentication and NOLOGIN roles for SQL
capabilities:

```text
tenant_a_owner            NOLOGIN, owns application schemas/objects
tenant_a_ro               NOLOGIN, SELECT capability
tenant_a_rw               NOLOGIN, DML capability, no DDL
tenant_a_runtime_ro       LOGIN + rds_iam, member of tenant_a_ro
tenant_a_runtime_rw       LOGIN + rds_iam, member of tenant_a_rw
tenant_a_migrator         LOGIN + rds_iam + NOINHERIT, may SET ROLE tenant_a_owner
```

The migration login must not be a general runtime credential. The owner role
must not be a login. Read-only and read-write are enforced by PostgreSQL and by
different IAM `dbuser` ARNs, not merely by differently named SDK methods.

For pooled multi-tenancy, IAM authenticates the workload, not the end user or
tenant. RLS must not blindly trust an arbitrary client-set GUC. Tenant context
must be transaction-local and validated against an authenticated application
principal or a database-side mapping. Dedicated-data and dedicated-account
tiers should use separate bindings, roles, and database boundaries rather than
depending solely on RLS.

## RDS Proxy

Production defaults to RDS Proxy with TLS and end-to-end IAM authentication.
It absorbs connection bursts and protects the database connection budget. The
client IAM policy must use the Proxy resource ID (`prx-...`) when the token is
generated for the Proxy endpoint; it must use the cluster resource ID only for
direct cluster connections. The Proxy's own role separately gets
`rds-db:connect` for the exact underlying cluster users.

The provider must publish both IDs as references and must never silently compile
a cluster-user ARN for a Proxy endpoint. Tests must reject that mismatch.

## EKS IAM separation

These mechanisms solve different problems:

- EKS Access Entries plus IAM Identity Center authorize humans/automation to
  use the Kubernetes API.
- EKS Pod Identity authorizes a Pod to obtain AWS credentials.
- `rds-db:connect` authorizes those AWS credentials to connect as one database
  user.
- PostgreSQL roles/RLS authorize SQL.

Do not map application database access through EKS Access Entries or
`aws-auth`. Do not use IRSA annotations for the Auto Mode baseline. Pod Identity
uses an EKS-side association and the `pods.eks.amazonaws.com` service principal;
the ServiceAccount contains only neutral binding metadata.

## Work in this IaC repository

- [x] Replace the IRSA-shaped workload compiler with EKS Pod Identity for the
      Auto Mode baseline.
- [x] Require a `pods.eks.amazonaws.com` trust policy with `sts:AssumeRole`,
      `sts:TagSession`, and confused-deputy/source-organization restrictions.
- [x] Materialize exact namespace/ServiceAccount Pod Identity associations.
- [x] Compile separate application-runtime, migration, and bootstrap database
      access identities. The initial application runtime class is read-write;
      a read-only class must be added only with an exact declared consumer so
      an unused standing identity is not created preemptively.
- [x] Publish Proxy resource ID, cluster resource ID, endpoint, Region,
      database, user, CA reference, identity reference, and network reference;
      publish no credential.
- [x] Fix Proxy client policies to use `prx-...`; retain cluster IDs only for
      direct connections and the Proxy-to-database role.
- [x] Grant exact master-secret access only to the bootstrap identity.
- [x] Test Proxy/cluster resource-ID target mismatch, user substitution,
      wildcard resources, malformed account/Region inputs, and exact bootstrap
      Secret/KMS/VPC-endpoint substitutions locally.
- [x] Test wrong organization, database user, namespace/ServiceAccount shape,
      exact role trust, and source-security-group network-attachment rendering
      across the materialized stack.
- [x] Replace the unsupported Auto Mode `SecurityGroupPolicy` realization with
      one dedicated `NodeClass`/`NodePool` and exact scheduling contract per
      runtime, migration, and bootstrap access class.
- [x] Separate all three access classes into restricted namespaces and emit an
      exact fail-closed Kyverno binding policy.
- [x] Remove the standing bootstrap Pod Identity association; export bootstrap
      only as a control-plane, just-in-time authorization plan.
- [x] Publish the checked, credential-free PostgreSQL access-profile contract
      and separate cluster-infrastructure handoff with content digests and
      explicit pending readiness.
- [x] Split runtime application projections from migration deploy-control
      projections; bootstrap remains control-plane-only.
- [x] Publish the infrastructure handoff as a strict checked contract with a
      top-level digest and digest-bound provider manifest bundles.
- [x] Publish signed, expiring, revocable, replay-protected PostgreSQL access
      observation evidence. Verification binds exact resource observations,
      controller/source authority, evidence lineage, and bootstrap proof and
      returns a separate ready decision without changing the pending profile.
- [ ] Apply the emitted cluster-scoped NodeClass/NodePool through the
      infrastructure-controller/GitOps lane, enforce exact deployment authority,
      and prove API-server admission and observed-state digest equality.
      Emission alone is not attachment.
- [ ] Add an exact read-only consumer identity and prove it cannot assume the
      application read-write role; this waits for the Codefly binding consumer
      contract rather than inventing an undeclared principal in IaC.
- [ ] Prove the real path in AWS: Pod Identity credentials, IAM token, TLS,
      Proxy, PostgreSQL login, read/write denial matrix, and CloudTrail/audit
      evidence.

## Work in Codefly (separate repository/agent)

- [ ] Move from password-shaped PostgreSQL configuration to the discriminated
      structured binding above while preserving the local password provider.
- [ ] Treat the checked `codefly.dev/postgres@0.0.103` value as a required
      compatibility declaration. Current Warden/Mind local service pins must be
      reconciled in Codefly before an application deployment is qualified.
- [ ] Add dynamic IAM token providers to each supported language SDK/pool.
- [ ] Make the existing raw connection-secret API fail explicitly for dynamic
      auth instead of returning a token.
- [ ] Keep the owner connection local-only; add a control-plane-only bootstrap
      binding for managed providers.
- [ ] Reconcile IAM LOGIN roles, NOLOGIN capability roles, grants, default
      privileges, extensions, and RLS inside the PostgreSQL deploy RPC.
- [ ] Run all migration code, checksums, locks, and release gates in Codefly.
- [ ] Deliver bindings per consumer entitlement so a read-only consumer never
      receives the write identity.
- [ ] Add local PostgreSQL integration tests plus real AWS dev tests for token
      refresh, pool reconnect, Proxy target, role denial, RLS, and secret
      non-disclosure.

## Primary references

- [AWS: IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html)
- [AWS: exact `rds-db:connect` resource policies](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html)
- [AWS: connect using IAM tokens](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.Connecting.html)
- [AWS: RDS Proxy IAM and end-to-end IAM](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-connecting.html)
- [AWS: RDS-managed master credentials](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html)
- [AWS: EKS Pod Identity associations](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html)
- [AWS: how EKS Pod Identity injects credentials](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html)
- [AWS: EKS Auto Mode NodeClass and Pod security groups](https://docs.aws.amazon.com/eks/latest/userguide/create-node-class.html)
- [AWS: EKS Auto Mode NodePool scheduling](https://docs.aws.amazon.com/eks/latest/userguide/create-node-pool.html)
- [AWS: EKS Auto Mode security](https://docs.aws.amazon.com/eks/latest/best-practices/autosecure.html)
