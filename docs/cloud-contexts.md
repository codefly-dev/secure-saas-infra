# Cloud Contexts

`CloudContext` is the credential-free boundary between infrastructure managed by
this repository and applications deployed by Codefly. It describes approved
capabilities and existing resource bindings; it does not give Codefly an AWS
SDK client, kubeconfig, password, access key, or administrator role.

The first catalog is
`security.deus.dev/cloud-context/v1alpha1` and contains two production AWS
contexts:

- `aws-platform-production`: trusted private EKS application runtime, immutable
  ECR registry, public/private DNS, workload identity, observability, and the
  three pre-provisioned PostgreSQL bindings; and
- `aws-execution-production`: isolated brokered runtime for customer-code jobs.

All six Warden/Mind components run as trusted application control services in
the platform context. Mind's `execution` component additionally receives a
delegated customer-code capability from the isolated execution context. The
scheduler does not turn into an untrusted workload and cannot pass provider
credentials to a job.

## Lifecycle truth

A generated catalog starts in `planned` phase. Planned contexts and bindings
have `observedGeneration: 0` and no verification timestamp or evidence
reference. The legacy v1 Codefly plan has a catalog-global readiness decision
for compatibility. New admission uses the
[cloud-context verification companion](cloud-context-verification.md), derives
only the selected placement closure, and requires short-lived Ed25519-signed,
content-addressed observation evidence.

The companion prevents a rendered stack-output reference from being mistaken
for observation evidence, but its current resolvers are deterministic local
test doubles. Only the future AWS validation gate may produce production
evidence after it proves outputs, IAM/TLS connectivity, network paths, registry
behavior, audit delivery, and database bindings.

## Publication boundary

`CloudContext` is a published, checked contract. The strict
`cloud-context-v1alpha1.schema.json`, semantic parser, canonical registry
digest, owned development fixture, and deterministic `render:cloud-contexts`
command form the supported application handoff. The renderer requires explicit
platform and execution account IDs and rejects the old single-account form.

Published catalogs remain `planned`; publication does not assert that an AWS
resource exists or is reachable. Only signed observation evidence from the
future AWS validation gate can promote the selected placement closure.

Platform and execution account IDs are intentionally separate and compile to
different provider and workload-identity boundaries. The renderer rejects the
old single `--account-id` form so an operator cannot accidentally erase the
account boundary from the production catalog.

## Pre-provisioned AWS resources

Modular platform stack examples enable `codeflyRegistry` with one exact
repository for each of the 18 current Warden/Mind services. Repositories are
KMS encrypted, immutable, scanned on push, inaccessible over insecure transport,
and protected from force deletion.

The platform and execution examples select the strict `warden-mind-v1`
`platformBlueprintPreset` with explicit environment CIDRs. This avoids copying
an application graph into six stack files while still compiling both context
stacks from the same provider-neutral blueprint. Supplying an inline
`platformBlueprint` and a preset together is rejected, as are unknown preset
fields, missing network domains, and unknown preset versions.

When a platform stack supplies the preset (or an inline versioned
`platformBlueprint`) together with `managedPostgresContractPath`, the relational
compiler creates only the three declared PostgreSQL boundaries. The path must
identify a checked JSON contract under `contracts/`; traversal and arbitrary
local files are rejected.

```yaml
secure-saas-infra:managedPostgresContractPath: contracts/managed-postgres-v1alpha1.json
secure-saas-infra:managedPostgresEnvironment: development
secure-saas-infra:awsOrganizationId: o-1234567890
```

The stack deliberately publishes separate projections:

- `databaseBindings`, `databaseAccessBindings`, and
  `postgresAccessProfiles`: application-safe runtime-only endpoint, IAM-auth,
  TLS, database user, identity, network, scheduling, content digest, and
  fail-closed readiness projections;
- `databaseMigrationBindings`, `databaseMigrationAccessBindings`, and
  `postgresMigrationAccessProfiles`: deploy-control-only migration projections,
  never application runtime outputs;
- `databaseInfrastructureHandoffs`: checked, content-addressed,
  infrastructure-controller-only Namespace, ServiceAccount, fail-closed
  Kyverno policy, EKS Auto Mode `NodeClass`/`NodePool`, and
  `ApplicationNetworkPolicy` bundles; and
- `databaseBootstrapBindings` plus `databaseBootstrapAccessBindings`: a
  control-only bootstrap projection that is never included in an application
  profile.

No password or IAM token is exported. Runtime, migration, and bootstrap use
separate restricted namespaces. Runtime and migration have persistent exact
Pod Identity associations; bootstrap has no standing association and requires
a separately authorized just-in-time infrastructure operation. Every v1alpha1
profile is immutable and fail-closed at `pending-infrastructure`; it cannot
represent `pending-bootstrap` or `ready`. Observed-state promotion uses the
separate checked `PostgresAccessObservationEvidence v1alpha1` contract, but no
real observer or evidence exists until the authorized controller and AWS-dev
runtime probes are deployed. Emitting a manifest or local fixture is not
readiness evidence.

The cluster-infrastructure/GitOps lane—not an application deployment—must apply
the cluster-scoped handoff. Application delivery may copy only the admitted
ServiceAccount, labels, annotations, selector, toleration, and binding digest
from an exact access profile only after a future observed-state evidence flow
authorizes deployment.

## Real AWS gate

Local tests prove compilation, resource shape, policy, reference safety, and
placement. A dedicated sandbox AWS account is still required before any catalog
can become `ready`. The real gate will require explicit authorization before
`pulumi up` and must validate:

1. platform and execution stack outputs;
2. ECR immutability, KMS encryption, scanning, and scoped push/pull identity;
3. EKS workload identity and private control-plane access;
4. exact SG-to-SG runtime and migration paths;
5. RDS Proxy IAM authentication and TLS verification for both database users;
6. backup, restore, deletion protection, audit, and cleanup evidence; and
7. denial from the wrong application, identity, context, or network boundary.

Physical infrastructure provisioning from Codefly remains deferred. In this
release Codefly selects a ready context and resolves existing bindings.
