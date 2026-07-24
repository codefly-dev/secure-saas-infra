# Cloud-Neutral Security and Tenancy Kernel

## Outcome

The platform owns a cloud-neutral model of security intent. AWS, GCP, and Azure
are adapters that compile this intent into native constructs; cloud resources do
not define the security model.

The reusable abstraction is deliberately not a generic `Vpc`. It models:

- trust zones and isolation boundaries;
- network domains and authorized flows;
- tenant placement and isolation tiers;
- data classification and encryption boundaries;
- short-lived identities and tenant-scoped grants;
- evidence sinks, retention, and audit coverage;
- capabilities a cloud adapter must prove before compilation.

The implementation lives under `src/core`. It has no Pulumi or cloud-provider
imports. `src/adapters/aws` translates the current AWS network configuration to
the neutral model, evaluates its invariants, and compiles it back to the AWS
deployment plan consumed by existing stacks.

## Processing Model

```text
PlatformBlueprint
      |
      v
Structural validation -----> SecurityGraph
      |                           |
      v                           v
Security invariants <------ reachability / access / evidence edges
      |
      v
Capability negotiation
      |
      v
AWS | GCP | Azure compiler
      |
      v
Provider-native Pulumi components
```

Compilation fails closed. An adapter cannot silently ignore a required
capability, and a blueprint with critical policy violations never reaches a
provider.

## Implemented

- [x] Versioned `PlatformBlueprint` schema.
- [x] Trust-zone, network-domain, flow, tenant, data, identity, grant, and
      evidence models.
- [x] Normalized security graph with reachability, access, placement, and audit
      edges.
- [x] Pure structural, network, tenant, data, identity, and evidence policies.
- [x] Adapter capability negotiation with fail-closed compilation.
- [x] AWS network adapter preserving existing `NetworkConfig` compatibility.
- [x] Network hub and single-account stacks routed through the AWS compiler.
- [x] Strict IPv4 parsing, parent containment, and overlapping-CIDR rejection.
- [x] Positive, negative, graph, capability, and AWS adapter contract tests.
- [x] Repository-specific Sigstore identity and image namespace trust generated
      during onboarding.
- [x] Strict `platformBlueprint` Pulumi input parsing with schema-version,
      unknown-field, type, and secret-material rejection. See
      [platform-blueprint.example.yaml](platform-blueprint.example.yaml).
- [x] Workload-plane intent and policies for private managed Kubernetes,
      external sandboxes, serverless capabilities, and microVM isolation.
- [x] Effective entitlement analysis across identity delegation chains, explicit
      denies, reviewed exceptions, and vendor confused-deputy bindings.
- [x] Cycle-safe transitive network reachability with exact violation paths,
      execution bypass detection, cross-tenant path detection, and inspected
      egress proofs.
- [x] Versioned v1alpha0-to-v1alpha1 migrations with frozen fixtures and a
      Pulumi-exported migration report.
- [x] Reference blueprints for pooled, dedicated-data, dedicated-network,
      dedicated-account, E2B BYOC, and microVM fallback isolation tiers.
- [x] AWS workload compiler selecting private EKS, E2B BYOC, or the explicit
      microVM fallback from workload intent, with typed native extensions.
- [x] Detached-spoke and cross-account routing plans with semantic stack-output
      bindings and explicit TGW-only route-table intent.
- [x] AWS artifact-storage compiler producing pooled or tenant-dedicated S3/KMS
      boundaries from data lifecycle, encryption, evidence, and audit intent.
- [x] Data-service and recovery intent with RPO/RTO, multi-AZ, deletion
      protection, deterministic final snapshots, locked backups, regional copy,
      restore-test cadence, and immutable recovery evidence.
- [x] Deterministic AWS identity, trust, S3, KMS, and workload-identity policy
      compilation with tenant prefixes, tenant keys, principal tags, external
      IDs, source bounds, and privilege-escalation guards.
- [x] Versioned shared provider contract fixtures; AWS passes every compliant
      and hostile reference blueprint.
- [x] Provider-neutral application deployments and a canonical independent
      Warden/Mind topology with distinct identities, data, dependencies,
      availability, release posture, and evidence.
- [x] Codefly PaaS compiler and renderer for local k3d and AWS EKS injection,
      pinned local agents and images, real workspace/module/service descriptors,
      independent namespaces, service accounts, scoped NetworkPolicies,
      disruption budgets, hardened overlays, and semantic blueprint labels.
- [x] Versioned cloud-neutral multi-tenant PaaS control-plane intent and strict
      policy/schema validation for endpoints, quotas, separated identities,
      sandboxes, scheduling, supply chain, durable state/recovery, and audit;
      plus Codefly injection into tenant namespaces, identities, quotas,
      broker-only networking, runtime classes, and builder admission.
- [x] Versioned cloud-neutral PaaS request authorization with strict parsing,
      capability and exact-RBAC evaluation, tenant/audience/resource binding,
      authentication-strength and sandbox-target checks, bounded expiry,
      one-use replay input, provenance/digest/idempotency requirements, and
      complete allow/deny audit decisions.
- [x] Versioned, strict-schema durable PaaS control state with compare-and-swap
      transitions, atomic capability/idempotency records, fair tenant queues,
      global/tenant concurrency, resource locking, bounded retry/deadlines,
      cleanup-evidenced cancellation, deployment history, and digest-safe
      rollback.
- [x] Versioned, strict-schema managed PostgreSQL intent with tenant/data/service
      binding, deterministic claim digests, recovery/capacity requirements,
      separate runtime/migration identity, reference-only IAM/TLS configuration,
      and no migration-code or provider-credential fields.
- [x] Generic resource-broker lifecycle with CAS revisions, atomic capability
      redemption/idempotency, generations, provider leases and fencing, bounded
      retry, drift, cleanup-evidenced cancellation, protected deletion,
      reference-only outputs, strict schemas, and deterministic fake-provider
      conformance.
- [x] AWS managed-Postgres injection: private Aurora/RDS Proxy broker plans,
      concrete EKS Pod Identity associations, dedicated runtime/migration/
      bootstrap identities, exact Warden/Mind service/data-boundary checks, and
      credential-free connection metadata. Codefly rendering is out of scope
      for this repository.
- [x] RDS-managed master credentials outside Pulumi state and end-to-end IAM RDS
      Proxy authentication in the concrete Aurora module, with exact runtime and
      migration database users plus SG-to-SG access boundaries and no VPC CIDR
      ingress.
- [x] Strict Codefly plan schema and compatibility gates for CLI range, agent
      protocol, exact local agent pins, and required deployment features.
- [x] SLSA-covered cross-repository security evidence with contract, schema,
      source, optional repository-revision, and rendered-tree hashes.
- [x] Clean-run dependency verification, machine-expiring advisory exceptions,
      a high/critical audit gate, and SPDX SBOM generation for CI and releases.

Run the scoped development validation from an ordinary checkout with:

```sh
npm run validate:local
```

`verify:all` is reserved for the management-seed fixed execution root on the
dedicated native-Linux qualifier. It is not a Codefly or ordinary-workstation
gate.

## TODO

The independently executable backlog—with task IDs, dependencies, deliverables,
acceptance criteria, tests, milestones, and the full definition of done—is in
[cloud-neutral-backlog.md](cloud-neutral-backlog.md).

The Codefly PaaS target and Warden/Mind product boundaries are specified in
[codefly-paas.md](codefly-paas.md).

### P0 — Complete the AWS vertical slice

- [x] Make `PlatformBlueprint` a supported Pulumi stack input, with schema
      validation and secrets-safe configuration loading.
- [x] Model workload planes so EKS, E2B BYOC, serverless, and microVM execution
      are compiled from intent rather than `createEks` flags.
- [x] Compile databases and backup/restore plans from `DataBoundary`; artifact
      stores and KMS ownership boundaries are now compiled from intent.
- [x] Generate tenant-scoped IAM/resource policies from `IdentityGrant`.
- [ ] Validate generated policies with IAM Access Analyzer before deployment.
- [x] Route detached spoke and network-routing stacks through the neutral plan.
- [ ] Convert AWS modules to `pulumi.ComponentResource` classes with explicit
      parent, provider, aliases, transformations, and protection options.
- [ ] Add stack-level policies proving every VPC has flow/DNS logs, every bucket
      has public-access blocking and encryption, and every firewall has both log
      types.

### P0 — Tenant isolation proofs

- [x] Add transitive path analysis, including broker and egress hops, rather
      than evaluating declared flow edges individually.
- [x] Prove no identity or network path crosses tenants without an explicit,
      reviewed platform-service exception.
- [x] Add pooled, dedicated-data, dedicated-network, and dedicated-account
      reference blueprints.
- [ ] Add mutation tests that remove or weaken one control at a time and require
      the expected invariant to fail.
- [ ] Emit a machine-readable isolation evidence report per preview and release.

### P1 — Provider contracts

- [ ] Define conformance fixtures every provider adapter must compile or reject.
- [ ] Implement a narrow GCP adapter for private VPC, Cloud NAT/firewall,
      workload identity, GKE, Cloud KMS, and immutable audit export.
- [ ] Use the GCP adapter to remove accidental AWS semantics from the core.
- [ ] Implement the Azure adapter only after the AWS/GCP contract stabilizes.
- [ ] Preserve native IAM/RBAC policy documents; normalize only the entitlement
      graph used for cross-cloud analysis.

### P1 — Verification depth

- [ ] Replace source-text policy tests with executable policy fixtures.
- [ ] Add Pulumi preview tests for compliant and deliberately hostile programs.
- [ ] Add ephemeral-account integration tests for routing, deny paths, tenant
      access, evidence delivery, backup restore, and break-glass access.
- [ ] Add property-based tests for CIDR allocation and generated tenant graphs.
- [ ] Record provider capability decisions and unsupported intent in release
      evidence.
- [ ] Clear the remaining Pulumi/OpenTelemetry transitive audit advisories when
      an upstream-compatible dependency set is available; block new high or
      critical advisories in CI.

### P2 — Productization

- [ ] Publish core and adapter packages with semantic versioning.
- [ ] Add migration/versioning rules for blueprint schema upgrades.
- [ ] Generate architecture diagrams, threat-model deltas, and control mappings
      from the same graph.
- [ ] Add cost and quota policies per tenant isolation tier.

## Non-Goals

- Hiding useful cloud-native capabilities.
- Pretending AWS IAM, GCP IAM, and Azure RBAC have identical semantics.
- Allowing provider escape hatches to bypass generic invariants.
- Treating Kubernetes namespaces or storage prefixes as hard tenant boundaries.
