# Cloud-context verification companion

Status: local contract implementation; production integration pending
Version: `evidence.security.deus.dev/cloud-context-observation/v1alpha1`
Owner: `secure-saas-infra`

## Why this is a companion contract

`CloudContext security.deus.dev/v1alpha1` is already a published compatibility
boundary. Its status contains an evidence URI, but a URI is not authenticated
proof and its legacy deployability check evaluates the whole catalog. Changing
those semantics in place would silently break existing Codefly consumers.

The verification companion leaves every v1alpha1 byte and required field
unchanged. A deployment admission consumer selects one application/component,
derives its dependency closure from the catalog, and redeems a separately
signed observation. The old global decision remains available only for legacy
compatibility; new deployment admission must use the companion decision.

## Ownership and authority

- IaC owns dependency derivation, provider-reference purposes, resolver policy,
  observation verification, and the placement decision.
- A resolver may observe one registered URI scheme. It receives a typed,
  digest-bound request; it does not receive Pulumi state, cloud credentials, a
  kubeconfig, raw database credentials, or signing authority.
- A trusted infrastructure observer signs the complete observation with
  Ed25519. The verifier receives only configured public keys.
- Codefly supplies the requested organization, platform tenant, application,
  component, and admission-request digest. It cannot choose the dependency set
  or turn a non-selected resource into a selected one.
- The replay store owns one atomic `redeem` operation. Production must use a
  durable store shared by all admission replicas.

## Decision flow

```text
CloudContext v1alpha1 desired catalog
  + exact deployment selection/request digest
  -> derive selected placement and dependency closure
  -> construct typed, subject-bound reference requests
  -> pre-authorize the complete resolver dispatch set
  -> resolve provider UIDs/versions and output digests
  -> sign short-lived observation with Ed25519
  -> verify content address, trust scope, time, signature, subject,
     desired state, placement, closure, policy, registry, lineage,
     resolutions, and dependency set
  -> atomically redeem evidence ID + nonce + request digest
  -> emit a content-addressed placement decision
```

Pre-authorization happens before the first resolver call. An unknown scheme or
out-of-scope purpose therefore produces zero resolver side effects. Replay
redemption happens last, after every cryptographic and semantic check passes.

## Selected dependency closure

The current closure includes the selected context and its exact runtime,
network, registry, identity, observability, DNS, and resource-binding
capabilities. A delegated runtime contributes only its delegated context and
runtime because that is all the v1alpha1 placement declares. The admission
caller cannot add or remove dependencies.

All current closure entries are required. Promotion-required and
optional/degraded dependency classes are deliberately deferred; adding them
without explicit semantics would create an ambiguous allow path.

A resource binding is permanently owned by the context that contains it.
Catalog validation rejects a placement that refers to a binding in another
context and rejects moving an already selected binding across contexts.

## Typed reference request

Every request binds:

- desired-catalog and placement digests;
- organization, platform tenant, environment, application, component, and
  admission-request digest;
- context, dependency kind/key/ID, dependency subject digest, and generation;
- canonical URI and exact registered scheme;
- purpose, confidentiality, projection, and semantic output type; and
- the canonical request digest.

The resolver registry is itself content-addressed. Each resolver declares one
scheme, implementation ID/version, owner, allowed purposes/confidentialities,
projection modes, output types, environments, organizations, tenants,
contexts, and maximum TTL. Registry construction rejects duplicate schemes,
wildcard authority, provider-credential acceptance, and value serialization.

The resolution contains only request/resolver identity, provider resource
UID/version, output digest, and lifetime. There is intentionally no raw `value`
field.

## Authenticated observation

The strict parser and published JSON Schema close every object. The signature
uses domain-separated canonical JSON:

```text
DEUS_CLOUD_CONTEXT_OBSERVATION_V1\0 || canonical-json(unsigned-envelope)
```

The envelope binds the desired catalog, placement, exact dependency closure,
resolver registry, admission policy, request, subject, observation generations,
provider resources and output digests, verifier identity/version/key, issued
time, expiry, nonce, and per-dependency previous observation digest.

Verification fails closed for a content-address mismatch, unknown or
out-of-scope verifier, revoked evidence/nonce/key, future or expired evidence,
excessive TTL, invalid signature, wrong subject, desired-state/placement/closure
substitution, policy/registry substitution, broken lineage, missing/extra
dependencies or resolutions, wrong provider output, stale resolution, and
replay.

## Stable denial families

- `CLOUD_REF_*`: URI, registry, resolver scope, substitution, authority, and
  resolution lifetime failures.
- `CLOUD_DEPENDENCY_*`: invalid or escaped dependency derivation.
- `CLOUD_OBSERVATION_*`: shape, trust, time, signature, subject, digest,
  lineage, dependency/resolution set, revocation, and replay failures.
- `CLOUD_BINDING_CONTEXT_MISMATCH`: a placement/binding context ownership
  violation in the compatibility catalog.

Callers must log the stable code and evidence digest, never a resolved value or
credential.

## What local tests prove

- Deterministic desired-state, placement, closure, request, registry,
  observation, and decision digests.
- Status-only changes do not create a desired-state digest cycle.
- Unknown schemes are denied before any resolver call.
- A Mind Postgres endpoint cannot replace a Warden endpoint.
- Moving a selected binding to the execution context is denied.
- Ed25519 tampering, untrusted keys, expiry, policy substitution, revocation,
  replay, and wrong deployment subject are denied.
- An unused degraded context does not block a verified Warden placement.
- The strict parser and Draft 2020-12 schema agree on the hostile shape corpus.

These tests do not prove AWS reachability or production observation. The local
resolver is a deterministic test double, not a deployable resolver.

## Production TODO

1. Implement one least-authority resolver per scheme with real timeout,
   not-found, unavailable, stale, and revocation behavior.
2. Run the observer under a short-lived infrastructure identity and store its
   private key in a signing service or equivalent non-exportable boundary.
3. Publish the public-key trust registry and revocations through an
   authenticated, versioned distribution path.
4. Use a durable, atomic, multi-replica replay store and test races, restarts,
   expiry cleanup, and partition behavior.
5. Store evidence in an immutable content-addressed location or pass it with
   independently verifiable provenance.
6. Bind authoritative account, region, and cluster UID when the production
   observer can obtain them; do not accept caller assertions.
7. Add promotion-required and optional/degraded semantics only with explicit
   denial and outage behavior.
8. Add the Codefly deployment-admission RPC that consumes this companion
   decision while preserving the legacy v1 plan.
9. Exercise the exact flow in disposable Kubernetes before AWS preview, then
   against AWS dev before any production claim.

No AWS API is called by the current implementation or its tests.
