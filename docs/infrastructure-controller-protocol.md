# Infrastructure Controller Protocol

Status: implemented IaC contract (`v1alpha1`)
Owner: `secure-saas-infra`
AWS required: no
External application platform required: no

This protocol is the cloud-neutral public boundary for requesting
infrastructure work. It deliberately stops before any CLI, application server,
or plugin integration. Those consumers may be added later through a separate
reviewed plan; the IaC contract does not depend on them.

## Trust boundary

The public request contains ordinary intent and an opaque
`authorizationContextId`. The infrastructure API host must resolve that ID to
transport-authenticated, cryptographically verified authorization state. The
caller cannot submit any of the following:

- provider credentials or Pulumi backend access;
- a plugin manifest or role grant;
- signature-verification, policy-check, or approval-verification booleans;
- raw provider construction or provider outputs.

After resolving identity, grants, capabilities, plan evidence, and approvals,
the trusted host constructs the normalized internal
`InfrastructureControllerRequest`. That internal request is evaluated again by
the controller before a mutation is dispatched.

```text
public typed intent
  -> transport-bound authorization lookup
  -> normalized internal authorization request
  -> policy + plan + approval evaluation
  -> fenced resource-provider operation
  -> reference-only observed output
```

The public and internal schemas are both closed: unknown fields fail before
authorization or provider dispatch.

## Protocol messages

The checked contract contains examples of every public message in
[`infrastructure-controller-protocol-v1alpha1.json`](../contracts/infrastructure-controller-protocol-v1alpha1.json).
Its strict schema is
[`infrastructure-controller-protocol-v1alpha1.schema.json`](../schemas/infrastructure-controller-protocol-v1alpha1.schema.json).

### Version negotiation

The client sends ordered supported date-versions plus required features. The
server selects its own highest-preference common version. Negotiation fails
closed when there is no common version or a required feature is unavailable.

A deprecated version must name a different, currently supported replacement
and an exact sunset epoch. Before sunset it remains compatible and returns
`INFRA_PROTOCOL_DEPRECATED_VERSION`. At or after sunset it becomes incompatible
and returns `INFRA_PROTOCOL_VERSION_SUNSET`. The clock is an explicit function
input so tests and evidence are deterministic.

### Operation request and response

An operation request binds:

- protocol version and request ID;
- authorization-context reference;
- organization, tenant, cloud context, claim, generation, and desired-state
  digest;
- one of `plan`, `reconcile`, `observe`, `cancel`, or `delete`;
- the reviewed plan digest and approval IDs where applicable;
- an idempotency key for mutations; and
- an absolute deadline.

`reconcile` and `delete` require a plan digest. `reconcile`, `cancel`, and
`delete` require an idempotency key. Read-only `plan` and `observe` requests
cannot smuggle mutation keys or approvals. Accepted responses contain an
operation ID and no reason codes; rejected responses contain no operation ID
and at least one stable reason code. Retry delays are legal only when at least
one reason is declared retryable by the catalog.

### Operation events

Events use a strictly increasing sequence and bind the same organization,
tenant, operation, generation, and desired-state digest throughout the chain.
Every event hashes its canonical contents and the previous event digest.
Terminal phases are exactly `succeeded`, `failed`, and `cancelled`; no event may
follow a terminal event. Failed events require a stable reason code, while
non-failure phases cannot carry misleading failure reasons.

The hash chain is tamper evidence, not a substitute for authenticated storage
or an evidence signature. Durable controller storage must enforce atomic
append/CAS semantics when this protocol is integrated.

### Resumable watch cursor

The cursor is opaque and HMAC-SHA-256 authenticated with a server-only key of
at least 32 bytes. Its payload binds organization, tenant, operation, next
sequence, and expiry. Verification rejects:

- malformed or non-canonical base64url encodings;
- signature changes;
- organization, tenant, or operation substitution; and
- expiry at the exact boundary.

Signing-key storage and rotation belong to the future controller runtime. A
runtime may verify against a bounded active/previous key set during rotation;
the key is never part of the protocol message or release evidence.

## Stable reason codes

`INFRASTRUCTURE_PROTOCOL_REASON_CODES` is the source of truth. Each code has a
category and immutable retry semantic. Transport adapters may map codes to
gRPC/HTTP/CLI presentation, but must preserve the machine-readable code in the
response and audit record. Unknown codes are invalid.

## Verification

The local G0/G1 gate is:

```sh
npm run validate:contracts
npm test
```

The tests cover unsupported versions/features, invalid deprecation,
post-sunset rejection, caller-supplied authority, invalid operation field
combinations, retry misuse, event mutation/sequence/terminal violations,
cursor malleability, signature tampering, tenant substitution, and expiry.

Passing these tests proves the pure contract/model behavior only. It does not
prove a future RPC transport, durable job store, authorization host, provider
worker, Kubernetes cluster, or AWS deployment.
