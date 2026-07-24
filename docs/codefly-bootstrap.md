# Codefly Bootstrap Seed Contract

> Deferred, non-executable design. Codefly is outside the current qualified
> IaC source closure. The `render:codefly*`, Kubernetes, and GitOps commands in
> this document are historical design examples and are not present or approved
> operator entrypoints in this release.

This repository now publishes the credential-free desired state for the first
Codefly organization. It is a bootstrap handoff contract, not an implementation
of the Codefly CLI or server transport.

The reference seed is
[`contracts/codefly-bootstrap-v1alpha1.json`](../contracts/codefly-bootstrap-v1alpha1.json).
Its strict schema is
[`schemas/codefly-bootstrap-v1alpha1.schema.json`](../schemas/codefly-bootstrap-v1alpha1.schema.json).

## What The Seed Owns

The bootstrap declaration owns only logical Codefly tenancy:

- the protected `codefly-system` realm, which ordinary organization APIs may
  not administer;
- the initial `deus` organization and its exact OIDC owner identity;
- least-privilege initial teams;
- modular `dev`, `staging`, and `prod` environment policy;
- credential-free platform and execution `CloudContext` references; and
- idempotency, deletion protection, desired-state digest, generation, and
  observation evidence.

It never contains an AWS access key, cloud credential, kubeconfig, database
password, provider resource ID, or Pulumi secret. Physical infrastructure and
provider authority remain outside the Codefly organization API.

## Initial Environment Posture

| Environment | State    | Artifact policy      | Data policy                              |
| ----------- | -------- | -------------------- | ---------------------------------------- |
| `dev`       | enabled  | build in environment | synthetic only; production data denied   |
| `staging`   | disabled | promote exact digest | synthetic only; production data denied   |
| `prod`      | enabled  | promote exact digest | production allowed; approval is required |

Every environment has different platform and execution context IDs, and no
context ID may be reused by another environment. A disabled environment has
deployment admission set to `deny`. An enabled environment still cannot deploy
until both referenced contexts are independently observed ready.

## Idempotency And Evidence

`seed.operationId` is stable and `seed.desiredStateDigest` is a SHA-256 digest
of the complete desired state, excluding observation status and the digest
field itself. Changing organization, identity, role, environment, context, or
policy data without recomputing the digest is rejected.

A planned seed is intentionally non-executable. The future bootstrap adapter
must first observe the prerequisites and set:

- `status.phase` to `ready`;
- `observedGeneration` equal to `generation`;
- an ISO verification time; and
- the exact digest- and generation-bound evidence URI returned by
  `codeflyBootstrapEvidenceRef`.

The server must reconcile `(operationId, desiredStateDigest)` idempotently:
the same pair is a no-op, the same operation with a different digest is an
explicit reconciliation conflict, and delete is denied by default. It must
write immutable audit evidence before reporting success.

## Render And Validate Locally

Render the checked-in reference declaration without network access:

```sh
npm run render:codefly-bootstrap
```

Override only public identity and organization coordinates when preparing a
real seed:

```sh
npm run render:codefly-bootstrap -- \
  --organization-id org-deus \
  --organization-slug deus \
  --organization-display-name Deus \
  --owner-issuer https://identity.example.com \
  --owner-audience codefly \
  --owner-subject oidc://identity.example.com/users/owner \
  --output artifacts/codefly-bootstrap.json
```

The renderer rejects unknown arguments and writes output mode `0600`. It does
not call Codefly or AWS. The TypeScript parser is the semantic enforcement
boundary; the JSON schema provides a portable structural boundary.

## Remaining Integration Work

This IaC slice deliberately stops before mutation. The Codefly CLI/server work
still needs to implement an authenticated bootstrap command/RPC, durable
idempotency storage, system-realm protection, transactional organization/team/
environment creation, immutable audit output, and read-after-write observation.
Only then can a verified response be used to mark this declaration `ready`.
