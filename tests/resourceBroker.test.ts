import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  RESOURCE_BROKER_STATE_API_VERSION,
  RESOURCE_CLAIM_API_VERSION,
  RESOURCE_PROVIDER_PROTOCOL_VERSION,
  acknowledgeResourceClaimCancellation,
  applyResourceClaim,
  cancelResourceClaim,
  completeResourceClaim,
  completeResourceClaimDeletion,
  createFakeResourceProvider,
  createResourceBrokerState,
  evaluateResourceProviderConformance,
  executeWithResourceProvider,
  failResourceClaim,
  leaseResourceClaim,
  parseResourceBrokerState,
  parseResourceClaimRequest,
  planWithResourceProvider,
  reportResourceClaimDrift,
  requestResourceClaimDeletion,
  resourceClaimRequestDigest,
  type BrokerMutationContext,
  type ResourceBrokerState,
  type ResourceClaimRequest,
  type ResourceProviderAdapter,
} from "../src/core";

const T0 = "2026-07-14T12:00:00.000Z";
const T1 = "2026-07-14T12:01:00.000Z";
const T2 = "2026-07-14T12:02:00.000Z";

test("resource broker atomically applies, leases, and completes a reference-only claim", () => {
  const claim = claimRequest();
  const applied = applyResourceClaim({
    state: createResourceBrokerState(),
    expectedRevision: 0,
    context: context("claim.apply", "apply-1", "cap-apply-1", T0),
    claim,
  });
  assert.equal(applied.state.revision, 1);
  assert.equal(applied.result.phase, "pending");
  assert.deepEqual(applied.state.redeemedCapabilityIds, ["cap-apply-1"]);

  const replay = applyResourceClaim({
    state: applied.state,
    expectedRevision: 1,
    context: context("claim.apply", "apply-1", "cap-apply-1", T0),
    claim,
  });
  assert.equal(replay.replayed, true);
  assert.equal(replay.state.revision, 1);
  assert.deepEqual(replay.events, []);

  const leased = lease(applied.state, T1);
  assert.equal(leased.state.revision, 2);
  assert.equal(leased.result.generation, 1);
  assert.match(leased.result.fenceToken, /^[a-f0-9]{64}$/);

  const provider = createFakeResourceProvider();
  const request = {
    claim,
    operation: "reconcile" as const,
    fenceToken: leased.result.fenceToken,
  };
  const plan = planWithResourceProvider(provider, request);
  const observation = executeWithResourceProvider(provider, request);
  assert.match(plan.planDigest, /^[a-f0-9]{64}$/);
  assert.equal(observation.outputs[0].kind, "reference");

  const completed = completeResourceClaim({
    state: leased.state,
    expectedRevision: 2,
    claimId: claim.claimId,
    providerId: provider.descriptor.id,
    generation: 1,
    fenceToken: leased.result.fenceToken,
    workloadIdentityVerified: true,
    observedStateDigest: observation.observedStateDigest,
    providerResourceRef: observation.providerResourceRef!,
    outputs: observation.outputs,
    occurredAt: T2,
  });
  assert.equal(completed.result.phase, "available");
  assert.equal(completed.result.observedGeneration, 1);
  assert.equal(completed.result.outputs[0].value, "broker://claim-a/resource");
  assert.doesNotThrow(() => parseResourceBrokerState(completed.state));
});

test("resource broker enforces generations, CAS, expired-lease fencing, and late-worker denial", () => {
  const first = apply(claimRequest());
  const originalLease = lease(first, T1, 30);
  const replacementLease = lease(
    originalLease.state,
    "2026-07-14T12:01:31.000Z",
    60,
  );
  assert.notEqual(
    originalLease.result.fenceToken,
    replacementLease.result.fenceToken,
  );
  assert.equal(replacementLease.result.attempt, 2);

  assert.throws(
    () =>
      completeResourceClaim({
        state: replacementLease.state,
        expectedRevision: replacementLease.state.revision,
        claimId: "claim-a",
        providerId: "fake-provider",
        generation: 1,
        fenceToken: originalLease.result.fenceToken,
        workloadIdentityVerified: true,
        observedStateDigest: "a".repeat(64),
        providerResourceRef: "provider://fake-provider/warden/claim-a",
        outputs: referenceOutputs(),
        occurredAt: T2,
      }),
    /stale generation or fence token/,
  );
  assert.throws(
    () =>
      leaseResourceClaim({
        state: replacementLease.state,
        expectedRevision: 1,
        claimId: "claim-a",
        providerId: "fake-provider",
        providerCapabilities: capabilities,
        workloadIdentityVerified: true,
        occurredAt: T2,
        leaseDurationSeconds: 60,
      }),
    /revision conflict/,
  );

  const available = complete(
    replacementLease.state,
    replacementLease.result,
    T2,
  );
  const generationTwo = claimRequest({
    generation: 2,
    desiredStateDigest: "b".repeat(64),
  });
  const updated = applyResourceClaim({
    state: available,
    expectedRevision: available.revision,
    context: context("claim.apply", "apply-2", "cap-apply-2", T2),
    claim: generationTwo,
  });
  assert.equal(updated.result.generation, 2);
  assert.equal(updated.result.phase, "pending");
  assert.equal(updated.result.outputs.length, 0);
  assert.throws(
    () =>
      applyResourceClaim({
        state: updated.state,
        expectedRevision: updated.state.revision,
        context: context("claim.apply", "apply-3", "cap-apply-3", T2),
        claim: claimRequest({ generation: 4 }),
      }),
    /advance exactly one generation/,
  );
});

test("running cancellation retains its fence until provider cleanup evidence", () => {
  const applied = apply(claimRequest());
  const leased = lease(applied, T1);
  const cancellation = cancelResourceClaim({
    state: leased.state,
    expectedRevision: leased.state.revision,
    context: context("claim.cancel", "cancel-1", "cap-cancel-1", T1),
  });
  assert.equal(cancellation.result.phase, "cancelling");
  assert.equal(cancellation.result.lease?.fenceToken, leased.result.fenceToken);
  assert.throws(
    () => complete(cancellation.state, leased.result, T2),
    /stale generation or fence token/,
  );
  const cancelled = acknowledgeResourceClaimCancellation({
    state: cancellation.state,
    expectedRevision: cancellation.state.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    generation: 1,
    fenceToken: leased.result.fenceToken,
    workloadIdentityVerified: true,
    cleanupEvidenceRef: "evidence://claim-a/cleanup/1",
    occurredAt: T2,
  });
  assert.equal(cancelled.result.phase, "cancelled");
  assert.equal(cancelled.result.lease, undefined);
  assert.equal(
    cancelled.result.cancellation?.cleanupEvidenceRef,
    "evidence://claim-a/cleanup/1",
  );
});

test("drift removes consumable outputs and reconciles under a new fence", () => {
  const first = apply(claimRequest());
  const firstLease = lease(first, T1);
  const available = complete(firstLease.state, firstLease.result, T2);
  const drifted = reportResourceClaimDrift({
    state: available,
    expectedRevision: available.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    workloadIdentityVerified: true,
    observedStateDigest: "d".repeat(64),
    occurredAt: "2026-07-14T12:03:00.000Z",
  });
  assert.equal(drifted.result.phase, "drifted");
  assert.equal(drifted.result.outputs.length, 0);
  const driftLease = lease(drifted.state, "2026-07-14T12:04:00.000Z");
  assert.notEqual(driftLease.result.fenceToken, firstLease.result.fenceToken);
});

test("deletion protection requires bound approval and finalization evidence", () => {
  const first = apply(claimRequest());
  const firstLease = lease(first, T1);
  const available = complete(firstLease.state, firstLease.result, T2);
  assert.throws(
    () =>
      requestResourceClaimDeletion({
        state: available,
        expectedRevision: available.revision,
        context: context("claim.delete", "delete-1", "cap-delete-1", T2),
        approvalEvidenceRef: "not-a-reference",
        finalizationEvidenceRef: "snapshot://claim-a/final/1",
      }),
    /safe evidence reference/,
  );
  const deletion = requestResourceClaimDeletion({
    state: available,
    expectedRevision: available.revision,
    context: context("claim.delete", "delete-1", "cap-delete-1", T2),
    approvalEvidenceRef: "evidence://claim-a/approval/delete-1",
    finalizationEvidenceRef: "snapshot://claim-a/final/1",
  });
  assert.equal(deletion.result.phase, "deleting");
  const deleteLease = lease(deletion.state, "2026-07-14T12:03:00.000Z");
  const destroyed = executeWithResourceProvider(createFakeResourceProvider(), {
    claim: claimRequest(),
    operation: "destroy",
    fenceToken: deleteLease.result.fenceToken,
  });
  assert.equal(destroyed.providerResourceRef, null);
  assert.deepEqual(destroyed.outputs, []);
  assert.throws(
    () =>
      completeResourceClaimDeletion({
        state: deleteLease.state,
        expectedRevision: deleteLease.state.revision,
        claimId: "claim-a",
        providerId: "fake-provider",
        generation: 1,
        fenceToken: deleteLease.result.fenceToken,
        workloadIdentityVerified: true,
        finalizationEvidenceRef: "snapshot://claim-a/final/substituted",
        occurredAt: "2026-07-14T12:04:00.000Z",
      }),
    /does not match approval/,
  );
  const deleted = completeResourceClaimDeletion({
    state: deleteLease.state,
    expectedRevision: deleteLease.state.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    generation: 1,
    fenceToken: deleteLease.result.fenceToken,
    workloadIdentityVerified: true,
    finalizationEvidenceRef: "snapshot://claim-a/final/1",
    occurredAt: "2026-07-14T12:04:00.000Z",
  });
  assert.equal(deleted.result.phase, "deleted");
  assert.equal(deleted.result.providerResourceRef, undefined);
  assert.deepEqual(deleted.result.outputs, []);
});

test("authorization, idempotency, capability redemption, and failure messages fail closed", () => {
  const claim = claimRequest();
  assert.throws(
    () =>
      applyResourceClaim({
        state: createResourceBrokerState(),
        expectedRevision: 0,
        context: {
          ...context("claim.apply", "apply-1", "cap-apply-1", T0),
          tenantId: "mind",
        },
        claim,
      }),
    /crosses its exact tenant or resource/,
  );
  const applied = apply(claim);
  assert.throws(
    () =>
      applyResourceClaim({
        state: applied,
        expectedRevision: applied.revision,
        context: context("claim.apply", "other-key", "cap-apply-1", T1),
        claim: claimRequest({ generation: 2 }),
      }),
    /already redeemed/,
  );
  assert.throws(
    () =>
      applyResourceClaim({
        state: applied,
        expectedRevision: applied.revision,
        context: context("claim.apply", "apply-1", "cap-apply-1", T0),
        claim: claimRequest({ desiredStateDigest: "b".repeat(64) }),
      }),
    /idempotency key was reused/,
  );
  const leased = lease(applied, T1);
  assert.throws(
    () =>
      failResourceClaim({
        state: leased.state,
        expectedRevision: leased.state.revision,
        claimId: "claim-a",
        providerId: "fake-provider",
        generation: 1,
        fenceToken: leased.result.fenceToken,
        workloadIdentityVerified: true,
        code: "PROVIDER_ERROR",
        message: "password=do-not-leak",
        retryable: true,
        occurredAt: T2,
      }),
    /contains secret material/,
  );
  const failed = failResourceClaim({
    state: leased.state,
    expectedRevision: leased.state.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    generation: 1,
    fenceToken: leased.result.fenceToken,
    workloadIdentityVerified: true,
    code: "PROVIDER_UNAVAILABLE",
    message: "Provider is temporarily unavailable.",
    retryable: true,
    occurredAt: T2,
  });
  assert.equal(failed.result.phase, "failed");
  assert.equal(failed.result.lease, undefined);
  const retryLease = lease(failed.state, "2026-07-14T12:03:00.000Z");
  assert.equal(retryLease.result.attempt, 2);
});

test("provider conformance rejects credentials, undeclared capabilities, extra fields, and secret outputs", () => {
  const claim = claimRequest();
  const evidence = evaluateResourceProviderConformance(
    createFakeResourceProvider(),
    claim,
  );
  assert.equal(evidence.apiVersion, RESOURCE_PROVIDER_PROTOCOL_VERSION);
  assert.equal(evidence.pass, true);
  assert.equal(evidence.checks.length, 7);

  assert.throws(
    () =>
      evaluateResourceProviderConformance(
        createFakeResourceProvider({ capabilities: ["private-network"] }),
        claim,
      ),
    /lacks capability/,
  );

  const insecure = createFakeResourceProvider() as any;
  insecure.descriptor.acceptsProviderCredentials = true;
  assert.throws(
    () => evaluateResourceProviderConformance(insecure, claim),
    /weakens the broker boundary/,
  );

  const extraRequest = {
    claim,
    operation: "reconcile" as const,
    fenceToken: "f".repeat(64),
    providerCredentials: "forbidden",
  };
  assert.throws(
    () =>
      planWithResourceProvider(
        createFakeResourceProvider(),
        extraRequest as any,
      ),
    /unknown field 'providerCredentials'/,
  );

  const secretOutput = maliciousProvider((result) => ({
    ...result,
    outputs: [{ name: "password", kind: "value", value: "unsafe" }],
  }));
  assert.throws(
    () =>
      executeWithResourceProvider(secretOutput, {
        claim,
        operation: "reconcile",
        fenceToken: "f".repeat(64),
      }),
    /output 'password' is forbidden/,
  );

  const extraResult = maliciousProvider((result) => ({
    ...result,
    secret: "unsafe",
  }));
  assert.throws(
    () =>
      executeWithResourceProvider(extraResult, {
        claim,
        operation: "reconcile",
        fenceToken: "f".repeat(64),
      }),
    /unknown field 'secret'/,
  );

  let sequence = 0;
  const nondeterministic = maliciousPlanProvider(() => {
    sequence += 1;
    return `ensure:ManagedPostgres_${sequence}`;
  });
  assert.throws(
    () => evaluateResourceProviderConformance(nondeterministic, claim),
    /planning is not deterministic/,
  );
});

test("claim and broker-state parsers reject unknown and internally inconsistent state", () => {
  assert.equal(
    parseResourceClaimRequest(claimRequest()).apiVersion,
    RESOURCE_CLAIM_API_VERSION,
  );
  assert.match(resourceClaimRequestDigest(claimRequest()), /^[a-f0-9]{64}$/);
  const unknown = { ...claimRequest(), provider: "aws" };
  assert.throws(
    () => parseResourceClaimRequest(unknown),
    /unknown field 'provider'/,
  );
  const availableWithoutOutputs = {
    ...apply(claimRequest()),
    apiVersion: RESOURCE_BROKER_STATE_API_VERSION,
  } as ResourceBrokerState;
  (availableWithoutOutputs.claims[0] as any).phase = "available";
  (availableWithoutOutputs.claims[0] as any).observedGeneration = 1;
  assert.throws(
    () => parseResourceBrokerState(availableWithoutOutputs),
    /lacks current observed state/,
  );
});

test("published resource claim and durable broker schemas are strict and versioned", () => {
  const claimSchema = JSON.parse(
    readFileSync("schemas/resource-claim-v1alpha1.schema.json", "utf8"),
  );
  const stateSchema = JSON.parse(
    readFileSync("schemas/resource-broker-state-v1alpha1.schema.json", "utf8"),
  );
  assert.equal(
    claimSchema.$defs.claim.properties.apiVersion.const,
    RESOURCE_CLAIM_API_VERSION,
  );
  assert.equal(claimSchema.$defs.claim.additionalProperties, false);
  assert.equal(
    claimSchema.$defs.lifecycle.properties.deletionProtection.const,
    true,
  );
  assert.equal(
    stateSchema.properties.apiVersion.const,
    RESOURCE_BROKER_STATE_API_VERSION,
  );
  assert.equal(stateSchema.additionalProperties, false);
  assert.equal(stateSchema.$defs.claimState.additionalProperties, false);
  assert.equal(stateSchema.$defs.output.additionalProperties, false);
});

const capabilities = [
  "private-network",
  "customer-managed-encryption",
  "multi-zone",
  "point-in-time-recovery",
  "workload-identity",
  "reference-only-outputs",
];

function claimRequest(
  overrides: Partial<ResourceClaimRequest> = {},
): ResourceClaimRequest {
  return {
    apiVersion: RESOURCE_CLAIM_API_VERSION,
    kind: "ResourceClaim",
    claimId: "claim-a",
    tenantId: "warden",
    generation: 1,
    resourceKind: "ManagedPostgres",
    resourceApiVersion: "security.deus.dev/managed-postgres/v1alpha1",
    desiredStateDigest: "a".repeat(64),
    desiredStateRef: "broker://claim-a/desired-state",
    requiredProviderCapabilities: capabilities,
    lifecycle: {
      deletionProtection: true,
      destructionApprovalRequired: true,
      finalizationEvidenceRequired: true,
      maxReconcileAttempts: 3,
    },
    ...overrides,
  };
}

function context(
  operation: BrokerMutationContext["operation"],
  idempotencyKey: string,
  capabilityId: string,
  occurredAt: string,
): BrokerMutationContext {
  return {
    actorId: "warden-deployer",
    tenantId: "warden",
    operation,
    resourceId: "claim-a",
    capabilityId,
    capabilityVerified: true,
    idempotencyKey,
    occurredAt,
  };
}

function apply(claim: ResourceClaimRequest): ResourceBrokerState {
  return applyResourceClaim({
    state: createResourceBrokerState(),
    expectedRevision: 0,
    context: context("claim.apply", "apply-1", "cap-apply-1", T0),
    claim,
  }).state;
}

function lease(
  state: ResourceBrokerState,
  occurredAt: string,
  leaseDurationSeconds = 300,
) {
  return leaseResourceClaim({
    state,
    expectedRevision: state.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    providerCapabilities: capabilities,
    workloadIdentityVerified: true,
    occurredAt,
    leaseDurationSeconds,
  });
}

function complete(
  state: ResourceBrokerState,
  providerLease: { generation: number; fenceToken: string },
  occurredAt: string,
): ResourceBrokerState {
  return completeResourceClaim({
    state,
    expectedRevision: state.revision,
    claimId: "claim-a",
    providerId: "fake-provider",
    generation: providerLease.generation,
    fenceToken: providerLease.fenceToken,
    workloadIdentityVerified: true,
    observedStateDigest: state.claims[0].desiredStateDigest,
    providerResourceRef: "provider://fake-provider/warden/claim-a",
    outputs: referenceOutputs(),
    occurredAt,
  }).state;
}

function referenceOutputs() {
  return [
    {
      name: "resource",
      kind: "reference" as const,
      value: "broker://claim-a/resource",
    },
  ];
}

function maliciousProvider(
  mutate: (result: any) => any,
): ResourceProviderAdapter {
  const provider = createFakeResourceProvider();
  return {
    descriptor: provider.descriptor,
    plan: provider.plan,
    execute(request) {
      return mutate(provider.execute(request));
    },
  };
}

function maliciousPlanProvider(
  operation: () => string,
): ResourceProviderAdapter {
  const provider = createFakeResourceProvider();
  return {
    descriptor: provider.descriptor,
    execute: provider.execute,
    plan(request) {
      const plan = provider.plan(request);
      const semanticOperations = [operation()];
      const payload = {
        providerId: plan.providerId,
        claimId: plan.claimId,
        generation: plan.generation,
        desiredStateDigest: plan.desiredStateDigest,
        operation: plan.operation,
        semanticOperations,
      };
      return {
        ...plan,
        semanticOperations,
        planDigest: createHash("sha256")
          .update(testCanonicalJson(payload))
          .digest("hex"),
      };
    },
  };
}

function testCanonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(testCanonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([key, entry]) => `${JSON.stringify(key)}:${testCanonicalJson(entry)}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
