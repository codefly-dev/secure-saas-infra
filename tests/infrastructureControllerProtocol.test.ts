import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
  INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
  INFRASTRUCTURE_PROTOCOL_REASON_CODES,
  InfrastructureProtocolError,
  acceptInfrastructureOperation,
  createInfrastructureOperationCursor,
  createInfrastructureOperationEvent,
  createReferenceInfrastructureControllerProtocolContract,
  negotiateInfrastructureControllerVersion,
  parseInfrastructureControllerProtocolContract,
  parseInfrastructureControllerVersionResponse,
  parseInfrastructureOperationRequest,
  parseInfrastructureOperationResponse,
  rejectInfrastructureOperation,
  validateInfrastructureOperationEvents,
  verifyInfrastructureOperationCursor,
  type InfrastructureControllerVersionPolicy,
  type InfrastructureOperationEvent,
} from "../src/core";

const CURRENT = CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION;
const KEY = "a-secure-test-only-cursor-key-with-more-than-32-bytes";

test("checked protocol contract is generated from the generic implementation", () => {
  const checked = JSON.parse(
    readFileSync(
      "contracts/infrastructure-controller-protocol-v1alpha1.json",
      "utf8",
    ),
  );
  const generated = createReferenceInfrastructureControllerProtocolContract();
  assert.deepEqual(checked, generated);
  assert.deepEqual(
    parseInfrastructureControllerProtocolContract(checked),
    generated,
  );
  assert.deepEqual(
    generated.reasonCodes,
    Object.keys(INFRASTRUCTURE_PROTOCOL_REASON_CODES),
  );
  assert.equal(generated.examples.operationRequest.target.tenantId, "tenant-a");
});

test("version negotiation selects server preference and fails closed", () => {
  const request = versionRequest(["2026-06-01", CURRENT], ["resumable-watch"]);
  const policy: InfrastructureControllerVersionPolicy = {
    supportedProtocolVersions: [CURRENT, "2026-06-01"],
    availableFeatures: ["resumable-watch", "operation-events"],
    deprecations: [],
  };
  const selected = negotiateInfrastructureControllerVersion(
    request,
    policy,
    1_800_000_000,
  );
  assert.equal(selected.compatible, true);
  assert.equal(selected.selectedProtocolVersion, CURRENT);
  assert.deepEqual(selected.reasonCodes, []);

  const unsupported = negotiateInfrastructureControllerVersion(
    versionRequest(["2025-01-01"], []),
    policy,
    1_800_000_000,
  );
  assert.equal(unsupported.compatible, false);
  assert.equal(unsupported.selectedProtocolVersion, null);
  assert.deepEqual(unsupported.reasonCodes, [
    "INFRA_PROTOCOL_UNSUPPORTED_VERSION",
  ]);

  const missingFeature = negotiateInfrastructureControllerVersion(
    versionRequest([CURRENT], ["unknown-feature"]),
    policy,
    1_800_000_000,
  );
  assert.equal(missingFeature.compatible, false);
  assert.deepEqual(missingFeature.reasonCodes, [
    "INFRA_PROTOCOL_REQUIRED_FEATURE_UNAVAILABLE",
  ]);
});

test("version deprecation always names a supported replacement", () => {
  const deprecated = "2026-06-01";
  const policy: InfrastructureControllerVersionPolicy = {
    supportedProtocolVersions: [deprecated, CURRENT],
    availableFeatures: [],
    deprecations: [
      {
        protocolVersion: deprecated,
        replacementProtocolVersion: CURRENT,
        sunsetEpochSeconds: 1_900_000_000,
      },
    ],
  };
  const response = negotiateInfrastructureControllerVersion(
    versionRequest([deprecated], []),
    policy,
    1_800_000_000,
  );
  assert.equal(response.compatible, true);
  assert.deepEqual(response.reasonCodes, ["INFRA_PROTOCOL_DEPRECATED_VERSION"]);
  assert.equal(response.deprecation?.replacementProtocolVersion, CURRENT);

  assertProtocolError(
    () =>
      negotiateInfrastructureControllerVersion(
        versionRequest([deprecated], []),
        {
          ...policy,
          deprecations: [
            {
              protocolVersion: deprecated,
              replacementProtocolVersion: "2027-01-01",
              sunsetEpochSeconds: 1_900_000_000,
            },
          ],
        },
        1_800_000_000,
      ),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  const sunset = negotiateInfrastructureControllerVersion(
    versionRequest([deprecated], []),
    policy,
    1_900_000_000,
  );
  assert.equal(sunset.compatible, false);
  assert.equal(sunset.selectedProtocolVersion, null);
  assert.deepEqual(sunset.reasonCodes, ["INFRA_PROTOCOL_VERSION_SUNSET"]);
  assert.equal(sunset.deprecation?.replacementProtocolVersion, CURRENT);
});

test("public operation intent rejects caller-supplied authority and credentials", () => {
  const reference = operationRequest();
  assert.deepEqual(parseInfrastructureOperationRequest(reference), reference);

  for (const forbidden of [
    "providerCredentials",
    "grant",
    "capability",
    "cryptographicallyVerified",
    "policyChecksPassed",
  ]) {
    const hostile: any = structuredClone(reference);
    hostile[forbidden] = forbidden === "providerCredentials" ? "secret" : true;
    assertProtocolError(
      () => parseInfrastructureOperationRequest(hostile),
      "INFRA_PROTOCOL_REQUEST_INVALID",
    );
  }
});

test("public operation intent enforces plan and idempotency combinations", () => {
  const reconcile: any = operationRequest();
  delete reconcile.planDigest;
  assertProtocolError(
    () => parseInfrastructureOperationRequest(reconcile),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  const plan: any = operationRequest({
    operation: "plan",
    planDigest: null,
    approvalIds: [],
    idempotencyKey: null,
  });
  assert.doesNotThrow(() => parseInfrastructureOperationRequest(plan));

  plan.idempotencyKey = "caller-smuggled-mutation-key";
  assertProtocolError(
    () => parseInfrastructureOperationRequest(plan),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  const cancel: any = operationRequest({
    operation: "cancel",
    planDigest: null,
    approvalIds: [],
  });
  assert.doesNotThrow(() => parseInfrastructureOperationRequest(cancel));
  cancel.approvalIds = ["approval-1"];
  assertProtocolError(
    () => parseInfrastructureOperationRequest(cancel),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );
});

test("operation responses keep acceptance and retry semantics unambiguous", () => {
  const request = parseInfrastructureOperationRequest(operationRequest());
  assert.deepEqual(acceptInfrastructureOperation(request, "operation-1"), {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationResponse",
    protocolVersion: CURRENT,
    requestId: "operation-request-1",
    outcome: "accepted",
    operationId: "operation-1",
    reasonCodes: [],
    retryAfterSeconds: null,
  });
  assert.deepEqual(
    parseInfrastructureOperationResponse(
      acceptInfrastructureOperation(request, "operation-1"),
    ),
    acceptInfrastructureOperation(request, "operation-1"),
  );
  const rejected = rejectInfrastructureOperation(
    request,
    ["INFRA_PROTOCOL_PROVIDER_UNAVAILABLE"],
    30,
  );
  assert.equal(rejected.outcome, "rejected");
  assert.equal(rejected.operationId, null);
  assert.equal(rejected.retryAfterSeconds, 30);
  assert.deepEqual(parseInfrastructureOperationResponse(rejected), rejected);
  assertProtocolError(
    () =>
      rejectInfrastructureOperation(
        request,
        ["INFRA_PROTOCOL_POLICY_DENIED"],
        30,
      ),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );
});

test("response parsers reject contradictory compatibility and operation outcomes", () => {
  const contract = createReferenceInfrastructureControllerProtocolContract();
  const versionResponse: any = structuredClone(
    contract.examples.versionResponse,
  );
  versionResponse.compatible = false;
  assertProtocolError(
    () => parseInfrastructureControllerVersionResponse(versionResponse),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  const operationResponse: any = structuredClone(
    contract.examples.operationResponse,
  );
  operationResponse.reasonCodes = ["INFRA_PROTOCOL_POLICY_DENIED"];
  assertProtocolError(
    () => parseInfrastructureOperationResponse(operationResponse),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );
});

test("operation events are monotonic, subject-bound, and digest chained", () => {
  const first = event(1, "accepted");
  const second = event(2, "planning", first);
  const terminal = event(3, "succeeded", second);
  assert.deepEqual(
    validateInfrastructureOperationEvents([first, second, terminal]),
    [first, second, terminal],
  );

  const tampered: any = structuredClone(second);
  tampered.phase = "reconciling";
  assertProtocolError(
    () => validateInfrastructureOperationEvents([first, tampered]),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  const skipped: any = structuredClone(second);
  skipped.sequence = 3;
  assertProtocolError(
    () => validateInfrastructureOperationEvents([first, skipped]),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );

  assertProtocolError(
    () => event(4, "observing", terminal),
    "INFRA_PROTOCOL_REQUEST_INVALID",
  );
});

test("resumable watch cursors reject tampering, expiry, and tenant substitution", () => {
  const subject = {
    organizationId: "organization-a",
    tenantId: "tenant-a",
    operationId: "operation-1",
  };
  const cursor = createInfrastructureOperationCursor(
    { ...subject, nextSequence: 3, expiresAtEpochSeconds: 1_800_000_300 },
    KEY,
  );
  assert.equal(
    verifyInfrastructureOperationCursor(cursor, KEY, subject, 1_800_000_000)
      .nextSequence,
    3,
  );

  const replacement = cursor.endsWith("A") ? "B" : "A";
  assertProtocolError(
    () =>
      verifyInfrastructureOperationCursor(
        `${cursor.slice(0, -1)}${replacement}`,
        KEY,
        subject,
        1_800_000_000,
      ),
    "INFRA_PROTOCOL_CURSOR_INVALID",
  );
  assertProtocolError(
    () =>
      verifyInfrastructureOperationCursor(
        cursor,
        KEY,
        { ...subject, tenantId: "tenant-b" },
        1_800_000_000,
      ),
    "INFRA_PROTOCOL_CURSOR_SUBJECT_MISMATCH",
  );
  assertProtocolError(
    () =>
      verifyInfrastructureOperationCursor(cursor, KEY, subject, 1_800_000_300),
    "INFRA_PROTOCOL_CURSOR_EXPIRED",
  );
  assertProtocolError(
    () =>
      createInfrastructureOperationCursor(
        { ...subject, nextSequence: 3, expiresAtEpochSeconds: 1_800_000_300 },
        "short",
      ),
    "INFRA_PROTOCOL_INTERNAL",
  );
});

function versionRequest(
  supportedProtocolVersions: readonly string[],
  requiredFeatures: readonly string[],
) {
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureControllerVersionRequest",
    requestId: "version-request-1",
    supportedProtocolVersions,
    requiredFeatures,
  };
}

function operationRequest(overrides: Record<string, unknown> = {}) {
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationRequest",
    protocolVersion: CURRENT,
    requestId: "operation-request-1",
    authorizationContextId: "authorization-context-1",
    target: {
      organizationId: "organization-a",
      tenantId: "tenant-a",
      contextId: "aws-development",
      claimId: "database-a",
      generation: 1,
      desiredStateDigest: "a".repeat(64),
    },
    operation: "reconcile",
    planDigest: "b".repeat(64),
    approvalIds: ["approval-1"],
    idempotencyKey: "idempotency-1",
    deadlineEpochSeconds: 1_800_000_120,
    ...overrides,
  };
}

function event(
  sequence: number,
  phase: "accepted" | "planning" | "observing" | "succeeded",
  previousEvent: InfrastructureOperationEvent | null = null,
) {
  return createInfrastructureOperationEvent({
    protocolVersion: CURRENT,
    operationId: "operation-1",
    organizationId: "organization-a",
    tenantId: "tenant-a",
    eventId: `event-${sequence}`,
    sequence,
    phase,
    generation: 1,
    desiredStateDigest: "a".repeat(64),
    occurredAt: `2026-07-16T12:00:0${sequence - 1}.000Z`,
    previousEvent,
  });
}

function assertProtocolError(fn: () => unknown, reasonCode: string): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof InfrastructureProtocolError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  });
}
