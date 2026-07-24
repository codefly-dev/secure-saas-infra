import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { InfrastructureOperation } from "./infrastructureController";

export const INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION =
  "security.deus.dev/infrastructure-controller-protocol/v1alpha1" as const;
export const CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION =
  "2026-07-16" as const;

export const INFRASTRUCTURE_PROTOCOL_REASON_CODES = Object.freeze({
  INFRA_PROTOCOL_UNSUPPORTED_VERSION: {
    category: "compatibility",
    retryable: false,
  },
  INFRA_PROTOCOL_REQUIRED_FEATURE_UNAVAILABLE: {
    category: "compatibility",
    retryable: false,
  },
  INFRA_PROTOCOL_DEPRECATED_VERSION: {
    category: "compatibility",
    retryable: false,
  },
  INFRA_PROTOCOL_VERSION_SUNSET: {
    category: "compatibility",
    retryable: false,
  },
  INFRA_PROTOCOL_REQUEST_INVALID: { category: "request", retryable: false },
  INFRA_PROTOCOL_AUTHENTICATION_REQUIRED: {
    category: "authorization",
    retryable: false,
  },
  INFRA_PROTOCOL_ORGANIZATION_DENIED: {
    category: "authorization",
    retryable: false,
  },
  INFRA_PROTOCOL_TENANT_DENIED: {
    category: "authorization",
    retryable: false,
  },
  INFRA_PROTOCOL_OPERATION_DENIED: {
    category: "authorization",
    retryable: false,
  },
  INFRA_PROTOCOL_CLAIM_CONFLICT: { category: "state", retryable: false },
  INFRA_PROTOCOL_IDEMPOTENCY_CONFLICT: {
    category: "state",
    retryable: false,
  },
  INFRA_PROTOCOL_PLAN_REQUIRED: { category: "policy", retryable: false },
  INFRA_PROTOCOL_PLAN_STALE: { category: "policy", retryable: false },
  INFRA_PROTOCOL_APPROVAL_REQUIRED: { category: "policy", retryable: false },
  INFRA_PROTOCOL_DEADLINE_EXCEEDED: {
    category: "request",
    retryable: true,
  },
  INFRA_PROTOCOL_OPERATION_NOT_FOUND: {
    category: "state",
    retryable: false,
  },
  INFRA_PROTOCOL_CURSOR_INVALID: { category: "watch", retryable: false },
  INFRA_PROTOCOL_CURSOR_EXPIRED: { category: "watch", retryable: true },
  INFRA_PROTOCOL_CURSOR_SUBJECT_MISMATCH: {
    category: "authorization",
    retryable: false,
  },
  INFRA_PROTOCOL_PROVIDER_UNAVAILABLE: {
    category: "provider",
    retryable: true,
  },
  INFRA_PROTOCOL_POLICY_DENIED: { category: "policy", retryable: false },
  INFRA_PROTOCOL_INTERNAL: { category: "internal", retryable: true },
} as const);

export type InfrastructureProtocolReasonCode =
  keyof typeof INFRASTRUCTURE_PROTOCOL_REASON_CODES;

export interface InfrastructureControllerVersionRequest {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureControllerVersionRequest";
  requestId: string;
  supportedProtocolVersions: readonly string[];
  requiredFeatures: readonly string[];
}

export interface InfrastructureControllerVersionDeprecation {
  protocolVersion: string;
  replacementProtocolVersion: string;
  sunsetEpochSeconds: number;
}

export interface InfrastructureControllerVersionResponse {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureControllerVersionResponse";
  requestId: string;
  compatible: boolean;
  selectedProtocolVersion: string | null;
  serverProtocolVersions: readonly string[];
  availableFeatures: readonly string[];
  reasonCodes: readonly InfrastructureProtocolReasonCode[];
  deprecation: InfrastructureControllerVersionDeprecation | null;
}

export interface InfrastructureControllerVersionPolicy {
  supportedProtocolVersions: readonly string[];
  availableFeatures: readonly string[];
  deprecations: readonly InfrastructureControllerVersionDeprecation[];
}

export interface InfrastructureOperationRequest {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureOperationRequest";
  protocolVersion: string;
  requestId: string;
  authorizationContextId: string;
  target: {
    organizationId: string;
    tenantId: string;
    contextId: string;
    claimId: string;
    generation: number;
    desiredStateDigest: string;
  };
  operation: InfrastructureOperation;
  planDigest: string | null;
  approvalIds: readonly string[];
  idempotencyKey: string | null;
  deadlineEpochSeconds: number;
}

export interface InfrastructureOperationResponse {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureOperationResponse";
  protocolVersion: string;
  requestId: string;
  outcome: "accepted" | "rejected";
  operationId: string | null;
  reasonCodes: readonly InfrastructureProtocolReasonCode[];
  retryAfterSeconds: number | null;
}

export interface InfrastructureOperationWatchRequest {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureOperationWatchRequest";
  protocolVersion: string;
  requestId: string;
  authorizationContextId: string;
  organizationId: string;
  tenantId: string;
  operationId: string;
  cursor: string | null;
  maxEvents: number;
  deadlineEpochSeconds: number;
}

export type InfrastructureOperationPhase =
  | "accepted"
  | "planning"
  | "planned"
  | "reconciling"
  | "observing"
  | "cancelling"
  | "deleting"
  | "succeeded"
  | "failed"
  | "cancelled";

export interface InfrastructureOperationEvent {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureOperationEvent";
  protocolVersion: string;
  operationId: string;
  organizationId: string;
  tenantId: string;
  eventId: string;
  sequence: number;
  phase: InfrastructureOperationPhase;
  terminal: boolean;
  generation: number;
  desiredStateDigest: string;
  occurredAt: string;
  reasonCodes: readonly InfrastructureProtocolReasonCode[];
  previousEventDigest: string | null;
  eventDigest: string;
}

export interface InfrastructureOperationEventInput {
  protocolVersion: string;
  operationId: string;
  organizationId: string;
  tenantId: string;
  eventId: string;
  sequence: number;
  phase: InfrastructureOperationPhase;
  generation: number;
  desiredStateDigest: string;
  occurredAt: string;
  reasonCodes?: readonly InfrastructureProtocolReasonCode[];
  previousEvent?: InfrastructureOperationEvent | null;
}

export interface InfrastructureOperationCursorSubject {
  organizationId: string;
  tenantId: string;
  operationId: string;
}

export interface InfrastructureOperationCursorValue extends InfrastructureOperationCursorSubject {
  nextSequence: number;
  expiresAtEpochSeconds: number;
}

export interface InfrastructureControllerProtocolContract {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION;
  kind: "InfrastructureControllerProtocolContract";
  currentProtocolVersion: string;
  supportedProtocolVersions: readonly string[];
  reasonCodes: readonly InfrastructureProtocolReasonCode[];
  examples: {
    versionRequest: InfrastructureControllerVersionRequest;
    versionResponse: InfrastructureControllerVersionResponse;
    operationRequest: InfrastructureOperationRequest;
    operationResponse: InfrastructureOperationResponse;
    watchRequest: InfrastructureOperationWatchRequest;
    events: readonly InfrastructureOperationEvent[];
  };
}

export class InfrastructureProtocolError extends Error {
  constructor(
    readonly reasonCode: InfrastructureProtocolReasonCode,
    message: string,
  ) {
    super(message);
    this.name = "InfrastructureProtocolError";
  }
}

export function parseInfrastructureControllerVersionRequest(
  value: unknown,
): InfrastructureControllerVersionRequest {
  const root = exactObject(value, "versionRequest", [
    "apiVersion",
    "kind",
    "requestId",
    "supportedProtocolVersions",
    "requiredFeatures",
  ]);
  return {
    apiVersion: literal(
      root.apiVersion,
      "versionRequest.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "versionRequest.kind",
      "InfrastructureControllerVersionRequest",
    ),
    requestId: identifier(root.requestId, "versionRequest.requestId"),
    supportedProtocolVersions: nonEmptyUniqueArray(
      root.supportedProtocolVersions,
      "versionRequest.supportedProtocolVersions",
      protocolVersion,
    ),
    requiredFeatures: uniqueArray(
      root.requiredFeatures,
      "versionRequest.requiredFeatures",
      identifier,
    ),
  };
}

export function parseInfrastructureControllerVersionResponse(
  value: unknown,
): InfrastructureControllerVersionResponse {
  const root = exactObject(value, "versionResponse", [
    "apiVersion",
    "kind",
    "requestId",
    "compatible",
    "selectedProtocolVersion",
    "serverProtocolVersions",
    "availableFeatures",
    "reasonCodes",
    "deprecation",
  ]);
  const compatible = booleanValue(
    root.compatible,
    "versionResponse.compatible",
  );
  const selectedProtocolVersion =
    root.selectedProtocolVersion === null
      ? null
      : protocolVersion(
          root.selectedProtocolVersion,
          "versionResponse.selectedProtocolVersion",
        );
  const serverProtocolVersions = nonEmptyUniqueArray(
    root.serverProtocolVersions,
    "versionResponse.serverProtocolVersions",
    protocolVersion,
  );
  const availableFeatures = uniqueArray(
    root.availableFeatures,
    "versionResponse.availableFeatures",
    identifier,
  );
  const reasonCodes = uniqueArray(
    root.reasonCodes,
    "versionResponse.reasonCodes",
    reasonCode,
  );
  const deprecation =
    root.deprecation === null
      ? null
      : parseVersionDeprecation(
          root.deprecation,
          "versionResponse.deprecation",
        );
  if (compatible !== (selectedProtocolVersion !== null)) {
    invalid(
      "versionResponse.compatible must exactly match selection of a protocol version.",
    );
  }
  if (
    selectedProtocolVersion !== null &&
    !serverProtocolVersions.includes(selectedProtocolVersion)
  ) {
    invalid(
      "versionResponse.selectedProtocolVersion must be advertised by the server.",
    );
  }
  if (!compatible && reasonCodes.length === 0) {
    invalid("an incompatible version response requires a reason code.");
  }
  if (deprecation !== null) {
    validateDeprecation(deprecation, serverProtocolVersions);
    if (compatible && selectedProtocolVersion !== deprecation.protocolVersion) {
      invalid(
        "versionResponse.deprecation must describe the selected version.",
      );
    }
    if (
      !reasonCodes.includes("INFRA_PROTOCOL_DEPRECATED_VERSION") &&
      !reasonCodes.includes("INFRA_PROTOCOL_VERSION_SUNSET")
    ) {
      invalid(
        "versionResponse.deprecation requires a deprecation reason code.",
      );
    }
  }
  return {
    apiVersion: literal(
      root.apiVersion,
      "versionResponse.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "versionResponse.kind",
      "InfrastructureControllerVersionResponse",
    ),
    requestId: identifier(root.requestId, "versionResponse.requestId"),
    compatible,
    selectedProtocolVersion,
    serverProtocolVersions,
    availableFeatures,
    reasonCodes,
    deprecation,
  };
}

export function negotiateInfrastructureControllerVersion(
  value: unknown,
  policy: InfrastructureControllerVersionPolicy,
  nowEpochSeconds: number,
): InfrastructureControllerVersionResponse {
  const request = parseInfrastructureControllerVersionRequest(value);
  const serverVersions = nonEmptyUniqueArray(
    policy.supportedProtocolVersions,
    "versionPolicy.supportedProtocolVersions",
    protocolVersion,
  );
  const availableFeatures = uniqueArray(
    policy.availableFeatures,
    "versionPolicy.availableFeatures",
    identifier,
  );
  const selected = serverVersions.find((entry) =>
    request.supportedProtocolVersions.includes(entry),
  );
  if (!selected) {
    return versionResponse(request, serverVersions, availableFeatures, null, [
      "INFRA_PROTOCOL_UNSUPPORTED_VERSION",
    ]);
  }
  const missingFeature = request.requiredFeatures.some(
    (feature) => !availableFeatures.includes(feature),
  );
  if (missingFeature) {
    return versionResponse(request, serverVersions, availableFeatures, null, [
      "INFRA_PROTOCOL_REQUIRED_FEATURE_UNAVAILABLE",
    ]);
  }
  const deprecation = policy.deprecations.find(
    (entry) => entry.protocolVersion === selected,
  );
  if (deprecation) validateDeprecation(deprecation, serverVersions);
  const now = positiveInteger(nowEpochSeconds, "nowEpochSeconds");
  if (deprecation && deprecation.sunsetEpochSeconds <= now) {
    return versionResponse(
      request,
      serverVersions,
      availableFeatures,
      null,
      ["INFRA_PROTOCOL_VERSION_SUNSET"],
      deprecation,
    );
  }
  return versionResponse(
    request,
    serverVersions,
    availableFeatures,
    selected,
    deprecation ? ["INFRA_PROTOCOL_DEPRECATED_VERSION"] : [],
    deprecation ?? null,
  );
}

export function parseInfrastructureOperationRequest(
  value: unknown,
): InfrastructureOperationRequest {
  const root = exactObject(value, "operationRequest", [
    "apiVersion",
    "kind",
    "protocolVersion",
    "requestId",
    "authorizationContextId",
    "target",
    "operation",
    "planDigest",
    "approvalIds",
    "idempotencyKey",
    "deadlineEpochSeconds",
  ]);
  const target = exactObject(root.target, "operationRequest.target", [
    "organizationId",
    "tenantId",
    "contextId",
    "claimId",
    "generation",
    "desiredStateDigest",
  ]);
  const operation = enumeration(root.operation, "operationRequest.operation", [
    "plan",
    "reconcile",
    "observe",
    "cancel",
    "delete",
  ]);
  const planDigest = nullableDigest(
    root.planDigest,
    "operationRequest.planDigest",
  );
  const approvalIds = uniqueArray(
    root.approvalIds,
    "operationRequest.approvalIds",
    identifier,
  );
  const idempotencyKey = nullableIdentifier(
    root.idempotencyKey,
    "operationRequest.idempotencyKey",
  );
  const requiresPlan = operation === "reconcile" || operation === "delete";
  const isMutation =
    operation === "reconcile" ||
    operation === "cancel" ||
    operation === "delete";
  if (requiresPlan !== (planDigest !== null)) {
    invalid(
      "operationRequest.planDigest must be present only for reconcile or delete.",
    );
  }
  if (!requiresPlan && approvalIds.length > 0) {
    invalid(
      "operationRequest.approvalIds are allowed only for reconcile or delete.",
    );
  }
  if (isMutation !== (idempotencyKey !== null)) {
    invalid(
      "operationRequest.idempotencyKey must be present only for mutations.",
    );
  }
  return {
    apiVersion: literal(
      root.apiVersion,
      "operationRequest.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "operationRequest.kind",
      "InfrastructureOperationRequest",
    ),
    protocolVersion: protocolVersion(
      root.protocolVersion,
      "operationRequest.protocolVersion",
    ),
    requestId: identifier(root.requestId, "operationRequest.requestId"),
    authorizationContextId: identifier(
      root.authorizationContextId,
      "operationRequest.authorizationContextId",
    ),
    target: {
      organizationId: identifier(
        target.organizationId,
        "operationRequest.target.organizationId",
      ),
      tenantId: identifier(target.tenantId, "operationRequest.target.tenantId"),
      contextId: identifier(
        target.contextId,
        "operationRequest.target.contextId",
      ),
      claimId: identifier(target.claimId, "operationRequest.target.claimId"),
      generation: positiveInteger(
        target.generation,
        "operationRequest.target.generation",
      ),
      desiredStateDigest: digest(
        target.desiredStateDigest,
        "operationRequest.target.desiredStateDigest",
      ),
    },
    operation,
    planDigest,
    approvalIds,
    idempotencyKey,
    deadlineEpochSeconds: positiveInteger(
      root.deadlineEpochSeconds,
      "operationRequest.deadlineEpochSeconds",
    ),
  };
}

export function acceptInfrastructureOperation(
  request: InfrastructureOperationRequest,
  operationId: string,
): InfrastructureOperationResponse {
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationResponse",
    protocolVersion: request.protocolVersion,
    requestId: request.requestId,
    outcome: "accepted",
    operationId: identifier(operationId, "operationId"),
    reasonCodes: [],
    retryAfterSeconds: null,
  };
}

export function parseInfrastructureOperationResponse(
  value: unknown,
): InfrastructureOperationResponse {
  const root = exactObject(value, "operationResponse", [
    "apiVersion",
    "kind",
    "protocolVersion",
    "requestId",
    "outcome",
    "operationId",
    "reasonCodes",
    "retryAfterSeconds",
  ]);
  const outcome = enumeration(root.outcome, "operationResponse.outcome", [
    "accepted",
    "rejected",
  ]);
  const operationId =
    root.operationId === null
      ? null
      : identifier(root.operationId, "operationResponse.operationId");
  const reasonCodes = uniqueArray(
    root.reasonCodes,
    "operationResponse.reasonCodes",
    reasonCode,
  );
  const retryAfterSeconds =
    root.retryAfterSeconds === null
      ? null
      : positiveInteger(
          root.retryAfterSeconds,
          "operationResponse.retryAfterSeconds",
        );
  if (retryAfterSeconds !== null && retryAfterSeconds > 86_400) {
    invalid("operationResponse.retryAfterSeconds must not exceed 86400.");
  }
  if (outcome === "accepted") {
    if (
      operationId === null ||
      reasonCodes.length !== 0 ||
      retryAfterSeconds !== null
    ) {
      invalid(
        "an accepted operation requires an operation ID and no rejection metadata.",
      );
    }
  } else {
    if (operationId !== null || reasonCodes.length === 0) {
      invalid(
        "a rejected operation requires reason codes and no operation ID.",
      );
    }
    if (
      retryAfterSeconds !== null &&
      !reasonCodes.some(
        (code) => INFRASTRUCTURE_PROTOCOL_REASON_CODES[code].retryable,
      )
    ) {
      invalid(
        "operationResponse.retryAfterSeconds requires a retryable reason code.",
      );
    }
  }
  return {
    apiVersion: literal(
      root.apiVersion,
      "operationResponse.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "operationResponse.kind",
      "InfrastructureOperationResponse",
    ),
    protocolVersion: protocolVersion(
      root.protocolVersion,
      "operationResponse.protocolVersion",
    ),
    requestId: identifier(root.requestId, "operationResponse.requestId"),
    outcome,
    operationId,
    reasonCodes,
    retryAfterSeconds,
  };
}

export function rejectInfrastructureOperation(
  request: Pick<
    InfrastructureOperationRequest,
    "protocolVersion" | "requestId"
  >,
  reasonCodes: readonly InfrastructureProtocolReasonCode[],
  retryAfterSeconds: number | null = null,
): InfrastructureOperationResponse {
  const reasons = nonEmptyUniqueArray(reasonCodes, "reasonCodes", reasonCode);
  if (
    retryAfterSeconds !== null &&
    (!Number.isInteger(retryAfterSeconds) || retryAfterSeconds < 1)
  ) {
    invalid("retryAfterSeconds must be a positive integer or null.");
  }
  if (
    retryAfterSeconds !== null &&
    !reasons.some(
      (code) => INFRASTRUCTURE_PROTOCOL_REASON_CODES[code].retryable,
    )
  ) {
    invalid("retryAfterSeconds requires at least one retryable reason code.");
  }
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationResponse",
    protocolVersion: protocolVersion(
      request.protocolVersion,
      "operationResponse.protocolVersion",
    ),
    requestId: identifier(request.requestId, "operationResponse.requestId"),
    outcome: "rejected",
    operationId: null,
    reasonCodes: reasons,
    retryAfterSeconds,
  };
}

export function parseInfrastructureOperationWatchRequest(
  value: unknown,
): InfrastructureOperationWatchRequest {
  const root = exactObject(value, "watchRequest", [
    "apiVersion",
    "kind",
    "protocolVersion",
    "requestId",
    "authorizationContextId",
    "organizationId",
    "tenantId",
    "operationId",
    "cursor",
    "maxEvents",
    "deadlineEpochSeconds",
  ]);
  const maxEvents = positiveInteger(root.maxEvents, "watchRequest.maxEvents");
  if (maxEvents > 100) invalid("watchRequest.maxEvents must not exceed 100.");
  return {
    apiVersion: literal(
      root.apiVersion,
      "watchRequest.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "watchRequest.kind",
      "InfrastructureOperationWatchRequest",
    ),
    protocolVersion: protocolVersion(
      root.protocolVersion,
      "watchRequest.protocolVersion",
    ),
    requestId: identifier(root.requestId, "watchRequest.requestId"),
    authorizationContextId: identifier(
      root.authorizationContextId,
      "watchRequest.authorizationContextId",
    ),
    organizationId: identifier(
      root.organizationId,
      "watchRequest.organizationId",
    ),
    tenantId: identifier(root.tenantId, "watchRequest.tenantId"),
    operationId: identifier(root.operationId, "watchRequest.operationId"),
    cursor:
      root.cursor === null ? null : cursor(root.cursor, "watchRequest.cursor"),
    maxEvents,
    deadlineEpochSeconds: positiveInteger(
      root.deadlineEpochSeconds,
      "watchRequest.deadlineEpochSeconds",
    ),
  };
}

export function createInfrastructureOperationEvent(
  input: InfrastructureOperationEventInput,
): InfrastructureOperationEvent {
  const phase = enumeration(input.phase, "event.phase", [
    "accepted",
    "planning",
    "planned",
    "reconciling",
    "observing",
    "cancelling",
    "deleting",
    "succeeded",
    "failed",
    "cancelled",
  ]);
  const terminal = ["succeeded", "failed", "cancelled"].includes(phase);
  const reasons = uniqueArray(
    input.reasonCodes ?? [],
    "event.reasonCodes",
    reasonCode,
  );
  if (phase === "failed" && reasons.length === 0) {
    invalid("failed events require at least one reason code.");
  }
  if (phase !== "failed" && reasons.length > 0) {
    invalid("only failed events may contain reason codes.");
  }
  const previous = input.previousEvent ?? null;
  const sequence = positiveInteger(input.sequence, "event.sequence");
  if (sequence === 1 && previous !== null) {
    invalid("the first event must not declare a previous event.");
  }
  if (sequence > 1) {
    if (!previous || previous.sequence !== sequence - 1) {
      invalid("an event must follow the immediately preceding sequence.");
    }
    if (
      previous.operationId !== input.operationId ||
      previous.organizationId !== input.organizationId ||
      previous.tenantId !== input.tenantId ||
      previous.generation !== input.generation ||
      previous.desiredStateDigest !== input.desiredStateDigest
    ) {
      invalid("an event chain must not change its operation subject.");
    }
    if (previous.terminal) invalid("a terminal event cannot be followed.");
  }
  const eventWithoutDigest = {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationEvent" as const,
    protocolVersion: protocolVersion(
      input.protocolVersion,
      "event.protocolVersion",
    ),
    operationId: identifier(input.operationId, "event.operationId"),
    organizationId: identifier(input.organizationId, "event.organizationId"),
    tenantId: identifier(input.tenantId, "event.tenantId"),
    eventId: identifier(input.eventId, "event.eventId"),
    sequence,
    phase,
    terminal,
    generation: positiveInteger(input.generation, "event.generation"),
    desiredStateDigest: digest(
      input.desiredStateDigest,
      "event.desiredStateDigest",
    ),
    occurredAt: timestamp(input.occurredAt, "event.occurredAt"),
    reasonCodes: reasons,
    previousEventDigest: previous?.eventDigest ?? null,
  };
  return {
    ...eventWithoutDigest,
    eventDigest: sha256(canonicalJson(eventWithoutDigest)),
  };
}

export function validateInfrastructureOperationEvents(
  values: readonly unknown[],
  options: {
    expectedFirstSequence?: number;
    expectedPreviousEventDigest?: string | null;
  } = {},
): InfrastructureOperationEvent[] {
  if (!Array.isArray(values) || values.length === 0) {
    invalid("an operation event page must contain at least one event.");
  }
  const expectedFirstSequence = options.expectedFirstSequence ?? 1;
  const expectedPreviousEventDigest =
    options.expectedPreviousEventDigest ?? null;
  const parsed = values.map((value, index) =>
    parseOperationEvent(value, index),
  );
  for (let index = 0; index < parsed.length; index += 1) {
    const event = parsed[index]!;
    const expectedSequence = expectedFirstSequence + index;
    const expectedPrevious =
      index === 0
        ? expectedPreviousEventDigest
        : parsed[index - 1]!.eventDigest;
    if (event.sequence !== expectedSequence) {
      invalid(`event sequence ${event.sequence} is not ${expectedSequence}.`);
    }
    if (event.previousEventDigest !== expectedPrevious) {
      invalid(`event ${event.sequence} has an invalid previous-event digest.`);
    }
    if (index > 0) {
      const prior = parsed[index - 1]!;
      if (
        prior.terminal ||
        prior.operationId !== event.operationId ||
        prior.organizationId !== event.organizationId ||
        prior.tenantId !== event.tenantId ||
        prior.generation !== event.generation ||
        prior.desiredStateDigest !== event.desiredStateDigest
      ) {
        invalid(`event ${event.sequence} breaks the operation event chain.`);
      }
    }
  }
  return parsed;
}

export function createInfrastructureOperationCursor(
  value: InfrastructureOperationCursorValue,
  signingKey: string | Uint8Array,
): string {
  const payload = validateCursorValue(value);
  const key = cursorSigningKey(signingKey);
  const encoded = Buffer.from(canonicalJson(payload)).toString("base64url");
  const signature = createHmac("sha256", key)
    .update(encoded)
    .digest("base64url");
  return `v1.${encoded}.${signature}`;
}

export function verifyInfrastructureOperationCursor(
  value: unknown,
  signingKey: string | Uint8Array,
  expectedSubject: InfrastructureOperationCursorSubject,
  nowEpochSeconds: number,
): InfrastructureOperationCursorValue {
  const encodedCursor = cursor(value, "cursor");
  const parts = encodedCursor.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") cursorInvalid();
  const encodedPayload = parts[1]!;
  const suppliedSignature = decodeBase64Url(parts[2]!);
  const expectedSignature = createHmac("sha256", cursorSigningKey(signingKey))
    .update(encodedPayload)
    .digest();
  if (
    suppliedSignature.length !== expectedSignature.length ||
    !timingSafeEqual(suppliedSignature, expectedSignature)
  ) {
    cursorInvalid();
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8"),
    );
  } catch {
    cursorInvalid();
  }
  const payload = validateCursorValue(decoded);
  const subject = {
    organizationId: identifier(
      expectedSubject.organizationId,
      "expected.organizationId",
    ),
    tenantId: identifier(expectedSubject.tenantId, "expected.tenantId"),
    operationId: identifier(
      expectedSubject.operationId,
      "expected.operationId",
    ),
  };
  if (
    payload.organizationId !== subject.organizationId ||
    payload.tenantId !== subject.tenantId ||
    payload.operationId !== subject.operationId
  ) {
    throw new InfrastructureProtocolError(
      "INFRA_PROTOCOL_CURSOR_SUBJECT_MISMATCH",
      "The operation cursor is not bound to the requested subject.",
    );
  }
  const now = positiveInteger(nowEpochSeconds, "nowEpochSeconds");
  if (payload.expiresAtEpochSeconds <= now) {
    throw new InfrastructureProtocolError(
      "INFRA_PROTOCOL_CURSOR_EXPIRED",
      "The operation cursor has expired.",
    );
  }
  return payload;
}

export function createReferenceInfrastructureControllerProtocolContract(): InfrastructureControllerProtocolContract {
  const policy: InfrastructureControllerVersionPolicy = {
    supportedProtocolVersions: [
      CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
    ],
    availableFeatures: [
      "operation-events",
      "resumable-watch",
      "stable-reason-codes",
    ],
    deprecations: [],
  };
  const versionRequest: InfrastructureControllerVersionRequest = {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureControllerVersionRequest",
    requestId: "version-request-1",
    supportedProtocolVersions: [
      CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
    ],
    requiredFeatures: ["operation-events", "resumable-watch"],
  };
  const versionResponse = negotiateInfrastructureControllerVersion(
    versionRequest,
    policy,
    1_800_000_000,
  );
  const operationRequest = parseInfrastructureOperationRequest({
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureOperationRequest",
    protocolVersion: CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
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
  });
  const operationResponse = acceptInfrastructureOperation(
    operationRequest,
    "operation-1",
  );
  const firstEvent = createInfrastructureOperationEvent({
    protocolVersion: CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
    operationId: "operation-1",
    organizationId: "organization-a",
    tenantId: "tenant-a",
    eventId: "event-1",
    sequence: 1,
    phase: "accepted",
    generation: 1,
    desiredStateDigest: "a".repeat(64),
    occurredAt: "2026-07-16T12:00:00.000Z",
  });
  const secondEvent = createInfrastructureOperationEvent({
    protocolVersion: CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
    operationId: "operation-1",
    organizationId: "organization-a",
    tenantId: "tenant-a",
    eventId: "event-2",
    sequence: 2,
    phase: "planning",
    generation: 1,
    desiredStateDigest: "a".repeat(64),
    occurredAt: "2026-07-16T12:00:01.000Z",
    previousEvent: firstEvent,
  });
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureControllerProtocolContract",
    currentProtocolVersion: CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
    supportedProtocolVersions: policy.supportedProtocolVersions,
    reasonCodes: Object.keys(
      INFRASTRUCTURE_PROTOCOL_REASON_CODES,
    ) as InfrastructureProtocolReasonCode[],
    examples: {
      versionRequest,
      versionResponse,
      operationRequest,
      operationResponse,
      watchRequest: parseInfrastructureOperationWatchRequest({
        apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
        kind: "InfrastructureOperationWatchRequest",
        protocolVersion: CURRENT_INFRASTRUCTURE_CONTROLLER_PROTOCOL_VERSION,
        requestId: "watch-request-1",
        authorizationContextId: "authorization-context-1",
        organizationId: "organization-a",
        tenantId: "tenant-a",
        operationId: "operation-1",
        cursor: null,
        maxEvents: 50,
        deadlineEpochSeconds: 1_800_000_120,
      }),
      events: [firstEvent, secondEvent],
    },
  };
}

export function parseInfrastructureControllerProtocolContract(
  value: unknown,
): InfrastructureControllerProtocolContract {
  const root = exactObject(value, "protocolContract", [
    "apiVersion",
    "kind",
    "currentProtocolVersion",
    "supportedProtocolVersions",
    "reasonCodes",
    "examples",
  ]);
  const examples = exactObject(root.examples, "protocolContract.examples", [
    "versionRequest",
    "versionResponse",
    "operationRequest",
    "operationResponse",
    "watchRequest",
    "events",
  ]);
  const currentProtocolVersion = protocolVersion(
    root.currentProtocolVersion,
    "protocolContract.currentProtocolVersion",
  );
  const supportedProtocolVersions = nonEmptyUniqueArray(
    root.supportedProtocolVersions,
    "protocolContract.supportedProtocolVersions",
    protocolVersion,
  );
  if (!supportedProtocolVersions.includes(currentProtocolVersion)) {
    invalid("the current protocol version must be in the supported set.");
  }
  const reasonCodes = nonEmptyUniqueArray(
    root.reasonCodes,
    "protocolContract.reasonCodes",
    reasonCode,
  );
  const expectedReasonCodes = Object.keys(
    INFRASTRUCTURE_PROTOCOL_REASON_CODES,
  ) as InfrastructureProtocolReasonCode[];
  if (
    reasonCodes.length !== expectedReasonCodes.length ||
    expectedReasonCodes.some((code) => !reasonCodes.includes(code))
  ) {
    invalid("protocolContract.reasonCodes must publish the complete catalog.");
  }
  const versionRequest = parseInfrastructureControllerVersionRequest(
    examples.versionRequest,
  );
  const versionResponse = parseInfrastructureControllerVersionResponse(
    examples.versionResponse,
  );
  const operationRequest = parseInfrastructureOperationRequest(
    examples.operationRequest,
  );
  const operationResponse = parseInfrastructureOperationResponse(
    examples.operationResponse,
  );
  const watchRequest = parseInfrastructureOperationWatchRequest(
    examples.watchRequest,
  );
  const events = validateInfrastructureOperationEvents(
    arrayValue(examples.events, "protocolContract.examples.events"),
  );
  if (
    versionRequest.requestId !== versionResponse.requestId ||
    versionResponse.serverProtocolVersions.length !==
      supportedProtocolVersions.length ||
    versionResponse.serverProtocolVersions.some(
      (entry) => !supportedProtocolVersions.includes(entry),
    )
  ) {
    invalid("the version examples do not describe the published contract.");
  }
  if (
    operationRequest.requestId !== operationResponse.requestId ||
    operationRequest.protocolVersion !== operationResponse.protocolVersion ||
    watchRequest.protocolVersion !== operationRequest.protocolVersion ||
    watchRequest.organizationId !== operationRequest.target.organizationId ||
    watchRequest.tenantId !== operationRequest.target.tenantId ||
    watchRequest.operationId !== operationResponse.operationId
  ) {
    invalid("the operation examples do not bind one protocol operation.");
  }
  if (
    events.some(
      (event) =>
        event.protocolVersion !== operationRequest.protocolVersion ||
        event.operationId !== operationResponse.operationId ||
        event.organizationId !== operationRequest.target.organizationId ||
        event.tenantId !== operationRequest.target.tenantId ||
        event.generation !== operationRequest.target.generation ||
        event.desiredStateDigest !== operationRequest.target.desiredStateDigest,
    )
  ) {
    invalid("the event examples do not bind the accepted operation subject.");
  }
  return {
    apiVersion: literal(
      root.apiVersion,
      "protocolContract.apiVersion",
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(
      root.kind,
      "protocolContract.kind",
      "InfrastructureControllerProtocolContract",
    ),
    currentProtocolVersion,
    supportedProtocolVersions,
    reasonCodes,
    examples: {
      versionRequest,
      versionResponse,
      operationRequest,
      operationResponse,
      watchRequest,
      events,
    },
  };
}

function versionResponse(
  request: InfrastructureControllerVersionRequest,
  serverProtocolVersions: readonly string[],
  availableFeatures: readonly string[],
  selectedProtocolVersion: string | null,
  reasonCodes: readonly InfrastructureProtocolReasonCode[],
  deprecation: InfrastructureControllerVersionDeprecation | null = null,
): InfrastructureControllerVersionResponse {
  return {
    apiVersion: INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    kind: "InfrastructureControllerVersionResponse",
    requestId: request.requestId,
    compatible: selectedProtocolVersion !== null,
    selectedProtocolVersion,
    serverProtocolVersions,
    availableFeatures,
    reasonCodes,
    deprecation,
  };
}

function validateDeprecation(
  value: InfrastructureControllerVersionDeprecation,
  supportedVersions: readonly string[],
): void {
  protocolVersion(value.protocolVersion, "deprecation.protocolVersion");
  protocolVersion(
    value.replacementProtocolVersion,
    "deprecation.replacementProtocolVersion",
  );
  positiveInteger(value.sunsetEpochSeconds, "deprecation.sunsetEpochSeconds");
  if (!supportedVersions.includes(value.replacementProtocolVersion)) {
    invalid("a deprecated version must name a supported replacement.");
  }
  if (value.protocolVersion === value.replacementProtocolVersion) {
    invalid("a deprecated version must name a different replacement.");
  }
}

function parseVersionDeprecation(
  value: unknown,
  path: string,
): InfrastructureControllerVersionDeprecation {
  const root = exactObject(value, path, [
    "protocolVersion",
    "replacementProtocolVersion",
    "sunsetEpochSeconds",
  ]);
  return {
    protocolVersion: protocolVersion(
      root.protocolVersion,
      `${path}.protocolVersion`,
    ),
    replacementProtocolVersion: protocolVersion(
      root.replacementProtocolVersion,
      `${path}.replacementProtocolVersion`,
    ),
    sunsetEpochSeconds: positiveInteger(
      root.sunsetEpochSeconds,
      `${path}.sunsetEpochSeconds`,
    ),
  };
}

function parseOperationEvent(
  value: unknown,
  index: number,
): InfrastructureOperationEvent {
  const path = `events[${index}]`;
  const root = exactObject(value, path, [
    "apiVersion",
    "kind",
    "protocolVersion",
    "operationId",
    "organizationId",
    "tenantId",
    "eventId",
    "sequence",
    "phase",
    "terminal",
    "generation",
    "desiredStateDigest",
    "occurredAt",
    "reasonCodes",
    "previousEventDigest",
    "eventDigest",
  ]);
  const phase = enumeration(root.phase, `${path}.phase`, [
    "accepted",
    "planning",
    "planned",
    "reconciling",
    "observing",
    "cancelling",
    "deleting",
    "succeeded",
    "failed",
    "cancelled",
  ]);
  const terminal = booleanValue(root.terminal, `${path}.terminal`);
  const reasonCodes = uniqueArray(
    root.reasonCodes,
    `${path}.reasonCodes`,
    reasonCode,
  );
  if (terminal !== ["succeeded", "failed", "cancelled"].includes(phase)) {
    invalid(`${path}.terminal does not match its phase.`);
  }
  if ((phase === "failed") !== reasonCodes.length > 0) {
    invalid(`${path}.reasonCodes do not match its phase.`);
  }
  const parsedWithoutDigest = {
    apiVersion: literal(
      root.apiVersion,
      `${path}.apiVersion`,
      INFRASTRUCTURE_CONTROLLER_PROTOCOL_API_VERSION,
    ),
    kind: literal(root.kind, `${path}.kind`, "InfrastructureOperationEvent"),
    protocolVersion: protocolVersion(
      root.protocolVersion,
      `${path}.protocolVersion`,
    ),
    operationId: identifier(root.operationId, `${path}.operationId`),
    organizationId: identifier(root.organizationId, `${path}.organizationId`),
    tenantId: identifier(root.tenantId, `${path}.tenantId`),
    eventId: identifier(root.eventId, `${path}.eventId`),
    sequence: positiveInteger(root.sequence, `${path}.sequence`),
    phase,
    terminal,
    generation: positiveInteger(root.generation, `${path}.generation`),
    desiredStateDigest: digest(
      root.desiredStateDigest,
      `${path}.desiredStateDigest`,
    ),
    occurredAt: timestamp(root.occurredAt, `${path}.occurredAt`),
    reasonCodes,
    previousEventDigest: nullableDigest(
      root.previousEventDigest,
      `${path}.previousEventDigest`,
    ),
  };
  const eventDigest = digest(root.eventDigest, `${path}.eventDigest`);
  if (eventDigest !== sha256(canonicalJson(parsedWithoutDigest))) {
    invalid(`${path}.eventDigest does not match the event contents.`);
  }
  return { ...parsedWithoutDigest, eventDigest };
}

function validateCursorValue(
  value: unknown,
): InfrastructureOperationCursorValue {
  const root = exactObject(value, "cursorPayload", [
    "organizationId",
    "tenantId",
    "operationId",
    "nextSequence",
    "expiresAtEpochSeconds",
  ]);
  return {
    organizationId: identifier(
      root.organizationId,
      "cursorPayload.organizationId",
    ),
    tenantId: identifier(root.tenantId, "cursorPayload.tenantId"),
    operationId: identifier(root.operationId, "cursorPayload.operationId"),
    nextSequence: positiveInteger(
      root.nextSequence,
      "cursorPayload.nextSequence",
    ),
    expiresAtEpochSeconds: positiveInteger(
      root.expiresAtEpochSeconds,
      "cursorPayload.expiresAtEpochSeconds",
    ),
  };
}

function cursorSigningKey(value: string | Uint8Array): Buffer {
  const key =
    typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
  if (key.length < 32) {
    throw new InfrastructureProtocolError(
      "INFRA_PROTOCOL_INTERNAL",
      "The cursor signing key must contain at least 32 bytes.",
    );
  }
  return key;
}

function cursorInvalid(): never {
  throw new InfrastructureProtocolError(
    "INFRA_PROTOCOL_CURSOR_INVALID",
    "The operation cursor is invalid.",
  );
}

function decodeBase64Url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) cursorInvalid();
  try {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.toString("base64url") !== value) cursorInvalid();
    return decoded;
  } catch {
    cursorInvalid();
  }
}

function exactObject(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) invalid(`${path}.${key} is not allowed.`);
  }
  for (const key of allowed) {
    if (!(key in input)) invalid(`${path}.${key} is required.`);
  }
  return input;
}

function uniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) invalid(`${path} must be an array.`);
  const parsed = value.map((entry, index) => parse(entry, `${path}[${index}]`));
  if (
    new Set(parsed.map((entry) => JSON.stringify(entry))).size !== parsed.length
  ) {
    invalid(`${path} must not contain duplicates.`);
  }
  return parsed;
}

function arrayValue(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) invalid(`${path} must be an array.`);
  return value;
}

function nonEmptyUniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
): T[] {
  const parsed = uniqueArray(value, path, parse);
  if (parsed.length === 0) invalid(`${path} must not be empty.`);
  return parsed;
}

function literal<const T extends string>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) invalid(`${path} must be '${expected}'.`);
  return expected;
}

function enumeration<const T extends readonly string[]>(
  value: unknown,
  path: string,
  allowed: T,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    invalid(`${path} must be one of ${allowed.join(", ")}.`);
  }
  return value as T[number];
}

function identifier(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    invalid(`${path} must be an exact identifier.`);
  }
  return value;
}

function protocolVersion(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/.test(value)
  ) {
    invalid(`${path} must be a date-version in YYYY-MM-DD form.`);
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== value
  ) {
    invalid(`${path} must be a real calendar date.`);
  }
  return value;
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    invalid(`${path} must be a positive safe integer.`);
  }
  return value as number;
}

function digest(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    invalid(`${path} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

function nullableDigest(value: unknown, path: string): string | null {
  return value === null ? null : digest(value, path);
}

function nullableIdentifier(value: unknown, path: string): string | null {
  return value === null ? null : identifier(value, path);
}

function timestamp(value: unknown, path: string): string {
  if (typeof value !== "string")
    invalid(`${path} must be an RFC 3339 timestamp.`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    invalid(`${path} must be a canonical RFC 3339 timestamp.`);
  }
  return value;
}

function booleanValue(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") invalid(`${path} must be a boolean.`);
  return value;
}

function cursor(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 2048 ||
    !/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)
  ) {
    throw new InfrastructureProtocolError(
      "INFRA_PROTOCOL_CURSOR_INVALID",
      `${path} is not a valid opaque operation cursor.`,
    );
  }
  return value;
}

function reasonCode(
  value: unknown,
  path: string,
): InfrastructureProtocolReasonCode {
  if (
    typeof value !== "string" ||
    !(value in INFRASTRUCTURE_PROTOCOL_REASON_CODES)
  ) {
    invalid(`${path} is not a stable infrastructure protocol reason code.`);
  }
  return value as InfrastructureProtocolReasonCode;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function invalid(message: string): never {
  throw new InfrastructureProtocolError(
    "INFRA_PROTOCOL_REQUEST_INVALID",
    message,
  );
}
