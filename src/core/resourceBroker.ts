import { createHash } from "node:crypto";

export const RESOURCE_CLAIM_API_VERSION =
  "security.deus.dev/resource-broker/v1alpha1" as const;
export const RESOURCE_BROKER_STATE_API_VERSION =
  "security.deus.dev/resource-broker-state/v1alpha1" as const;
export const RESOURCE_PROVIDER_PROTOCOL_VERSION =
  "security.deus.dev/resource-provider/v1alpha1" as const;

export type ResourceClaimPhase =
  | "pending"
  | "reconciling"
  | "available"
  | "failed"
  | "drifted"
  | "cancelling"
  | "cancelled"
  | "deleting"
  | "deleted";

export interface ResourceClaimRequest {
  apiVersion: typeof RESOURCE_CLAIM_API_VERSION;
  kind: "ResourceClaim";
  claimId: string;
  tenantId: string;
  generation: number;
  resourceKind: string;
  resourceApiVersion: string;
  desiredStateDigest: string;
  desiredStateRef: string;
  requiredProviderCapabilities: readonly string[];
  lifecycle: {
    deletionProtection: true;
    destructionApprovalRequired: true;
    finalizationEvidenceRequired: true;
    maxReconcileAttempts: number;
  };
}

export interface ResourceBrokerOutput {
  name: string;
  kind: "reference" | "value";
  value: string | number | boolean;
}

export interface ResourceProviderLease {
  providerId: string;
  generation: number;
  fenceToken: string;
  attempt: number;
  acquiredAt: string;
  expiresAt: string;
}

export interface ResourceClaimFailure {
  code: string;
  message: string;
  retryable: boolean;
  attempt: number;
  occurredAt: string;
}

export interface ResourceClaimState extends ResourceClaimRequest {
  phase: ResourceClaimPhase;
  observedGeneration: number;
  providerResourceRef?: string;
  outputs: readonly ResourceBrokerOutput[];
  lease?: ResourceProviderLease;
  failure?: ResourceClaimFailure;
  drift?: {
    observedStateDigest: string;
    detectedAt: string;
  };
  deletion?: {
    requestedAt: string;
    requestedBy: string;
    approvalEvidenceRef: string;
    finalizationEvidenceRef: string;
  };
  cancellation?: {
    requestedAt: string;
    requestedBy: string;
    cleanupEvidenceRef?: string;
  };
}

export interface ResourceBrokerIdempotencyRecord {
  tenantId: string;
  operation: BrokerMutationOperation;
  claimId: string;
  key: string;
  payloadDigest: string;
  capabilityId: string;
  committedRevision: number;
}

export interface ResourceBrokerState {
  apiVersion: typeof RESOURCE_BROKER_STATE_API_VERSION;
  revision: number;
  claims: readonly ResourceClaimState[];
  idempotencyRecords: readonly ResourceBrokerIdempotencyRecord[];
  redeemedCapabilityIds: readonly string[];
}

export type BrokerMutationOperation =
  | "claim.apply"
  | "claim.cancel"
  | "claim.delete";

export interface BrokerMutationContext {
  actorId: string;
  tenantId: string;
  operation: BrokerMutationOperation;
  resourceId: string;
  capabilityId: string;
  capabilityVerified: true;
  idempotencyKey: string;
  occurredAt: string;
}

export interface ResourceBrokerEvent {
  apiVersion: typeof RESOURCE_BROKER_STATE_API_VERSION;
  eventId: string;
  type:
    | "claim-applied"
    | "provider-leased"
    | "claim-available"
    | "claim-failed"
    | "claim-drifted"
    | "cancellation-requested"
    | "claim-cancelled"
    | "deletion-requested"
    | "claim-deleted";
  revision: number;
  claimId: string;
  tenantId: string;
  generation: number;
  desiredStateDigest: string;
  occurredAt: string;
  actorId?: string;
  providerId?: string;
  fenceToken?: string;
}

export interface ResourceBrokerTransition<T = ResourceClaimState> {
  state: ResourceBrokerState;
  result: T;
  events: readonly ResourceBrokerEvent[];
  replayed: boolean;
}

export interface ResourceProviderDescriptor {
  id: string;
  protocolVersion: typeof RESOURCE_PROVIDER_PROTOCOL_VERSION;
  resourceKinds: readonly string[];
  capabilities: readonly string[];
  mutationMode: "broker-only";
  acceptsProviderCredentials: false;
  outputMode: "reference-only";
  deterministicPlanning: true;
}

export interface ResourceProviderRequest {
  claim: ResourceClaimRequest;
  operation: "reconcile" | "destroy";
  fenceToken: string;
}

export interface ResourceProviderPlan {
  providerId: string;
  claimId: string;
  generation: number;
  desiredStateDigest: string;
  operation: "reconcile" | "destroy";
  semanticOperations: readonly string[];
  planDigest: string;
}

export interface ResourceProviderResult {
  providerId: string;
  claimId: string;
  generation: number;
  fenceToken: string;
  operation: "reconcile" | "destroy";
  observedStateDigest: string;
  providerResourceRef: string | null;
  outputs: readonly ResourceBrokerOutput[];
}

export interface ResourceProviderAdapter {
  descriptor: ResourceProviderDescriptor;
  plan(request: ResourceProviderRequest): ResourceProviderPlan;
  execute(request: ResourceProviderRequest): ResourceProviderResult;
}

export interface ResourceProviderConformanceEvidence {
  apiVersion: typeof RESOURCE_PROVIDER_PROTOCOL_VERSION;
  providerId: string;
  claimId: string;
  pass: true;
  checks: readonly [
    "descriptor-secure",
    "capabilities-satisfied",
    "plan-deterministic",
    "plan-digest-valid",
    "reconcile-deterministic",
    "outputs-reference-only",
    "destroy-reference-free",
  ];
  planDigest: string;
}

export function createResourceBrokerState(): ResourceBrokerState {
  return {
    apiVersion: RESOURCE_BROKER_STATE_API_VERSION,
    revision: 0,
    claims: [],
    idempotencyRecords: [],
    redeemedCapabilityIds: [],
  };
}

export function parseResourceClaimRequest(
  value: unknown,
): ResourceClaimRequest {
  const input = exactObject(value, "claim", [
    "apiVersion",
    "kind",
    "claimId",
    "tenantId",
    "generation",
    "resourceKind",
    "resourceApiVersion",
    "desiredStateDigest",
    "desiredStateRef",
    "requiredProviderCapabilities",
    "lifecycle",
  ]);
  const lifecycle = exactObject(input.lifecycle, "claim.lifecycle", [
    "deletionProtection",
    "destructionApprovalRequired",
    "finalizationEvidenceRequired",
    "maxReconcileAttempts",
  ]);
  const claim: ResourceClaimRequest = {
    apiVersion: literal(
      input.apiVersion,
      "claim.apiVersion",
      RESOURCE_CLAIM_API_VERSION,
    ),
    kind: literal(input.kind, "claim.kind", "ResourceClaim"),
    claimId: identifier(input.claimId, "claim.claimId"),
    tenantId: identifier(input.tenantId, "claim.tenantId"),
    generation: positiveInteger(input.generation, "claim.generation"),
    resourceKind: resourceKind(input.resourceKind, "claim.resourceKind"),
    resourceApiVersion: apiVersion(
      input.resourceApiVersion,
      "claim.resourceApiVersion",
    ),
    desiredStateDigest: digest(
      input.desiredStateDigest,
      "claim.desiredStateDigest",
    ),
    desiredStateRef: reference(input.desiredStateRef, "claim.desiredStateRef", [
      "broker",
    ]),
    requiredProviderCapabilities: uniqueIdentifiers(
      input.requiredProviderCapabilities,
      "claim.requiredProviderCapabilities",
    ),
    lifecycle: {
      deletionProtection: trueLiteral(
        lifecycle.deletionProtection,
        "claim.lifecycle.deletionProtection",
      ),
      destructionApprovalRequired: trueLiteral(
        lifecycle.destructionApprovalRequired,
        "claim.lifecycle.destructionApprovalRequired",
      ),
      finalizationEvidenceRequired: trueLiteral(
        lifecycle.finalizationEvidenceRequired,
        "claim.lifecycle.finalizationEvidenceRequired",
      ),
      maxReconcileAttempts: boundedInteger(
        lifecycle.maxReconcileAttempts,
        "claim.lifecycle.maxReconcileAttempts",
        1,
        10,
      ),
    },
  };
  if (claim.requiredProviderCapabilities.length === 0) {
    throw new Error("claim.requiredProviderCapabilities cannot be empty.");
  }
  return claim;
}

export function parseResourceBrokerState(value: unknown): ResourceBrokerState {
  const input = exactObject(value, "resourceBrokerState", [
    "apiVersion",
    "revision",
    "claims",
    "idempotencyRecords",
    "redeemedCapabilityIds",
  ]);
  const state: ResourceBrokerState = {
    apiVersion: literal(
      input.apiVersion,
      "resourceBrokerState.apiVersion",
      RESOURCE_BROKER_STATE_API_VERSION,
    ),
    revision: nonNegativeInteger(
      input.revision,
      "resourceBrokerState.revision",
    ),
    claims: array(input.claims, "resourceBrokerState.claims", parseClaimState),
    idempotencyRecords: array(
      input.idempotencyRecords,
      "resourceBrokerState.idempotencyRecords",
      parseIdempotencyRecord,
    ),
    redeemedCapabilityIds: uniqueIdentifiers(
      input.redeemedCapabilityIds,
      "resourceBrokerState.redeemedCapabilityIds",
    ),
  };
  assertResourceBrokerState(state);
  return state;
}

export function assertResourceBrokerState(state: ResourceBrokerState): void {
  const claimIds = new Set<string>();
  for (const [index, rawClaim] of state.claims.entries()) {
    const claim = parseClaimState(
      rawClaim,
      `resourceBrokerState.claims[${index}]`,
    );
    if (claimIds.has(claim.claimId)) {
      throw new Error(`Resource claim '${claim.claimId}' is duplicated.`);
    }
    claimIds.add(claim.claimId);
    if (claim.observedGeneration > claim.generation) {
      throw new Error(
        `Resource claim '${claim.claimId}' observed a future generation.`,
      );
    }
    if (
      (["reconciling", "cancelling"].includes(claim.phase) && !claim.lease) ||
      (Boolean(claim.lease) &&
        !["reconciling", "cancelling", "deleting"].includes(claim.phase))
    ) {
      throw new Error(
        `Resource claim '${claim.claimId}' has inconsistent lease state.`,
      );
    }
    if (claim.phase === "available") {
      if (
        claim.observedGeneration !== claim.generation ||
        !claim.providerResourceRef ||
        claim.outputs.length === 0
      ) {
        throw new Error(
          `Available resource claim '${claim.claimId}' lacks current observed state.`,
        );
      }
    }
    if (claim.phase === "deleted" && claim.outputs.length !== 0) {
      throw new Error(
        `Deleted resource claim '${claim.claimId}' retains outputs.`,
      );
    }
    validateOutputs(claim.outputs);
  }
  const recordKeys = new Set<string>();
  for (const [index, rawRecord] of state.idempotencyRecords.entries()) {
    const record = parseIdempotencyRecord(
      rawRecord,
      `resourceBrokerState.idempotencyRecords[${index}]`,
    );
    const key = `${record.tenantId}/${record.operation}/${record.claimId}/${record.key}`;
    if (recordKeys.has(key)) {
      throw new Error(
        `Resource broker idempotency record '${key}' is duplicated.`,
      );
    }
    recordKeys.add(key);
    if (!state.redeemedCapabilityIds.includes(record.capabilityId)) {
      throw new Error(
        `Resource broker idempotency record '${key}' has no redeemed capability.`,
      );
    }
  }
  if (
    new Set(
      uniqueIdentifiers(
        state.redeemedCapabilityIds,
        "resourceBrokerState.redeemedCapabilityIds",
      ),
    ).size !== state.redeemedCapabilityIds.length
  ) {
    throw new Error("Resource broker capability redemption is duplicated.");
  }
}

export function applyResourceClaim(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  context: BrokerMutationContext;
  claim: ResourceClaimRequest;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = parseResourceClaimRequest(args.claim);
  const payloadDigest = sha256(canonicalJson(claim));
  const replay = mutationReplay(
    state,
    args.context,
    "claim.apply",
    payloadDigest,
  );
  if (replay) return replayTransition(state, replay);
  validateMutationContext(args.context, "claim.apply", claim);
  const existing = state.claims.find(
    (candidate) => candidate.claimId === claim.claimId,
  );
  if (!existing && claim.generation !== 1) {
    throw new Error("A new resource claim must begin at generation 1.");
  }
  if (existing) {
    if (
      existing.tenantId !== claim.tenantId ||
      existing.resourceKind !== claim.resourceKind ||
      existing.resourceApiVersion !== claim.resourceApiVersion
    ) {
      throw new Error(
        `Resource claim '${claim.claimId}' cannot change tenant or resource type.`,
      );
    }
    if (claim.generation !== existing.generation + 1) {
      throw new Error(
        `Resource claim '${claim.claimId}' must advance exactly one generation.`,
      );
    }
    if (["reconciling", "cancelling", "deleting"].includes(existing.phase)) {
      throw new Error(
        `Resource claim '${claim.claimId}' cannot advance while work is active.`,
      );
    }
  }
  const nextClaim: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "pending",
    observedGeneration: existing?.observedGeneration ?? 0,
    providerResourceRef: existing?.providerResourceRef,
    outputs: [],
  };
  const next = commitMutation(
    state,
    args.context,
    payloadDigest,
    upsertClaim(state.claims, nextClaim),
  );
  return transition(
    next,
    nextClaim,
    event(next, nextClaim, "claim-applied", args.context.occurredAt, {
      actorId: args.context.actorId,
    }),
  );
}

export function leaseResourceClaim(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  providerCapabilities: readonly string[];
  workloadIdentityVerified: true;
  occurredAt: string;
  leaseDurationSeconds: number;
}): ResourceBrokerTransition<ResourceProviderLease> {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = requireClaim(state, args.claimId);
  identifier(args.providerId, "providerId");
  if (args.workloadIdentityVerified !== true) {
    throw new Error("Resource provider workload identity is not verified.");
  }
  timestamp(args.occurredAt, "occurredAt");
  if (
    !Number.isInteger(args.leaseDurationSeconds) ||
    args.leaseDurationSeconds < 1 ||
    args.leaseDurationSeconds > 900
  ) {
    throw new Error(
      "Resource provider lease must be between 1 and 900 seconds.",
    );
  }
  const capabilities = new Set(args.providerCapabilities);
  const missing = claim.requiredProviderCapabilities.filter(
    (capability) => !capabilities.has(capability),
  );
  if (missing.length > 0) {
    throw new Error(
      `Resource provider '${args.providerId}' lacks capability: ${missing.sort().join(", ")}.`,
    );
  }
  const now = Date.parse(args.occurredAt);
  const activeLease = claim.lease && Date.parse(claim.lease.expiresAt) > now;
  if (activeLease) {
    throw new Error(
      `Resource claim '${claim.claimId}' already has an active lease.`,
    );
  }
  const eligible =
    claim.phase === "pending" ||
    claim.phase === "drifted" ||
    claim.phase === "deleting" ||
    (claim.phase === "failed" && claim.failure?.retryable === true) ||
    (claim.phase === "reconciling" && Boolean(claim.lease));
  if (!eligible) {
    throw new Error(
      `Resource claim '${claim.claimId}' cannot be leased from phase '${claim.phase}'.`,
    );
  }
  const attempt = (claim.lease?.attempt ?? claim.failure?.attempt ?? 0) + 1;
  if (attempt > claim.lifecycle.maxReconcileAttempts) {
    throw new Error(
      `Resource claim '${claim.claimId}' exhausted its reconcile attempts.`,
    );
  }
  const lease: ResourceProviderLease = {
    providerId: args.providerId,
    generation: claim.generation,
    fenceToken: sha256(
      canonicalJson({
        claimId: claim.claimId,
        generation: claim.generation,
        providerId: args.providerId,
        attempt,
        revision: state.revision + 1,
        occurredAt: args.occurredAt,
      }),
    ),
    attempt,
    acquiredAt: args.occurredAt,
    expiresAt: new Date(now + args.leaseDurationSeconds * 1000).toISOString(),
  };
  const leased: ResourceClaimState = {
    ...structuredClone(claim),
    phase: claim.phase === "deleting" ? "deleting" : "reconciling",
    lease,
    failure: undefined,
  };
  const next = commitState(state, upsertClaim(state.claims, leased));
  return transition(
    next,
    lease,
    event(next, leased, "provider-leased", args.occurredAt, {
      providerId: args.providerId,
      fenceToken: lease.fenceToken,
    }),
  );
}

export function completeResourceClaim(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  generation: number;
  fenceToken: string;
  workloadIdentityVerified: true;
  observedStateDigest: string;
  providerResourceRef: string;
  outputs: readonly ResourceBrokerOutput[];
  occurredAt: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = providerClaim(state, args, "reconciling");
  const observed = digest(args.observedStateDigest, "observedStateDigest");
  if (observed !== claim.desiredStateDigest) {
    throw new Error(
      `Resource claim '${claim.claimId}' provider observed the wrong desired state.`,
    );
  }
  const providerResourceRef = reference(
    args.providerResourceRef,
    "providerResourceRef",
    ["provider"],
  );
  validateOutputs(args.outputs);
  if (args.outputs.length === 0) {
    throw new Error("An available resource claim requires outputs.");
  }
  const available: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "available",
    observedGeneration: claim.generation,
    providerResourceRef,
    outputs: structuredClone(args.outputs),
    lease: undefined,
    failure: undefined,
    drift: undefined,
  };
  const next = commitState(state, upsertClaim(state.claims, available));
  return transition(
    next,
    available,
    event(next, available, "claim-available", args.occurredAt, {
      providerId: args.providerId,
      fenceToken: args.fenceToken,
    }),
  );
}

export function failResourceClaim(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  generation: number;
  fenceToken: string;
  workloadIdentityVerified: true;
  code: string;
  message: string;
  retryable: boolean;
  occurredAt: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = providerClaim(state, args, "reconciling");
  const failure: ResourceClaimFailure = {
    code: reasonCode(args.code, "code"),
    message: safeMessage(args.message, "message"),
    retryable: boolean(args.retryable, "retryable"),
    attempt: claim.lease!.attempt,
    occurredAt: timestamp(args.occurredAt, "occurredAt"),
  };
  const failed: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "failed",
    lease: undefined,
    failure,
  };
  const next = commitState(state, upsertClaim(state.claims, failed));
  return transition(
    next,
    failed,
    event(next, failed, "claim-failed", args.occurredAt, {
      providerId: args.providerId,
      fenceToken: args.fenceToken,
    }),
  );
}

export function reportResourceClaimDrift(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  workloadIdentityVerified: true;
  observedStateDigest: string;
  occurredAt: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = requireClaim(state, args.claimId);
  providerIdentity(args.providerId, args.workloadIdentityVerified);
  if (claim.phase !== "available") {
    throw new Error(
      `Resource claim '${claim.claimId}' cannot record drift from phase '${claim.phase}'.`,
    );
  }
  const observedStateDigest = digest(
    args.observedStateDigest,
    "observedStateDigest",
  );
  if (observedStateDigest === claim.desiredStateDigest) {
    throw new Error(`Resource claim '${claim.claimId}' has no drift.`);
  }
  const drifted: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "drifted",
    outputs: [],
    drift: {
      observedStateDigest,
      detectedAt: timestamp(args.occurredAt, "occurredAt"),
    },
  };
  const next = commitState(state, upsertClaim(state.claims, drifted));
  return transition(
    next,
    drifted,
    event(next, drifted, "claim-drifted", args.occurredAt, {
      providerId: args.providerId,
    }),
  );
}

export function cancelResourceClaim(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  context: BrokerMutationContext;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = requireClaim(state, args.context.resourceId);
  const payloadDigest = sha256(
    canonicalJson({ claimId: claim.claimId, generation: claim.generation }),
  );
  const replay = mutationReplay(
    state,
    args.context,
    "claim.cancel",
    payloadDigest,
  );
  if (replay) return replayTransition(state, replay);
  validateMutationContext(args.context, "claim.cancel", claim);
  if (!["pending", "reconciling", "failed", "drifted"].includes(claim.phase)) {
    throw new Error(
      `Resource claim '${claim.claimId}' cannot be cancelled from phase '${claim.phase}'.`,
    );
  }
  const cancelling = claim.phase === "reconciling";
  const cancelled: ResourceClaimState = {
    ...structuredClone(claim),
    phase: cancelling ? "cancelling" : "cancelled",
    outputs: [],
    lease: cancelling ? claim.lease : undefined,
    cancellation: {
      requestedAt: args.context.occurredAt,
      requestedBy: args.context.actorId,
    },
  };
  const next = commitMutation(
    state,
    args.context,
    payloadDigest,
    upsertClaim(state.claims, cancelled),
  );
  return transition(
    next,
    cancelled,
    event(
      next,
      cancelled,
      cancelling ? "cancellation-requested" : "claim-cancelled",
      args.context.occurredAt,
      { actorId: args.context.actorId },
    ),
  );
}

export function acknowledgeResourceClaimCancellation(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  generation: number;
  fenceToken: string;
  workloadIdentityVerified: true;
  cleanupEvidenceRef: string;
  occurredAt: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = providerClaim(state, args, "cancelling");
  reference(args.cleanupEvidenceRef, "cleanupEvidenceRef", ["evidence"]);
  const cancelled: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "cancelled",
    lease: undefined,
    outputs: [],
    cancellation: {
      requestedAt: claim.cancellation!.requestedAt,
      requestedBy: claim.cancellation!.requestedBy,
      cleanupEvidenceRef: args.cleanupEvidenceRef,
    },
  };
  const next = commitState(state, upsertClaim(state.claims, cancelled));
  return transition(
    next,
    cancelled,
    event(next, cancelled, "claim-cancelled", args.occurredAt, {
      providerId: args.providerId,
      fenceToken: args.fenceToken,
    }),
  );
}

export function requestResourceClaimDeletion(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  context: BrokerMutationContext;
  approvalEvidenceRef: string;
  finalizationEvidenceRef: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = requireClaim(state, args.context.resourceId);
  const approvalEvidenceRef = reference(
    args.approvalEvidenceRef,
    "approvalEvidenceRef",
    ["evidence"],
  );
  const finalizationEvidenceRef = reference(
    args.finalizationEvidenceRef,
    "finalizationEvidenceRef",
    ["evidence", "snapshot"],
  );
  const payloadDigest = sha256(
    canonicalJson({
      claimId: claim.claimId,
      generation: claim.generation,
      approvalEvidenceRef,
      finalizationEvidenceRef,
    }),
  );
  const replay = mutationReplay(
    state,
    args.context,
    "claim.delete",
    payloadDigest,
  );
  if (replay) return replayTransition(state, replay);
  validateMutationContext(args.context, "claim.delete", claim);
  if (claim.phase !== "available" && claim.phase !== "cancelled") {
    throw new Error(
      `Resource claim '${claim.claimId}' cannot be deleted from phase '${claim.phase}'.`,
    );
  }
  const deleting: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "deleting",
    outputs: [],
    deletion: {
      requestedAt: args.context.occurredAt,
      requestedBy: args.context.actorId,
      approvalEvidenceRef,
      finalizationEvidenceRef,
    },
  };
  const next = commitMutation(
    state,
    args.context,
    payloadDigest,
    upsertClaim(state.claims, deleting),
  );
  return transition(
    next,
    deleting,
    event(next, deleting, "deletion-requested", args.context.occurredAt, {
      actorId: args.context.actorId,
    }),
  );
}

export function completeResourceClaimDeletion(args: {
  state: ResourceBrokerState;
  expectedRevision: number;
  claimId: string;
  providerId: string;
  generation: number;
  fenceToken: string;
  workloadIdentityVerified: true;
  finalizationEvidenceRef: string;
  occurredAt: string;
}): ResourceBrokerTransition {
  const state = checkedState(args.state, args.expectedRevision);
  const claim = providerClaim(state, args, "deleting");
  const finalizationEvidenceRef = reference(
    args.finalizationEvidenceRef,
    "finalizationEvidenceRef",
    ["evidence", "snapshot"],
  );
  if (finalizationEvidenceRef !== claim.deletion?.finalizationEvidenceRef) {
    throw new Error(
      `Resource claim '${claim.claimId}' deletion evidence does not match approval.`,
    );
  }
  const deleted: ResourceClaimState = {
    ...structuredClone(claim),
    phase: "deleted",
    observedGeneration: claim.generation,
    providerResourceRef: undefined,
    outputs: [],
    lease: undefined,
  };
  const next = commitState(state, upsertClaim(state.claims, deleted));
  return transition(
    next,
    deleted,
    event(next, deleted, "claim-deleted", args.occurredAt, {
      providerId: args.providerId,
      fenceToken: args.fenceToken,
    }),
  );
}

export function createFakeResourceProvider(
  args: {
    id?: string;
    resourceKinds?: readonly string[];
    capabilities?: readonly string[];
    failClaimIds?: readonly string[];
  } = {},
): ResourceProviderAdapter {
  const descriptor: ResourceProviderDescriptor = {
    id: args.id ?? "fake-provider",
    protocolVersion: RESOURCE_PROVIDER_PROTOCOL_VERSION,
    resourceKinds: args.resourceKinds ?? ["ManagedPostgres"],
    capabilities: args.capabilities ?? [
      "private-network",
      "explicit-source-boundaries",
      "customer-managed-encryption",
      "multi-zone",
      "point-in-time-recovery",
      "workload-identity",
      "reference-only-outputs",
    ],
    mutationMode: "broker-only",
    acceptsProviderCredentials: false,
    outputMode: "reference-only",
    deterministicPlanning: true,
  };
  const failures = new Set(args.failClaimIds ?? []);
  return {
    descriptor,
    plan(request) {
      const normalized = validateProviderRequest(descriptor, request);
      const semanticOperations =
        normalized.operation === "destroy"
          ? [`delete:${normalized.claim.resourceKind}`]
          : [`ensure:${normalized.claim.resourceKind}`];
      const plan = {
        providerId: descriptor.id,
        claimId: normalized.claim.claimId,
        generation: normalized.claim.generation,
        desiredStateDigest: normalized.claim.desiredStateDigest,
        operation: normalized.operation,
        semanticOperations,
      };
      return {
        ...plan,
        planDigest: sha256(canonicalJson(plan)),
      };
    },
    execute(request) {
      const normalized = validateProviderRequest(descriptor, request);
      if (failures.has(normalized.claim.claimId)) {
        throw new Error("FAKE_PROVIDER_FAILURE");
      }
      const destroying = normalized.operation === "destroy";
      return {
        providerId: descriptor.id,
        claimId: normalized.claim.claimId,
        generation: normalized.claim.generation,
        fenceToken: normalized.fenceToken,
        operation: normalized.operation,
        observedStateDigest: normalized.claim.desiredStateDigest,
        providerResourceRef: destroying
          ? null
          : `provider://${descriptor.id}/${normalized.claim.tenantId}/${normalized.claim.claimId}`,
        outputs: destroying
          ? []
          : [
              {
                name: "resource",
                kind: "reference",
                value: `broker://${normalized.claim.claimId}/resource`,
              },
            ],
      };
    },
  };
}

export function planWithResourceProvider(
  adapter: ResourceProviderAdapter,
  request: ResourceProviderRequest,
): ResourceProviderPlan {
  const descriptor = validateProviderDescriptor(adapter.descriptor);
  const normalized = validateProviderRequest(descriptor, request);
  const raw = exactObject(
    adapter.plan(structuredClone(normalized)),
    "providerPlan",
    [
      "providerId",
      "claimId",
      "generation",
      "desiredStateDigest",
      "operation",
      "semanticOperations",
      "planDigest",
    ],
  );
  const plan: ResourceProviderPlan = {
    providerId: identifier(raw.providerId, "providerPlan.providerId"),
    claimId: identifier(raw.claimId, "providerPlan.claimId"),
    generation: positiveInteger(raw.generation, "providerPlan.generation"),
    desiredStateDigest: digest(
      raw.desiredStateDigest,
      "providerPlan.desiredStateDigest",
    ),
    operation: enumValue(raw.operation, "providerPlan.operation", [
      "reconcile",
      "destroy",
    ]),
    semanticOperations: semanticOperations(
      raw.semanticOperations,
      "providerPlan.semanticOperations",
    ),
    planDigest: digest(raw.planDigest, "providerPlan.planDigest"),
  };
  const expected = sha256(
    canonicalJson({
      providerId: plan.providerId,
      claimId: plan.claimId,
      generation: plan.generation,
      desiredStateDigest: plan.desiredStateDigest,
      operation: plan.operation,
      semanticOperations: plan.semanticOperations,
    }),
  );
  if (
    plan.providerId !== descriptor.id ||
    plan.claimId !== normalized.claim.claimId ||
    plan.generation !== normalized.claim.generation ||
    plan.desiredStateDigest !== normalized.claim.desiredStateDigest ||
    plan.operation !== normalized.operation ||
    plan.planDigest !== expected ||
    !Array.isArray(plan.semanticOperations) ||
    plan.semanticOperations.length === 0
  ) {
    throw new Error(
      `Resource provider '${descriptor.id}' returned an invalid plan.`,
    );
  }
  return structuredClone(plan);
}

export function executeWithResourceProvider(
  adapter: ResourceProviderAdapter,
  request: ResourceProviderRequest,
): ResourceProviderResult {
  const descriptor = validateProviderDescriptor(adapter.descriptor);
  const normalized = validateProviderRequest(descriptor, request);
  const raw = exactObject(
    adapter.execute(structuredClone(normalized)),
    "providerResult",
    [
      "providerId",
      "claimId",
      "generation",
      "fenceToken",
      "operation",
      "observedStateDigest",
      "providerResourceRef",
      "outputs",
    ],
  );
  const result: ResourceProviderResult = {
    providerId: identifier(raw.providerId, "providerResult.providerId"),
    claimId: identifier(raw.claimId, "providerResult.claimId"),
    generation: positiveInteger(raw.generation, "providerResult.generation"),
    fenceToken: digest(raw.fenceToken, "providerResult.fenceToken"),
    operation: enumValue(raw.operation, "providerResult.operation", [
      "reconcile",
      "destroy",
    ]),
    observedStateDigest: digest(
      raw.observedStateDigest,
      "providerResult.observedStateDigest",
    ),
    providerResourceRef:
      raw.providerResourceRef === null
        ? null
        : reference(
            raw.providerResourceRef,
            "providerResult.providerResourceRef",
            ["provider"],
          ),
    outputs: array(raw.outputs, "providerResult.outputs", parseOutput),
  };
  if (
    result.providerId !== descriptor.id ||
    result.claimId !== normalized.claim.claimId ||
    result.generation !== normalized.claim.generation ||
    result.fenceToken !== normalized.fenceToken ||
    result.operation !== normalized.operation ||
    result.observedStateDigest !== normalized.claim.desiredStateDigest
  ) {
    throw new Error(
      `Resource provider '${descriptor.id}' returned a result outside its fenced claim.`,
    );
  }
  validateOutputs(result.outputs);
  if (normalized.operation === "destroy") {
    if (result.providerResourceRef !== null || result.outputs.length !== 0) {
      throw new Error(
        `Resource provider '${descriptor.id}' retained outputs after destroy.`,
      );
    }
  } else {
    if (!result.providerResourceRef || result.outputs.length === 0) {
      throw new Error(
        `Resource provider '${descriptor.id}' returned incomplete observed state.`,
      );
    }
    reference(result.providerResourceRef, "providerResourceRef", ["provider"]);
  }
  return structuredClone(result);
}

export function evaluateResourceProviderConformance(
  adapter: ResourceProviderAdapter,
  claim: ResourceClaimRequest,
): ResourceProviderConformanceEvidence {
  const descriptor = validateProviderDescriptor(adapter.descriptor);
  const normalizedClaim = parseResourceClaimRequest(claim);
  const request: ResourceProviderRequest = {
    claim: normalizedClaim,
    operation: "reconcile",
    fenceToken: "f".repeat(64),
  };
  const firstPlan = planWithResourceProvider(adapter, request);
  const secondPlan = planWithResourceProvider(adapter, request);
  if (canonicalJson(firstPlan) !== canonicalJson(secondPlan)) {
    throw new Error(
      `Resource provider '${descriptor.id}' planning is not deterministic.`,
    );
  }
  const firstResult = executeWithResourceProvider(adapter, request);
  const secondResult = executeWithResourceProvider(adapter, request);
  if (canonicalJson(firstResult) !== canonicalJson(secondResult)) {
    throw new Error(
      `Resource provider '${descriptor.id}' reconciliation is not deterministic.`,
    );
  }
  executeWithResourceProvider(adapter, { ...request, operation: "destroy" });
  return {
    apiVersion: RESOURCE_PROVIDER_PROTOCOL_VERSION,
    providerId: descriptor.id,
    claimId: normalizedClaim.claimId,
    pass: true,
    checks: [
      "descriptor-secure",
      "capabilities-satisfied",
      "plan-deterministic",
      "plan-digest-valid",
      "reconcile-deterministic",
      "outputs-reference-only",
      "destroy-reference-free",
    ],
    planDigest: firstPlan.planDigest,
  };
}

export function resourceClaimRequestDigest(
  claim: ResourceClaimRequest,
): string {
  return sha256(canonicalJson(parseResourceClaimRequest(claim)));
}

function parseClaimState(value: unknown, path: string): ResourceClaimState {
  const input = exactObject(value, path, [
    "apiVersion",
    "kind",
    "claimId",
    "tenantId",
    "generation",
    "resourceKind",
    "resourceApiVersion",
    "desiredStateDigest",
    "desiredStateRef",
    "requiredProviderCapabilities",
    "lifecycle",
    "phase",
    "observedGeneration",
    "providerResourceRef",
    "outputs",
    "lease",
    "failure",
    "drift",
    "deletion",
    "cancellation",
  ]);
  const claim = parseResourceClaimRequest(claimRequestView(input));
  return {
    ...claim,
    phase: enumValue(input.phase, `${path}.phase`, [
      "pending",
      "reconciling",
      "available",
      "failed",
      "drifted",
      "cancelling",
      "cancelled",
      "deleting",
      "deleted",
    ]),
    observedGeneration: nonNegativeInteger(
      input.observedGeneration,
      `${path}.observedGeneration`,
    ),
    providerResourceRef:
      input.providerResourceRef === undefined
        ? undefined
        : reference(input.providerResourceRef, `${path}.providerResourceRef`, [
            "provider",
          ]),
    outputs: array(input.outputs, `${path}.outputs`, parseOutput),
    lease:
      input.lease === undefined
        ? undefined
        : parseLease(input.lease, `${path}.lease`),
    failure:
      input.failure === undefined
        ? undefined
        : parseFailure(input.failure, `${path}.failure`),
    drift:
      input.drift === undefined
        ? undefined
        : parseDrift(input.drift, `${path}.drift`),
    deletion:
      input.deletion === undefined
        ? undefined
        : parseDeletion(input.deletion, `${path}.deletion`),
    cancellation:
      input.cancellation === undefined
        ? undefined
        : parseCancellation(input.cancellation, `${path}.cancellation`),
  };
}

function claimRequestView(value: any): unknown {
  return {
    apiVersion: value.apiVersion,
    kind: value.kind,
    claimId: value.claimId,
    tenantId: value.tenantId,
    generation: value.generation,
    resourceKind: value.resourceKind,
    resourceApiVersion: value.resourceApiVersion,
    desiredStateDigest: value.desiredStateDigest,
    desiredStateRef: value.desiredStateRef,
    requiredProviderCapabilities: value.requiredProviderCapabilities,
    lifecycle: value.lifecycle,
  };
}

function parseOutput(value: unknown, path: string): ResourceBrokerOutput {
  const input = exactObject(value, path, ["name", "kind", "value"]);
  const output: ResourceBrokerOutput = {
    name: identifier(input.name, `${path}.name`),
    kind: enumValue(input.kind, `${path}.kind`, ["reference", "value"]),
    value: scalar(input.value, `${path}.value`),
  };
  validateOutputs([output]);
  return output;
}

function parseLease(value: unknown, path: string): ResourceProviderLease {
  const input = exactObject(value, path, [
    "providerId",
    "generation",
    "fenceToken",
    "attempt",
    "acquiredAt",
    "expiresAt",
  ]);
  const lease = {
    providerId: identifier(input.providerId, `${path}.providerId`),
    generation: positiveInteger(input.generation, `${path}.generation`),
    fenceToken: digest(input.fenceToken, `${path}.fenceToken`),
    attempt: positiveInteger(input.attempt, `${path}.attempt`),
    acquiredAt: timestamp(input.acquiredAt, `${path}.acquiredAt`),
    expiresAt: timestamp(input.expiresAt, `${path}.expiresAt`),
  };
  if (Date.parse(lease.expiresAt) <= Date.parse(lease.acquiredAt)) {
    throw new Error(`${path}.expiresAt must follow acquiredAt.`);
  }
  return lease;
}

function parseFailure(value: unknown, path: string): ResourceClaimFailure {
  const input = exactObject(value, path, [
    "code",
    "message",
    "retryable",
    "attempt",
    "occurredAt",
  ]);
  return {
    code: reasonCode(input.code, `${path}.code`),
    message: safeMessage(input.message, `${path}.message`),
    retryable: boolean(input.retryable, `${path}.retryable`),
    attempt: positiveInteger(input.attempt, `${path}.attempt`),
    occurredAt: timestamp(input.occurredAt, `${path}.occurredAt`),
  };
}

function parseDrift(value: unknown, path: string) {
  const input = exactObject(value, path, ["observedStateDigest", "detectedAt"]);
  return {
    observedStateDigest: digest(
      input.observedStateDigest,
      `${path}.observedStateDigest`,
    ),
    detectedAt: timestamp(input.detectedAt, `${path}.detectedAt`),
  };
}

function parseDeletion(value: unknown, path: string) {
  const input = exactObject(value, path, [
    "requestedAt",
    "requestedBy",
    "approvalEvidenceRef",
    "finalizationEvidenceRef",
  ]);
  return {
    requestedAt: timestamp(input.requestedAt, `${path}.requestedAt`),
    requestedBy: identifier(input.requestedBy, `${path}.requestedBy`),
    approvalEvidenceRef: reference(
      input.approvalEvidenceRef,
      `${path}.approvalEvidenceRef`,
      ["evidence"],
    ),
    finalizationEvidenceRef: reference(
      input.finalizationEvidenceRef,
      `${path}.finalizationEvidenceRef`,
      ["evidence", "snapshot"],
    ),
  };
}

function parseCancellation(value: unknown, path: string) {
  const input = exactObject(value, path, [
    "requestedAt",
    "requestedBy",
    "cleanupEvidenceRef",
  ]);
  return {
    requestedAt: timestamp(input.requestedAt, `${path}.requestedAt`),
    requestedBy: identifier(input.requestedBy, `${path}.requestedBy`),
    cleanupEvidenceRef:
      input.cleanupEvidenceRef === undefined
        ? undefined
        : reference(input.cleanupEvidenceRef, `${path}.cleanupEvidenceRef`, [
            "evidence",
          ]),
  };
}

function parseIdempotencyRecord(
  value: unknown,
  path: string,
): ResourceBrokerIdempotencyRecord {
  const input = exactObject(value, path, [
    "tenantId",
    "operation",
    "claimId",
    "key",
    "payloadDigest",
    "capabilityId",
    "committedRevision",
  ]);
  return {
    tenantId: identifier(input.tenantId, `${path}.tenantId`),
    operation: enumValue(input.operation, `${path}.operation`, [
      "claim.apply",
      "claim.cancel",
      "claim.delete",
    ]),
    claimId: identifier(input.claimId, `${path}.claimId`),
    key: identifier(input.key, `${path}.key`),
    payloadDigest: digest(input.payloadDigest, `${path}.payloadDigest`),
    capabilityId: identifier(input.capabilityId, `${path}.capabilityId`),
    committedRevision: positiveInteger(
      input.committedRevision,
      `${path}.committedRevision`,
    ),
  };
}

function checkedState(
  state: ResourceBrokerState,
  expectedRevision: number,
): ResourceBrokerState {
  assertResourceBrokerState(state);
  if (state.revision !== expectedRevision) {
    throw new Error(
      `Resource broker revision conflict: expected ${expectedRevision}, current ${state.revision}.`,
    );
  }
  return structuredClone(state);
}

function validateMutationContext(
  context: BrokerMutationContext,
  operation: BrokerMutationOperation,
  claim: Pick<ResourceClaimRequest, "tenantId" | "claimId">,
) {
  if (context.operation !== operation) {
    throw new Error(`Broker mutation context must authorize '${operation}'.`);
  }
  if (context.capabilityVerified !== true) {
    throw new Error("Broker mutation capability is not verified.");
  }
  identifier(context.actorId, "context.actorId");
  identifier(context.capabilityId, "context.capabilityId");
  identifier(context.idempotencyKey, "context.idempotencyKey");
  timestamp(context.occurredAt, "context.occurredAt");
  if (
    context.tenantId !== claim.tenantId ||
    context.resourceId !== claim.claimId
  ) {
    throw new Error(
      "Broker mutation context crosses its exact tenant or resource.",
    );
  }
}

function mutationReplay(
  state: ResourceBrokerState,
  context: BrokerMutationContext,
  operation: BrokerMutationOperation,
  payloadDigest: string,
): ResourceClaimState | undefined {
  const existing = state.idempotencyRecords.find(
    (record) =>
      record.tenantId === context.tenantId &&
      record.operation === operation &&
      record.claimId === context.resourceId &&
      record.key === context.idempotencyKey,
  );
  if (!existing) return undefined;
  if (
    existing.payloadDigest !== payloadDigest ||
    existing.capabilityId !== context.capabilityId
  ) {
    throw new Error(
      "Broker idempotency key was reused with a different payload.",
    );
  }
  return requireClaim(state, existing.claimId);
}

function commitMutation(
  state: ResourceBrokerState,
  context: BrokerMutationContext,
  payloadDigest: string,
  claims: readonly ResourceClaimState[],
): ResourceBrokerState {
  if (state.redeemedCapabilityIds.includes(context.capabilityId)) {
    throw new Error(
      `Broker capability '${context.capabilityId}' was already redeemed.`,
    );
  }
  const revision = state.revision + 1;
  const next: ResourceBrokerState = {
    ...structuredClone(state),
    revision,
    claims: structuredClone(claims),
    idempotencyRecords: [
      ...state.idempotencyRecords,
      {
        tenantId: context.tenantId,
        operation: context.operation,
        claimId: context.resourceId,
        key: context.idempotencyKey,
        payloadDigest,
        capabilityId: context.capabilityId,
        committedRevision: revision,
      },
    ],
    redeemedCapabilityIds: [
      ...state.redeemedCapabilityIds,
      context.capabilityId,
    ],
  };
  assertResourceBrokerState(next);
  return next;
}

function commitState(
  state: ResourceBrokerState,
  claims: readonly ResourceClaimState[],
): ResourceBrokerState {
  const next = {
    ...structuredClone(state),
    revision: state.revision + 1,
    claims: structuredClone(claims),
  };
  assertResourceBrokerState(next);
  return next;
}

function providerClaim(
  state: ResourceBrokerState,
  args: {
    claimId: string;
    providerId: string;
    generation: number;
    fenceToken: string;
    workloadIdentityVerified: true;
    occurredAt: string;
  },
  phase: ResourceClaimPhase,
): ResourceClaimState {
  const claim = requireClaim(state, args.claimId);
  providerIdentity(args.providerId, args.workloadIdentityVerified);
  timestamp(args.occurredAt, "occurredAt");
  if (
    claim.phase !== phase ||
    !claim.lease ||
    claim.lease.providerId !== args.providerId ||
    claim.lease.generation !== args.generation ||
    claim.generation !== args.generation ||
    claim.lease.fenceToken !== args.fenceToken
  ) {
    throw new Error(
      `Resource provider completion for '${claim.claimId}' has a stale generation or fence token.`,
    );
  }
  if (Date.parse(claim.lease.expiresAt) < Date.parse(args.occurredAt)) {
    throw new Error(
      `Resource provider lease for '${claim.claimId}' has expired.`,
    );
  }
  return claim;
}

function providerIdentity(providerId: string, verified: true) {
  identifier(providerId, "providerId");
  if (verified !== true) {
    throw new Error("Resource provider workload identity is not verified.");
  }
}

function validateProviderDescriptor(
  descriptor: ResourceProviderDescriptor,
): ResourceProviderDescriptor {
  const input = exactObject(descriptor, "provider", [
    "id",
    "protocolVersion",
    "resourceKinds",
    "capabilities",
    "mutationMode",
    "acceptsProviderCredentials",
    "outputMode",
    "deterministicPlanning",
  ]);
  if (
    input.protocolVersion !== RESOURCE_PROVIDER_PROTOCOL_VERSION ||
    input.mutationMode !== "broker-only" ||
    input.acceptsProviderCredentials !== false ||
    input.outputMode !== "reference-only" ||
    input.deterministicPlanning !== true
  ) {
    throw new Error(
      "Resource provider descriptor weakens the broker boundary.",
    );
  }
  const resourceKinds = uniqueResourceKinds(
    input.resourceKinds,
    "provider.resourceKinds",
  );
  const capabilities = uniqueIdentifiers(
    input.capabilities,
    "provider.capabilities",
  );
  if (resourceKinds.length === 0 || capabilities.length === 0) {
    throw new Error("Resource provider must declare kinds and capabilities.");
  }
  return {
    id: identifier(input.id, "provider.id"),
    protocolVersion: RESOURCE_PROVIDER_PROTOCOL_VERSION,
    resourceKinds,
    capabilities,
    mutationMode: "broker-only",
    acceptsProviderCredentials: false,
    outputMode: "reference-only",
    deterministicPlanning: true,
  };
}

function validateProviderRequest(
  descriptor: ResourceProviderDescriptor,
  request: ResourceProviderRequest,
): ResourceProviderRequest {
  const input = exactObject(request, "providerRequest", [
    "claim",
    "operation",
    "fenceToken",
  ]);
  const claim = parseResourceClaimRequest(input.claim);
  if (!descriptor.resourceKinds.includes(claim.resourceKind)) {
    throw new Error(
      `Resource provider '${descriptor.id}' does not support '${claim.resourceKind}'.`,
    );
  }
  const missing = claim.requiredProviderCapabilities.filter(
    (capability) => !descriptor.capabilities.includes(capability),
  );
  if (missing.length > 0) {
    throw new Error(
      `Resource provider '${descriptor.id}' lacks capability: ${missing.sort().join(", ")}.`,
    );
  }
  const operation = enumValue(input.operation, "provider.operation", [
    "reconcile",
    "destroy",
  ]);
  return {
    claim,
    operation,
    fenceToken: digest(input.fenceToken, "provider.fenceToken"),
  };
}

function validateOutputs(outputs: readonly ResourceBrokerOutput[]): void {
  const names = new Set<string>();
  for (const output of outputs) {
    const name = identifier(output.name, "output.name");
    if (/^(?:password|secret|token|credential|private-key)$/i.test(name)) {
      throw new Error(`Resource provider output '${name}' is forbidden.`);
    }
    if (names.has(name)) {
      throw new Error(`Resource provider output '${name}' is duplicated.`);
    }
    names.add(name);
    if (output.kind === "reference") {
      if (typeof output.value !== "string") {
        throw new Error(
          `Resource provider reference '${name}' must be a string.`,
        );
      }
      reference(output.value, `output.${name}`, [
        "broker",
        "provider",
        "identity",
        "evidence",
      ]);
    } else if (output.kind === "value") {
      scalar(output.value, `output.${name}`);
      if (
        typeof output.value === "string" &&
        /:\/\/[^\s/@:]+:[^\s/@]+@/.test(output.value)
      ) {
        throw new Error(
          `Resource provider value '${name}' contains credentials.`,
        );
      }
    } else {
      throw new Error(
        `Resource provider output '${name}' has an invalid kind.`,
      );
    }
  }
}

function requireClaim(
  state: ResourceBrokerState,
  claimId: string,
): ResourceClaimState {
  const claim = state.claims.find((candidate) => candidate.claimId === claimId);
  if (!claim) throw new Error(`Resource claim '${claimId}' does not exist.`);
  return structuredClone(claim);
}

function upsertClaim(
  claims: readonly ResourceClaimState[],
  claim: ResourceClaimState,
): readonly ResourceClaimState[] {
  return [
    ...claims.filter((candidate) => candidate.claimId !== claim.claimId),
    claim,
  ]
    .map((candidate) => structuredClone(candidate))
    .sort((left, right) => left.claimId.localeCompare(right.claimId));
}

function transition<T>(
  state: ResourceBrokerState,
  result: T,
  eventValue: ResourceBrokerEvent,
): ResourceBrokerTransition<T> {
  return {
    state,
    result: structuredClone(result),
    events: [eventValue],
    replayed: false,
  };
}

function replayTransition(
  state: ResourceBrokerState,
  claim: ResourceClaimState,
): ResourceBrokerTransition {
  return {
    state: structuredClone(state),
    result: structuredClone(claim),
    events: [],
    replayed: true,
  };
}

function event(
  state: ResourceBrokerState,
  claim: ResourceClaimState,
  type: ResourceBrokerEvent["type"],
  occurredAt: string,
  extra: Pick<ResourceBrokerEvent, "actorId" | "providerId" | "fenceToken">,
): ResourceBrokerEvent {
  const base = {
    apiVersion: RESOURCE_BROKER_STATE_API_VERSION,
    type,
    revision: state.revision,
    claimId: claim.claimId,
    tenantId: claim.tenantId,
    generation: claim.generation,
    desiredStateDigest: claim.desiredStateDigest,
    occurredAt: timestamp(occurredAt, "occurredAt"),
    ...extra,
  };
  return { ...base, eventId: sha256(canonicalJson(base)) };
}

function exactObject(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const object = value as Record<string, unknown>;
  for (const key of Object.keys(object)) {
    if (!allowed.includes(key))
      throw new Error(`${path} has unknown field '${key}'.`);
  }
  for (const key of allowed) {
    if (!(key in object) && !optionalStateField(key)) {
      throw new Error(`${path}.${key} is required.`);
    }
  }
  return object;
}

function optionalStateField(key: string): boolean {
  return [
    "providerResourceRef",
    "lease",
    "failure",
    "drift",
    "deletion",
    "cancellation",
    "cleanupEvidenceRef",
  ].includes(key);
}

function identifier(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/.test(value)
  ) {
    throw new Error(`${path} must be a bounded identifier.`);
  }
  return value;
}

function resourceKind(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z][A-Za-z0-9]{0,126}$/.test(value)
  ) {
    throw new Error(`${path} must be a bounded resource kind.`);
  }
  return value;
}

function reasonCode(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9_]{1,63}$/.test(value)) {
    throw new Error(`${path} must be a stable reason code.`);
  }
  return value;
}

function safeMessage(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    throw new Error(`${path} must be a bounded message.`);
  }
  if (
    /(?:password|secret|token|credential|private[_ -]?key)\s*[=:]/i.test(
      value,
    ) ||
    /:\/\/[^\s/@:]+:[^\s/@]+@/.test(value) ||
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value) ||
    /AKIA[0-9A-Z]{16}/.test(value)
  ) {
    throw new Error(`${path} contains secret material.`);
  }
  return value;
}

function apiVersion(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9.-]+\/[a-z0-9.-]+\/v[0-9]+(?:alpha|beta)?[0-9]*$/.test(value)
  ) {
    throw new Error(`${path} must be a versioned resource API.`);
  }
  return value;
}

function reference(
  value: unknown,
  path: string,
  schemes: readonly string[],
): string {
  if (typeof value !== "string" || value.length > 512) {
    throw new Error(`${path} must be a bounded reference.`);
  }
  const scheme = /^([a-z][a-z0-9-]*):\/\/(.+)$/.exec(value)?.[1];
  if (!scheme || !schemes.includes(scheme) || value.includes("@")) {
    throw new Error(`${path} must be a safe ${schemes.join("/")} reference.`);
  }
  return value;
}

function digest(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${path} must be a SHA-256 digest.`);
  }
  return value;
}

function timestamp(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(`${path} must be an RFC 3339 UTC timestamp.`);
  }
  return value;
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${path} must be a positive integer.`);
  }
  return value as number;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new Error(`${path} must be a non-negative integer.`);
  }
  return value as number;
}

function boundedInteger(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number {
  if (
    !Number.isInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new Error(`${path} must be between ${minimum} and ${maximum}.`);
  }
  return value as number;
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be boolean.`);
  return value;
}

function trueLiteral(value: unknown, path: string): true {
  if (value !== true) throw new Error(`${path} must be true.`);
  return true;
}

function literal<T extends string>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) throw new Error(`${path} must be '${expected}'.`);
  return expected;
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  values: readonly T[],
): T {
  if (typeof value !== "string" || !values.includes(value as T)) {
    throw new Error(`${path} must be one of: ${values.join(", ")}.`);
  }
  return value as T;
}

function uniqueIdentifiers(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  const result = value.map((entry, index) =>
    identifier(entry, `${path}[${index}]`),
  );
  if (new Set(result).size !== result.length) {
    throw new Error(`${path} must contain unique values.`);
  }
  return result;
}

function uniqueResourceKinds(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  const result = value.map((entry, index) =>
    resourceKind(entry, `${path}[${index}]`),
  );
  if (new Set(result).size !== result.length) {
    throw new Error(`${path} must contain unique values.`);
  }
  return result;
}

function semanticOperations(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array.`);
  }
  const result = value.map((entry, index) => {
    if (
      typeof entry !== "string" ||
      !/^[a-z][A-Za-z0-9:._-]{0,127}$/.test(entry)
    ) {
      throw new Error(`${path}[${index}] must be a semantic operation.`);
    }
    return entry;
  });
  if (new Set(result).size !== result.length) {
    throw new Error(`${path} must contain unique values.`);
  }
  return result;
}

function array<T>(
  value: unknown,
  path: string,
  parser: (entry: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  return value.map((entry, index) => parser(entry, `${path}[${index}]`));
}

function scalar(value: unknown, path: string): string | number | boolean {
  if (
    !["string", "number", "boolean"].includes(typeof value) ||
    (typeof value === "number" && !Number.isFinite(value)) ||
    (typeof value === "string" && value.length > 512)
  ) {
    throw new Error(`${path} must be a bounded scalar.`);
  }
  return value as string | number | boolean;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
