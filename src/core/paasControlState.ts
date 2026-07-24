import { createHash } from "node:crypto";
import type { PaasSecurityIntent } from "./paas";
import type { PaasAuthorizationDecision } from "./paasAuthorization";

export const PAAS_CONTROL_STATE_API_VERSION =
  "security.deus.dev/paas-control-state/v1alpha1" as const;

export type PaasJobOperation = "build" | "deploy" | "rollback";
export type PaasJobStatus =
  | "queued"
  | "running"
  | "cancelling"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "timed-out";
export type PaasWorkerRole = "builder" | "deployer";

export interface PaasControlJob {
  id: string;
  tenantId: string;
  operation: PaasJobOperation;
  resource: string;
  sourceRevision?: string;
  artifactDigest?: string;
  status: PaasJobStatus;
  workerRole: PaasWorkerRole;
  idempotencyKey: string;
  capabilityId?: string;
  createdAtEpochSeconds: number;
  updatedAtEpochSeconds: number;
  deadlineAtEpochSeconds: number;
  startedAtEpochSeconds?: number;
  completedAtEpochSeconds?: number;
  attempt: number;
  maxAttempts: number;
  lastErrorCode?: string;
  cancellationReason?: "user" | "deadline";
  cleanupEvidence?: string;
  resultArtifactDigest?: string;
}

export interface PaasDeploymentRecord {
  tenantId: string;
  resource: string;
  activeArtifactDigest: string;
  previousArtifactDigests: readonly string[];
  generation: number;
  updatedAtEpochSeconds: number;
  sourceJobId: string;
}

export interface PaasIdempotencyRecord {
  action: "enqueue" | "cancel";
  tenantId: string;
  idempotencyKey: string;
  fingerprint: string;
  jobId: string;
}

export interface PaasCapabilityRedemption {
  capabilityId: string;
  tenantId: string;
  jobId: string;
  redeemedAtEpochSeconds: number;
}

export interface PaasControlState {
  apiVersion: typeof PAAS_CONTROL_STATE_API_VERSION;
  revision: number;
  lastScheduledTenant: string | null;
  jobs: Readonly<Record<string, PaasControlJob>>;
  tenantQueues: Readonly<Record<string, readonly string[]>>;
  idempotency: Readonly<Record<string, PaasIdempotencyRecord>>;
  redeemedCapabilities: Readonly<Record<string, PaasCapabilityRedemption>>;
  resourceLocks: Readonly<Record<string, string>>;
  deployments: Readonly<Record<string, PaasDeploymentRecord>>;
}

export type PaasControlEventType =
  | "job-enqueued"
  | "capability-redeemed"
  | "job-started"
  | "job-retry-queued"
  | "job-succeeded"
  | "job-failed"
  | "job-cancellation-requested"
  | "job-cancelled"
  | "job-timed-out"
  | "deployment-promoted"
  | "deployment-rolled-back";

export interface PaasControlEvent {
  type: PaasControlEventType;
  stateRevision: number;
  atEpochSeconds: number;
  tenantId: string;
  jobId: string;
  resource: string;
}

export type PaasControlTransitionCode =
  | "ACCEPTED"
  | "DEDUPLICATED"
  | "NO_CHANGE"
  | "STATE_REVISION_CONFLICT"
  | "STATE_INVARIANT_VIOLATION"
  | "COMMAND_INVALID"
  | "AUTHORIZATION_DENIED"
  | "AUTHORIZATION_BINDING_INVALID"
  | "TENANT_UNKNOWN"
  | "JOB_ALREADY_EXISTS"
  | "JOB_NOT_FOUND"
  | "JOB_NOT_RUNNING"
  | "JOB_DEADLINE_EXCEEDED"
  | "JOB_NOT_CANCELLABLE"
  | "IDEMPOTENCY_CONFLICT"
  | "CAPABILITY_REPLAYED"
  | "ROLLBACK_TARGET_UNKNOWN"
  | "WORKER_IDENTITY_MISMATCH"
  | "CLEANUP_EVIDENCE_REQUIRED";

export interface PaasControlTransition {
  accepted: boolean;
  code: PaasControlTransitionCode;
  state: PaasControlState;
  events: readonly PaasControlEvent[];
  jobId?: string;
}

export interface PaasEnqueueJobCommand {
  expectedRevision: number;
  jobId: string;
  tenantId: string;
  operation: PaasJobOperation;
  resource: string;
  idempotencyKey: string;
  requestedAtEpochSeconds: number;
  maxAttempts: number;
  sourceRevision?: string;
  artifactDigest?: string;
  authorization: PaasAuthorizationDecision;
}

export interface PaasScheduleCommand {
  expectedRevision: number;
  nowEpochSeconds: number;
  maxStarts?: number;
}

export interface PaasCompleteJobCommand {
  expectedRevision: number;
  jobId: string;
  tenantId: string;
  workerRole: PaasWorkerRole;
  completedAtEpochSeconds: number;
  outcome: "succeeded" | "failed";
  retryable?: boolean;
  errorCode?: string;
  resultArtifactDigest?: string;
}

export interface PaasCancelJobCommand {
  expectedRevision: number;
  jobId: string;
  tenantId: string;
  idempotencyKey: string;
  requestedAtEpochSeconds: number;
  authorization: PaasAuthorizationDecision;
}

export interface PaasAcknowledgeCancellationCommand {
  expectedRevision: number;
  jobId: string;
  tenantId: string;
  workerRole: PaasWorkerRole;
  acknowledgedAtEpochSeconds: number;
  cleanupEvidence: string;
}

export function createPaasControlState(
  intent: PaasSecurityIntent,
): PaasControlState {
  return {
    apiVersion: PAAS_CONTROL_STATE_API_VERSION,
    revision: 0,
    lastScheduledTenant: null,
    jobs: {},
    tenantQueues: Object.fromEntries(
      intent.tenants.map((tenant) => [tenant.tenantId, []]),
    ),
    idempotency: {},
    redeemedCapabilities: {},
    resourceLocks: {},
    deployments: {},
  };
}

export function parsePaasControlState(
  value: unknown,
  intent: PaasSecurityIntent,
): PaasControlState {
  const root = stateObject(
    value,
    "paasControlState",
    [
      "apiVersion",
      "revision",
      "lastScheduledTenant",
      "jobs",
      "tenantQueues",
      "idempotency",
      "redeemedCapabilities",
      "resourceLocks",
      "deployments",
    ],
    [],
  );
  const apiVersion = stateString(root.apiVersion, "apiVersion");
  if (apiVersion !== PAAS_CONTROL_STATE_API_VERSION) {
    throw new Error(
      `paasControlState.apiVersion must be '${PAAS_CONTROL_STATE_API_VERSION}'.`,
    );
  }
  const state: PaasControlState = {
    apiVersion,
    revision: stateInteger(root.revision, "revision", 0),
    lastScheduledTenant:
      root.lastScheduledTenant === null
        ? null
        : stateName(root.lastScheduledTenant, "lastScheduledTenant"),
    jobs: stateRecord(root.jobs, "jobs", parseStateJob),
    tenantQueues: stateRecord(
      root.tenantQueues,
      "tenantQueues",
      (entry, path) => stateStringArray(entry, path, true),
    ),
    idempotency: stateRecord(
      root.idempotency,
      "idempotency",
      parseIdempotencyRecord,
    ),
    redeemedCapabilities: stateRecord(
      root.redeemedCapabilities,
      "redeemedCapabilities",
      parseCapabilityRedemption,
    ),
    resourceLocks: stateRecord(
      root.resourceLocks,
      "resourceLocks",
      stateString,
    ),
    deployments: stateRecord(
      root.deployments,
      "deployments",
      parseDeploymentRecord,
    ),
  };
  assertPaasControlState(state, intent);
  return state;
}

function parseStateJob(value: unknown, path: string): PaasControlJob {
  const input = stateObject(
    value,
    path,
    [
      "id",
      "tenantId",
      "operation",
      "resource",
      "status",
      "workerRole",
      "idempotencyKey",
      "createdAtEpochSeconds",
      "updatedAtEpochSeconds",
      "deadlineAtEpochSeconds",
      "attempt",
      "maxAttempts",
    ],
    [
      "sourceRevision",
      "artifactDigest",
      "capabilityId",
      "startedAtEpochSeconds",
      "completedAtEpochSeconds",
      "lastErrorCode",
      "cancellationReason",
      "cleanupEvidence",
      "resultArtifactDigest",
    ],
  );
  const job: PaasControlJob = {
    id: stateJobId(input.id, `${path}.id`),
    tenantId: stateName(input.tenantId, `${path}.tenantId`),
    operation: stateEnum(input.operation, `${path}.operation`, [
      "build",
      "deploy",
      "rollback",
    ]),
    resource: stateResource(input.resource, `${path}.resource`),
    status: stateEnum(input.status, `${path}.status`, [
      "queued",
      "running",
      "cancelling",
      "succeeded",
      "failed",
      "cancelled",
      "timed-out",
    ]),
    workerRole: stateEnum(input.workerRole, `${path}.workerRole`, [
      "builder",
      "deployer",
    ]),
    idempotencyKey: stateString(input.idempotencyKey, `${path}.idempotencyKey`),
    createdAtEpochSeconds: stateInteger(
      input.createdAtEpochSeconds,
      `${path}.createdAtEpochSeconds`,
      0,
    ),
    updatedAtEpochSeconds: stateInteger(
      input.updatedAtEpochSeconds,
      `${path}.updatedAtEpochSeconds`,
      0,
    ),
    deadlineAtEpochSeconds: stateInteger(
      input.deadlineAtEpochSeconds,
      `${path}.deadlineAtEpochSeconds`,
      0,
    ),
    attempt: stateInteger(input.attempt, `${path}.attempt`, 0),
    maxAttempts: stateInteger(input.maxAttempts, `${path}.maxAttempts`, 1),
  };
  assignOptionalString(job, input, "sourceRevision", path, /^[a-f0-9]{40,64}$/);
  assignOptionalString(
    job,
    input,
    "artifactDigest",
    path,
    /^sha256:[a-f0-9]{64}$/,
  );
  assignOptionalString(job, input, "capabilityId", path);
  assignOptionalInteger(job, input, "startedAtEpochSeconds", path);
  assignOptionalInteger(job, input, "completedAtEpochSeconds", path);
  assignOptionalString(job, input, "lastErrorCode", path);
  if ("cancellationReason" in input) {
    job.cancellationReason = stateEnum(
      input.cancellationReason,
      `${path}.cancellationReason`,
      ["user", "deadline"],
    );
  }
  assignOptionalString(job, input, "cleanupEvidence", path);
  assignOptionalString(
    job,
    input,
    "resultArtifactDigest",
    path,
    /^sha256:[a-f0-9]{64}$/,
  );
  return job;
}

function parseIdempotencyRecord(
  value: unknown,
  path: string,
): PaasIdempotencyRecord {
  const input = stateObject(
    value,
    path,
    ["action", "tenantId", "idempotencyKey", "fingerprint", "jobId"],
    [],
  );
  return {
    action: stateEnum(input.action, `${path}.action`, ["enqueue", "cancel"]),
    tenantId: stateName(input.tenantId, `${path}.tenantId`),
    idempotencyKey: stateString(input.idempotencyKey, `${path}.idempotencyKey`),
    fingerprint: statePattern(
      input.fingerprint,
      `${path}.fingerprint`,
      /^[a-f0-9]{64}$/,
    ),
    jobId: stateJobId(input.jobId, `${path}.jobId`),
  };
}

function parseCapabilityRedemption(
  value: unknown,
  path: string,
): PaasCapabilityRedemption {
  const input = stateObject(
    value,
    path,
    ["capabilityId", "tenantId", "jobId", "redeemedAtEpochSeconds"],
    [],
  );
  return {
    capabilityId: stateString(input.capabilityId, `${path}.capabilityId`),
    tenantId: stateName(input.tenantId, `${path}.tenantId`),
    jobId: stateJobId(input.jobId, `${path}.jobId`),
    redeemedAtEpochSeconds: stateInteger(
      input.redeemedAtEpochSeconds,
      `${path}.redeemedAtEpochSeconds`,
      0,
    ),
  };
}

function parseDeploymentRecord(
  value: unknown,
  path: string,
): PaasDeploymentRecord {
  const input = stateObject(
    value,
    path,
    [
      "tenantId",
      "resource",
      "activeArtifactDigest",
      "previousArtifactDigests",
      "generation",
      "updatedAtEpochSeconds",
      "sourceJobId",
    ],
    [],
  );
  return {
    tenantId: stateName(input.tenantId, `${path}.tenantId`),
    resource: stateResource(input.resource, `${path}.resource`),
    activeArtifactDigest: statePattern(
      input.activeArtifactDigest,
      `${path}.activeArtifactDigest`,
      /^sha256:[a-f0-9]{64}$/,
    ),
    previousArtifactDigests: stateStringArray(
      input.previousArtifactDigests,
      `${path}.previousArtifactDigests`,
      true,
      /^sha256:[a-f0-9]{64}$/,
    ),
    generation: stateInteger(input.generation, `${path}.generation`, 1),
    updatedAtEpochSeconds: stateInteger(
      input.updatedAtEpochSeconds,
      `${path}.updatedAtEpochSeconds`,
      0,
    ),
    sourceJobId: stateJobId(input.sourceJobId, `${path}.sourceJobId`),
  };
}

export function enqueuePaasJob(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: PaasEnqueueJobCommand,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  if (!validEnqueueCommand(command)) return rejected(state, "COMMAND_INVALID");
  const tenant = intent.tenants.find(
    (candidate) => candidate.tenantId === command.tenantId,
  );
  if (!tenant) return rejected(state, "TENANT_UNKNOWN");
  if (!authorizationBinds(command.authorization, command, command.operation)) {
    return rejected(
      state,
      command.authorization.allowed
        ? "AUTHORIZATION_BINDING_INVALID"
        : "AUTHORIZATION_DENIED",
    );
  }

  const fingerprint = enqueueFingerprint(command);
  const idempotencyKey = stateKey(command.tenantId, command.idempotencyKey);
  const existing = state.idempotency[idempotencyKey];
  if (existing) {
    if (existing.action === "enqueue" && existing.fingerprint === fingerprint) {
      return {
        accepted: true,
        code: "DEDUPLICATED",
        state,
        events: [],
        jobId: existing.jobId,
      };
    }
    return rejected(state, "IDEMPOTENCY_CONFLICT");
  }
  if (command.expectedRevision !== state.revision) {
    return rejected(state, "STATE_REVISION_CONFLICT");
  }
  if (state.jobs[command.jobId]) return rejected(state, "JOB_ALREADY_EXISTS");
  if (
    command.operation === "rollback" &&
    !knownRollbackTarget(state, command)
  ) {
    return rejected(state, "ROLLBACK_TARGET_UNKNOWN");
  }
  const capabilityId = command.authorization.capabilityToRedeem ?? undefined;
  const capabilityKey = capabilityId ? stateKey(capabilityId) : undefined;
  if (capabilityKey && state.redeemedCapabilities[capabilityKey]) {
    return rejected(state, "CAPABILITY_REPLAYED");
  }

  const next = mutableState(state);
  const revision = state.revision + 1;
  const job: PaasControlJob = {
    id: command.jobId,
    tenantId: command.tenantId,
    operation: command.operation,
    resource: command.resource,
    ...(command.sourceRevision
      ? { sourceRevision: command.sourceRevision }
      : {}),
    ...(command.artifactDigest
      ? { artifactDigest: command.artifactDigest }
      : {}),
    status: "queued",
    workerRole: command.operation === "build" ? "builder" : "deployer",
    idempotencyKey: command.idempotencyKey,
    ...(capabilityId ? { capabilityId } : {}),
    createdAtEpochSeconds: command.requestedAtEpochSeconds,
    updatedAtEpochSeconds: command.requestedAtEpochSeconds,
    deadlineAtEpochSeconds:
      command.requestedAtEpochSeconds + tenant.maxExecutionMinutes * 60,
    attempt: 0,
    maxAttempts: command.maxAttempts,
  };
  next.jobs[command.jobId] = job;
  next.tenantQueues[command.tenantId].push(command.jobId);
  next.idempotency[idempotencyKey] = {
    action: "enqueue",
    tenantId: command.tenantId,
    idempotencyKey: command.idempotencyKey,
    fingerprint,
    jobId: command.jobId,
  };
  const events: PaasControlEvent[] = [
    event("job-enqueued", revision, command.requestedAtEpochSeconds, job),
  ];
  if (capabilityId && capabilityKey) {
    next.redeemedCapabilities[capabilityKey] = {
      capabilityId,
      tenantId: command.tenantId,
      jobId: command.jobId,
      redeemedAtEpochSeconds: command.requestedAtEpochSeconds,
    };
    events.push(
      event(
        "capability-redeemed",
        revision,
        command.requestedAtEpochSeconds,
        job,
      ),
    );
  }
  return accepted(finalize(next, revision), events, command.jobId);
}

export function schedulePaasJobs(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: PaasScheduleCommand,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  if (
    command.expectedRevision !== state.revision ||
    !validEpoch(command.nowEpochSeconds)
  ) {
    return rejected(
      state,
      command.expectedRevision !== state.revision
        ? "STATE_REVISION_CONFLICT"
        : "COMMAND_INVALID",
    );
  }
  const maxStarts = command.maxStarts ?? intent.scheduling.maxGlobalConcurrency;
  if (!Number.isInteger(maxStarts) || maxStarts < 1) {
    return rejected(state, "COMMAND_INVALID");
  }
  const next = mutableState(state);
  const revision = state.revision + 1;
  const events: PaasControlEvent[] = [];
  expireQueuedJobs(next, command.nowEpochSeconds, revision, events);
  const tenantIds = intent.tenants
    .map((tenant) => tenant.tenantId)
    .sort((left, right) => left.localeCompare(right));
  let started = 0;
  while (
    started < maxStarts &&
    activeJobs(next).length < intent.scheduling.maxGlobalConcurrency
  ) {
    const tenantId = nextEligibleTenant(next, intent, tenantIds);
    if (!tenantId) break;
    const jobId = next.tenantQueues[tenantId].shift();
    if (!jobId) break;
    const job = next.jobs[jobId];
    job.status = "running";
    job.startedAtEpochSeconds = command.nowEpochSeconds;
    job.updatedAtEpochSeconds = command.nowEpochSeconds;
    job.attempt += 1;
    next.resourceLocks[resourceKey(job.tenantId, job.resource)] = job.id;
    next.lastScheduledTenant = tenantId;
    events.push(event("job-started", revision, command.nowEpochSeconds, job));
    started += 1;
  }
  if (events.length === 0) {
    return { accepted: true, code: "NO_CHANGE", state, events: [] };
  }
  return accepted(finalize(next, revision), events);
}

export function completePaasJob(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: PaasCompleteJobCommand,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  if (command.expectedRevision !== state.revision) {
    return rejected(state, "STATE_REVISION_CONFLICT");
  }
  if (!validEpoch(command.completedAtEpochSeconds)) {
    return rejected(state, "COMMAND_INVALID");
  }
  const current = state.jobs[command.jobId];
  if (!current || current.tenantId !== command.tenantId) {
    return rejected(state, "JOB_NOT_FOUND");
  }
  if (current.status !== "running") return rejected(state, "JOB_NOT_RUNNING");
  if (current.workerRole !== command.workerRole) {
    return rejected(state, "WORKER_IDENTITY_MISMATCH");
  }
  if (
    command.completedAtEpochSeconds >= current.deadlineAtEpochSeconds ||
    command.completedAtEpochSeconds < (current.startedAtEpochSeconds ?? 0)
  ) {
    return rejected(state, "JOB_DEADLINE_EXCEEDED");
  }
  if (
    command.outcome === "succeeded" &&
    current.operation === "build" &&
    !validDigest(command.resultArtifactDigest)
  ) {
    return rejected(state, "COMMAND_INVALID");
  }
  if (
    command.outcome === "failed" &&
    (!nonEmpty(command.errorCode) || command.resultArtifactDigest)
  ) {
    return rejected(state, "COMMAND_INVALID");
  }

  const next = mutableState(state);
  const job = next.jobs[command.jobId];
  const revision = state.revision + 1;
  const events: PaasControlEvent[] = [];
  delete next.resourceLocks[resourceKey(job.tenantId, job.resource)];
  job.updatedAtEpochSeconds = command.completedAtEpochSeconds;
  delete job.startedAtEpochSeconds;

  if (command.outcome === "failed") {
    job.lastErrorCode = command.errorCode;
    if (
      command.retryable === true &&
      job.attempt < job.maxAttempts &&
      command.completedAtEpochSeconds < job.deadlineAtEpochSeconds
    ) {
      job.status = "queued";
      next.tenantQueues[job.tenantId].push(job.id);
      events.push(
        event(
          "job-retry-queued",
          revision,
          command.completedAtEpochSeconds,
          job,
        ),
      );
    } else {
      job.status = "failed";
      job.completedAtEpochSeconds = command.completedAtEpochSeconds;
      events.push(
        event("job-failed", revision, command.completedAtEpochSeconds, job),
      );
    }
  } else {
    job.status = "succeeded";
    job.completedAtEpochSeconds = command.completedAtEpochSeconds;
    if (command.resultArtifactDigest) {
      job.resultArtifactDigest = command.resultArtifactDigest;
    }
    events.push(
      event("job-succeeded", revision, command.completedAtEpochSeconds, job),
    );
    if (job.operation === "deploy" || job.operation === "rollback") {
      promoteDeployment(next, job, command.completedAtEpochSeconds);
      events.push(
        event(
          job.operation === "deploy"
            ? "deployment-promoted"
            : "deployment-rolled-back",
          revision,
          command.completedAtEpochSeconds,
          job,
        ),
      );
    }
  }
  return accepted(finalize(next, revision), events, job.id);
}

export function cancelPaasJob(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: PaasCancelJobCommand,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  const current = state.jobs[command.jobId];
  if (!current || current.tenantId !== command.tenantId) {
    return rejected(state, "JOB_NOT_FOUND");
  }
  if (
    !validEpoch(command.requestedAtEpochSeconds) ||
    !nonEmpty(command.idempotencyKey) ||
    command.requestedAtEpochSeconds < current.createdAtEpochSeconds
  ) {
    return rejected(state, "COMMAND_INVALID");
  }
  if (!authorizationBinds(command.authorization, command, "cancel", current)) {
    return rejected(
      state,
      command.authorization.allowed
        ? "AUTHORIZATION_BINDING_INVALID"
        : "AUTHORIZATION_DENIED",
    );
  }
  const fingerprint = cancelFingerprint(command, current);
  const idempotencyKey = stateKey(command.tenantId, command.idempotencyKey);
  const existing = state.idempotency[idempotencyKey];
  if (existing) {
    if (existing.action === "cancel" && existing.fingerprint === fingerprint) {
      return {
        accepted: true,
        code: "DEDUPLICATED",
        state,
        events: [],
        jobId: current.id,
      };
    }
    return rejected(state, "IDEMPOTENCY_CONFLICT");
  }
  if (command.expectedRevision !== state.revision) {
    return rejected(state, "STATE_REVISION_CONFLICT");
  }
  if (current.status !== "queued" && current.status !== "running") {
    return rejected(state, "JOB_NOT_CANCELLABLE");
  }
  const capabilityId = command.authorization.capabilityToRedeem ?? undefined;
  const capabilityKey = capabilityId ? stateKey(capabilityId) : undefined;
  if (capabilityKey && state.redeemedCapabilities[capabilityKey]) {
    return rejected(state, "CAPABILITY_REPLAYED");
  }

  const next = mutableState(state);
  const job = next.jobs[current.id];
  const revision = state.revision + 1;
  const events: PaasControlEvent[] = [];
  next.idempotency[idempotencyKey] = {
    action: "cancel",
    tenantId: command.tenantId,
    idempotencyKey: command.idempotencyKey,
    fingerprint,
    jobId: job.id,
  };
  if (capabilityId && capabilityKey) {
    next.redeemedCapabilities[capabilityKey] = {
      capabilityId,
      tenantId: command.tenantId,
      jobId: job.id,
      redeemedAtEpochSeconds: command.requestedAtEpochSeconds,
    };
    events.push(
      event(
        "capability-redeemed",
        revision,
        command.requestedAtEpochSeconds,
        job,
      ),
    );
  }
  job.updatedAtEpochSeconds = command.requestedAtEpochSeconds;
  job.cancellationReason = "user";
  if (job.status === "queued") {
    next.tenantQueues[job.tenantId] = next.tenantQueues[job.tenantId].filter(
      (queued) => queued !== job.id,
    );
    job.status = "cancelled";
    job.completedAtEpochSeconds = command.requestedAtEpochSeconds;
    events.push(
      event("job-cancelled", revision, command.requestedAtEpochSeconds, job),
    );
  } else {
    job.status = "cancelling";
    events.push(
      event(
        "job-cancellation-requested",
        revision,
        command.requestedAtEpochSeconds,
        job,
      ),
    );
  }
  return accepted(finalize(next, revision), events, job.id);
}

export function acknowledgePaasJobCancellation(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: PaasAcknowledgeCancellationCommand,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  if (command.expectedRevision !== state.revision) {
    return rejected(state, "STATE_REVISION_CONFLICT");
  }
  const current = state.jobs[command.jobId];
  if (!current || current.tenantId !== command.tenantId) {
    return rejected(state, "JOB_NOT_FOUND");
  }
  if (current.status !== "cancelling") {
    return rejected(state, "JOB_NOT_CANCELLABLE");
  }
  if (current.workerRole !== command.workerRole) {
    return rejected(state, "WORKER_IDENTITY_MISMATCH");
  }
  if (
    !validEpoch(command.acknowledgedAtEpochSeconds) ||
    !nonEmpty(command.cleanupEvidence) ||
    command.acknowledgedAtEpochSeconds < current.updatedAtEpochSeconds
  ) {
    return rejected(state, "CLEANUP_EVIDENCE_REQUIRED");
  }

  const next = mutableState(state);
  const job = next.jobs[current.id];
  const revision = state.revision + 1;
  delete next.resourceLocks[resourceKey(job.tenantId, job.resource)];
  job.status =
    job.cancellationReason === "deadline" ? "timed-out" : "cancelled";
  job.updatedAtEpochSeconds = command.acknowledgedAtEpochSeconds;
  job.completedAtEpochSeconds = command.acknowledgedAtEpochSeconds;
  job.cleanupEvidence = command.cleanupEvidence;
  delete job.startedAtEpochSeconds;
  return accepted(
    finalize(next, revision),
    [
      event(
        job.status === "timed-out" ? "job-timed-out" : "job-cancelled",
        revision,
        command.acknowledgedAtEpochSeconds,
        job,
      ),
    ],
    job.id,
  );
}

export function sweepExpiredPaasJobs(
  state: PaasControlState,
  intent: PaasSecurityIntent,
  command: Pick<PaasScheduleCommand, "expectedRevision" | "nowEpochSeconds">,
): PaasControlTransition {
  const invariant = stateInvariantError(state, intent);
  if (invariant) return rejected(state, "STATE_INVARIANT_VIOLATION");
  if (command.expectedRevision !== state.revision) {
    return rejected(state, "STATE_REVISION_CONFLICT");
  }
  if (!validEpoch(command.nowEpochSeconds)) {
    return rejected(state, "COMMAND_INVALID");
  }
  const next = mutableState(state);
  const revision = state.revision + 1;
  const events: PaasControlEvent[] = [];
  expireQueuedJobs(next, command.nowEpochSeconds, revision, events);
  for (const job of Object.values(next.jobs)) {
    if (
      job.status === "running" &&
      job.deadlineAtEpochSeconds <= command.nowEpochSeconds
    ) {
      job.status = "cancelling";
      job.cancellationReason = "deadline";
      job.updatedAtEpochSeconds = command.nowEpochSeconds;
      events.push(
        event(
          "job-cancellation-requested",
          revision,
          command.nowEpochSeconds,
          job,
        ),
      );
    }
  }
  if (events.length === 0) {
    return { accepted: true, code: "NO_CHANGE", state, events: [] };
  }
  return accepted(finalize(next, revision), events);
}

export function assertPaasControlState(
  state: PaasControlState,
  intent: PaasSecurityIntent,
): void {
  const error = stateInvariantError(state, intent);
  if (error) throw new Error(`Invalid PaaS control state: ${error}`);
}

function stateInvariantError(
  state: PaasControlState,
  intent: PaasSecurityIntent,
): string | null {
  if (
    state.apiVersion !== PAAS_CONTROL_STATE_API_VERSION ||
    !Number.isInteger(state.revision) ||
    state.revision < 0
  ) {
    return "invalid API version or revision";
  }
  const tenantIds = intent.tenants.map((tenant) => tenant.tenantId).sort();
  if (
    JSON.stringify(Object.keys(state.tenantQueues).sort()) !==
    JSON.stringify(tenantIds)
  ) {
    return "tenant queues do not match the security intent";
  }
  if (
    state.lastScheduledTenant !== null &&
    !tenantIds.includes(state.lastScheduledTenant)
  ) {
    return "last scheduled tenant is not declared";
  }
  const queuedIds = Object.values(state.tenantQueues).flat();
  if (new Set(queuedIds).size !== queuedIds.length) {
    return "a job appears in more than one queue position";
  }
  for (const [tenantId, queue] of Object.entries(state.tenantQueues)) {
    for (const jobId of queue) {
      const job = state.jobs[jobId];
      if (!job || job.tenantId !== tenantId || job.status !== "queued") {
        return `queue '${tenantId}' contains an invalid job '${jobId}'`;
      }
    }
  }
  for (const [jobKey, job] of Object.entries(state.jobs)) {
    const tenant = intent.tenants.find(
      (candidate) => candidate.tenantId === job.tenantId,
    );
    if (
      jobKey !== job.id ||
      !tenant ||
      !/^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$/.test(job.id) ||
      !boundedResource(job.resource) ||
      !nonEmpty(job.idempotencyKey) ||
      !validEpoch(job.createdAtEpochSeconds) ||
      !validEpoch(job.updatedAtEpochSeconds) ||
      !validEpoch(job.deadlineAtEpochSeconds) ||
      job.deadlineAtEpochSeconds <= job.createdAtEpochSeconds ||
      job.deadlineAtEpochSeconds - job.createdAtEpochSeconds >
        tenant.maxExecutionMinutes * 60 ||
      job.updatedAtEpochSeconds < job.createdAtEpochSeconds ||
      !Number.isInteger(job.attempt) ||
      job.attempt < 0 ||
      !Number.isInteger(job.maxAttempts) ||
      job.maxAttempts < 1 ||
      job.maxAttempts > 5 ||
      (job.operation === "build" &&
        !/^[a-f0-9]{40,64}$/.test(job.sourceRevision ?? "")) ||
      (job.operation !== "build" && !validDigest(job.artifactDigest)) ||
      (job.operation === "build" && job.workerRole !== "builder") ||
      (job.operation !== "build" && job.workerRole !== "deployer")
    ) {
      return `job '${job.id}' has invalid durable fields`;
    }
    const inQueue = queuedIds.includes(job.id);
    if ((job.status === "queued") !== inQueue) {
      return `job '${job.id}' queue membership does not match its status`;
    }
    const lock = state.resourceLocks[resourceKey(job.tenantId, job.resource)];
    const active = job.status === "running" || job.status === "cancelling";
    const terminal = new Set<PaasJobStatus>([
      "succeeded",
      "failed",
      "cancelled",
      "timed-out",
    ]).has(job.status);
    if (
      (active && !validEpoch(job.startedAtEpochSeconds)) ||
      (terminal && !validEpoch(job.completedAtEpochSeconds)) ||
      (job.startedAtEpochSeconds !== undefined &&
        job.startedAtEpochSeconds < job.createdAtEpochSeconds) ||
      (job.completedAtEpochSeconds !== undefined &&
        job.completedAtEpochSeconds < job.createdAtEpochSeconds)
    ) {
      return `job '${job.id}' lifecycle timestamps are incomplete`;
    }
    if (active && lock !== job.id) {
      return `active job '${job.id}' does not own its resource lock`;
    }
  }
  for (const [lock, jobId] of Object.entries(state.resourceLocks)) {
    const job = state.jobs[jobId];
    if (
      !job ||
      (job.status !== "running" && job.status !== "cancelling") ||
      resourceKey(job.tenantId, job.resource) !== lock
    ) {
      return `resource lock '${lock}' does not reference its active job`;
    }
  }
  if (activeJobs(state).length > intent.scheduling.maxGlobalConcurrency) {
    return "global concurrency exceeds the security intent";
  }
  for (const tenant of intent.tenants) {
    const active = activeJobs(state).filter(
      (job) => job.tenantId === tenant.tenantId,
    );
    if (
      active.filter((job) => job.operation === "build").length >
        tenant.maxConcurrentBuilds ||
      active.filter((job) => job.operation !== "build").length >
        tenant.maxConcurrentDeployments
    ) {
      return `tenant '${tenant.tenantId}' concurrency exceeds its quota`;
    }
  }
  for (const [key, record] of Object.entries(state.idempotency)) {
    const job = state.jobs[record.jobId];
    if (
      !job ||
      record.tenantId !== job.tenantId ||
      stateKey(record.tenantId, record.idempotencyKey) !== key
    ) {
      return `idempotency record references missing job '${record.jobId}'`;
    }
  }
  for (const [key, redemption] of Object.entries(state.redeemedCapabilities)) {
    const job = state.jobs[redemption.jobId];
    if (
      !job ||
      redemption.tenantId !== job.tenantId ||
      stateKey(redemption.capabilityId) !== key
    ) {
      return `capability redemption references missing job '${redemption.jobId}'`;
    }
  }
  for (const [key, deployment] of Object.entries(state.deployments)) {
    const sourceJob = state.jobs[deployment.sourceJobId];
    if (
      !tenantIds.includes(deployment.tenantId) ||
      !boundedResource(deployment.resource) ||
      resourceKey(deployment.tenantId, deployment.resource) !== key ||
      !validDigest(deployment.activeArtifactDigest) ||
      deployment.previousArtifactDigests.some(
        (artifact) => !validDigest(artifact),
      ) ||
      deployment.previousArtifactDigests.length > 20 ||
      deployment.previousArtifactDigests.includes(
        deployment.activeArtifactDigest,
      ) ||
      new Set(deployment.previousArtifactDigests).size !==
        deployment.previousArtifactDigests.length ||
      !Number.isInteger(deployment.generation) ||
      deployment.generation < 1 ||
      !sourceJob ||
      sourceJob.status !== "succeeded" ||
      sourceJob.tenantId !== deployment.tenantId ||
      sourceJob.resource !== deployment.resource ||
      sourceJob.artifactDigest !== deployment.activeArtifactDigest
    ) {
      return `deployment '${key}' has invalid durable fields`;
    }
  }
  return null;
}

type MutableState = {
  apiVersion: typeof PAAS_CONTROL_STATE_API_VERSION;
  revision: number;
  lastScheduledTenant: string | null;
  jobs: Record<string, PaasControlJob>;
  tenantQueues: Record<string, string[]>;
  idempotency: Record<string, PaasIdempotencyRecord>;
  redeemedCapabilities: Record<string, PaasCapabilityRedemption>;
  resourceLocks: Record<string, string>;
  deployments: Record<string, PaasDeploymentRecord>;
};

function mutableState(state: PaasControlState): MutableState {
  return structuredClone(state) as MutableState;
}

function finalize(state: MutableState, revision: number): PaasControlState {
  state.revision = revision;
  return state;
}

function accepted(
  state: PaasControlState,
  events: readonly PaasControlEvent[],
  jobId?: string,
): PaasControlTransition {
  return {
    accepted: true,
    code: "ACCEPTED",
    state,
    events,
    ...(jobId ? { jobId } : {}),
  };
}

function rejected(
  state: PaasControlState,
  code: Exclude<PaasControlTransitionCode, "ACCEPTED" | "DEDUPLICATED">,
): PaasControlTransition {
  return { accepted: false, code, state, events: [] };
}

function validEnqueueCommand(command: PaasEnqueueJobCommand) {
  if (
    !/^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$/.test(command.jobId) ||
    !nonEmpty(command.tenantId) ||
    !boundedResource(command.resource) ||
    !nonEmpty(command.idempotencyKey) ||
    !validEpoch(command.requestedAtEpochSeconds) ||
    !Number.isInteger(command.maxAttempts) ||
    command.maxAttempts < 1 ||
    command.maxAttempts > 5
  ) {
    return false;
  }
  if (command.operation === "build") {
    return /^[a-f0-9]{40,64}$/.test(command.sourceRevision ?? "");
  }
  return validDigest(command.artifactDigest);
}

function authorizationBinds(
  decision: PaasAuthorizationDecision,
  command: PaasEnqueueJobCommand | PaasCancelJobCommand,
  operation: PaasJobOperation | "cancel",
  job?: PaasControlJob,
) {
  const resource = "resource" in command ? command.resource : job?.resource;
  const sourceRevision =
    "sourceRevision" in command ? (command.sourceRevision ?? null) : null;
  const artifactDigest =
    "artifactDigest" in command ? (command.artifactDigest ?? null) : null;
  return (
    decision.allowed &&
    decision.evaluatedAtEpochSeconds === command.requestedAtEpochSeconds &&
    decision.audit["decision-epoch-seconds"] ===
      command.requestedAtEpochSeconds &&
    decision.audit["authorization-decision"] === "allow" &&
    decision.audit.tenant === command.tenantId &&
    decision.audit.operation === operation &&
    decision.audit.resource === resource &&
    decision.audit["idempotency-key"] === command.idempotencyKey &&
    decision.audit["source-revision"] === sourceRevision &&
    decision.audit["artifact-digest"] === artifactDigest &&
    (decision.capabilityToRedeem === null ||
      decision.audit["capability-id"] === decision.capabilityToRedeem)
  );
}

function enqueueFingerprint(command: PaasEnqueueJobCommand) {
  return digest({
    action: "enqueue",
    tenantId: command.tenantId,
    operation: command.operation,
    resource: command.resource,
    sourceRevision: command.sourceRevision ?? null,
    artifactDigest: command.artifactDigest ?? null,
  });
}

function cancelFingerprint(command: PaasCancelJobCommand, job: PaasControlJob) {
  return digest({
    action: "cancel",
    tenantId: command.tenantId,
    jobId: command.jobId,
    resource: job.resource,
  });
}

function knownRollbackTarget(
  state: PaasControlState,
  command: PaasEnqueueJobCommand,
) {
  const deployment =
    state.deployments[resourceKey(command.tenantId, command.resource)];
  return Boolean(
    deployment &&
    command.artifactDigest &&
    deployment.previousArtifactDigests.includes(command.artifactDigest),
  );
}

function nextEligibleTenant(
  state: MutableState,
  intent: PaasSecurityIntent,
  tenantIds: readonly string[],
): string | undefined {
  const start = state.lastScheduledTenant
    ? (tenantIds.indexOf(state.lastScheduledTenant) + 1) % tenantIds.length
    : 0;
  for (let offset = 0; offset < tenantIds.length; offset += 1) {
    const tenantId = tenantIds[(start + offset) % tenantIds.length];
    const jobId = state.tenantQueues[tenantId]?.[0];
    if (!jobId) continue;
    const job = state.jobs[jobId];
    const tenant = intent.tenants.find(
      (candidate) => candidate.tenantId === tenantId,
    )!;
    const active = activeJobs(state).filter(
      (candidate) => candidate.tenantId === tenantId,
    );
    const atQuota =
      job.operation === "build"
        ? active.filter((candidate) => candidate.operation === "build")
            .length >= tenant.maxConcurrentBuilds
        : active.filter((candidate) => candidate.operation !== "build")
            .length >= tenant.maxConcurrentDeployments;
    if (
      !atQuota &&
      !state.resourceLocks[resourceKey(job.tenantId, job.resource)]
    ) {
      return tenantId;
    }
  }
  return undefined;
}

function expireQueuedJobs(
  state: MutableState,
  now: number,
  revision: number,
  events: PaasControlEvent[],
) {
  for (const [tenantId, queue] of Object.entries(state.tenantQueues)) {
    const retained: string[] = [];
    for (const jobId of queue) {
      const job = state.jobs[jobId];
      if (job.deadlineAtEpochSeconds <= now) {
        job.status = "timed-out";
        job.cancellationReason = "deadline";
        job.updatedAtEpochSeconds = now;
        job.completedAtEpochSeconds = now;
        events.push(event("job-timed-out", revision, now, job));
      } else {
        retained.push(jobId);
      }
    }
    state.tenantQueues[tenantId] = retained;
  }
}

function promoteDeployment(
  state: MutableState,
  job: PaasControlJob,
  now: number,
) {
  const artifact = job.artifactDigest!;
  const key = resourceKey(job.tenantId, job.resource);
  const current = state.deployments[key];
  const history = current
    ? (current.activeArtifactDigest === artifact
        ? [...current.previousArtifactDigests]
        : [
            current.activeArtifactDigest,
            ...current.previousArtifactDigests.filter(
              (candidate) => candidate !== artifact,
            ),
          ]
      ).slice(0, 20)
    : [];
  state.deployments[key] = {
    tenantId: job.tenantId,
    resource: job.resource,
    activeArtifactDigest: artifact,
    previousArtifactDigests: history,
    generation: (current?.generation ?? 0) + 1,
    updatedAtEpochSeconds: now,
    sourceJobId: job.id,
  };
}

function activeJobs(state: Pick<PaasControlState, "jobs">) {
  return Object.values(state.jobs).filter(
    (job) => job.status === "running" || job.status === "cancelling",
  );
}

function event(
  type: PaasControlEventType,
  stateRevision: number,
  atEpochSeconds: number,
  job: PaasControlJob,
): PaasControlEvent {
  return {
    type,
    stateRevision,
    atEpochSeconds,
    tenantId: job.tenantId,
    jobId: job.id,
    resource: job.resource,
  };
}

function resourceKey(tenantId: string, resource: string) {
  return stateKey("resource", tenantId, resource);
}

function stateKey(...parts: string[]) {
  return digest(parts);
}

function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function validDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function boundedResource(value: unknown): value is string {
  return nonEmpty(value) && !value.includes("*");
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function validEpoch(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function stateObject(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(input).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new Error(`${path} has unknown field '${unknown.sort()[0]}'.`);
  }
  const missing = required.filter((key) => !(key in input));
  if (missing.length > 0) {
    throw new Error(`${path} is missing required field '${missing[0]}'.`);
  }
  return input;
}

function stateRecord<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
): Readonly<Record<string, T>> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      parse(entry, `${path}.${key}`),
    ]),
  );
}

function stateString(value: unknown, path: string): string {
  if (!nonEmpty(value)) throw new Error(`${path} must be a non-empty string.`);
  return value;
}

function statePattern(value: unknown, path: string, pattern: RegExp): string {
  const parsed = stateString(value, path);
  if (!pattern.test(parsed)) throw new Error(`${path} has an invalid format.`);
  return parsed;
}

function stateName(value: unknown, path: string): string {
  return statePattern(value, path, /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/);
}

function stateJobId(value: unknown, path: string): string {
  return statePattern(value, path, /^[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?$/);
}

function stateResource(value: unknown, path: string): string {
  const parsed = stateString(value, path);
  if (parsed.includes("*")) {
    throw new Error(`${path} must be an exact resource without wildcards.`);
  }
  return parsed;
}

function stateInteger(value: unknown, path: string, minimum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new Error(
      `${path} must be an integer greater than or equal to ${minimum}.`,
    );
  }
  return value as number;
}

function stateEnum<const T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function stateStringArray(
  value: unknown,
  path: string,
  allowEmpty: boolean,
  pattern?: RegExp,
): readonly string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(`${path} must be an array.`);
  }
  const parsed = value.map((entry, index) =>
    pattern
      ? statePattern(entry, `${path}[${index}]`, pattern)
      : stateString(entry, `${path}[${index}]`),
  );
  if (new Set(parsed).size !== parsed.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return parsed;
}

type OptionalStringJobField =
  | "sourceRevision"
  | "artifactDigest"
  | "capabilityId"
  | "lastErrorCode"
  | "cleanupEvidence"
  | "resultArtifactDigest";

function assignOptionalString(
  job: PaasControlJob,
  input: Record<string, unknown>,
  field: OptionalStringJobField,
  path: string,
  pattern?: RegExp,
) {
  if (!(field in input)) return;
  job[field] = pattern
    ? statePattern(input[field], `${path}.${field}`, pattern)
    : stateString(input[field], `${path}.${field}`);
}

type OptionalIntegerJobField =
  | "startedAtEpochSeconds"
  | "completedAtEpochSeconds";

function assignOptionalInteger(
  job: PaasControlJob,
  input: Record<string, unknown>,
  field: OptionalIntegerJobField,
  path: string,
) {
  if (!(field in input)) return;
  job[field] = stateInteger(input[field], `${path}.${field}`, 0);
}
