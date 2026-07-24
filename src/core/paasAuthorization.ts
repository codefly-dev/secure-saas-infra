import type {
  PaasExecutionTarget,
  PaasOperation,
  PaasSecurityIntent,
} from "./paas";

export const PAAS_AUTHORIZATION_REQUEST_API_VERSION =
  "security.deus.dev/paas-authorization-request/v1alpha1" as const;

export type PaasAuthenticationMethod = "oidc" | "mtls";

export interface PaasRequestActor {
  id: string;
  tenantId: string;
  authenticationMethods: readonly PaasAuthenticationMethod[];
}

export interface PaasCapability {
  id: string;
  issuer: string;
  subject: string;
  tenantId: string;
  audience: string;
  operations: readonly PaasOperation[];
  resources: readonly string[];
  issuedAtEpochSeconds: number;
  notBeforeEpochSeconds: number;
  expiresAtEpochSeconds: number;
  cryptographicallyVerified: boolean;
  oneUse: boolean;
}

export interface PaasRbacGrant {
  id: string;
  subject: string;
  tenantId: string;
  endpointId: string;
  operations: readonly PaasOperation[];
  resources: readonly string[];
  expiresAtEpochSeconds?: number;
}

export interface PaasAuthorizationRequest {
  apiVersion: typeof PAAS_AUTHORIZATION_REQUEST_API_VERSION;
  requestId: string;
  endpointId: string;
  actor: PaasRequestActor;
  tenantId: string;
  operation: PaasOperation;
  resource: string;
  executionTarget: PaasExecutionTarget;
  idempotencyKey?: string;
  sourceRevision?: string;
  artifactDigest?: string;
  capability?: PaasCapability;
}

export interface PaasAuthorizationState {
  nowEpochSeconds: number;
  redeemedCapabilityIds: ReadonlySet<string>;
  rbacGrants?: readonly PaasRbacGrant[];
}

export type PaasAuthorizationReasonCode =
  | "PAAS_AUTH_REQUEST_INVALID"
  | "PAAS_AUTH_ENDPOINT_UNKNOWN"
  | "PAAS_AUTH_OPERATION_UNDECLARED"
  | "PAAS_AUTH_TENANT_UNKNOWN"
  | "PAAS_AUTH_TENANT_MISMATCH"
  | "PAAS_AUTHENTICATION_INSUFFICIENT"
  | "PAAS_AUTH_EXECUTION_TARGET_INVALID"
  | "PAAS_AUTH_HOST_EXECUTION_DENIED"
  | "PAAS_AUTH_IDEMPOTENCY_KEY_MISSING"
  | "PAAS_AUTH_SOURCE_REVISION_MISSING"
  | "PAAS_AUTH_ARTIFACT_DIGEST_MISSING"
  | "PAAS_AUTH_CAPABILITY_MISSING"
  | "PAAS_AUTH_CAPABILITY_INVALID"
  | "PAAS_AUTH_CAPABILITY_UNVERIFIED"
  | "PAAS_AUTH_CAPABILITY_ISSUER_UNTRUSTED"
  | "PAAS_AUTH_CAPABILITY_SUBJECT_MISMATCH"
  | "PAAS_AUTH_CAPABILITY_TENANT_MISMATCH"
  | "PAAS_AUTH_CAPABILITY_AUDIENCE_MISMATCH"
  | "PAAS_AUTH_CAPABILITY_OPERATION_DENIED"
  | "PAAS_AUTH_CAPABILITY_RESOURCE_DENIED"
  | "PAAS_AUTH_CAPABILITY_TIME_INVALID"
  | "PAAS_AUTH_CAPABILITY_TTL_EXCEEDED"
  | "PAAS_AUTH_CAPABILITY_REPLAYED"
  | "PAAS_AUTH_CAPABILITY_NOT_ONE_USE"
  | "PAAS_AUTH_RBAC_GRANT_MISSING"
  | "PAAS_AUTHORIZATION_MODE_UNSAFE";

export interface PaasAuthorizationAuditRecord {
  actor: string;
  tenant: string;
  "request-id": string;
  operation: PaasOperation;
  endpoint: string;
  resource: string;
  "execution-target": PaasExecutionTarget;
  "source-revision": string | null;
  "artifact-digest": string | null;
  "authorization-decision": "allow" | "deny";
  "decision-epoch-seconds": number;
  "reason-codes": readonly PaasAuthorizationReasonCode[];
  "capability-id": string | null;
  "idempotency-key": string | null;
}

export interface PaasAuthorizationDecision {
  allowed: boolean;
  evaluatedAtEpochSeconds: number;
  reasonCodes: readonly PaasAuthorizationReasonCode[];
  capabilityToRedeem: string | null;
  audit: PaasAuthorizationAuditRecord;
}

const authorizationOperations: readonly PaasOperation[] = [
  "build",
  "deploy",
  "cancel",
  "rollback",
  "read-state",
  "read-file",
  "write-file",
  "exec-command",
  "open-terminal",
  "push-artifact",
  "pull-artifact",
  "invoke-agent",
];

const readOnlyOperations = new Set<PaasOperation>([
  "read-state",
  "read-file",
  "pull-artifact",
]);
const sourceRevisionOperations = new Set<PaasOperation>(["build"]);
const artifactDigestOperations = new Set<PaasOperation>([
  "deploy",
  "rollback",
  "push-artifact",
  "pull-artifact",
]);

export function parsePaasAuthorizationRequest(
  value: unknown,
): PaasAuthorizationRequest {
  const root = authorizationObject(
    value,
    "paasAuthorizationRequest",
    [
      "apiVersion",
      "requestId",
      "endpointId",
      "actor",
      "tenantId",
      "operation",
      "resource",
      "executionTarget",
    ],
    ["idempotencyKey", "sourceRevision", "artifactDigest", "capability"],
  );
  const apiVersion = authorizationString(root.apiVersion, "apiVersion");
  if (apiVersion !== PAAS_AUTHORIZATION_REQUEST_API_VERSION) {
    throw new Error(
      `paasAuthorizationRequest.apiVersion must be '${PAAS_AUTHORIZATION_REQUEST_API_VERSION}'.`,
    );
  }
  const request: PaasAuthorizationRequest = {
    apiVersion,
    requestId: authorizationString(root.requestId, "requestId"),
    endpointId: authorizationName(root.endpointId, "endpointId"),
    actor: parseActor(root.actor),
    tenantId: authorizationName(root.tenantId, "tenantId"),
    operation: authorizationEnum(
      root.operation,
      "operation",
      authorizationOperations,
    ),
    resource: authorizationResource(root.resource, "resource"),
    executionTarget: authorizationEnum(
      root.executionTarget,
      "executionTarget",
      ["control-plane", "tenant-sandbox", "host"],
    ),
  };
  if ("idempotencyKey" in root) {
    request.idempotencyKey = authorizationString(
      root.idempotencyKey,
      "idempotencyKey",
    );
  }
  if ("sourceRevision" in root) {
    request.sourceRevision = authorizationPattern(
      root.sourceRevision,
      "sourceRevision",
      /^[a-f0-9]{40,64}$/,
    );
  }
  if ("artifactDigest" in root) {
    request.artifactDigest = authorizationPattern(
      root.artifactDigest,
      "artifactDigest",
      /^sha256:[a-f0-9]{64}$/,
    );
  }
  if ("capability" in root) {
    request.capability = parseCapability(root.capability);
  }
  return request;
}

function parseActor(value: unknown): PaasRequestActor {
  const input = authorizationObject(
    value,
    "actor",
    ["id", "tenantId", "authenticationMethods"],
    [],
  );
  return {
    id: authorizationString(input.id, "actor.id"),
    tenantId: authorizationName(input.tenantId, "actor.tenantId"),
    authenticationMethods: authorizationArray(
      input.authenticationMethods,
      "actor.authenticationMethods",
      (entry, index) =>
        authorizationEnum(entry, `actor.authenticationMethods[${index}]`, [
          "oidc",
          "mtls",
        ]),
    ),
  };
}

function parseCapability(value: unknown): PaasCapability {
  const path = "capability";
  const input = authorizationObject(
    value,
    path,
    [
      "id",
      "issuer",
      "subject",
      "tenantId",
      "audience",
      "operations",
      "resources",
      "issuedAtEpochSeconds",
      "notBeforeEpochSeconds",
      "expiresAtEpochSeconds",
      "cryptographicallyVerified",
      "oneUse",
    ],
    [],
  );
  return {
    id: authorizationString(input.id, `${path}.id`),
    issuer: authorizationName(input.issuer, `${path}.issuer`),
    subject: authorizationString(input.subject, `${path}.subject`),
    tenantId: authorizationName(input.tenantId, `${path}.tenantId`),
    audience: authorizationName(input.audience, `${path}.audience`),
    operations: authorizationArray(
      input.operations,
      `${path}.operations`,
      (entry, index) =>
        authorizationEnum(
          entry,
          `${path}.operations[${index}]`,
          authorizationOperations,
        ),
    ),
    resources: authorizationArray(
      input.resources,
      `${path}.resources`,
      (entry, index) =>
        authorizationResource(entry, `${path}.resources[${index}]`),
    ),
    issuedAtEpochSeconds: authorizationEpoch(
      input.issuedAtEpochSeconds,
      `${path}.issuedAtEpochSeconds`,
    ),
    notBeforeEpochSeconds: authorizationEpoch(
      input.notBeforeEpochSeconds,
      `${path}.notBeforeEpochSeconds`,
    ),
    expiresAtEpochSeconds: authorizationEpoch(
      input.expiresAtEpochSeconds,
      `${path}.expiresAtEpochSeconds`,
    ),
    cryptographicallyVerified: authorizationBoolean(
      input.cryptographicallyVerified,
      `${path}.cryptographicallyVerified`,
    ),
    oneUse: authorizationBoolean(input.oneUse, `${path}.oneUse`),
  };
}

export function authorizePaasRequest(
  intent: PaasSecurityIntent,
  request: PaasAuthorizationRequest,
  state: PaasAuthorizationState,
): PaasAuthorizationDecision {
  const reasons: PaasAuthorizationReasonCode[] = [];
  const deny = (code: PaasAuthorizationReasonCode) => {
    if (!reasons.includes(code)) reasons.push(code);
  };
  const endpoint = intent.endpoints.find(
    (candidate) => candidate.id === request.endpointId,
  );
  const mutating = !readOnlyOperations.has(request.operation);

  if (
    !nonEmpty(request.requestId) ||
    request.apiVersion !== PAAS_AUTHORIZATION_REQUEST_API_VERSION ||
    !nonEmpty(request.actor?.id) ||
    !nonEmpty(request.actor?.tenantId) ||
    !Array.isArray(request.actor?.authenticationMethods) ||
    request.actor.authenticationMethods.some(
      (method) => method !== "oidc" && method !== "mtls",
    ) ||
    !nonEmpty(request.tenantId) ||
    !boundedResource(request.resource) ||
    !Number.isInteger(state.nowEpochSeconds) ||
    state.nowEpochSeconds < 0
  ) {
    deny("PAAS_AUTH_REQUEST_INVALID");
  }
  if (!endpoint) {
    deny("PAAS_AUTH_ENDPOINT_UNKNOWN");
  } else {
    if (!endpoint.operations.includes(request.operation)) {
      deny("PAAS_AUTH_OPERATION_UNDECLARED");
    }
    if (!authenticationSatisfies(endpoint.authentication, request.actor)) {
      deny("PAAS_AUTHENTICATION_INSUFFICIENT");
    }
    if (request.executionTarget === "host") {
      deny("PAAS_AUTH_HOST_EXECUTION_DENIED");
    }
    if (request.executionTarget !== endpoint.executionTarget) {
      deny("PAAS_AUTH_EXECUTION_TARGET_INVALID");
    }
  }
  if (!intent.tenants.some((tenant) => tenant.tenantId === request.tenantId)) {
    deny("PAAS_AUTH_TENANT_UNKNOWN");
  }
  if (
    request.actor?.tenantId !== request.tenantId ||
    (endpoint?.tenantBindingRequired && !request.tenantId)
  ) {
    deny("PAAS_AUTH_TENANT_MISMATCH");
  }
  if (
    mutating &&
    intent.accessControl.idempotencyKeys &&
    !nonEmpty(request.idempotencyKey)
  ) {
    deny("PAAS_AUTH_IDEMPOTENCY_KEY_MISSING");
  }
  if (
    sourceRevisionOperations.has(request.operation) &&
    !/^[a-f0-9]{40,64}$/.test(request.sourceRevision ?? "")
  ) {
    deny("PAAS_AUTH_SOURCE_REVISION_MISSING");
  }
  if (
    artifactDigestOperations.has(request.operation) &&
    !/^sha256:[a-f0-9]{64}$/.test(request.artifactDigest ?? "")
  ) {
    deny("PAAS_AUTH_ARTIFACT_DIGEST_MISSING");
  }

  if (endpoint?.authorization === "capability") {
    evaluateCapability(intent, request, state, mutating, deny);
  } else if (endpoint?.authorization === "rbac") {
    if (!hasRbacGrant(request, state)) {
      deny("PAAS_AUTH_RBAC_GRANT_MISSING");
    }
  } else if (endpoint) {
    deny("PAAS_AUTHORIZATION_MODE_UNSAFE");
  }

  const allowed = reasons.length === 0;
  const capabilityToRedeem =
    allowed && request.capability?.oneUse ? request.capability.id : null;
  return {
    allowed,
    evaluatedAtEpochSeconds: state.nowEpochSeconds,
    reasonCodes: reasons,
    capabilityToRedeem,
    audit: {
      actor: request.actor?.id ?? "",
      tenant: request.tenantId ?? "",
      "request-id": request.requestId ?? "",
      operation: request.operation,
      endpoint: request.endpointId ?? "",
      resource: request.resource ?? "",
      "execution-target": request.executionTarget,
      "source-revision": request.sourceRevision ?? null,
      "artifact-digest": request.artifactDigest ?? null,
      "authorization-decision": allowed ? "allow" : "deny",
      "decision-epoch-seconds": state.nowEpochSeconds,
      "reason-codes": reasons,
      "capability-id": request.capability?.id ?? null,
      "idempotency-key": request.idempotencyKey ?? null,
    },
  };
}

function evaluateCapability(
  intent: PaasSecurityIntent,
  request: PaasAuthorizationRequest,
  state: PaasAuthorizationState,
  mutating: boolean,
  deny: (code: PaasAuthorizationReasonCode) => void,
) {
  const capability = request.capability;
  if (!capability) {
    deny("PAAS_AUTH_CAPABILITY_MISSING");
    return;
  }
  const operations = Array.isArray(capability.operations)
    ? capability.operations
    : [];
  const resources = Array.isArray(capability.resources)
    ? capability.resources
    : [];
  if (
    !nonEmpty(capability.id) ||
    !nonEmpty(capability.issuer) ||
    !nonEmpty(capability.subject) ||
    !nonEmpty(capability.tenantId) ||
    !nonEmpty(capability.audience) ||
    operations.length === 0 ||
    resources.length === 0 ||
    typeof capability.cryptographicallyVerified !== "boolean" ||
    typeof capability.oneUse !== "boolean"
  ) {
    deny("PAAS_AUTH_CAPABILITY_INVALID");
  }
  if (!capability.cryptographicallyVerified) {
    deny("PAAS_AUTH_CAPABILITY_UNVERIFIED");
  }
  if (
    !intent.accessControl.trustedCapabilityIssuers.includes(capability.issuer)
  ) {
    deny("PAAS_AUTH_CAPABILITY_ISSUER_UNTRUSTED");
  }
  if (capability.subject !== request.actor.id) {
    deny("PAAS_AUTH_CAPABILITY_SUBJECT_MISMATCH");
  }
  if (capability.tenantId !== request.tenantId) {
    deny("PAAS_AUTH_CAPABILITY_TENANT_MISMATCH");
  }
  if (capability.audience !== request.endpointId) {
    deny("PAAS_AUTH_CAPABILITY_AUDIENCE_MISMATCH");
  }
  if (!operations.includes(request.operation)) {
    deny("PAAS_AUTH_CAPABILITY_OPERATION_DENIED");
  }
  if (
    !resources.includes(request.resource) ||
    resources.some((resource) => !boundedResource(resource))
  ) {
    deny("PAAS_AUTH_CAPABILITY_RESOURCE_DENIED");
  }
  if (
    !Number.isInteger(capability.issuedAtEpochSeconds) ||
    !Number.isInteger(capability.notBeforeEpochSeconds) ||
    !Number.isInteger(capability.expiresAtEpochSeconds) ||
    capability.issuedAtEpochSeconds < 0 ||
    capability.notBeforeEpochSeconds < capability.issuedAtEpochSeconds ||
    capability.expiresAtEpochSeconds <= capability.notBeforeEpochSeconds ||
    state.nowEpochSeconds < capability.notBeforeEpochSeconds ||
    state.nowEpochSeconds >= capability.expiresAtEpochSeconds
  ) {
    deny("PAAS_AUTH_CAPABILITY_TIME_INVALID");
  }
  if (
    capability.expiresAtEpochSeconds - capability.issuedAtEpochSeconds >
    intent.accessControl.maxCapabilityTtlSeconds
  ) {
    deny("PAAS_AUTH_CAPABILITY_TTL_EXCEEDED");
  }
  if (state.redeemedCapabilityIds.has(capability.id)) {
    deny("PAAS_AUTH_CAPABILITY_REPLAYED");
  }
  if (mutating && intent.accessControl.oneUseMutations && !capability.oneUse) {
    deny("PAAS_AUTH_CAPABILITY_NOT_ONE_USE");
  }
}

function hasRbacGrant(
  request: PaasAuthorizationRequest,
  state: PaasAuthorizationState,
) {
  return (state.rbacGrants ?? []).some(
    (grant) =>
      nonEmpty(grant.id) &&
      grant.subject === request.actor.id &&
      grant.tenantId === request.tenantId &&
      grant.endpointId === request.endpointId &&
      Array.isArray(grant.operations) &&
      grant.operations.includes(request.operation) &&
      Array.isArray(grant.resources) &&
      grant.resources.includes(request.resource) &&
      grant.resources.every(boundedResource) &&
      (grant.expiresAtEpochSeconds === undefined ||
        (Number.isInteger(grant.expiresAtEpochSeconds) &&
          state.nowEpochSeconds < grant.expiresAtEpochSeconds)),
  );
}

function authenticationSatisfies(
  required: PaasSecurityIntent["endpoints"][number]["authentication"],
  actor: PaasRequestActor | undefined,
) {
  const methods = new Set(actor?.authenticationMethods ?? []);
  if (required === "oidc") return methods.has("oidc");
  if (required === "mtls") return methods.has("mtls");
  if (required === "oidc+mtls") {
    return methods.has("oidc") && methods.has("mtls");
  }
  return false;
}

function boundedResource(value: unknown): value is string {
  return nonEmpty(value) && !value.includes("*");
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function authorizationObject(
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

function authorizationString(value: unknown, path: string): string {
  if (!nonEmpty(value)) throw new Error(`${path} must be a non-empty string.`);
  return value;
}

function authorizationName(value: unknown, path: string): string {
  const name = authorizationString(value, path);
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(name)) {
    throw new Error(`${path} must be a lowercase DNS-style name.`);
  }
  return name;
}

function authorizationResource(value: unknown, path: string): string {
  const resource = authorizationString(value, path);
  if (resource.includes("*")) {
    throw new Error(`${path} must be an exact resource without wildcards.`);
  }
  return resource;
}

function authorizationPattern(
  value: unknown,
  path: string,
  pattern: RegExp,
): string {
  const parsed = authorizationString(value, path);
  if (!pattern.test(parsed)) throw new Error(`${path} has an invalid format.`);
  return parsed;
}

function authorizationEpoch(value: unknown, path: string): number {
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new Error(`${path} must be a non-negative integer.`);
  }
  return value as number;
}

function authorizationBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be boolean.`);
  return value;
}

function authorizationEnum<const T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function authorizationArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, index: number) => T,
): readonly T[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array.`);
  }
  const parsed = value.map(parse);
  if (new Set(parsed).size !== parsed.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return parsed;
}
