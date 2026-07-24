import { createHash } from "node:crypto";

export const INFRASTRUCTURE_CONTROLLER_API_VERSION =
  "security.deus.dev/infrastructure-controller/v1alpha1" as const;
export const INFRASTRUCTURE_STACK_OWNERSHIP_API_VERSION =
  "security.deus.dev/infrastructure-stack-ownership/v1alpha1" as const;

// InfrastructureControllerRequest is the normalized, internal authorization
// input assembled by a trusted infrastructure API host. A public RPC must carry the
// signed capability token and ordinary user intent; it must not let a plugin
// supply its own manifest, role grant, or cryptographic-verification result.
// The host loads the installed manifest and durable grant, verifies the token,
// then constructs this envelope for deterministic policy evaluation/audit.

export type InfrastructureOperation =
  | "plan"
  | "reconcile"
  | "observe"
  | "cancel"
  | "delete";

export type InfrastructureAction =
  | "infra.claim.plan"
  | "infra.claim.reconcile"
  | "infra.claim.observe"
  | "infra.claim.cancel"
  | "infra.claim.delete";

export type InfrastructureEnvironmentClass =
  | "nonproduction"
  | "preproduction"
  | "production";

export interface InfrastructureActor {
  principalId: string;
  organizationId: string;
  tenantId: string;
  authenticationMethods: readonly ("oidc" | "mtls")[];
}

export interface InfrastructureClaimTarget {
  claimId: string;
  tenantId: string;
  contextId: string;
  generation: number;
  desiredStateDigest: string;
}

export interface InfrastructurePluginPermission {
  action: InfrastructureAction;
  resourcePrefix: string;
}

export interface InfrastructureRequestPlugin {
  pluginId: string;
  kind: "infrastructure-request";
  sandbox: {
    network: "broker-only";
    providerCredentials: false;
    pulumiBackendAccess: false;
    kubernetesAdminAccess: false;
    hostAccess: false;
    unixSockets: false;
  };
  permissions: readonly InfrastructurePluginPermission[];
}

export interface InfrastructureRoleGrant {
  grantId: string;
  subjectId: string;
  organizationId: string;
  tenantId: string;
  actions: readonly InfrastructureAction[];
  resourcePrefixes: readonly string[];
  expiresAtEpochSeconds: number;
}

export interface InfrastructureCapability {
  capabilityId: string;
  format: "v2-ed25519";
  issuer: string;
  subjectId: string;
  audience: string;
  organizationId: string;
  tenantId: string;
  action: InfrastructureAction;
  resource: string;
  claimGeneration: number;
  desiredStateDigest: string;
  planDigest: string | null;
  issuedAtEpochSeconds: number;
  notBeforeEpochSeconds: number;
  expiresAtEpochSeconds: number;
  oneUse: boolean;
  cryptographicallyVerified: boolean;
}

export interface InfrastructurePlanBinding {
  planDigest: string;
  desiredStateDigest: string;
  controllerVersion: string;
  providerId: string;
  providerVersion: string;
  createdAtEpochSeconds: number;
  expiresAtEpochSeconds: number;
  policyChecksPassed: boolean;
  destructive: boolean;
}

export interface InfrastructureApproval {
  approvalId: string;
  approverPrincipalId: string;
  planDigest: string;
  approvedAtEpochSeconds: number;
}

export interface InfrastructureControllerRequest {
  apiVersion: typeof INFRASTRUCTURE_CONTROLLER_API_VERSION;
  kind: "InfrastructureControllerRequest";
  requestId: string;
  operation: InfrastructureOperation;
  environmentClass: InfrastructureEnvironmentClass;
  actor: InfrastructureActor;
  claim: InfrastructureClaimTarget;
  plugin: InfrastructureRequestPlugin;
  grant: InfrastructureRoleGrant;
  capability: InfrastructureCapability;
  plan: InfrastructurePlanBinding | null;
  approvals: readonly InfrastructureApproval[];
  idempotencyKey: string | null;
  deadlineEpochSeconds: number;
}

export interface InfrastructureAuthorizationState {
  nowEpochSeconds: number;
  expectedAudience: string;
  trustedCapabilityIssuers: readonly string[];
  redeemedCapabilityIds: ReadonlySet<string>;
  maxCapabilityTtlSeconds: number;
}

export type InfrastructureAuthorizationReasonCode =
  | "INFRA_REQUEST_INVALID"
  | "INFRA_AUTHENTICATION_INSUFFICIENT"
  | "INFRA_ORGANIZATION_MISMATCH"
  | "INFRA_TENANT_MISMATCH"
  | "INFRA_PLUGIN_MANIFEST_DENIED"
  | "INFRA_ROLE_GRANT_DENIED"
  | "INFRA_ROLE_GRANT_EXPIRED"
  | "INFRA_CAPABILITY_UNVERIFIED"
  | "INFRA_CAPABILITY_ISSUER_UNTRUSTED"
  | "INFRA_CAPABILITY_AUDIENCE_MISMATCH"
  | "INFRA_CAPABILITY_BINDING_MISMATCH"
  | "INFRA_CAPABILITY_TIME_INVALID"
  | "INFRA_CAPABILITY_TTL_EXCEEDED"
  | "INFRA_CAPABILITY_NOT_ONE_USE"
  | "INFRA_CAPABILITY_REPLAYED"
  | "INFRA_IDEMPOTENCY_KEY_MISSING"
  | "INFRA_DEADLINE_INVALID"
  | "INFRA_PLAN_REQUIRED"
  | "INFRA_PLAN_UNEXPECTED"
  | "INFRA_PLAN_INVALID"
  | "INFRA_PLAN_DIGEST_MISMATCH"
  | "INFRA_POLICY_CHECKS_FAILED"
  | "INFRA_APPROVAL_INSUFFICIENT";

export interface InfrastructureAuthorizationAuditRecord {
  requestId: string;
  operation: InfrastructureOperation | "invalid";
  actor: string | null;
  organization: string | null;
  tenant: string | null;
  context: string | null;
  claim: string | null;
  generation: number | null;
  desiredStateDigest: string | null;
  planDigest: string | null;
  capabilityId: string | null;
  grantId: string | null;
  decision: "allow" | "deny";
  evaluatedAtEpochSeconds: number;
  reasonCodes: readonly InfrastructureAuthorizationReasonCode[];
}

export interface InfrastructureAuthorizationDecision {
  allowed: boolean;
  reasonCodes: readonly InfrastructureAuthorizationReasonCode[];
  capabilityToRedeem: string | null;
  audit: InfrastructureAuthorizationAuditRecord;
}

export interface InfrastructureStackOwnershipMetadata {
  apiVersion: typeof INFRASTRUCTURE_STACK_OWNERSHIP_API_VERSION;
  kind: "InfrastructureStackOwnership";
  stackId: string;
  controllerOfRecord: "infrastructure-controller";
  providerId: string;
  organizationId: string;
  tenantId: string;
  environmentClass: InfrastructureEnvironmentClass;
  contextId: string;
  claimId: string;
  generation: number;
  desiredStateDigest: string;
  controllerVersion: string;
  createdAt: string;
  expiresAt: string | null;
  deletionProtection: true;
  ownershipDigest: string;
}

const operationActions: Readonly<
  Record<InfrastructureOperation, InfrastructureAction>
> = {
  plan: "infra.claim.plan",
  reconcile: "infra.claim.reconcile",
  observe: "infra.claim.observe",
  cancel: "infra.claim.cancel",
  delete: "infra.claim.delete",
};

const mutationOperations = new Set<InfrastructureOperation>([
  "reconcile",
  "cancel",
  "delete",
]);

export function infrastructureAction(
  operation: InfrastructureOperation,
): InfrastructureAction {
  return operationActions[operation];
}

export function infrastructureResource(
  organizationId: string,
  tenantId: string,
  contextId: string,
  claimId: string,
): string {
  for (const [name, value] of [
    ["organizationId", organizationId],
    ["tenantId", tenantId],
    ["contextId", contextId],
    ["claimId", claimId],
  ] as const) {
    assertIdentifier(value, name);
  }
  return `organization/${organizationId}/tenant/${tenantId}/context/${contextId}/claim/${claimId}`;
}

export function infrastructureClaimResourcePrefix(
  organizationId: string,
  tenantId: string,
  contextId: string,
): string {
  for (const [name, value] of [
    ["organizationId", organizationId],
    ["tenantId", tenantId],
    ["contextId", contextId],
  ] as const) {
    assertIdentifier(value, name);
  }
  return `organization/${organizationId}/tenant/${tenantId}/context/${contextId}/claim/`;
}

export function parseInfrastructureControllerRequest(
  value: unknown,
): InfrastructureControllerRequest {
  const root = exactObject(value, "request", [
    "apiVersion",
    "kind",
    "requestId",
    "operation",
    "environmentClass",
    "actor",
    "claim",
    "plugin",
    "grant",
    "capability",
    "plan",
    "approvals",
    "idempotencyKey",
    "deadlineEpochSeconds",
  ]);
  const actor = exactObject(root.actor, "request.actor", [
    "principalId",
    "organizationId",
    "tenantId",
    "authenticationMethods",
  ]);
  const claim = exactObject(root.claim, "request.claim", [
    "claimId",
    "tenantId",
    "contextId",
    "generation",
    "desiredStateDigest",
  ]);
  const plugin = exactObject(root.plugin, "request.plugin", [
    "pluginId",
    "kind",
    "sandbox",
    "permissions",
  ]);
  const sandbox = exactObject(plugin.sandbox, "request.plugin.sandbox", [
    "network",
    "providerCredentials",
    "pulumiBackendAccess",
    "kubernetesAdminAccess",
    "hostAccess",
    "unixSockets",
  ]);
  const grant = exactObject(root.grant, "request.grant", [
    "grantId",
    "subjectId",
    "organizationId",
    "tenantId",
    "actions",
    "resourcePrefixes",
    "expiresAtEpochSeconds",
  ]);
  const capability = exactObject(root.capability, "request.capability", [
    "capabilityId",
    "format",
    "issuer",
    "subjectId",
    "audience",
    "organizationId",
    "tenantId",
    "action",
    "resource",
    "claimGeneration",
    "desiredStateDigest",
    "planDigest",
    "issuedAtEpochSeconds",
    "notBeforeEpochSeconds",
    "expiresAtEpochSeconds",
    "oneUse",
    "cryptographicallyVerified",
  ]);

  const parsed: InfrastructureControllerRequest = {
    apiVersion: literal(
      root.apiVersion,
      "request.apiVersion",
      INFRASTRUCTURE_CONTROLLER_API_VERSION,
    ),
    kind: literal(root.kind, "request.kind", "InfrastructureControllerRequest"),
    requestId: identifier(root.requestId, "request.requestId"),
    operation: enumeration(root.operation, "request.operation", [
      "plan",
      "reconcile",
      "observe",
      "cancel",
      "delete",
    ]),
    environmentClass: enumeration(
      root.environmentClass,
      "request.environmentClass",
      ["nonproduction", "preproduction", "production"],
    ),
    actor: {
      principalId: identifier(actor.principalId, "request.actor.principalId"),
      organizationId: identifier(
        actor.organizationId,
        "request.actor.organizationId",
      ),
      tenantId: identifier(actor.tenantId, "request.actor.tenantId"),
      authenticationMethods: nonEmptyUniqueArray(
        actor.authenticationMethods,
        "request.actor.authenticationMethods",
        (entry, path) => enumeration(entry, path, ["oidc", "mtls"]),
      ),
    },
    claim: {
      claimId: identifier(claim.claimId, "request.claim.claimId"),
      tenantId: identifier(claim.tenantId, "request.claim.tenantId"),
      contextId: identifier(claim.contextId, "request.claim.contextId"),
      generation: positiveInteger(claim.generation, "request.claim.generation"),
      desiredStateDigest: sha256(
        claim.desiredStateDigest,
        "request.claim.desiredStateDigest",
      ),
    },
    plugin: {
      pluginId: identifier(plugin.pluginId, "request.plugin.pluginId"),
      kind: literal(
        plugin.kind,
        "request.plugin.kind",
        "infrastructure-request",
      ),
      sandbox: {
        network: literal(
          sandbox.network,
          "request.plugin.sandbox.network",
          "broker-only",
        ),
        providerCredentials: literal(
          sandbox.providerCredentials,
          "request.plugin.sandbox.providerCredentials",
          false,
        ),
        pulumiBackendAccess: literal(
          sandbox.pulumiBackendAccess,
          "request.plugin.sandbox.pulumiBackendAccess",
          false,
        ),
        kubernetesAdminAccess: literal(
          sandbox.kubernetesAdminAccess,
          "request.plugin.sandbox.kubernetesAdminAccess",
          false,
        ),
        hostAccess: literal(
          sandbox.hostAccess,
          "request.plugin.sandbox.hostAccess",
          false,
        ),
        unixSockets: literal(
          sandbox.unixSockets,
          "request.plugin.sandbox.unixSockets",
          false,
        ),
      },
      permissions: nonEmptyUniqueArray(
        plugin.permissions,
        "request.plugin.permissions",
        parsePluginPermission,
        (entry) => `${entry.action}|${entry.resourcePrefix}`,
      ),
    },
    grant: {
      grantId: identifier(grant.grantId, "request.grant.grantId"),
      subjectId: identifier(grant.subjectId, "request.grant.subjectId"),
      organizationId: identifier(
        grant.organizationId,
        "request.grant.organizationId",
      ),
      tenantId: identifier(grant.tenantId, "request.grant.tenantId"),
      actions: nonEmptyUniqueArray(
        grant.actions,
        "request.grant.actions",
        parseAction,
      ),
      resourcePrefixes: nonEmptyUniqueArray(
        grant.resourcePrefixes,
        "request.grant.resourcePrefixes",
        resourcePrefix,
      ),
      expiresAtEpochSeconds: positiveInteger(
        grant.expiresAtEpochSeconds,
        "request.grant.expiresAtEpochSeconds",
      ),
    },
    capability: {
      capabilityId: identifier(
        capability.capabilityId,
        "request.capability.capabilityId",
      ),
      format: literal(
        capability.format,
        "request.capability.format",
        "v2-ed25519",
      ),
      issuer: credentialFreeHttpsUrl(
        capability.issuer,
        "request.capability.issuer",
      ),
      subjectId: identifier(
        capability.subjectId,
        "request.capability.subjectId",
      ),
      audience: identifier(capability.audience, "request.capability.audience"),
      organizationId: identifier(
        capability.organizationId,
        "request.capability.organizationId",
      ),
      tenantId: identifier(capability.tenantId, "request.capability.tenantId"),
      action: parseAction(capability.action, "request.capability.action"),
      resource: exactResource(
        capability.resource,
        "request.capability.resource",
      ),
      claimGeneration: positiveInteger(
        capability.claimGeneration,
        "request.capability.claimGeneration",
      ),
      desiredStateDigest: sha256(
        capability.desiredStateDigest,
        "request.capability.desiredStateDigest",
      ),
      planDigest: nullableSha256(
        capability.planDigest,
        "request.capability.planDigest",
      ),
      issuedAtEpochSeconds: positiveInteger(
        capability.issuedAtEpochSeconds,
        "request.capability.issuedAtEpochSeconds",
      ),
      notBeforeEpochSeconds: positiveInteger(
        capability.notBeforeEpochSeconds,
        "request.capability.notBeforeEpochSeconds",
      ),
      expiresAtEpochSeconds: positiveInteger(
        capability.expiresAtEpochSeconds,
        "request.capability.expiresAtEpochSeconds",
      ),
      oneUse: booleanValue(capability.oneUse, "request.capability.oneUse"),
      cryptographicallyVerified: booleanValue(
        capability.cryptographicallyVerified,
        "request.capability.cryptographicallyVerified",
      ),
    },
    plan: root.plan === null ? null : parsePlan(root.plan, "request.plan"),
    approvals: uniqueArray(
      root.approvals,
      "request.approvals",
      parseApproval,
      (approval) => approval.approverPrincipalId,
    ),
    idempotencyKey:
      root.idempotencyKey === null
        ? null
        : identifier(root.idempotencyKey, "request.idempotencyKey"),
    deadlineEpochSeconds: positiveInteger(
      root.deadlineEpochSeconds,
      "request.deadlineEpochSeconds",
    ),
  };

  return parsed;
}

export function authorizeInfrastructureControllerRequest(
  value: unknown,
  state: InfrastructureAuthorizationState,
): InfrastructureAuthorizationDecision {
  let request: InfrastructureControllerRequest;
  try {
    request = parseInfrastructureControllerRequest(value);
  } catch {
    const reasonCodes: InfrastructureAuthorizationReasonCode[] = [
      "INFRA_REQUEST_INVALID",
    ];
    return {
      allowed: false,
      reasonCodes,
      capabilityToRedeem: null,
      audit: {
        requestId: "invalid",
        operation: "invalid",
        actor: null,
        organization: null,
        tenant: null,
        context: null,
        claim: null,
        generation: null,
        desiredStateDigest: null,
        planDigest: null,
        capabilityId: null,
        grantId: null,
        decision: "deny",
        evaluatedAtEpochSeconds: state.nowEpochSeconds,
        reasonCodes,
      },
    };
  }

  const reasons: InfrastructureAuthorizationReasonCode[] = [];
  const deny = (reason: InfrastructureAuthorizationReasonCode) => {
    if (!reasons.includes(reason)) reasons.push(reason);
  };
  const expectedAction = infrastructureAction(request.operation);
  const expectedResource = infrastructureResource(
    request.actor.organizationId,
    request.claim.tenantId,
    request.claim.contextId,
    request.claim.claimId,
  );
  const isMutation = mutationOperations.has(request.operation);

  if (
    !request.actor.authenticationMethods.includes("oidc") ||
    !request.actor.authenticationMethods.includes("mtls")
  ) {
    deny("INFRA_AUTHENTICATION_INSUFFICIENT");
  }
  if (
    request.actor.organizationId !== request.capability.organizationId ||
    request.actor.organizationId !== request.grant.organizationId
  ) {
    deny("INFRA_ORGANIZATION_MISMATCH");
  }
  if (
    request.actor.tenantId !== request.claim.tenantId ||
    request.actor.tenantId !== request.capability.tenantId ||
    request.actor.tenantId !== request.grant.tenantId
  ) {
    deny("INFRA_TENANT_MISMATCH");
  }

  if (
    !request.plugin.permissions.some(
      (permission) =>
        permission.action === expectedAction &&
        expectedResource.startsWith(permission.resourcePrefix),
    )
  ) {
    deny("INFRA_PLUGIN_MANIFEST_DENIED");
  }

  if (
    request.grant.subjectId !== request.actor.principalId ||
    !request.grant.actions.includes(expectedAction) ||
    !request.grant.resourcePrefixes.some((prefix) =>
      expectedResource.startsWith(prefix),
    )
  ) {
    deny("INFRA_ROLE_GRANT_DENIED");
  }
  if (request.grant.expiresAtEpochSeconds <= state.nowEpochSeconds) {
    deny("INFRA_ROLE_GRANT_EXPIRED");
  }

  if (!request.capability.cryptographicallyVerified) {
    deny("INFRA_CAPABILITY_UNVERIFIED");
  }
  if (!state.trustedCapabilityIssuers.includes(request.capability.issuer)) {
    deny("INFRA_CAPABILITY_ISSUER_UNTRUSTED");
  }
  if (request.capability.audience !== state.expectedAudience) {
    deny("INFRA_CAPABILITY_AUDIENCE_MISMATCH");
  }
  if (
    request.capability.subjectId !== request.actor.principalId ||
    request.capability.action !== expectedAction ||
    request.capability.resource !== expectedResource ||
    request.capability.claimGeneration !== request.claim.generation ||
    request.capability.desiredStateDigest !== request.claim.desiredStateDigest
  ) {
    deny("INFRA_CAPABILITY_BINDING_MISMATCH");
  }
  if (
    request.capability.issuedAtEpochSeconds > state.nowEpochSeconds ||
    request.capability.notBeforeEpochSeconds > state.nowEpochSeconds ||
    request.capability.expiresAtEpochSeconds <= state.nowEpochSeconds ||
    request.capability.notBeforeEpochSeconds <
      request.capability.issuedAtEpochSeconds
  ) {
    deny("INFRA_CAPABILITY_TIME_INVALID");
  }
  if (
    request.capability.expiresAtEpochSeconds -
      request.capability.issuedAtEpochSeconds >
    state.maxCapabilityTtlSeconds
  ) {
    deny("INFRA_CAPABILITY_TTL_EXCEEDED");
  }
  if (isMutation && !request.capability.oneUse) {
    deny("INFRA_CAPABILITY_NOT_ONE_USE");
  }
  if (state.redeemedCapabilityIds.has(request.capability.capabilityId)) {
    deny("INFRA_CAPABILITY_REPLAYED");
  }

  if (isMutation && request.idempotencyKey === null) {
    deny("INFRA_IDEMPOTENCY_KEY_MISSING");
  }
  if (
    request.deadlineEpochSeconds <= state.nowEpochSeconds ||
    request.deadlineEpochSeconds > request.capability.expiresAtEpochSeconds
  ) {
    deny("INFRA_DEADLINE_INVALID");
  }

  authorizePlanAndApprovals(request, state, deny);

  const allowed = reasons.length === 0;
  return {
    allowed,
    reasonCodes: reasons,
    capabilityToRedeem:
      allowed && isMutation ? request.capability.capabilityId : null,
    audit: {
      requestId: request.requestId,
      operation: request.operation,
      actor: request.actor.principalId,
      organization: request.actor.organizationId,
      tenant: request.claim.tenantId,
      context: request.claim.contextId,
      claim: request.claim.claimId,
      generation: request.claim.generation,
      desiredStateDigest: request.claim.desiredStateDigest,
      planDigest: request.plan?.planDigest ?? null,
      capabilityId: request.capability.capabilityId,
      grantId: request.grant.grantId,
      decision: allowed ? "allow" : "deny",
      evaluatedAtEpochSeconds: state.nowEpochSeconds,
      reasonCodes: reasons,
    },
  };
}

export function createReferenceInfrastructureControllerRequest(
  operation: InfrastructureOperation = "plan",
  environmentClass: InfrastructureEnvironmentClass = "nonproduction",
): InfrastructureControllerRequest {
  const now = 1_800_000_000;
  const organizationId = "org-deus";
  const tenantId = "warden";
  const contextId =
    environmentClass === "production"
      ? "aws-platform-production"
      : environmentClass === "preproduction"
        ? "aws-platform-staging"
        : "aws-platform-dev";
  const claimId = "postgres-warden";
  const desiredStateDigest = "a".repeat(64);
  const planDigest = "b".repeat(64);
  const action = infrastructureAction(operation);
  const resource = infrastructureResource(
    organizationId,
    tenantId,
    contextId,
    claimId,
  );
  const resourcePrefix = infrastructureClaimResourcePrefix(
    organizationId,
    tenantId,
    contextId,
  );
  const requiresPlan = operation === "reconcile" || operation === "delete";
  const requiredApprovalCount =
    operation === "delete"
      ? 2
      : operation === "reconcile" && environmentClass === "production"
        ? 1
        : 0;

  return parseInfrastructureControllerRequest({
    apiVersion: INFRASTRUCTURE_CONTROLLER_API_VERSION,
    kind: "InfrastructureControllerRequest",
    requestId: `request-${operation}-1`,
    operation,
    environmentClass,
    actor: {
      principalId: "operator-1",
      organizationId,
      tenantId,
      authenticationMethods: ["oidc", "mtls"],
    },
    claim: {
      claimId,
      tenantId,
      contextId,
      generation: 1,
      desiredStateDigest,
    },
    plugin: {
      pluginId: "infrastructure-request-adapter",
      kind: "infrastructure-request",
      sandbox: {
        network: "broker-only",
        providerCredentials: false,
        pulumiBackendAccess: false,
        kubernetesAdminAccess: false,
        hostAccess: false,
        unixSockets: false,
      },
      permissions: [{ action, resourcePrefix }],
    },
    grant: {
      grantId: `grant-${operation}-1`,
      subjectId: "operator-1",
      organizationId,
      tenantId,
      actions: [action],
      resourcePrefixes: [resourcePrefix],
      expiresAtEpochSeconds: now + 600,
    },
    capability: {
      capabilityId: `cap-${operation}-1`,
      format: "v2-ed25519",
      issuer: "https://auth.infrastructure.invalid",
      subjectId: "operator-1",
      audience: "infrastructure-controller",
      organizationId,
      tenantId,
      action,
      resource,
      claimGeneration: 1,
      desiredStateDigest,
      planDigest: requiresPlan ? planDigest : null,
      issuedAtEpochSeconds: now - 10,
      notBeforeEpochSeconds: now - 10,
      expiresAtEpochSeconds: now + 300,
      oneUse: mutationOperations.has(operation),
      cryptographicallyVerified: true,
    },
    plan: requiresPlan
      ? {
          planDigest,
          desiredStateDigest,
          controllerVersion: "1.0.0",
          providerId: "aws-managed-postgres",
          providerVersion: "1.0.0",
          createdAtEpochSeconds: now - 60,
          expiresAtEpochSeconds: now + 300,
          policyChecksPassed: true,
          destructive: operation === "delete",
        }
      : null,
    approvals: Array.from({ length: requiredApprovalCount }, (_, index) => ({
      approvalId: `approval-${index + 1}`,
      approverPrincipalId: `approver-${index + 1}`,
      planDigest,
      approvedAtEpochSeconds: now - 5 + index,
    })),
    idempotencyKey: mutationOperations.has(operation)
      ? `idempotency-${operation}-1`
      : null,
    deadlineEpochSeconds: now + 120,
  });
}

export function createInfrastructureStackOwnership(
  request: InfrastructureControllerRequest,
  input: {
    stackId: string;
    providerId: string;
    controllerVersion: string;
    createdAt: string;
    expiresAt?: string | null;
  },
): InfrastructureStackOwnershipMetadata {
  const metadata: InfrastructureStackOwnershipMetadata = {
    apiVersion: INFRASTRUCTURE_STACK_OWNERSHIP_API_VERSION,
    kind: "InfrastructureStackOwnership",
    stackId: identifier(input.stackId, "stackId"),
    controllerOfRecord: "infrastructure-controller",
    providerId: identifier(input.providerId, "providerId"),
    organizationId: request.actor.organizationId,
    tenantId: request.claim.tenantId,
    environmentClass: request.environmentClass,
    contextId: request.claim.contextId,
    claimId: request.claim.claimId,
    generation: request.claim.generation,
    desiredStateDigest: request.claim.desiredStateDigest,
    controllerVersion: version(input.controllerVersion, "controllerVersion"),
    createdAt: timestamp(input.createdAt, "createdAt"),
    expiresAt:
      input.expiresAt == null ? null : timestamp(input.expiresAt, "expiresAt"),
    deletionProtection: true,
    ownershipDigest: "0".repeat(64),
  };
  metadata.ownershipDigest = infrastructureStackOwnershipDigest(metadata);
  assertInfrastructureStackOwnership(metadata);
  return metadata;
}

export function infrastructureStackOwnershipDigest(
  metadata: InfrastructureStackOwnershipMetadata,
): string {
  const { ownershipDigest: _ownershipDigest, ...desired } = metadata;
  return createHash("sha256").update(stableJson(desired)).digest("hex");
}

export function assertInfrastructureStackOwnership(
  metadata: InfrastructureStackOwnershipMetadata,
): void {
  if (metadata.apiVersion !== INFRASTRUCTURE_STACK_OWNERSHIP_API_VERSION) {
    throw new Error("Infrastructure stack ownership API version is invalid.");
  }
  if (metadata.kind !== "InfrastructureStackOwnership") {
    throw new Error("Infrastructure stack ownership kind is invalid.");
  }
  for (const [name, value] of [
    ["stackId", metadata.stackId],
    ["providerId", metadata.providerId],
    ["organizationId", metadata.organizationId],
    ["tenantId", metadata.tenantId],
    ["contextId", metadata.contextId],
    ["claimId", metadata.claimId],
  ] as const) {
    assertIdentifier(value, name);
  }
  positiveInteger(metadata.generation, "generation");
  sha256(metadata.desiredStateDigest, "desiredStateDigest");
  version(metadata.controllerVersion, "controllerVersion");
  timestamp(metadata.createdAt, "createdAt");
  if (metadata.expiresAt !== null) {
    timestamp(metadata.expiresAt, "expiresAt");
    if (Date.parse(metadata.expiresAt) <= Date.parse(metadata.createdAt)) {
      throw new Error("Infrastructure stack ownership expiry is not future.");
    }
  }
  if (metadata.deletionProtection !== true) {
    throw new Error("Infrastructure stack deletion protection must be true.");
  }
  if (
    infrastructureStackOwnershipDigest(metadata) !== metadata.ownershipDigest
  ) {
    throw new Error("Infrastructure stack ownership digest does not match.");
  }
}

function authorizePlanAndApprovals(
  request: InfrastructureControllerRequest,
  state: InfrastructureAuthorizationState,
  deny: (reason: InfrastructureAuthorizationReasonCode) => void,
): void {
  const requiresPlan =
    request.operation === "reconcile" || request.operation === "delete";
  if (!requiresPlan) {
    if (request.plan !== null) deny("INFRA_PLAN_UNEXPECTED");
    if (request.capability.planDigest !== null) {
      deny("INFRA_PLAN_DIGEST_MISMATCH");
    }
    return;
  }
  if (request.plan === null) {
    deny("INFRA_PLAN_REQUIRED");
    return;
  }
  if (
    request.plan.desiredStateDigest !== request.claim.desiredStateDigest ||
    request.plan.expiresAtEpochSeconds <= state.nowEpochSeconds ||
    request.plan.createdAtEpochSeconds > state.nowEpochSeconds ||
    request.plan.expiresAtEpochSeconds <= request.plan.createdAtEpochSeconds ||
    request.plan.destructive !== (request.operation === "delete")
  ) {
    deny("INFRA_PLAN_INVALID");
  }
  if (
    request.capability.planDigest !== request.plan.planDigest ||
    request.approvals.some(
      (approval) => approval.planDigest !== request.plan!.planDigest,
    )
  ) {
    deny("INFRA_PLAN_DIGEST_MISMATCH");
  }
  if (!request.plan.policyChecksPassed) {
    deny("INFRA_POLICY_CHECKS_FAILED");
  }
  if (
    request.approvals.some(
      (approval) =>
        approval.approverPrincipalId === request.actor.principalId ||
        approval.approvedAtEpochSeconds < request.plan!.createdAtEpochSeconds ||
        approval.approvedAtEpochSeconds > state.nowEpochSeconds,
    )
  ) {
    deny("INFRA_APPROVAL_INSUFFICIENT");
  }
  const requiredApprovals =
    request.operation === "delete"
      ? 2
      : request.environmentClass === "production"
        ? 1
        : 0;
  if (request.approvals.length < requiredApprovals) {
    deny("INFRA_APPROVAL_INSUFFICIENT");
  }
}

function parsePluginPermission(
  value: unknown,
  path: string,
): InfrastructurePluginPermission {
  const input = exactObject(value, path, ["action", "resourcePrefix"]);
  return {
    action: parseAction(input.action, `${path}.action`),
    resourcePrefix: resourcePrefix(
      input.resourcePrefix,
      `${path}.resourcePrefix`,
    ),
  };
}

function parsePlan(value: unknown, path: string): InfrastructurePlanBinding {
  const input = exactObject(value, path, [
    "planDigest",
    "desiredStateDigest",
    "controllerVersion",
    "providerId",
    "providerVersion",
    "createdAtEpochSeconds",
    "expiresAtEpochSeconds",
    "policyChecksPassed",
    "destructive",
  ]);
  return {
    planDigest: sha256(input.planDigest, `${path}.planDigest`),
    desiredStateDigest: sha256(
      input.desiredStateDigest,
      `${path}.desiredStateDigest`,
    ),
    controllerVersion: version(
      input.controllerVersion,
      `${path}.controllerVersion`,
    ),
    providerId: identifier(input.providerId, `${path}.providerId`),
    providerVersion: version(input.providerVersion, `${path}.providerVersion`),
    createdAtEpochSeconds: positiveInteger(
      input.createdAtEpochSeconds,
      `${path}.createdAtEpochSeconds`,
    ),
    expiresAtEpochSeconds: positiveInteger(
      input.expiresAtEpochSeconds,
      `${path}.expiresAtEpochSeconds`,
    ),
    policyChecksPassed: booleanValue(
      input.policyChecksPassed,
      `${path}.policyChecksPassed`,
    ),
    destructive: booleanValue(input.destructive, `${path}.destructive`),
  };
}

function parseApproval(value: unknown, path: string): InfrastructureApproval {
  const input = exactObject(value, path, [
    "approvalId",
    "approverPrincipalId",
    "planDigest",
    "approvedAtEpochSeconds",
  ]);
  return {
    approvalId: identifier(input.approvalId, `${path}.approvalId`),
    approverPrincipalId: identifier(
      input.approverPrincipalId,
      `${path}.approverPrincipalId`,
    ),
    planDigest: sha256(input.planDigest, `${path}.planDigest`),
    approvedAtEpochSeconds: positiveInteger(
      input.approvedAtEpochSeconds,
      `${path}.approvedAtEpochSeconds`,
    ),
  };
}

function parseAction(value: unknown, path: string): InfrastructureAction {
  return enumeration(value, path, [
    "infra.claim.plan",
    "infra.claim.reconcile",
    "infra.claim.observe",
    "infra.claim.cancel",
    "infra.claim.delete",
  ]);
}

function exactObject(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) {
      throw new Error(`${path}.${key} is not allowed.`);
    }
  }
  for (const key of allowed) {
    if (!(key in input)) {
      throw new Error(`${path}.${key} is required.`);
    }
  }
  return input;
}

function uniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
  key: (entry: T) => unknown = (entry) => entry,
): T[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  const parsed = value.map((entry, index) => parse(entry, `${path}[${index}]`));
  const keys = parsed.map((entry) => JSON.stringify(key(entry)));
  if (new Set(keys).size !== keys.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return parsed;
}

function nonEmptyUniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
  key: (entry: T) => unknown = (entry) => entry,
): T[] {
  const parsed = uniqueArray(value, path, parse, key);
  if (parsed.length === 0) {
    throw new Error(`${path} must not be empty.`);
  }
  return parsed;
}

function literal<T extends string | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) throw new Error(`${path} must be '${expected}'.`);
  return expected;
}

function enumeration<const T extends readonly string[]>(
  value: unknown,
  path: string,
  allowed: T,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new Error(`${path} must be one of ${allowed.join(", ")}.`);
  }
  return value as T[number];
}

function identifier(value: unknown, path: string): string {
  if (typeof value !== "string") throw new Error(`${path} must be a string.`);
  assertIdentifier(value, path);
  return value;
}

function assertIdentifier(value: string, path: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new Error(`${path} must be an exact identifier.`);
  }
  if (value.includes("*") || value.includes("..")) {
    throw new Error(`${path} must not contain wildcard or traversal syntax.`);
  }
}

function exactResource(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^organization\/[A-Za-z0-9._:-]+\/tenant\/[A-Za-z0-9._:-]+\/context\/[A-Za-z0-9._:-]+\/claim\/[A-Za-z0-9._:-]+$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact infrastructure resource.`);
  }
  return value;
}

function resourcePrefix(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^organization\/[A-Za-z0-9._:-]+\/tenant\/[A-Za-z0-9._:-]+\/context\/[A-Za-z0-9._:-]+\/claim\/$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact tenant/context claim prefix.`);
  }
  return value;
}

function sha256(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${path} must be a lowercase SHA-256 digest.`);
  }
  return value;
}

function nullableSha256(value: unknown, path: string): string | null {
  return value === null ? null : sha256(value, path);
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new Error(`${path} must be a positive integer.`);
  }
  return value as number;
}

function booleanValue(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be boolean.`);
  return value;
}

function credentialFreeHttpsUrl(value: unknown, path: string): string {
  if (typeof value !== "string") throw new Error(`${path} must be a URL.`);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${path} must be a valid HTTPS URL.`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(`${path} must be a credential-free HTTPS URL.`);
  }
  return value;
}

function version(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value)
  ) {
    throw new Error(`${path} must be an exact semantic version.`);
  }
  return value;
}

function timestamp(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(`${path} must be an RFC3339 UTC timestamp.`);
  }
  return value;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
