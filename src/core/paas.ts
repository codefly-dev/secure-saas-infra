export const PAAS_SECURITY_API_VERSION =
  "security.deus.dev/paas-security/v1alpha1" as const;

export type PaasOperation =
  | "build"
  | "deploy"
  | "cancel"
  | "rollback"
  | "read-state"
  | "read-file"
  | "write-file"
  | "exec-command"
  | "open-terminal"
  | "push-artifact"
  | "pull-artifact"
  | "invoke-agent";

export type PaasExecutionTarget = "control-plane" | "tenant-sandbox" | "host";

export type PaasIdentityRole =
  | "control-plane"
  | "builder"
  | "deployer"
  | "egress"
  | "registry"
  | "runtime"
  | "audit";

export interface PaasTenantQuota {
  tenantId: string;
  maxConcurrentBuilds: number;
  maxConcurrentDeployments: number;
  maxCpu: string;
  maxMemory: string;
  maxStorage: string;
  maxExecutionMinutes: number;
}

export interface PaasEndpoint {
  id: string;
  exposure: "private" | "public";
  authentication: "none" | "oidc" | "mtls" | "oidc+mtls";
  authorization: "none" | "rbac" | "capability";
  tenantBindingRequired: boolean;
  directHostExecution: boolean;
  executionTarget: Exclude<PaasExecutionTarget, "host">;
  operations: readonly PaasOperation[];
}

export interface PaasAccessControl {
  denyByDefault: boolean;
  trustedCapabilityIssuers: readonly string[];
  maxCapabilityTtlSeconds: number;
  oneUseMutations: boolean;
  idempotencyKeys: boolean;
}

export interface PaasIdentity {
  id: string;
  role: PaasIdentityRole;
  shortLived: boolean;
  tenantScoped: boolean;
}

export interface PaasSandbox {
  trust: "trusted" | "untrusted";
  isolation: "container" | "microvm" | "dedicated-vm";
  ephemeral: boolean;
  privileged: boolean;
  hostNetwork: boolean;
  hostPid: boolean;
  hostPathMounts: boolean;
  containerSocket: boolean;
  ambientCloudCredentials: boolean;
  egress: "none" | "brokered" | "direct";
  perTenant: boolean;
  maxLifetimeMinutes: number;
}

export interface PaasScheduling {
  perTenantQueues: boolean;
  fairScheduling: boolean;
  cancellation: boolean;
  timeouts: boolean;
  maxGlobalConcurrency: number;
}

export interface PaasSupplyChain {
  digestPinned: boolean;
  signatureVerification: boolean;
  provenanceVerification: boolean;
  sbomRequired: boolean;
  immutableArtifacts: boolean;
  retentionDays: number;
}

export interface PaasDeploymentState {
  durable: boolean;
  encrypted: boolean;
  idempotencyKeys: boolean;
  perTenantLocks: boolean;
  rollback: boolean;
  backup: boolean;
  restoreTests: boolean;
  regionalRecovery: boolean;
}

export interface PaasAudit {
  immutable: boolean;
  retentionDays: number;
  requiredFields: readonly string[];
  denialEvents: boolean;
}

export interface PaasSecurityIntent {
  apiVersion: typeof PAAS_SECURITY_API_VERSION;
  name: string;
  environment: string;
  tenants: readonly PaasTenantQuota[];
  endpoints: readonly PaasEndpoint[];
  accessControl: PaasAccessControl;
  identities: readonly PaasIdentity[];
  builder: PaasSandbox;
  runtime: PaasSandbox;
  scheduling: PaasScheduling;
  supplyChain: PaasSupplyChain;
  deploymentState: PaasDeploymentState;
  audit: PaasAudit;
}

export interface PaasSecurityViolation {
  code: string;
  severity: "critical" | "high" | "medium";
  message: string;
  path?: string;
}

const requiredRoles: readonly PaasIdentityRole[] = [
  "control-plane",
  "builder",
  "deployer",
  "egress",
  "registry",
  "runtime",
  "audit",
];
const requiredOperations: readonly PaasOperation[] = [
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
const operations = requiredOperations;
const sandboxOperations = new Set<PaasOperation>([
  "read-file",
  "write-file",
  "exec-command",
  "open-terminal",
  "invoke-agent",
]);
const requiredAuditFields = [
  "actor",
  "tenant",
  "request-id",
  "operation",
  "source-revision",
  "artifact-digest",
  "authorization-decision",
  "decision-epoch-seconds",
];

export function parsePaasSecurityIntent(value: unknown): PaasSecurityIntent {
  const root = strictObject(value, "paasSecurityIntent", [
    "apiVersion",
    "name",
    "environment",
    "tenants",
    "endpoints",
    "accessControl",
    "identities",
    "builder",
    "runtime",
    "scheduling",
    "supplyChain",
    "deploymentState",
    "audit",
  ]);
  const apiVersion = stringValue(root.apiVersion, "apiVersion");
  if (apiVersion !== PAAS_SECURITY_API_VERSION) {
    throw new Error(
      `paasSecurityIntent.apiVersion must be '${PAAS_SECURITY_API_VERSION}'.`,
    );
  }
  const intent: PaasSecurityIntent = {
    apiVersion,
    name: nameValue(root.name, "name"),
    environment: nameValue(root.environment, "environment"),
    tenants: arrayValue(root.tenants, "tenants").map((entry, index) =>
      parseTenant(entry, `tenants[${index}]`),
    ),
    endpoints: arrayValue(root.endpoints, "endpoints").map((entry, index) =>
      parseEndpoint(entry, `endpoints[${index}]`),
    ),
    accessControl: parseAccessControl(root.accessControl),
    identities: arrayValue(root.identities, "identities").map((entry, index) =>
      parseIdentity(entry, `identities[${index}]`),
    ),
    builder: parseSandbox(root.builder, "builder"),
    runtime: parseSandbox(root.runtime, "runtime"),
    scheduling: parseScheduling(root.scheduling),
    supplyChain: parseSupplyChain(root.supplyChain),
    deploymentState: parseDeploymentState(root.deploymentState),
    audit: parseAudit(root.audit),
  };
  assertPaasSecurityIntent(intent);
  return intent;
}

function parseTenant(value: unknown, path: string): PaasTenantQuota {
  const input = strictObject(value, path, [
    "tenantId",
    "maxConcurrentBuilds",
    "maxConcurrentDeployments",
    "maxCpu",
    "maxMemory",
    "maxStorage",
    "maxExecutionMinutes",
  ]);
  return {
    tenantId: nameValue(input.tenantId, `${path}.tenantId`),
    maxConcurrentBuilds: positiveInteger(
      input.maxConcurrentBuilds,
      `${path}.maxConcurrentBuilds`,
    ),
    maxConcurrentDeployments: positiveInteger(
      input.maxConcurrentDeployments,
      `${path}.maxConcurrentDeployments`,
    ),
    maxCpu: stringValue(input.maxCpu, `${path}.maxCpu`),
    maxMemory: stringValue(input.maxMemory, `${path}.maxMemory`),
    maxStorage: stringValue(input.maxStorage, `${path}.maxStorage`),
    maxExecutionMinutes: positiveInteger(
      input.maxExecutionMinutes,
      `${path}.maxExecutionMinutes`,
    ),
  };
}

function parseEndpoint(value: unknown, path: string): PaasEndpoint {
  const input = strictObject(value, path, [
    "id",
    "exposure",
    "authentication",
    "authorization",
    "tenantBindingRequired",
    "directHostExecution",
    "executionTarget",
    "operations",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    exposure: enumValue(input.exposure, `${path}.exposure`, [
      "private",
      "public",
    ]),
    authentication: enumValue(input.authentication, `${path}.authentication`, [
      "none",
      "oidc",
      "mtls",
      "oidc+mtls",
    ]),
    authorization: enumValue(input.authorization, `${path}.authorization`, [
      "none",
      "rbac",
      "capability",
    ]),
    tenantBindingRequired: booleanValue(
      input.tenantBindingRequired,
      `${path}.tenantBindingRequired`,
    ),
    directHostExecution: booleanValue(
      input.directHostExecution,
      `${path}.directHostExecution`,
    ),
    executionTarget: enumValue(
      input.executionTarget,
      `${path}.executionTarget`,
      ["control-plane", "tenant-sandbox"],
    ),
    operations: uniqueStrings(
      arrayValue(input.operations, `${path}.operations`).map(
        (operation, index) =>
          enumValue(operation, `${path}.operations[${index}]`, operations),
      ),
      `${path}.operations`,
    ),
  };
}

function parseAccessControl(value: unknown): PaasAccessControl {
  const path = "accessControl";
  const input = strictObject(value, path, [
    "denyByDefault",
    "trustedCapabilityIssuers",
    "maxCapabilityTtlSeconds",
    "oneUseMutations",
    "idempotencyKeys",
  ]);
  return {
    denyByDefault: booleanValue(input.denyByDefault, `${path}.denyByDefault`),
    trustedCapabilityIssuers: uniqueStrings(
      arrayValue(
        input.trustedCapabilityIssuers,
        `${path}.trustedCapabilityIssuers`,
      ).map((issuer, index) =>
        nameValue(issuer, `${path}.trustedCapabilityIssuers[${index}]`),
      ),
      `${path}.trustedCapabilityIssuers`,
    ),
    maxCapabilityTtlSeconds: positiveInteger(
      input.maxCapabilityTtlSeconds,
      `${path}.maxCapabilityTtlSeconds`,
    ),
    oneUseMutations: booleanValue(
      input.oneUseMutations,
      `${path}.oneUseMutations`,
    ),
    idempotencyKeys: booleanValue(
      input.idempotencyKeys,
      `${path}.idempotencyKeys`,
    ),
  };
}

function parseIdentity(value: unknown, path: string): PaasIdentity {
  const input = strictObject(value, path, [
    "id",
    "role",
    "shortLived",
    "tenantScoped",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    role: enumValue(input.role, `${path}.role`, requiredRoles),
    shortLived: booleanValue(input.shortLived, `${path}.shortLived`),
    tenantScoped: booleanValue(input.tenantScoped, `${path}.tenantScoped`),
  };
}

function parseSandbox(value: unknown, path: string): PaasSandbox {
  const input = strictObject(value, path, [
    "trust",
    "isolation",
    "ephemeral",
    "privileged",
    "hostNetwork",
    "hostPid",
    "hostPathMounts",
    "containerSocket",
    "ambientCloudCredentials",
    "egress",
    "perTenant",
    "maxLifetimeMinutes",
  ]);
  return {
    trust: enumValue(input.trust, `${path}.trust`, ["trusted", "untrusted"]),
    isolation: enumValue(input.isolation, `${path}.isolation`, [
      "container",
      "microvm",
      "dedicated-vm",
    ]),
    ephemeral: booleanValue(input.ephemeral, `${path}.ephemeral`),
    privileged: booleanValue(input.privileged, `${path}.privileged`),
    hostNetwork: booleanValue(input.hostNetwork, `${path}.hostNetwork`),
    hostPid: booleanValue(input.hostPid, `${path}.hostPid`),
    hostPathMounts: booleanValue(
      input.hostPathMounts,
      `${path}.hostPathMounts`,
    ),
    containerSocket: booleanValue(
      input.containerSocket,
      `${path}.containerSocket`,
    ),
    ambientCloudCredentials: booleanValue(
      input.ambientCloudCredentials,
      `${path}.ambientCloudCredentials`,
    ),
    egress: enumValue(input.egress, `${path}.egress`, [
      "none",
      "brokered",
      "direct",
    ]),
    perTenant: booleanValue(input.perTenant, `${path}.perTenant`),
    maxLifetimeMinutes: positiveInteger(
      input.maxLifetimeMinutes,
      `${path}.maxLifetimeMinutes`,
    ),
  };
}

function parseScheduling(value: unknown): PaasScheduling {
  const path = "scheduling";
  const input = strictObject(value, path, [
    "perTenantQueues",
    "fairScheduling",
    "cancellation",
    "timeouts",
    "maxGlobalConcurrency",
  ]);
  return {
    perTenantQueues: booleanValue(
      input.perTenantQueues,
      `${path}.perTenantQueues`,
    ),
    fairScheduling: booleanValue(
      input.fairScheduling,
      `${path}.fairScheduling`,
    ),
    cancellation: booleanValue(input.cancellation, `${path}.cancellation`),
    timeouts: booleanValue(input.timeouts, `${path}.timeouts`),
    maxGlobalConcurrency: positiveInteger(
      input.maxGlobalConcurrency,
      `${path}.maxGlobalConcurrency`,
    ),
  };
}

function parseSupplyChain(value: unknown): PaasSupplyChain {
  const path = "supplyChain";
  const input = strictObject(value, path, [
    "digestPinned",
    "signatureVerification",
    "provenanceVerification",
    "sbomRequired",
    "immutableArtifacts",
    "retentionDays",
  ]);
  return {
    digestPinned: booleanValue(input.digestPinned, `${path}.digestPinned`),
    signatureVerification: booleanValue(
      input.signatureVerification,
      `${path}.signatureVerification`,
    ),
    provenanceVerification: booleanValue(
      input.provenanceVerification,
      `${path}.provenanceVerification`,
    ),
    sbomRequired: booleanValue(input.sbomRequired, `${path}.sbomRequired`),
    immutableArtifacts: booleanValue(
      input.immutableArtifacts,
      `${path}.immutableArtifacts`,
    ),
    retentionDays: positiveInteger(
      input.retentionDays,
      `${path}.retentionDays`,
    ),
  };
}

function parseDeploymentState(value: unknown): PaasDeploymentState {
  const path = "deploymentState";
  const fields = [
    "durable",
    "encrypted",
    "idempotencyKeys",
    "perTenantLocks",
    "rollback",
    "backup",
    "restoreTests",
    "regionalRecovery",
  ] as const;
  const input = strictObject(value, path, fields);
  return Object.fromEntries(
    fields.map((field) => [
      field,
      booleanValue(input[field], `${path}.${field}`),
    ]),
  ) as unknown as PaasDeploymentState;
}

function parseAudit(value: unknown): PaasAudit {
  const path = "audit";
  const input = strictObject(value, path, [
    "immutable",
    "retentionDays",
    "requiredFields",
    "denialEvents",
  ]);
  return {
    immutable: booleanValue(input.immutable, `${path}.immutable`),
    retentionDays: positiveInteger(
      input.retentionDays,
      `${path}.retentionDays`,
    ),
    requiredFields: uniqueStrings(
      arrayValue(input.requiredFields, `${path}.requiredFields`).map(
        (field, index) =>
          stringValue(field, `${path}.requiredFields[${index}]`),
      ),
      `${path}.requiredFields`,
    ),
    denialEvents: booleanValue(input.denialEvents, `${path}.denialEvents`),
  };
}

export function evaluatePaasSecurityIntent(
  intent: PaasSecurityIntent,
): PaasSecurityViolation[] {
  const violations: PaasSecurityViolation[] = [];
  const tenantIds = intent.tenants.map((tenant) => tenant.tenantId);
  for (const duplicate of duplicates(tenantIds)) {
    violations.push(
      violation(
        "PAAS_DUPLICATE_TENANT",
        "critical",
        `Tenant '${duplicate}' is declared more than once.`,
      ),
    );
  }
  if (intent.tenants.length === 0) {
    violations.push(
      violation(
        "PAAS_TENANT_QUOTA_MISSING",
        "critical",
        "At least one tenant quota is required.",
      ),
    );
  }
  for (const tenant of intent.tenants) {
    if (
      tenant.maxConcurrentBuilds < 1 ||
      tenant.maxConcurrentDeployments < 1 ||
      tenant.maxExecutionMinutes < 1 ||
      !tenant.maxCpu.trim() ||
      !tenant.maxMemory.trim() ||
      !tenant.maxStorage.trim()
    ) {
      violations.push(
        violation(
          "PAAS_TENANT_QUOTA_INVALID",
          "critical",
          `Tenant '${tenant.tenantId}' must have positive concurrency, lifetime, CPU, memory, and storage bounds.`,
          `tenants.${tenant.tenantId}`,
        ),
      );
    }
  }

  const declaredOperations = new Set<PaasOperation>();
  for (const duplicate of duplicates(
    intent.endpoints.map((endpoint) => endpoint.id),
  )) {
    violations.push(
      violation(
        "PAAS_DUPLICATE_ENDPOINT",
        "critical",
        `PaaS endpoint '${duplicate}' is declared more than once.`,
      ),
    );
  }
  for (const endpoint of intent.endpoints) {
    endpoint.operations.forEach((operation) =>
      declaredOperations.add(operation),
    );
    if (endpoint.authentication === "none") {
      violations.push(
        violation(
          "PAAS_ENDPOINT_UNAUTHENTICATED",
          "critical",
          `Endpoint '${endpoint.id}' permits unauthenticated access.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (endpoint.authorization === "none") {
      violations.push(
        violation(
          "PAAS_ENDPOINT_UNAUTHORIZED",
          "critical",
          `Endpoint '${endpoint.id}' has no authorization decision point.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (
      endpoint.exposure === "public" &&
      endpoint.authentication !== "oidc+mtls"
    ) {
      violations.push(
        violation(
          "PAAS_PUBLIC_ENDPOINT_WEAK_AUTH",
          "critical",
          `Public endpoint '${endpoint.id}' requires both OIDC and mTLS.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (!endpoint.tenantBindingRequired) {
      violations.push(
        violation(
          "PAAS_ENDPOINT_TENANT_UNBOUND",
          "critical",
          `Endpoint '${endpoint.id}' does not bind authorization to a tenant.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (endpoint.directHostExecution) {
      violations.push(
        violation(
          "PAAS_ENDPOINT_HOST_EXECUTION",
          "critical",
          `Endpoint '${endpoint.id}' can execute directly on the host.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (
      endpoint.operations.some((operation) =>
        sandboxOperations.has(operation),
      ) &&
      endpoint.executionTarget !== "tenant-sandbox"
    ) {
      violations.push(
        violation(
          "PAAS_ENDPOINT_SANDBOX_BYPASS",
          "critical",
          `Endpoint '${endpoint.id}' exposes file, command, terminal, or agent operations outside a tenant sandbox.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
    if (endpoint.operations.length === 0) {
      violations.push(
        violation(
          "PAAS_ENDPOINT_OPERATION_UNBOUNDED",
          "high",
          `Endpoint '${endpoint.id}' has no explicit operation allowlist.`,
          `endpoints.${endpoint.id}`,
        ),
      );
    }
  }
  for (const operation of requiredOperations) {
    if (!declaredOperations.has(operation)) {
      violations.push(
        violation(
          "PAAS_OPERATION_MISSING",
          "high",
          `PaaS operation '${operation}' has no governed endpoint.`,
        ),
      );
    }
  }

  if (
    !intent.accessControl.denyByDefault ||
    intent.accessControl.trustedCapabilityIssuers.length === 0 ||
    intent.accessControl.maxCapabilityTtlSeconds > 900 ||
    !intent.accessControl.oneUseMutations ||
    !intent.accessControl.idempotencyKeys
  ) {
    violations.push(
      violation(
        "PAAS_ACCESS_CONTROL_WEAK",
        "critical",
        "Access control must deny by default, trust an explicit issuer set, cap capabilities at 15 minutes, and require one-use/idempotent mutations.",
        "accessControl",
      ),
    );
  }

  const identityIds = intent.identities.map((identity) => identity.id);
  for (const duplicate of duplicates(identityIds)) {
    violations.push(
      violation(
        "PAAS_IDENTITY_REUSED",
        "critical",
        `PaaS identity '${duplicate}' is reused across trust roles.`,
      ),
    );
  }
  for (const role of requiredRoles) {
    const identities = intent.identities.filter(
      (identity) => identity.role === role,
    );
    if (identities.length !== 1) {
      violations.push(
        violation(
          "PAAS_IDENTITY_ROLE_CARDINALITY",
          "critical",
          `PaaS role '${role}' requires exactly one distinct identity.`,
        ),
      );
      continue;
    }
    if (!identities[0].shortLived) {
      violations.push(
        violation(
          "PAAS_IDENTITY_LONG_LIVED",
          "critical",
          `PaaS role '${role}' uses a long-lived identity.`,
          `identities.${identities[0].id}`,
        ),
      );
    }
    if (
      new Set<PaasIdentityRole>([
        "builder",
        "deployer",
        "egress",
        "runtime",
      ]).has(role) &&
      !identities[0].tenantScoped
    ) {
      violations.push(
        violation(
          "PAAS_IDENTITY_TENANT_UNBOUND",
          "critical",
          `PaaS role '${role}' must derive a tenant-scoped workload identity.`,
          `identities.${identities[0].id}`,
        ),
      );
    }
  }

  evaluateSandbox("builder", intent.builder, violations);
  evaluateSandbox("runtime", intent.runtime, violations);
  if (intent.builder.trust !== "untrusted") {
    violations.push(
      violation(
        "PAAS_BUILDER_TRUST_INVALID",
        "critical",
        "Customer-controlled builds must always be treated as untrusted.",
      ),
    );
  }

  if (
    !intent.scheduling.perTenantQueues ||
    !intent.scheduling.fairScheduling ||
    !intent.scheduling.cancellation ||
    !intent.scheduling.timeouts ||
    intent.scheduling.maxGlobalConcurrency < 1
  ) {
    violations.push(
      violation(
        "PAAS_SCHEDULER_UNBOUNDED",
        "critical",
        "Scheduling requires bounded global concurrency, per-tenant queues, fairness, cancellation, and timeouts.",
      ),
    );
  }

  if (
    !intent.supplyChain.digestPinned ||
    !intent.supplyChain.signatureVerification ||
    !intent.supplyChain.provenanceVerification ||
    !intent.supplyChain.sbomRequired ||
    !intent.supplyChain.immutableArtifacts ||
    intent.supplyChain.retentionDays < 30
  ) {
    violations.push(
      violation(
        "PAAS_SUPPLY_CHAIN_WEAK",
        "critical",
        "Artifacts require digests, signatures, provenance, SBOMs, immutability, and at least 30 days retention.",
      ),
    );
  }

  if (
    !intent.deploymentState.durable ||
    !intent.deploymentState.encrypted ||
    !intent.deploymentState.idempotencyKeys ||
    !intent.deploymentState.perTenantLocks ||
    !intent.deploymentState.rollback
  ) {
    violations.push(
      violation(
        "PAAS_STATE_UNSAFE",
        "critical",
        "Deployment state requires durability, encryption, idempotency, tenant locks, and rollback.",
      ),
    );
  }
  if (
    !intent.deploymentState.backup ||
    !intent.deploymentState.restoreTests ||
    !intent.deploymentState.regionalRecovery
  ) {
    violations.push(
      violation(
        "PAAS_RECOVERY_UNPROVEN",
        "high",
        "Deployment state requires backups, restore testing, and regional recovery.",
      ),
    );
  }

  if (
    !intent.audit.immutable ||
    !intent.audit.denialEvents ||
    intent.audit.retentionDays < 365
  ) {
    violations.push(
      violation(
        "PAAS_AUDIT_WEAK",
        "critical",
        "PaaS audit evidence must be immutable, include denials, and be retained for at least 365 days.",
      ),
    );
  }
  const auditFields = new Set(intent.audit.requiredFields);
  const missingAuditFields = requiredAuditFields.filter(
    (field) => !auditFields.has(field),
  );
  if (missingAuditFields.length > 0) {
    violations.push(
      violation(
        "PAAS_AUDIT_FIELDS_MISSING",
        "critical",
        `PaaS audit evidence is missing fields: ${missingAuditFields.join(", ")}.`,
      ),
    );
  }
  return violations;
}

export function assertPaasSecurityIntent(intent: PaasSecurityIntent): void {
  const violations = evaluatePaasSecurityIntent(intent);
  if (violations.length === 0) return;
  throw new Error(
    `PaaS security intent '${intent.name}' violates security invariants:\n${violations
      .map((entry) => `- [${entry.severity}] ${entry.code}: ${entry.message}`)
      .join("\n")}`,
  );
}

export function createSecurePaasSecurityIntent(
  tenantIds: readonly string[],
): PaasSecurityIntent {
  return {
    apiVersion: PAAS_SECURITY_API_VERSION,
    name: "codefly-multi-tenant-paas",
    environment: "production",
    tenants: tenantIds.map((tenantId) => ({
      tenantId,
      maxConcurrentBuilds: 4,
      maxConcurrentDeployments: 2,
      maxCpu: "16",
      maxMemory: "32Gi",
      maxStorage: "200Gi",
      maxExecutionMinutes: 30,
    })),
    endpoints: [
      {
        id: "codefly-api",
        exposure: "private",
        authentication: "mtls",
        authorization: "capability",
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: "control-plane",
        operations: ["build", "deploy", "cancel", "rollback", "read-state"],
      },
      {
        id: "codefly-workspace-api",
        exposure: "private",
        authentication: "mtls",
        authorization: "capability",
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: "tenant-sandbox",
        operations: ["read-file", "write-file"],
      },
      {
        id: "codefly-exec-api",
        exposure: "private",
        authentication: "mtls",
        authorization: "capability",
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: "tenant-sandbox",
        operations: ["exec-command", "open-terminal"],
      },
      {
        id: "codefly-registry-api",
        exposure: "private",
        authentication: "mtls",
        authorization: "capability",
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: "control-plane",
        operations: ["push-artifact", "pull-artifact"],
      },
      {
        id: "codefly-agent-api",
        exposure: "private",
        authentication: "mtls",
        authorization: "capability",
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: "tenant-sandbox",
        operations: ["invoke-agent"],
      },
    ],
    accessControl: {
      denyByDefault: true,
      trustedCapabilityIssuers: ["codefly-control-plane"],
      maxCapabilityTtlSeconds: 300,
      oneUseMutations: true,
      idempotencyKeys: true,
    },
    identities: requiredRoles.map((role) => ({
      id: `codefly-${role}`,
      role,
      shortLived: true,
      tenantScoped: new Set<PaasIdentityRole>([
        "builder",
        "deployer",
        "egress",
        "runtime",
      ]).has(role),
    })),
    builder: secureSandbox("untrusted", "microvm", 30),
    runtime: secureSandbox("trusted", "container", 1440),
    scheduling: {
      perTenantQueues: true,
      fairScheduling: true,
      cancellation: true,
      timeouts: true,
      maxGlobalConcurrency: 32,
    },
    supplyChain: {
      digestPinned: true,
      signatureVerification: true,
      provenanceVerification: true,
      sbomRequired: true,
      immutableArtifacts: true,
      retentionDays: 365,
    },
    deploymentState: {
      durable: true,
      encrypted: true,
      idempotencyKeys: true,
      perTenantLocks: true,
      rollback: true,
      backup: true,
      restoreTests: true,
      regionalRecovery: true,
    },
    audit: {
      immutable: true,
      retentionDays: 2555,
      requiredFields: requiredAuditFields,
      denialEvents: true,
    },
  };
}

function secureSandbox(
  trust: PaasSandbox["trust"],
  isolation: PaasSandbox["isolation"],
  maxLifetimeMinutes: number,
): PaasSandbox {
  return {
    trust,
    isolation,
    ephemeral: true,
    privileged: false,
    hostNetwork: false,
    hostPid: false,
    hostPathMounts: false,
    containerSocket: false,
    ambientCloudCredentials: false,
    egress: "brokered",
    perTenant: true,
    maxLifetimeMinutes,
  };
}

function evaluateSandbox(
  name: "builder" | "runtime",
  sandbox: PaasSandbox,
  violations: PaasSecurityViolation[],
) {
  if (
    sandbox.trust === "untrusted" &&
    sandbox.isolation !== "microvm" &&
    sandbox.isolation !== "dedicated-vm"
  ) {
    violations.push(
      violation(
        "PAAS_SANDBOX_WEAK_ISOLATION",
        "critical",
        `${name} sandbox requires a microVM or dedicated VM for untrusted execution.`,
        name,
      ),
    );
  }
  if (sandbox.privileged) {
    violations.push(
      violation(
        "PAAS_SANDBOX_PRIVILEGED",
        "critical",
        `${name} sandbox cannot be privileged.`,
        name,
      ),
    );
  }
  if (
    sandbox.hostNetwork ||
    sandbox.hostPid ||
    sandbox.hostPathMounts ||
    sandbox.containerSocket
  ) {
    violations.push(
      violation(
        "PAAS_SANDBOX_HOST_ACCESS",
        "critical",
        `${name} sandbox cannot access host namespaces, host paths, or the container socket.`,
        name,
      ),
    );
  }
  if (sandbox.ambientCloudCredentials) {
    violations.push(
      violation(
        "PAAS_SANDBOX_AMBIENT_CREDENTIALS",
        "critical",
        `${name} sandbox cannot receive ambient cloud credentials.`,
        name,
      ),
    );
  }
  if (sandbox.egress === "direct") {
    violations.push(
      violation(
        "PAAS_SANDBOX_DIRECT_EGRESS",
        "critical",
        `${name} sandbox egress must be absent or brokered.`,
        name,
      ),
    );
  }
  if (
    !sandbox.ephemeral ||
    !sandbox.perTenant ||
    sandbox.maxLifetimeMinutes < 1
  ) {
    violations.push(
      violation(
        "PAAS_SANDBOX_LIFECYCLE_UNBOUNDED",
        "critical",
        `${name} sandbox must be ephemeral, tenant-bound, and time-bounded.`,
        name,
      ),
    );
  }
}

function violation(
  code: string,
  severity: PaasSecurityViolation["severity"],
  message: string,
  path?: string,
): PaasSecurityViolation {
  return { code, severity, message, ...(path ? { path } : {}) };
}

function duplicates(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const duplicate = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) duplicate.add(value);
    seen.add(value);
  }
  return [...duplicate].sort();
}

function strictObject(
  value: unknown,
  path: string,
  allowedKeys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  const unknown = Object.keys(input).filter(
    (key) => !allowedKeys.includes(key),
  );
  if (unknown.length > 0) {
    throw new Error(`${path} has unknown field '${unknown.sort()[0]}'.`);
  }
  const missing = allowedKeys.filter((key) => !(key in input));
  if (missing.length > 0) {
    throw new Error(`${path} is missing required field '${missing[0]}'.`);
  }
  return input;
}

function arrayValue(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  return value;
}

function stringValue(value: unknown, path: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${path} must be a non-empty string.`);
  }
  return value;
}

function nameValue(value: unknown, path: string): string {
  const name = stringValue(value, path);
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(name)) {
    throw new Error(`${path} must be a lowercase DNS-style name.`);
  }
  return name;
}

function booleanValue(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be boolean.`);
  return value;
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${path} must be a positive integer.`);
  }
  return value as number;
}

function enumValue<const T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function uniqueStrings<const T extends string>(
  values: readonly T[],
  path: string,
): readonly T[] {
  if (new Set(values).size !== values.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return values;
}
