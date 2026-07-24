import { createHash } from "node:crypto";

export const CODEFLY_BOOTSTRAP_API_VERSION =
  "paas.codefly.dev/bootstrap/v1alpha1" as const;

export type CodeflyEnvironmentClass =
  | "nonproduction"
  | "preproduction"
  | "production";

export interface CodeflyBootstrapStatus {
  phase: "planned" | "ready" | "degraded" | "unavailable";
  generation: number;
  observedGeneration: number;
  verifiedAt: string | null;
  evidenceRef: string | null;
}

export interface CodeflyBootstrapEnvironment {
  id: string;
  class: CodeflyEnvironmentClass;
  enabled: boolean;
  contexts: {
    platformContextId: string;
    executionContextId: string;
  };
  deploymentAdmission: "require-ready-contexts" | "deny";
  dataPolicy: {
    productionData: "allow" | "deny";
    syntheticDataRequired: boolean;
  };
  releasePolicy: {
    artifactFlow: "build-in-environment" | "promote-exact-digest";
    allowedGitRefs: string[];
    approvalRequired: boolean;
    signedImagesRequired: true;
    provenanceRequired: true;
    sbomRequired: true;
    evidenceRequired: true;
  };
  ephemeralPreviewsAllowed: boolean;
}

export interface CodeflyBootstrapIntent {
  apiVersion: typeof CODEFLY_BOOTSTRAP_API_VERSION;
  kind: "CodeflyBootstrap";
  name: string;
  seed: {
    operationId: string;
    desiredStateDigest: string;
    reconciliation: "exact";
    duplicateSubmission: "idempotent";
    deletion: "deny";
  };
  systemRealm: {
    id: string;
    ordinaryOrganizationApiAccess: false;
    owner: "bootstrap-iac";
  };
  organization: {
    id: string;
    slug: string;
    displayName: string;
    initialOwner: {
      authentication: "oidc";
      issuer: string;
      audience: string;
      subject: string;
    };
    teams: Array<{
      id: string;
      roles: Array<
        "organization-admin" | "platform-operator" | "developer" | "auditor"
      >;
    }>;
  };
  environments: CodeflyBootstrapEnvironment[];
  status: CodeflyBootstrapStatus;
}

export interface ReferenceCodeflyBootstrapOptions {
  organizationId?: string;
  organizationSlug?: string;
  organizationDisplayName?: string;
  ownerIssuer?: string;
  ownerAudience?: string;
  ownerSubject?: string;
}

export function createReferenceCodeflyBootstrap(
  options: ReferenceCodeflyBootstrapOptions = {},
): CodeflyBootstrapIntent {
  const organizationSlug = options.organizationSlug ?? "deus";
  const intent: CodeflyBootstrapIntent = {
    apiVersion: CODEFLY_BOOTSTRAP_API_VERSION,
    kind: "CodeflyBootstrap",
    name: `${organizationSlug}-initial-bootstrap`,
    seed: {
      operationId: `${organizationSlug}-bootstrap-v1`,
      desiredStateDigest: "0".repeat(64),
      reconciliation: "exact",
      duplicateSubmission: "idempotent",
      deletion: "deny",
    },
    systemRealm: {
      id: "codefly-system",
      ordinaryOrganizationApiAccess: false,
      owner: "bootstrap-iac",
    },
    organization: {
      id: options.organizationId ?? "org-deus",
      slug: organizationSlug,
      displayName: options.organizationDisplayName ?? "Deus",
      initialOwner: {
        authentication: "oidc",
        issuer: options.ownerIssuer ?? "https://identity.deus.dev",
        audience: options.ownerAudience ?? "codefly",
        subject:
          options.ownerSubject ??
          "oidc://identity.deus.dev/users/bootstrap-owner",
      },
      teams: [
        { id: "platform-admins", roles: ["organization-admin"] },
        { id: "platform-operators", roles: ["platform-operator"] },
        { id: "developers", roles: ["developer"] },
        { id: "security-auditors", roles: ["auditor"] },
      ],
    },
    environments: [
      environment({
        id: "dev",
        class: "nonproduction",
        enabled: true,
        platformContextId: "aws-platform-dev",
        executionContextId: "aws-execution-dev",
        artifactFlow: "build-in-environment",
        allowedGitRefs: ["refs/heads/main"],
        approvalRequired: false,
        productionData: "deny",
        syntheticDataRequired: true,
        ephemeralPreviewsAllowed: true,
      }),
      environment({
        id: "staging",
        class: "preproduction",
        enabled: false,
        platformContextId: "aws-platform-staging",
        executionContextId: "aws-execution-staging",
        artifactFlow: "promote-exact-digest",
        allowedGitRefs: ["refs/heads/main"],
        approvalRequired: true,
        productionData: "deny",
        syntheticDataRequired: true,
        ephemeralPreviewsAllowed: false,
      }),
      environment({
        id: "prod",
        class: "production",
        enabled: true,
        platformContextId: "aws-platform-production",
        executionContextId: "aws-execution-production",
        artifactFlow: "promote-exact-digest",
        allowedGitRefs: ["refs/heads/main"],
        approvalRequired: true,
        productionData: "allow",
        syntheticDataRequired: false,
        ephemeralPreviewsAllowed: false,
      }),
    ],
    status: {
      phase: "planned",
      generation: 1,
      observedGeneration: 0,
      verifiedAt: null,
      evidenceRef: null,
    },
  };
  intent.seed.desiredStateDigest = computeDesiredStateDigest(intent);
  assertCodeflyBootstrapIntent(intent);
  return intent;
}

export function parseCodeflyBootstrapIntent(
  value: unknown,
): CodeflyBootstrapIntent {
  const root = object(value, "bootstrap", [
    "apiVersion",
    "kind",
    "name",
    "seed",
    "systemRealm",
    "organization",
    "environments",
    "status",
  ]);
  const seed = object(root.seed, "bootstrap.seed", [
    "operationId",
    "desiredStateDigest",
    "reconciliation",
    "duplicateSubmission",
    "deletion",
  ]);
  const systemRealm = object(root.systemRealm, "bootstrap.systemRealm", [
    "id",
    "ordinaryOrganizationApiAccess",
    "owner",
  ]);
  const organization = object(root.organization, "bootstrap.organization", [
    "id",
    "slug",
    "displayName",
    "initialOwner",
    "teams",
  ]);
  const initialOwner = object(
    organization.initialOwner,
    "bootstrap.organization.initialOwner",
    ["authentication", "issuer", "audience", "subject"],
  );
  const teams = array(organization.teams, "bootstrap.organization.teams").map(
    (team, index) => {
      const parsed = object(team, `bootstrap.organization.teams[${index}]`, [
        "id",
        "roles",
      ]);
      return {
        id: text(parsed.id, `bootstrap.organization.teams[${index}].id`),
        roles: array(
          parsed.roles,
          `bootstrap.organization.teams[${index}].roles`,
        ).map((role, roleIndex) =>
          enumValue(
            role,
            `bootstrap.organization.teams[${index}].roles[${roleIndex}]`,
            [
              "organization-admin",
              "platform-operator",
              "developer",
              "auditor",
            ] as const,
          ),
        ),
      };
    },
  );
  const environments = array(root.environments, "bootstrap.environments").map(
    parseEnvironment,
  );
  const status = parseStatus(root.status);
  const parsed: CodeflyBootstrapIntent = {
    apiVersion: literal(
      root.apiVersion,
      "bootstrap.apiVersion",
      CODEFLY_BOOTSTRAP_API_VERSION,
    ),
    kind: literal(root.kind, "bootstrap.kind", "CodeflyBootstrap"),
    name: text(root.name, "bootstrap.name"),
    seed: {
      operationId: text(seed.operationId, "bootstrap.seed.operationId"),
      desiredStateDigest: text(
        seed.desiredStateDigest,
        "bootstrap.seed.desiredStateDigest",
      ),
      reconciliation: literal(
        seed.reconciliation,
        "bootstrap.seed.reconciliation",
        "exact",
      ),
      duplicateSubmission: literal(
        seed.duplicateSubmission,
        "bootstrap.seed.duplicateSubmission",
        "idempotent",
      ),
      deletion: literal(seed.deletion, "bootstrap.seed.deletion", "deny"),
    },
    systemRealm: {
      id: text(systemRealm.id, "bootstrap.systemRealm.id"),
      ordinaryOrganizationApiAccess: literal(
        systemRealm.ordinaryOrganizationApiAccess,
        "bootstrap.systemRealm.ordinaryOrganizationApiAccess",
        false,
      ),
      owner: literal(
        systemRealm.owner,
        "bootstrap.systemRealm.owner",
        "bootstrap-iac",
      ),
    },
    organization: {
      id: text(organization.id, "bootstrap.organization.id"),
      slug: text(organization.slug, "bootstrap.organization.slug"),
      displayName: text(
        organization.displayName,
        "bootstrap.organization.displayName",
      ),
      initialOwner: {
        authentication: literal(
          initialOwner.authentication,
          "bootstrap.organization.initialOwner.authentication",
          "oidc",
        ),
        issuer: text(
          initialOwner.issuer,
          "bootstrap.organization.initialOwner.issuer",
        ),
        audience: text(
          initialOwner.audience,
          "bootstrap.organization.initialOwner.audience",
        ),
        subject: text(
          initialOwner.subject,
          "bootstrap.organization.initialOwner.subject",
        ),
      },
      teams,
    },
    environments,
    status,
  };
  assertCodeflyBootstrapIntent(parsed);
  return parsed;
}

export function assertCodeflyBootstrapIntent(
  intent: CodeflyBootstrapIntent,
): void {
  safeId(intent.name, "bootstrap.name");
  safeId(intent.seed.operationId, "bootstrap.seed.operationId");
  safeId(intent.systemRealm.id, "bootstrap.systemRealm.id");
  safeId(intent.organization.id, "bootstrap.organization.id");
  safeId(intent.organization.slug, "bootstrap.organization.slug");
  if (intent.systemRealm.id === intent.organization.id) {
    throw new Error("Codefly system realm and organization IDs must differ.");
  }
  if (!intent.organization.displayName.trim()) {
    throw new Error("Codefly bootstrap organization displayName is required.");
  }
  const owner = intent.organization.initialOwner;
  assertOidcIssuer(owner.issuer);
  exactAuthority(owner.audience, "initial owner audience");
  exactAuthority(owner.subject, "initial owner subject");

  uniqueBy(intent.organization.teams, (team) => team.id, "team ID");
  if (intent.organization.teams.length === 0) {
    throw new Error(
      "Codefly bootstrap requires at least one organization team.",
    );
  }
  for (const team of intent.organization.teams) {
    safeId(team.id, `team '${team.id}'`);
    if (
      team.roles.length === 0 ||
      new Set(team.roles).size !== team.roles.length
    ) {
      throw new Error(`Codefly bootstrap team '${team.id}' has invalid roles.`);
    }
  }
  if (
    !intent.organization.teams.some((team) =>
      team.roles.includes("organization-admin"),
    )
  ) {
    throw new Error("Codefly bootstrap requires an organization-admin team.");
  }

  if (intent.environments.length === 0) {
    throw new Error("Codefly bootstrap requires at least one environment.");
  }
  uniqueBy(
    intent.environments,
    (environment) => environment.id,
    "environment ID",
  );
  const contexts: string[] = [];
  for (const item of intent.environments) {
    assertEnvironment(item);
    contexts.push(
      item.contexts.platformContextId,
      item.contexts.executionContextId,
    );
  }
  if (new Set(contexts).size !== contexts.length) {
    throw new Error(
      "Codefly bootstrap environments must not share CloudContext IDs.",
    );
  }
  const production = intent.environments.filter(
    (environment) => environment.class === "production",
  );
  if (production.length !== 1 || !production[0].enabled) {
    throw new Error(
      "Codefly bootstrap requires exactly one enabled production environment.",
    );
  }
  if (
    !intent.environments.some(
      (environment) =>
        environment.class === "nonproduction" && environment.enabled,
    )
  ) {
    throw new Error(
      "Codefly bootstrap requires an enabled nonproduction environment.",
    );
  }
  assertStatus(intent.status);
  if (!/^[a-f0-9]{64}$/.test(intent.seed.desiredStateDigest)) {
    throw new Error(
      "Codefly bootstrap seed desiredStateDigest must be a SHA-256 digest.",
    );
  }
  if (intent.seed.desiredStateDigest !== computeDesiredStateDigest(intent)) {
    throw new Error(
      "Codefly bootstrap seed desiredStateDigest does not match desired state.",
    );
  }
}

export function assertExecutableCodeflyBootstrap(
  intent: CodeflyBootstrapIntent,
): void {
  assertCodeflyBootstrapIntent(intent);
  const status = intent.status;
  if (
    status.phase !== "ready" ||
    status.observedGeneration !== status.generation ||
    !status.verifiedAt ||
    !status.evidenceRef
  ) {
    throw new Error(
      "Codefly bootstrap is not executable until its generation and evidence are ready.",
    );
  }
  if (status.evidenceRef !== codeflyBootstrapEvidenceRef(intent)) {
    throw new Error(
      "Codefly bootstrap evidence must bind the exact desired-state digest and generation.",
    );
  }
}

export function codeflyBootstrapDesiredStateDigest(
  intent: CodeflyBootstrapIntent,
): string {
  assertCodeflyBootstrapIntent(intent);
  return intent.seed.desiredStateDigest;
}

export function codeflyBootstrapEvidenceRef(
  intent: CodeflyBootstrapIntent,
): string {
  return `evidence://codefly-bootstrap/${intent.name}/${intent.seed.desiredStateDigest}/generation/${intent.status.generation}`;
}

function environment(options: {
  id: string;
  class: CodeflyEnvironmentClass;
  enabled: boolean;
  platformContextId: string;
  executionContextId: string;
  artifactFlow: "build-in-environment" | "promote-exact-digest";
  allowedGitRefs: string[];
  approvalRequired: boolean;
  productionData: "allow" | "deny";
  syntheticDataRequired: boolean;
  ephemeralPreviewsAllowed: boolean;
}): CodeflyBootstrapEnvironment {
  return {
    id: options.id,
    class: options.class,
    enabled: options.enabled,
    contexts: {
      platformContextId: options.platformContextId,
      executionContextId: options.executionContextId,
    },
    deploymentAdmission: options.enabled ? "require-ready-contexts" : "deny",
    dataPolicy: {
      productionData: options.productionData,
      syntheticDataRequired: options.syntheticDataRequired,
    },
    releasePolicy: {
      artifactFlow: options.artifactFlow,
      allowedGitRefs: options.allowedGitRefs,
      approvalRequired: options.approvalRequired,
      signedImagesRequired: true,
      provenanceRequired: true,
      sbomRequired: true,
      evidenceRequired: true,
    },
    ephemeralPreviewsAllowed: options.ephemeralPreviewsAllowed,
  };
}

function parseEnvironment(
  value: unknown,
  index: number,
): CodeflyBootstrapEnvironment {
  const path = `bootstrap.environments[${index}]`;
  const item = object(value, path, [
    "id",
    "class",
    "enabled",
    "contexts",
    "deploymentAdmission",
    "dataPolicy",
    "releasePolicy",
    "ephemeralPreviewsAllowed",
  ]);
  const contexts = object(item.contexts, `${path}.contexts`, [
    "platformContextId",
    "executionContextId",
  ]);
  const dataPolicy = object(item.dataPolicy, `${path}.dataPolicy`, [
    "productionData",
    "syntheticDataRequired",
  ]);
  const releasePolicy = object(item.releasePolicy, `${path}.releasePolicy`, [
    "artifactFlow",
    "allowedGitRefs",
    "approvalRequired",
    "signedImagesRequired",
    "provenanceRequired",
    "sbomRequired",
    "evidenceRequired",
  ]);
  return {
    id: text(item.id, `${path}.id`),
    class: enumValue(item.class, `${path}.class`, [
      "nonproduction",
      "preproduction",
      "production",
    ] as const),
    enabled: boolean(item.enabled, `${path}.enabled`),
    contexts: {
      platformContextId: text(
        contexts.platformContextId,
        `${path}.contexts.platformContextId`,
      ),
      executionContextId: text(
        contexts.executionContextId,
        `${path}.contexts.executionContextId`,
      ),
    },
    deploymentAdmission: enumValue(
      item.deploymentAdmission,
      `${path}.deploymentAdmission`,
      ["require-ready-contexts", "deny"] as const,
    ),
    dataPolicy: {
      productionData: enumValue(
        dataPolicy.productionData,
        `${path}.dataPolicy.productionData`,
        ["allow", "deny"] as const,
      ),
      syntheticDataRequired: boolean(
        dataPolicy.syntheticDataRequired,
        `${path}.dataPolicy.syntheticDataRequired`,
      ),
    },
    releasePolicy: {
      artifactFlow: enumValue(
        releasePolicy.artifactFlow,
        `${path}.releasePolicy.artifactFlow`,
        ["build-in-environment", "promote-exact-digest"] as const,
      ),
      allowedGitRefs: array(
        releasePolicy.allowedGitRefs,
        `${path}.releasePolicy.allowedGitRefs`,
      ).map((ref, refIndex) =>
        text(ref, `${path}.releasePolicy.allowedGitRefs[${refIndex}]`),
      ),
      approvalRequired: boolean(
        releasePolicy.approvalRequired,
        `${path}.releasePolicy.approvalRequired`,
      ),
      signedImagesRequired: literal(
        releasePolicy.signedImagesRequired,
        `${path}.releasePolicy.signedImagesRequired`,
        true,
      ),
      provenanceRequired: literal(
        releasePolicy.provenanceRequired,
        `${path}.releasePolicy.provenanceRequired`,
        true,
      ),
      sbomRequired: literal(
        releasePolicy.sbomRequired,
        `${path}.releasePolicy.sbomRequired`,
        true,
      ),
      evidenceRequired: literal(
        releasePolicy.evidenceRequired,
        `${path}.releasePolicy.evidenceRequired`,
        true,
      ),
    },
    ephemeralPreviewsAllowed: boolean(
      item.ephemeralPreviewsAllowed,
      `${path}.ephemeralPreviewsAllowed`,
    ),
  };
}

function parseStatus(value: unknown): CodeflyBootstrapStatus {
  const status = object(value, "bootstrap.status", [
    "phase",
    "generation",
    "observedGeneration",
    "verifiedAt",
    "evidenceRef",
  ]);
  return {
    phase: enumValue(status.phase, "bootstrap.status.phase", [
      "planned",
      "ready",
      "degraded",
      "unavailable",
    ] as const),
    generation: integer(status.generation, "bootstrap.status.generation"),
    observedGeneration: integer(
      status.observedGeneration,
      "bootstrap.status.observedGeneration",
    ),
    verifiedAt: nullableText(status.verifiedAt, "bootstrap.status.verifiedAt"),
    evidenceRef: nullableText(
      status.evidenceRef,
      "bootstrap.status.evidenceRef",
    ),
  };
}

function assertEnvironment(item: CodeflyBootstrapEnvironment) {
  safeId(item.id, `environment '${item.id}'`);
  safeId(item.contexts.platformContextId, `${item.id} platform context`);
  safeId(item.contexts.executionContextId, `${item.id} execution context`);
  if (item.contexts.platformContextId === item.contexts.executionContextId) {
    throw new Error(
      `Codefly environment '${item.id}' must separate platform and execution contexts.`,
    );
  }
  if (
    (item.enabled && item.deploymentAdmission !== "require-ready-contexts") ||
    (!item.enabled && item.deploymentAdmission !== "deny")
  ) {
    throw new Error(
      `Codefly environment '${item.id}' admission does not match enabled state.`,
    );
  }
  if (
    item.class === "production" &&
    (item.dataPolicy.productionData !== "allow" ||
      item.dataPolicy.syntheticDataRequired ||
      !item.releasePolicy.approvalRequired ||
      item.releasePolicy.artifactFlow !== "promote-exact-digest" ||
      item.ephemeralPreviewsAllowed)
  ) {
    throw new Error(
      `Codefly production environment '${item.id}' weakens production policy.`,
    );
  }
  if (
    item.class !== "production" &&
    (item.dataPolicy.productionData !== "deny" ||
      !item.dataPolicy.syntheticDataRequired)
  ) {
    throw new Error(
      `Codefly non-production environment '${item.id}' must deny production data and require synthetic data.`,
    );
  }
  if (
    item.class === "preproduction" &&
    (!item.releasePolicy.approvalRequired ||
      item.releasePolicy.artifactFlow !== "promote-exact-digest" ||
      item.ephemeralPreviewsAllowed)
  ) {
    throw new Error(
      `Codefly preproduction environment '${item.id}' weakens promotion policy.`,
    );
  }
  if (item.releasePolicy.allowedGitRefs.length === 0) {
    throw new Error(
      `Codefly environment '${item.id}' requires allowed Git refs.`,
    );
  }
  if (
    new Set(item.releasePolicy.allowedGitRefs).size !==
    item.releasePolicy.allowedGitRefs.length
  ) {
    throw new Error(`Codefly environment '${item.id}' has duplicate Git refs.`);
  }
  for (const ref of item.releasePolicy.allowedGitRefs) {
    if (
      !/^refs\/(?:heads|tags)\/[A-Za-z0-9._/-]+$/.test(ref) ||
      /[*?]/.test(ref)
    ) {
      throw new Error(
        `Codefly environment '${item.id}' Git ref '${ref}' must be exact.`,
      );
    }
  }
}

function assertStatus(status: CodeflyBootstrapStatus) {
  if (status.generation < 1 || status.observedGeneration < 0) {
    throw new Error("Codefly bootstrap generations are invalid.");
  }
  if (status.observedGeneration > status.generation) {
    throw new Error(
      "Codefly bootstrap observed generation is ahead of desired state.",
    );
  }
  if (status.phase === "planned") {
    if (
      status.observedGeneration !== 0 ||
      status.verifiedAt !== null ||
      status.evidenceRef !== null
    ) {
      throw new Error(
        "Planned Codefly bootstrap status cannot claim evidence.",
      );
    }
    return;
  }
  if (
    status.observedGeneration !== status.generation ||
    !status.verifiedAt ||
    !status.evidenceRef
  ) {
    throw new Error(
      "Observed Codefly bootstrap status requires matching generation and evidence.",
    );
  }
  if (Number.isNaN(Date.parse(status.verifiedAt))) {
    throw new Error("Codefly bootstrap verifiedAt must be an ISO timestamp.");
  }
  exactReference(status.evidenceRef, "bootstrap evidence reference");
}

function assertOidcIssuer(value: string) {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(
      "Codefly bootstrap initial owner issuer must be an HTTPS URL.",
    );
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(
      "Codefly bootstrap initial owner issuer must be an exact credential-free HTTPS URL.",
    );
  }
}

function exactAuthority(value: string, label: string) {
  if (!value || value.length > 512 || /[*?\s]/.test(value)) {
    throw new Error(`Codefly bootstrap ${label} must be exact.`);
  }
  if (/(?:password|secret|token|access[_-]?key|private[_-]?key)/i.test(value)) {
    throw new Error(
      `Codefly bootstrap ${label} cannot contain credential material.`,
    );
  }
}

function exactReference(value: string, label: string) {
  if (!/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~:/-]+$/.test(value)) {
    throw new Error(`Codefly ${label} must be an exact reference URI.`);
  }
  exactAuthority(value, label);
}

function safeId(value: string, label: string) {
  if (!/^[a-z0-9][a-z0-9.-]{0,126}[a-z0-9]$|^[a-z0-9]$/.test(value)) {
    throw new Error(`Codefly ${label} must be a safe stable ID.`);
  }
}

function uniqueBy<T>(
  values: readonly T[],
  select: (value: T) => string,
  label: string,
) {
  const selected = values.map(select);
  if (new Set(selected).size !== selected.length) {
    throw new Error(`Codefly bootstrap has duplicate ${label}.`);
  }
}

function object(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const result = value as Record<string, unknown>;
  for (const key of Object.keys(result)) {
    if (!allowed.includes(key))
      throw new Error(`${path}.${key} is not allowed.`);
  }
  for (const key of allowed) {
    if (!(key in result)) throw new Error(`${path}.${key} is required.`);
  }
  return result;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  return value;
}

function text(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) {
    throw new Error(`${path} must be a non-empty bounded string.`);
  }
  return value;
}

function nullableText(value: unknown, path: string): string | null {
  return value === null ? null : text(value, path);
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be a boolean.`);
  return value;
}

function integer(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value))
    throw new Error(`${path} must be an integer.`);
  return value as number;
}

function literal<T extends string | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected)
    throw new Error(`${path} must equal ${String(expected)}.`);
  return expected;
}

function enumValue<const T extends readonly string[]>(
  value: unknown,
  path: string,
  allowed: T,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new Error(`${path} must be one of ${allowed.join(", ")}.`);
  }
  return value as T[number];
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function computeDesiredStateDigest(intent: CodeflyBootstrapIntent): string {
  const { status: _status, ...desiredState } = intent;
  const { desiredStateDigest: _digest, ...seed } = desiredState.seed;
  return createHash("sha256")
    .update(canonicalJson({ ...desiredState, seed }))
    .digest("hex");
}
