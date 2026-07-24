import { createHash } from "node:crypto";
import {
  assertAuthenticVerifiedCloudContextPlacement,
  type VerifiedCloudContextPlacement,
} from "./cloudContextVerification";
import {
  assertAuthenticVerifiedPostgresAccessDecision,
  type VerifiedPostgresAccessDecision,
} from "./postgresAccessObservation";

export interface VerifiedRuntimeDeploymentAdmission {
  state: "admitted";
  admitted: true;
  organizationId: string;
  platformTenantId: string;
  environment: "development" | "staging" | "production";
  applicationId: string;
  componentId: string;
  requestDigest: string;
  placementDigest: string;
  cloudContextDecisionDigest: string;
  resources: readonly {
    kind: "ManagedPostgres";
    bindingId: string;
    accessClass: "runtime";
    profileId: string;
    profileSpecDigest: string;
    handoffSpecDigest: string;
    evidenceDigest: string;
    decisionDigest: string;
  }[];
  evaluatedAt: string;
  expiresAt: string;
  decisionDigest: string;
}

export function assertRuntimeDeploymentAdmission(args: {
  cloudContext: VerifiedCloudContextPlacement;
  postgres: readonly VerifiedPostgresAccessDecision[];
  now: string;
}): VerifiedRuntimeDeploymentAdmission {
  const now = timestamp(args.now, "now");
  assertAuthenticVerifiedCloudContextPlacement(args.cloudContext);
  const cloud = args.cloudContext;
  assertActiveDecision(
    cloud.evaluatedAt,
    cloud.expiresAt,
    now,
    "cloud-context",
  );

  const selectedBindings = cloud.dependencies
    .filter((dependency) => dependency.kind === "resource-binding")
    .map((dependency) => dependency.id)
    .sort();
  const placementBindings = [...cloud.placement.resourceBindingIds].sort();
  assertExactInventory(
    selectedBindings,
    placementBindings,
    "DEPLOYMENT_ADMISSION_CLOUD_BINDING_MISMATCH",
    "verified dependency closure does not exactly match placement resource bindings",
  );

  const postgresByBinding = new Map<string, VerifiedPostgresAccessDecision>();
  for (const decision of args.postgres) {
    assertAuthenticVerifiedPostgresAccessDecision(decision);
    assertActiveDecision(
      decision.evaluatedAt,
      decision.expiresAt,
      now,
      `PostgreSQL binding '${decision.bindingId}'`,
    );
    if (decision.accessClass !== "runtime") {
      fail(
        "DEPLOYMENT_ADMISSION_ACCESS_CLASS_DENIED",
        `application runtime admission cannot consume '${decision.accessClass}' access for '${decision.bindingId}'`,
      );
    }
    if (postgresByBinding.has(decision.bindingId)) {
      fail(
        "DEPLOYMENT_ADMISSION_DUPLICATE_RESOURCE",
        `PostgreSQL binding '${decision.bindingId}' has more than one runtime readiness decision`,
      );
    }
    postgresByBinding.set(decision.bindingId, decision);
  }
  assertExactInventory(
    [...postgresByBinding.keys()].sort(),
    selectedBindings,
    "DEPLOYMENT_ADMISSION_RESOURCE_SET_MISMATCH",
    "PostgreSQL runtime readiness decisions do not exactly cover the selected resource bindings",
  );

  const resources = selectedBindings.map((bindingId) => {
    const decision = postgresByBinding.get(bindingId)!;
    return {
      kind: "ManagedPostgres" as const,
      bindingId,
      accessClass: "runtime" as const,
      profileId: decision.profileId,
      profileSpecDigest: decision.profileSpecDigest,
      handoffSpecDigest: decision.handoffSpecDigest,
      evidenceDigest: decision.evidenceDigest,
      decisionDigest: decision.decisionDigest,
    };
  });
  const expiresAt = [
    cloud.expiresAt,
    ...args.postgres.map((decision) => decision.expiresAt),
  ].sort()[0]!;
  const subject = {
    state: "admitted" as const,
    admitted: true as const,
    organizationId: cloud.organizationId,
    platformTenantId: cloud.platformTenantId,
    environment: cloud.environment,
    applicationId: cloud.applicationId,
    componentId: cloud.componentId,
    requestDigest: cloud.requestDigest,
    placementDigest: cloud.placementDigest,
    cloudContextDecisionDigest: cloud.decisionDigest,
    resources,
    evaluatedAt: now,
    expiresAt,
  };
  return {
    ...subject,
    decisionDigest: sha256(canonicalJson(subject)),
  };
}

function assertActiveDecision(
  evaluatedAtValue: string,
  expiresAtValue: string,
  nowValue: string,
  label: string,
): void {
  const evaluatedAt = timestamp(evaluatedAtValue, `${label}.evaluatedAt`);
  const expiresAt = timestamp(expiresAtValue, `${label}.expiresAt`);
  const now = Date.parse(nowValue);
  if (Date.parse(evaluatedAt) > now) {
    fail(
      "DEPLOYMENT_ADMISSION_FUTURE_DECISION",
      `${label} readiness decision is future-dated`,
    );
  }
  if (Date.parse(expiresAt) <= now) {
    fail(
      "DEPLOYMENT_ADMISSION_EXPIRED_DECISION",
      `${label} readiness decision has expired`,
    );
  }
}

function assertExactInventory(
  actual: readonly string[],
  expected: readonly string[],
  code: string,
  message: string,
): void {
  if (
    new Set(actual).size !== actual.length ||
    new Set(expected).size !== expected.length ||
    canonicalJson(actual) !== canonicalJson(expected)
  ) {
    fail(code, message);
  }
}

function timestamp(value: unknown, path: string): string {
  if (typeof value !== "string")
    fail("DEPLOYMENT_ADMISSION_TIME", `${path} must be a timestamp`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail(
      "DEPLOYMENT_ADMISSION_TIME",
      `${path} must be a canonical calendar timestamp`,
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fail(code: string, message: string): never {
  throw new Error(`${code}: ${message}`);
}
