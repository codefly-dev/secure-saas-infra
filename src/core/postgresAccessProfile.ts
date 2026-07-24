import { createHash } from "node:crypto";
import { assertCredentialFreeJson } from "./credentialFree";

export const POSTGRES_ACCESS_PROFILE_API_VERSION =
  "security.deus.dev/postgres-access-profile/v1alpha1" as const;

export type PostgresAccessClass = "runtime" | "migration";
export type PostgresAccessBlocker =
  | "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED"
  | "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED"
  | "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED";

export interface PostgresAccessProfile {
  apiVersion: typeof POSTGRES_ACCESS_PROFILE_API_VERSION;
  kind: "PostgresAccessProfile";
  id: string;
  bindingId: string;
  profileSpecDigest: string;
  application: {
    applicationId: string;
    componentId: string;
    serviceRef: string;
    dataBoundaryId: string;
  };
  accessClass: PostgresAccessClass;
  connection: {
    endpoint: string;
    port: 5432;
    databaseName: string;
    tls: {
      mode: "verify-full";
      caCertIdentifier: string;
      caBundleRef: string;
    };
  };
  authentication: {
    kind: "aws-rds-iam";
    region: string;
    target: "rds-proxy";
    resourceId: string;
    databaseUser: string;
    tokenDelivery: "per-physical-connection";
  };
  identity: {
    semanticIdentityId: string;
    roleArn: string;
    namespace: string;
    serviceAccount: string;
    podIdentityAssociationId: string;
  };
  network: {
    securityGroupId: string;
    exposure: "private";
    sourceBoundaryMode: "exact-pod-security-group";
  };
  enforcement: {
    bindingDigest: string;
    workloadBundleDigest: string;
    requiredPodLabels: Readonly<Record<string, string>>;
    requiredPodAnnotations: Readonly<Record<string, string>>;
    requiredPodScheduling: {
      nodeSelector: Readonly<Record<string, string>>;
      tolerations: ReadonlyArray<{
        key: string;
        operator: "Equal";
        value: string;
        effect: "NoSchedule";
      }>;
    };
  };
  readiness: {
    state: "pending-infrastructure";
    ready: false;
    blockers: readonly PostgresAccessBlocker[];
    evidenceRefs: readonly [];
  };
  credentials: null;
}

export function parsePostgresAccessProfile(
  value: unknown,
): PostgresAccessProfile {
  assertCredentialFreeJson(value, {
    code: "POSTGRES_ACCESS_PROFILE_CREDENTIAL_MATERIAL",
    path: "postgresAccessProfile",
    allowedNullKeys: ["credentials"],
  });
  const input = exactObject(value, "postgresAccessProfile", [
    "apiVersion",
    "kind",
    "id",
    "bindingId",
    "profileSpecDigest",
    "application",
    "accessClass",
    "connection",
    "authentication",
    "identity",
    "network",
    "enforcement",
    "readiness",
    "credentials",
  ]);
  const application = exactObject(input.application, "application", [
    "applicationId",
    "componentId",
    "serviceRef",
    "dataBoundaryId",
  ]);
  const connection = exactObject(input.connection, "connection", [
    "endpoint",
    "port",
    "databaseName",
    "tls",
  ]);
  const tls = exactObject(connection.tls, "connection.tls", [
    "mode",
    "caCertIdentifier",
    "caBundleRef",
  ]);
  const authentication = exactObject(input.authentication, "authentication", [
    "kind",
    "region",
    "target",
    "resourceId",
    "databaseUser",
    "tokenDelivery",
  ]);
  const identity = exactObject(input.identity, "identity", [
    "semanticIdentityId",
    "roleArn",
    "namespace",
    "serviceAccount",
    "podIdentityAssociationId",
  ]);
  const network = exactObject(input.network, "network", [
    "securityGroupId",
    "exposure",
    "sourceBoundaryMode",
  ]);
  const enforcement = exactObject(input.enforcement, "enforcement", [
    "bindingDigest",
    "workloadBundleDigest",
    "requiredPodLabels",
    "requiredPodAnnotations",
    "requiredPodScheduling",
  ]);
  const scheduling = exactObject(
    enforcement.requiredPodScheduling,
    "enforcement.requiredPodScheduling",
    ["nodeSelector", "tolerations"],
  );
  const readiness = exactObject(input.readiness, "readiness", [
    "state",
    "ready",
    "blockers",
    "evidenceRefs",
  ]);
  const accessClass = oneOf(input.accessClass, "accessClass", [
    "runtime",
    "migration",
  ] as const);
  const profile: PostgresAccessProfile = {
    apiVersion: exact(
      input.apiVersion,
      "apiVersion",
      POSTGRES_ACCESS_PROFILE_API_VERSION,
    ),
    kind: exact(input.kind, "kind", "PostgresAccessProfile"),
    id: identifier(input.id, "id"),
    bindingId: identifier(input.bindingId, "bindingId"),
    profileSpecDigest: digest(input.profileSpecDigest, "profileSpecDigest"),
    application: {
      applicationId: identifier(
        application.applicationId,
        "application.applicationId",
      ),
      componentId: identifier(
        application.componentId,
        "application.componentId",
      ),
      serviceRef: serviceRef(application.serviceRef),
      dataBoundaryId: identifier(
        application.dataBoundaryId,
        "application.dataBoundaryId",
      ),
    },
    accessClass,
    connection: {
      endpoint: hostname(connection.endpoint, "connection.endpoint"),
      port: exact(connection.port, "connection.port", 5432),
      databaseName: postgresIdentifier(
        connection.databaseName,
        "connection.databaseName",
      ),
      tls: {
        mode: exact(tls.mode, "connection.tls.mode", "verify-full"),
        caCertIdentifier: nonEmpty(
          tls.caCertIdentifier,
          "connection.tls.caCertIdentifier",
          128,
        ),
        caBundleRef: exactReference(
          tls.caBundleRef,
          "connection.tls.caBundleRef",
        ),
      },
    },
    authentication: {
      kind: exact(authentication.kind, "authentication.kind", "aws-rds-iam"),
      region: awsRegion(authentication.region, "authentication.region"),
      target: exact(
        authentication.target,
        "authentication.target",
        "rds-proxy",
      ),
      resourceId: rdsProxyResourceId(authentication.resourceId),
      databaseUser: postgresIdentifier(
        authentication.databaseUser,
        "authentication.databaseUser",
      ),
      tokenDelivery: exact(
        authentication.tokenDelivery,
        "authentication.tokenDelivery",
        "per-physical-connection",
      ),
    },
    identity: {
      semanticIdentityId: identifier(
        identity.semanticIdentityId,
        "identity.semanticIdentityId",
      ),
      roleArn: exactRoleArn(identity.roleArn),
      namespace: dnsLabel(identity.namespace, "identity.namespace"),
      serviceAccount: dnsLabel(
        identity.serviceAccount,
        "identity.serviceAccount",
      ),
      podIdentityAssociationId: nonEmpty(
        identity.podIdentityAssociationId,
        "identity.podIdentityAssociationId",
        128,
      ),
    },
    network: {
      securityGroupId: securityGroupId(network.securityGroupId),
      exposure: exact(network.exposure, "network.exposure", "private"),
      sourceBoundaryMode: exact(
        network.sourceBoundaryMode,
        "network.sourceBoundaryMode",
        "exact-pod-security-group",
      ),
    },
    enforcement: {
      bindingDigest: digest(enforcement.bindingDigest, "bindingDigest"),
      workloadBundleDigest: digest(
        enforcement.workloadBundleDigest,
        "workloadBundleDigest",
      ),
      requiredPodLabels: exactStringMap(
        enforcement.requiredPodLabels,
        "enforcement.requiredPodLabels",
      ),
      requiredPodAnnotations: exactStringMap(
        enforcement.requiredPodAnnotations,
        "enforcement.requiredPodAnnotations",
      ),
      requiredPodScheduling: {
        nodeSelector: exactStringMap(
          scheduling.nodeSelector,
          "enforcement.requiredPodScheduling.nodeSelector",
        ),
        tolerations: nonEmptyArray(
          scheduling.tolerations,
          "enforcement.requiredPodScheduling.tolerations",
          (entry, index) => parseToleration(entry, index),
        ),
      },
    },
    readiness: {
      state: exact(
        readiness.state,
        "readiness.state",
        "pending-infrastructure",
      ),
      ready: exact(readiness.ready, "readiness.ready", false),
      blockers: uniqueArray(
        readiness.blockers,
        "readiness.blockers",
        (entry, index) =>
          oneOf(entry, `readiness.blockers[${index}]`, [
            "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
            "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
            "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
          ] as const),
      ),
      evidenceRefs: exactEmptyArray(
        readiness.evidenceRefs,
        "readiness.evidenceRefs",
      ),
    },
    credentials: exact(input.credentials, "credentials", null),
  };
  assertSemantics(profile);
  return profile;
}

function assertSemantics(profile: PostgresAccessProfile) {
  if (profile.id !== `${profile.bindingId}-${profile.accessClass}`) {
    throw new Error("id must exactly bind bindingId and accessClass.");
  }
  const [, module] = profile.application.serviceRef.split("/");
  if (module !== profile.application.componentId) {
    throw new Error(
      "application.serviceRef must bind the exact application component.",
    );
  }
  if (
    profile.enforcement.requiredPodAnnotations[
      "security.deus.dev/workload-identity-binding-digest"
    ] !== profile.enforcement.bindingDigest
  ) {
    throw new Error(
      "requiredPodAnnotations must carry the exact workload identity binding digest.",
    );
  }
  if (!exactPendingBlockers(profile.readiness.blockers)) {
    throw new Error(
      "pending-infrastructure requires the exact fail-closed blocker set.",
    );
  }
  if (profile.profileSpecDigest !== postgresAccessProfileSpecDigest(profile)) {
    throw new Error(
      "profileSpecDigest must bind the exact credential-free access profile specification.",
    );
  }
}

export type PostgresAccessProfileDigestSubject = Omit<
  PostgresAccessProfile,
  "profileSpecDigest" | "readiness" | "credentials"
>;

export function postgresAccessProfileSpecDigest(
  profile: PostgresAccessProfileDigestSubject | PostgresAccessProfile,
): string {
  const {
    profileSpecDigest: _profileSpecDigest,
    readiness: _readiness,
    credentials: _credentials,
    ...subject
  } = profile as PostgresAccessProfile;
  return createHash("sha256").update(canonicalJson(subject)).digest("hex");
}

function exactPendingBlockers(
  blockers: readonly PostgresAccessBlocker[],
): boolean {
  const expected: readonly PostgresAccessBlocker[] = [
    "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
    "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
    "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
  ];
  return JSON.stringify(blockers) === JSON.stringify(expected);
}

function parseToleration(value: unknown, index: number) {
  const path = `enforcement.requiredPodScheduling.tolerations[${index}]`;
  const input = exactObject(value, path, [
    "key",
    "operator",
    "value",
    "effect",
  ]);
  return {
    key: nonEmpty(input.key, `${path}.key`, 253),
    operator: exact(input.operator, `${path}.operator`, "Equal"),
    value: nonEmpty(input.value, `${path}.value`, 63),
    effect: exact(input.effect, `${path}.effect`, "NoSchedule"),
  } as const;
}

function exactObject(value: unknown, path: string, keys: readonly string[]) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${path} must have exactly: ${expected.join(", ")}.`);
  }
  return record;
}

function exact<T>(value: unknown, path: string, expected: T): T {
  if (value !== expected)
    throw new Error(`${path} must equal ${String(expected)}.`);
  return expected;
}

function nonEmpty(value: unknown, path: string, maxLength = 512): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    throw new Error(`${path} must be a non-empty bounded string.`);
  }
  return value;
}

function identifier(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(result)) {
    throw new Error(`${path} must be an exact identifier.`);
  }
  return result;
}

function dnsLabel(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (result.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(result)) {
    throw new Error(`${path} must be a Kubernetes DNS label.`);
  }
  return result;
}

function postgresIdentifier(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(result)) {
    throw new Error(`${path} must be a PostgreSQL identifier.`);
  }
  return result;
}

function serviceRef(value: unknown): string {
  const result = nonEmpty(value, "application.serviceRef");
  if (!/^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/.test(result)) {
    throw new Error(
      "application.serviceRef must be workspace/component/service.",
    );
  }
  return result;
}

function hostname(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (
    result.length > 253 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(result) ||
    !result.includes(".")
  ) {
    throw new Error(`${path} must be one exact DNS hostname.`);
  }
  return result;
}

function awsRegion(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(result)) {
    throw new Error(`${path} must be one exact AWS region.`);
  }
  return result;
}

function rdsProxyResourceId(value: unknown): string {
  const result = nonEmpty(value, "authentication.resourceId");
  if (!/^prx-[a-z0-9]{17}$/.test(result)) {
    throw new Error(
      "authentication.resourceId must be one RDS Proxy resource ID.",
    );
  }
  return result;
}

function exactRoleArn(value: unknown): string {
  const result = nonEmpty(value, "identity.roleArn");
  if (
    !/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(
      result,
    )
  ) {
    throw new Error("identity.roleArn must be one exact IAM role ARN.");
  }
  return result;
}

function securityGroupId(value: unknown): string {
  const result = nonEmpty(value, "network.securityGroupId");
  if (!/^sg-[a-f0-9]{17}$/.test(result)) {
    throw new Error(
      "network.securityGroupId must be one exact security group ID.",
    );
  }
  return result;
}

function digest(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (!/^[a-f0-9]{64}$/.test(result)) {
    throw new Error(`${path} must be a lowercase SHA-256 digest.`);
  }
  return result;
}

function exactReference(value: unknown, path: string): string {
  const result = nonEmpty(value, path);
  if (!/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9][A-Za-z0-9._:/=-]*$/.test(result)) {
    throw new Error(`${path} must be one opaque exact reference.`);
  }
  return result;
}

function exactStringMap(value: unknown, path: string): Record<string, string> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const entries = Object.entries(value);
  if (entries.length === 0) throw new Error(`${path} must not be empty.`);
  const result: Record<string, string> = {};
  for (const [key, entry] of entries) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > 512) {
      throw new Error(`${path}.${key} must be a non-empty bounded string.`);
    }
    result[key] = entry;
  }
  return result;
}

function oneOf<const T extends readonly string[]>(
  value: unknown,
  path: string,
  choices: T,
): T[number] {
  if (typeof value !== "string" || !choices.includes(value)) {
    throw new Error(`${path} must be one of ${choices.join(", ")}.`);
  }
  return value as T[number];
}

function uniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, index: number) => T,
): T[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  const result = value.map(parse);
  if (
    new Set(result.map((entry) => JSON.stringify(entry))).size !== result.length
  ) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return result;
}

function nonEmptyArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, index: number) => T,
): T[] {
  const result = uniqueArray(value, path, parse);
  if (result.length === 0) throw new Error(`${path} must not be empty.`);
  return result;
}

function exactEmptyArray(value: unknown, path: string): readonly [] {
  if (!Array.isArray(value) || value.length !== 0) {
    throw new Error(`${path} must be an empty array in v1alpha1.`);
  }
  return [];
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
