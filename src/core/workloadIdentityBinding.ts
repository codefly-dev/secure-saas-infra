import { createHash } from "node:crypto";

export const WORKLOAD_IDENTITY_BINDING_API_VERSION =
  "security.deus.dev/workload-identity-binding/v1alpha1" as const;

export type WorkloadIdentityEnvironment =
  | "development"
  | "staging"
  | "production";

export interface WorkloadIdentityBinding {
  apiVersion: typeof WORKLOAD_IDENTITY_BINDING_API_VERSION;
  kind: "WorkloadIdentityBinding";
  id: string;
  organizationId: string;
  platformTenantId: string;
  applicationId: string;
  environment: WorkloadIdentityEnvironment;
  cloudContext: {
    id: string;
    generation: number;
  };
  identityId: string;
  kubernetes: {
    clusterUid: string;
    namespace: string;
    serviceAccount: string;
    oidcSubject: string;
    spiffeTrustDomain: string;
    spiffeId: string;
    audience: string;
    automountServiceAccountToken: false;
  };
  cloud: {
    provider: "aws" | "gcp" | "azure";
    roleRef: string;
    maxSessionDurationSeconds: number;
    administrator: false;
    shared: false;
  };
  allowedResourceIds: readonly string[];
  networkBoundary: {
    id: string;
    attachmentKind: "pod-security-group";
    providerResourceRef: string;
    enforcingMode: "strict";
  };
  evidence: {
    bindingDigest: string;
    verificationEvidenceRef: string;
    verificationEvidenceDigest: string;
    verifiedAt: string;
    expiresAt: string;
  };
}

export interface WorkloadIdentityBindingCatalog {
  apiVersion: typeof WORKLOAD_IDENTITY_BINDING_API_VERSION;
  kind: "WorkloadIdentityBindingCatalog";
  bindings: readonly WorkloadIdentityBinding[];
}

export interface WorkloadIdentityPlacement {
  organizationId: string;
  platformTenantId: string;
  applicationId: string;
  environment: WorkloadIdentityEnvironment;
  cloudContextId: string;
  cloudContextGeneration: number;
  identityId: string;
  namespace: string;
  serviceAccount: string;
}

export function parseWorkloadIdentityBinding(
  value: unknown,
): WorkloadIdentityBinding {
  const input = exactObject(value, "workloadIdentityBinding", [
    "apiVersion",
    "kind",
    "id",
    "organizationId",
    "platformTenantId",
    "applicationId",
    "environment",
    "cloudContext",
    "identityId",
    "kubernetes",
    "cloud",
    "allowedResourceIds",
    "networkBoundary",
    "evidence",
  ]);
  const context = exactObject(input.cloudContext, "cloudContext", [
    "id",
    "generation",
  ]);
  const kubernetes = exactObject(input.kubernetes, "kubernetes", [
    "clusterUid",
    "namespace",
    "serviceAccount",
    "oidcSubject",
    "spiffeTrustDomain",
    "spiffeId",
    "audience",
    "automountServiceAccountToken",
  ]);
  const cloud = exactObject(input.cloud, "cloud", [
    "provider",
    "roleRef",
    "maxSessionDurationSeconds",
    "administrator",
    "shared",
  ]);
  const network = exactObject(input.networkBoundary, "networkBoundary", [
    "id",
    "attachmentKind",
    "providerResourceRef",
    "enforcingMode",
  ]);
  const evidence = exactObject(input.evidence, "evidence", [
    "bindingDigest",
    "verificationEvidenceRef",
    "verificationEvidenceDigest",
    "verifiedAt",
    "expiresAt",
  ]);
  const binding: WorkloadIdentityBinding = {
    apiVersion: literal(
      input.apiVersion,
      "apiVersion",
      WORKLOAD_IDENTITY_BINDING_API_VERSION,
    ),
    kind: literal(input.kind, "kind", "WorkloadIdentityBinding"),
    id: kubernetesLabelValue(input.id, "id"),
    organizationId: identifier(input.organizationId, "organizationId"),
    platformTenantId: identifier(input.platformTenantId, "platformTenantId"),
    applicationId: identifier(input.applicationId, "applicationId"),
    environment: enumValue(input.environment, "environment", [
      "development",
      "staging",
      "production",
    ]),
    cloudContext: {
      id: identifier(context.id, "cloudContext.id"),
      generation: positiveInteger(
        context.generation,
        "cloudContext.generation",
      ),
    },
    identityId: identifier(input.identityId, "identityId"),
    kubernetes: {
      clusterUid: identifier(kubernetes.clusterUid, "kubernetes.clusterUid"),
      namespace: dnsLabel(kubernetes.namespace, "kubernetes.namespace"),
      serviceAccount: dnsLabel(
        kubernetes.serviceAccount,
        "kubernetes.serviceAccount",
      ),
      oidcSubject: exactSubject(
        kubernetes.oidcSubject,
        "kubernetes.oidcSubject",
      ),
      spiffeTrustDomain: trustDomain(
        kubernetes.spiffeTrustDomain,
        "kubernetes.spiffeTrustDomain",
      ),
      spiffeId: exactSpiffeId(kubernetes.spiffeId, "kubernetes.spiffeId"),
      audience: exactAudience(kubernetes.audience, "kubernetes.audience"),
      automountServiceAccountToken: literal(
        kubernetes.automountServiceAccountToken,
        "kubernetes.automountServiceAccountToken",
        false,
      ),
    },
    cloud: {
      provider: enumValue(cloud.provider, "cloud.provider", [
        "aws",
        "gcp",
        "azure",
      ]),
      roleRef: exactProviderResource(cloud.roleRef, "cloud.roleRef"),
      maxSessionDurationSeconds: boundedInteger(
        cloud.maxSessionDurationSeconds,
        "cloud.maxSessionDurationSeconds",
        900,
        3600,
      ),
      administrator: literal(cloud.administrator, "cloud.administrator", false),
      shared: literal(cloud.shared, "cloud.shared", false),
    },
    allowedResourceIds: nonEmptyUniqueArray(
      input.allowedResourceIds,
      "allowedResourceIds",
      identifier,
    ),
    networkBoundary: {
      id: identifier(network.id, "networkBoundary.id"),
      attachmentKind: literal(
        network.attachmentKind,
        "networkBoundary.attachmentKind",
        "pod-security-group",
      ),
      providerResourceRef: exactReference(
        network.providerResourceRef,
        "networkBoundary.providerResourceRef",
      ),
      enforcingMode: literal(
        network.enforcingMode,
        "networkBoundary.enforcingMode",
        "strict",
      ),
    },
    evidence: {
      bindingDigest: digest(evidence.bindingDigest, "evidence.bindingDigest"),
      verificationEvidenceRef: exactReference(
        evidence.verificationEvidenceRef,
        "evidence.verificationEvidenceRef",
      ),
      verificationEvidenceDigest: digest(
        evidence.verificationEvidenceDigest,
        "evidence.verificationEvidenceDigest",
      ),
      verifiedAt: timestamp(evidence.verifiedAt, "evidence.verifiedAt"),
      expiresAt: timestamp(evidence.expiresAt, "evidence.expiresAt"),
    },
  };
  assertBindingSemantics(binding);
  return binding;
}

export function parseWorkloadIdentityBindingCatalog(
  value: unknown,
): WorkloadIdentityBindingCatalog {
  const input = exactObject(value, "workloadIdentityBindingCatalog", [
    "apiVersion",
    "kind",
    "bindings",
  ]);
  const catalog: WorkloadIdentityBindingCatalog = {
    apiVersion: literal(
      input.apiVersion,
      "apiVersion",
      WORKLOAD_IDENTITY_BINDING_API_VERSION,
    ),
    kind: literal(input.kind, "kind", "WorkloadIdentityBindingCatalog"),
    bindings: nonEmptyUniqueArray(
      input.bindings,
      "bindings",
      parseWorkloadIdentityBinding,
    ),
  };
  assertWorkloadIdentityBindingCatalog(catalog);
  return catalog;
}

export function assertWorkloadIdentityBindingCatalog(
  catalog: WorkloadIdentityBindingCatalog,
): void {
  const seen = new Map<string, string>();
  for (const binding of catalog.bindings) {
    for (const [label, value] of [
      ["binding ID", binding.id],
      ["Kubernetes subject", binding.kubernetes.oidcSubject],
      [
        "Kubernetes ServiceAccount",
        `${binding.kubernetes.clusterUid}/${binding.kubernetes.namespace}/${binding.kubernetes.serviceAccount}`,
      ],
      ["cloud role", `${binding.cloud.provider}/${binding.cloud.roleRef}`],
      [
        "network boundary",
        `${binding.cloud.provider}/${binding.networkBoundary.providerResourceRef}`,
      ],
    ] as const) {
      const key = `${label}:${value}`;
      const owner = seen.get(key);
      if (owner) {
        throw new Error(
          `Workload identity ${label} '${value}' is shared by bindings '${owner}' and '${binding.id}'.`,
        );
      }
      seen.set(key, binding.id);
    }
  }
}

export function selectWorkloadIdentityBinding(
  catalog: WorkloadIdentityBindingCatalog,
  placement: WorkloadIdentityPlacement,
): WorkloadIdentityBinding {
  assertWorkloadIdentityBindingCatalog(catalog);
  const matches = catalog.bindings.filter(
    (binding) =>
      binding.organizationId === placement.organizationId &&
      binding.platformTenantId === placement.platformTenantId &&
      binding.applicationId === placement.applicationId &&
      binding.environment === placement.environment &&
      binding.cloudContext.id === placement.cloudContextId &&
      binding.cloudContext.generation === placement.cloudContextGeneration &&
      binding.identityId === placement.identityId &&
      binding.kubernetes.namespace === placement.namespace &&
      binding.kubernetes.serviceAccount === placement.serviceAccount,
  );
  if (matches.length !== 1) {
    throw new Error(
      `Workload identity placement must select exactly one binding; found ${matches.length}.`,
    );
  }
  return matches[0];
}

export function workloadIdentityBindingDigest(
  binding: Omit<WorkloadIdentityBinding, "evidence">,
): string {
  return createHash("sha256").update(canonicalJson(binding)).digest("hex");
}

function assertBindingSemantics(binding: WorkloadIdentityBinding): void {
  const expectedSubject = `system:serviceaccount:${binding.kubernetes.namespace}:${binding.kubernetes.serviceAccount}`;
  if (binding.kubernetes.oidcSubject !== expectedSubject) {
    throw new Error(
      `kubernetes.oidcSubject must exactly match namespace and ServiceAccount '${expectedSubject}'.`,
    );
  }
  const expectedSpiffeId = `spiffe://${binding.kubernetes.spiffeTrustDomain}/ns/${binding.kubernetes.namespace}/sa/${binding.kubernetes.serviceAccount}`;
  if (binding.kubernetes.spiffeId !== expectedSpiffeId) {
    throw new Error(
      `kubernetes.spiffeId must exactly match namespace and ServiceAccount '${expectedSpiffeId}'.`,
    );
  }
  const expectedDigest = workloadIdentityBindingDigest(
    withoutEvidence(binding),
  );
  if (binding.evidence.bindingDigest !== expectedDigest) {
    throw new Error(
      "evidence.bindingDigest does not match the exact workload identity binding.",
    );
  }
  if (
    Date.parse(binding.evidence.expiresAt) <=
    Date.parse(binding.evidence.verifiedAt)
  ) {
    throw new Error("evidence.expiresAt must be after evidence.verifiedAt.");
  }
}

function withoutEvidence(
  binding: WorkloadIdentityBinding,
): Omit<WorkloadIdentityBinding, "evidence"> {
  const { evidence: _evidence, ...subject } = binding;
  return subject;
}

function exactObject(
  value: unknown,
  path: string,
  keys: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  const actual = Object.keys(input).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${path} must contain exactly: ${expected.join(", ")}.`);
  }
  return input;
}

function literal<T extends string | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected)
    throw new Error(`${path} must be ${String(expected)}.`);
  return expected;
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function identifier(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^[a-z][a-z0-9._:-]*$/.test(value) ||
    value.includes("..") ||
    value.includes("*")
  ) {
    throw new Error(`${path} must be a safe exact identifier.`);
  }
  return value;
}

function dnsLabel(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact Kubernetes DNS label.`);
  }
  return value;
}

function kubernetesLabelValue(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(value)
  ) {
    throw new Error(`${path} must be a Kubernetes label-safe value.`);
  }
  return value;
}

function exactSubject(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^system:serviceaccount:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(
      value,
    ) ||
    value.includes("*")
  ) {
    throw new Error(`${path} must be an exact Kubernetes OIDC subject.`);
  }
  return value;
}

function trustDomain(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact SPIFFE trust domain.`);
  }
  return value;
}

function exactSpiffeId(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !/^spiffe:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\/ns\/[a-z0-9.-]+\/sa\/[a-z0-9.-]+$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact SPIFFE ID.`);
  }
  return value;
}

function exactAudience(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact OIDC audience.`);
  }
  return value;
}

function exactProviderResource(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/=-]*$/.test(value) ||
    value.includes("*") ||
    value.includes("..") ||
    /(?:password|secret|credential|access[_-]?key|session[_-]?token)/i.test(
      value,
    )
  ) {
    throw new Error(
      `${path} must be an exact credential-free provider resource.`,
    );
  }
  return value;
}

function exactReference(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~:/-]+$/.test(value) ||
    value.includes("@") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("*") ||
    value.includes("..") ||
    /(?:password|secret|credential|access[_-]?key|session[_-]?token)/i.test(
      value,
    )
  ) {
    throw new Error(`${path} must be a credential-free exact reference URI.`);
  }
  return value;
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${path} must be a positive integer.`);
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
    !Number.isSafeInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new Error(`${path} must be between ${minimum} and ${maximum}.`);
  }
  return value as number;
}

function nonEmptyUniqueArray<T>(
  value: unknown,
  path: string,
  parse: (value: unknown, path: string) => T,
): readonly T[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array.`);
  }
  const result = value.map((entry, index) => parse(entry, `${path}[${index}]`));
  if (
    new Set(result.map((entry) => canonicalJson(entry))).size !== result.length
  ) {
    throw new Error(`${path} must contain unique entries.`);
  }
  return result;
}

function digest(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error(`${path} must be a lowercase SHA-256 digest.`);
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
  const canonical = new Date(Date.parse(value)).toISOString();
  if (value !== canonical && value !== canonical.replace(".000Z", "Z")) {
    throw new Error(`${path} must be a canonical calendar timestamp.`);
  }
  return value;
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
