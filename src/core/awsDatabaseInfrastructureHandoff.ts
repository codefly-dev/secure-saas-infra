import { createHash } from "node:crypto";
import { assertCredentialFreeJson } from "./credentialFree";

export const AWS_DATABASE_INFRASTRUCTURE_HANDOFF_API_VERSION =
  "infrastructure.deus.dev/aws-database-infrastructure-handoff/v1alpha1" as const;

const accessClasses = ["runtime", "migration", "bootstrap"] as const;

export interface ParsedAwsDatabaseInfrastructureHandoff {
  apiVersion: typeof AWS_DATABASE_INFRASTRUCTURE_HANDOFF_API_VERSION;
  kind: "AwsDatabaseInfrastructureHandoff";
  bindingId: string;
  handoffSpecDigest: string;
  owner: "external-iac";
  authorizedConsumer: "infrastructure-controller";
  applicationMutationAllowed: false;
  deploymentAuthorization: {
    state: "pending-identity-binding";
    directPodCreationAllowed: false;
    namespaceWriteAccess: "exclusive-controller";
    allowedWorkloadKinds: {
      runtime: readonly ["Deployment"];
      migration: readonly ["Job"];
      bootstrap: readonly ["Job"];
    };
    requiredActorEvidence: readonly [
      "exact-controller-service-account",
      "exact-source-repository-and-path",
      "namespace-rbac-denial-matrix",
      "direct-pod-creation-denied",
    ];
  };
  accessClasses: Record<
    (typeof accessClasses)[number],
    {
      namespace: string;
      serviceAccount: string;
      activationMode: "persistent" | "just-in-time";
      podIdentityAssociationId: string | null;
      bindingDigest: string;
      workloadBundleDigest: string;
      manifests: Record<string, unknown>;
    }
  >;
  readiness: {
    state: "pending-application";
    reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED";
    requiredEvidence: readonly [
      "namespace-observed",
      "service-account-observed",
      "admission-policy-enforced",
      "application-network-policy-enforced",
      "node-class-ready",
      "node-pool-ready",
      "pod-identity-association-observed",
      "deployment-authority-observed",
    ];
  };
}

export function parseAwsDatabaseInfrastructureHandoff(
  value: unknown,
): ParsedAwsDatabaseInfrastructureHandoff {
  assertPlainJson(value, "databaseInfrastructureHandoff");
  assertCredentialFreeJson(value, {
    code: "AWS_DB_HANDOFF_CREDENTIAL_MATERIAL",
    path: "databaseInfrastructureHandoff",
  });
  const input = exactObject(value, "handoff", [
    "apiVersion",
    "kind",
    "bindingId",
    "handoffSpecDigest",
    "owner",
    "authorizedConsumer",
    "applicationMutationAllowed",
    "deploymentAuthorization",
    "accessClasses",
    "readiness",
  ]);
  const authorization = exactObject(
    input.deploymentAuthorization,
    "handoff.deploymentAuthorization",
    [
      "state",
      "directPodCreationAllowed",
      "namespaceWriteAccess",
      "allowedWorkloadKinds",
      "requiredActorEvidence",
    ],
  );
  const allowedKinds = exactObject(
    authorization.allowedWorkloadKinds,
    "handoff.deploymentAuthorization.allowedWorkloadKinds",
    accessClasses,
  );
  const rawAccess = exactObject(
    input.accessClasses,
    "handoff.accessClasses",
    accessClasses,
  );
  const bindingId = identifier(input.bindingId, "handoff.bindingId");
  const parsedAccess = Object.fromEntries(
    accessClasses.map((accessClass) => {
      const path = `handoff.accessClasses.${accessClass}`;
      const entry = exactObject(rawAccess[accessClass], path, [
        "namespace",
        "serviceAccount",
        "activationMode",
        "podIdentityAssociationId",
        "bindingDigest",
        "workloadBundleDigest",
        "manifests",
      ]);
      const namespace = dnsLabel(entry.namespace, `${path}.namespace`);
      const serviceAccount = dnsLabel(
        entry.serviceAccount,
        `${path}.serviceAccount`,
      );
      const bindingDigest = digest(
        entry.bindingDigest,
        `${path}.bindingDigest`,
      );
      const workloadBundleDigest = digest(
        entry.workloadBundleDigest,
        `${path}.workloadBundleDigest`,
      );
      const manifests = nonEmptyObject(entry.manifests, `${path}.manifests`);
      assertManifestIdentity({
        manifests,
        namespace,
        serviceAccount,
        bindingDigest,
        bindingId,
        accessClass,
        path: `${path}.manifests`,
      });
      if (handoffDigest(manifests) !== workloadBundleDigest) {
        fail(
          "AWS_DB_HANDOFF_BUNDLE_DIGEST",
          `${path}.workloadBundleDigest must bind the exact manifest bundle`,
        );
      }
      const persistent = accessClass !== "bootstrap";
      return [
        accessClass,
        {
          namespace,
          serviceAccount,
          activationMode: exact(
            entry.activationMode,
            `${path}.activationMode`,
            persistent ? "persistent" : "just-in-time",
          ),
          podIdentityAssociationId: persistent
            ? opaque(
                entry.podIdentityAssociationId,
                `${path}.podIdentityAssociationId`,
              )
            : exact(
                entry.podIdentityAssociationId,
                `${path}.podIdentityAssociationId`,
                null,
              ),
          bindingDigest,
          workloadBundleDigest,
          manifests,
        },
      ];
    }),
  ) as ParsedAwsDatabaseInfrastructureHandoff["accessClasses"];
  const readiness = exactObject(input.readiness, "handoff.readiness", [
    "state",
    "reason",
    "requiredEvidence",
  ]);
  const parsed: ParsedAwsDatabaseInfrastructureHandoff = {
    apiVersion: exact(
      input.apiVersion,
      "handoff.apiVersion",
      AWS_DATABASE_INFRASTRUCTURE_HANDOFF_API_VERSION,
    ),
    kind: exact(input.kind, "handoff.kind", "AwsDatabaseInfrastructureHandoff"),
    bindingId,
    handoffSpecDigest: digest(
      input.handoffSpecDigest,
      "handoff.handoffSpecDigest",
    ),
    owner: exact(input.owner, "handoff.owner", "external-iac"),
    authorizedConsumer: exact(
      input.authorizedConsumer,
      "handoff.authorizedConsumer",
      "infrastructure-controller",
    ),
    applicationMutationAllowed: exact(
      input.applicationMutationAllowed,
      "handoff.applicationMutationAllowed",
      false,
    ),
    deploymentAuthorization: {
      state: exact(
        authorization.state,
        "handoff.deploymentAuthorization.state",
        "pending-identity-binding",
      ),
      directPodCreationAllowed: exact(
        authorization.directPodCreationAllowed,
        "handoff.deploymentAuthorization.directPodCreationAllowed",
        false,
      ),
      namespaceWriteAccess: exact(
        authorization.namespaceWriteAccess,
        "handoff.deploymentAuthorization.namespaceWriteAccess",
        "exclusive-controller",
      ),
      allowedWorkloadKinds: {
        runtime: exactArray(
          allowedKinds.runtime,
          "handoff.deploymentAuthorization.allowedWorkloadKinds.runtime",
          ["Deployment"],
        ),
        migration: exactArray(
          allowedKinds.migration,
          "handoff.deploymentAuthorization.allowedWorkloadKinds.migration",
          ["Job"],
        ),
        bootstrap: exactArray(
          allowedKinds.bootstrap,
          "handoff.deploymentAuthorization.allowedWorkloadKinds.bootstrap",
          ["Job"],
        ),
      },
      requiredActorEvidence: exactArray(
        authorization.requiredActorEvidence,
        "handoff.deploymentAuthorization.requiredActorEvidence",
        [
          "exact-controller-service-account",
          "exact-source-repository-and-path",
          "namespace-rbac-denial-matrix",
          "direct-pod-creation-denied",
        ],
      ),
    },
    accessClasses: parsedAccess,
    readiness: {
      state: exact(
        readiness.state,
        "handoff.readiness.state",
        "pending-application",
      ),
      reason: exact(
        readiness.reason,
        "handoff.readiness.reason",
        "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
      ),
      requiredEvidence: exactArray(
        readiness.requiredEvidence,
        "handoff.readiness.requiredEvidence",
        [
          "namespace-observed",
          "service-account-observed",
          "admission-policy-enforced",
          "application-network-policy-enforced",
          "node-class-ready",
          "node-pool-ready",
          "pod-identity-association-observed",
          "deployment-authority-observed",
        ],
      ),
    },
  };
  const { handoffSpecDigest, ...subject } = parsed;
  if (handoffSpecDigest !== handoffDigest(subject)) {
    fail(
      "AWS_DB_HANDOFF_SPEC_DIGEST",
      "handoffSpecDigest must bind the exact infrastructure handoff",
    );
  }
  return parsed;
}

export function awsDatabaseInfrastructureHandoffDigest(value: unknown): string {
  return parseAwsDatabaseInfrastructureHandoff(value).handoffSpecDigest;
}

function assertManifestIdentity(args: {
  manifests: Record<string, unknown>;
  namespace: string;
  serviceAccount: string;
  bindingDigest: string;
  bindingId: string;
  accessClass: (typeof accessClasses)[number];
  path: string;
}) {
  const namespace = nonEmptyObject(
    args.manifests.namespace,
    `${args.path}.namespace`,
  );
  const namespaceMetadata = nonEmptyObject(
    namespace.metadata,
    `${args.path}.namespace.metadata`,
  );
  if (namespaceMetadata.name !== args.namespace) {
    fail(
      "AWS_DB_HANDOFF_NAMESPACE_SUBSTITUTION",
      `${args.path}.namespace must bind the exact namespace`,
    );
  }
  const serviceAccount = nonEmptyObject(
    args.manifests.serviceAccount,
    `${args.path}.serviceAccount`,
  );
  const serviceAccountMetadata = nonEmptyObject(
    serviceAccount.metadata,
    `${args.path}.serviceAccount.metadata`,
  );
  if (
    serviceAccountMetadata.name !== args.serviceAccount ||
    serviceAccountMetadata.namespace !== args.namespace
  ) {
    fail(
      "AWS_DB_HANDOFF_SERVICE_ACCOUNT_SUBSTITUTION",
      `${args.path}.serviceAccount must bind the exact namespace and name`,
    );
  }
  const annotations = nonEmptyObject(
    args.manifests.requiredPodAnnotations,
    `${args.path}.requiredPodAnnotations`,
  );
  if (
    annotations["security.deus.dev/workload-identity-binding-digest"] !==
    args.bindingDigest
  ) {
    fail(
      "AWS_DB_HANDOFF_BINDING_DIGEST",
      `${args.path}.requiredPodAnnotations must carry the exact binding digest`,
    );
  }
  const applicationNetworkPolicy = nonEmptyObject(
    args.manifests.applicationNetworkPolicy,
    `${args.path}.applicationNetworkPolicy`,
  );
  const networkPolicyMetadata = nonEmptyObject(
    applicationNetworkPolicy.metadata,
    `${args.path}.applicationNetworkPolicy.metadata`,
  );
  if (networkPolicyMetadata.namespace !== args.namespace) {
    fail(
      "AWS_DB_HANDOFF_NETWORK_POLICY_SUBSTITUTION",
      `${args.path}.applicationNetworkPolicy must bind the exact namespace`,
    );
  }
  const nodeClass = nonEmptyObject(
    args.manifests.nodeClass,
    `${args.path}.nodeClass`,
  );
  const nodeClassMetadata = nonEmptyObject(
    nodeClass.metadata,
    `${args.path}.nodeClass.metadata`,
  );
  const nodePool = nonEmptyObject(
    args.manifests.nodePool,
    `${args.path}.nodePool`,
  );
  const nodePoolMetadata = nonEmptyObject(
    nodePool.metadata,
    `${args.path}.nodePool.metadata`,
  );
  const expectedManagedName = `${args.bindingId}-${args.accessClass}-access`;
  if (
    typeof nodeClassMetadata.name !== "string" ||
    nodeClassMetadata.name !== nodePoolMetadata.name ||
    nodeClassMetadata.name !== expectedManagedName
  ) {
    fail(
      "AWS_DB_HANDOFF_NODE_PLACEMENT_SUBSTITUTION",
      `${args.path}.nodeClass and nodePool must bind the same non-empty name`,
    );
  }
  const admissionPolicy = nonEmptyObject(
    args.manifests.admissionPolicy,
    `${args.path}.admissionPolicy`,
  );
  const admissionMetadata = nonEmptyObject(
    admissionPolicy.metadata,
    `${args.path}.admissionPolicy.metadata`,
  );
  if (
    admissionMetadata.name !== nodeClassMetadata.name ||
    networkPolicyMetadata.name !== nodeClassMetadata.name
  ) {
    fail(
      "AWS_DB_HANDOFF_NODE_PLACEMENT_SUBSTITUTION",
      `${args.path} admission, network, NodeClass, and NodePool resources must share one exact managed name`,
    );
  }
  const scheduling = nonEmptyObject(
    args.manifests.requiredPodScheduling,
    `${args.path}.requiredPodScheduling`,
  );
  const selector = nonEmptyObject(
    scheduling.nodeSelector,
    `${args.path}.requiredPodScheduling.nodeSelector`,
  );
  const selectorEntries = Object.entries(selector);
  const tolerations = scheduling.tolerations;
  if (
    selectorEntries.length !== 1 ||
    !selectorEntries[0][0].startsWith(
      "node-restriction.kubernetes.io/database-access-",
    ) ||
    !Array.isArray(tolerations) ||
    tolerations.length !== 1 ||
    tolerations[0]?.key !== selectorEntries[0][0] ||
    tolerations[0]?.value !== selectorEntries[0][1] ||
    tolerations[0]?.operator !== "Equal" ||
    tolerations[0]?.effect !== "NoSchedule"
  ) {
    fail(
      "AWS_DB_HANDOFF_NODE_PLACEMENT_SUBSTITUTION",
      `${args.path}.requiredPodScheduling must bind one NodeRestriction selector to its exact NoSchedule toleration`,
    );
  }
  for (const required of ["requiredPodLabels"]) {
    nonEmptyObject(args.manifests[required], `${args.path}.${required}`);
  }
}

function exactObject(value: unknown, path: string, keys: readonly string[]) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("AWS_DB_HANDOFF_OBJECT", `${path} must be an object`);
  }
  const result = value as Record<string, unknown>;
  const actual = Object.keys(result).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      "AWS_DB_HANDOFF_FIELDS",
      `${path} must have exactly: ${expected.join(", ")}`,
    );
  }
  return result;
}

function nonEmptyObject(value: unknown, path: string) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length === 0
  ) {
    fail("AWS_DB_HANDOFF_OBJECT", `${path} must be a non-empty object`);
  }
  return value as Record<string, unknown>;
}

function exact<T>(value: unknown, path: string, expected: T): T {
  if (value !== expected) {
    fail("AWS_DB_HANDOFF_LITERAL", `${path} must equal ${String(expected)}`);
  }
  return expected;
}

function exactArray<const T extends readonly string[]>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (
    !Array.isArray(value) ||
    JSON.stringify(value) !== JSON.stringify(expected)
  ) {
    fail(
      "AWS_DB_HANDOFF_ARRAY",
      `${path} must equal ${JSON.stringify(expected)}`,
    );
  }
  return expected;
}

function bounded(value: unknown, path: string, maxLength = 512): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    fail("AWS_DB_HANDOFF_STRING", `${path} must be a bounded string`);
  }
  return value;
}

function identifier(value: unknown, path: string): string {
  const result = bounded(value, path, 128);
  if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(result)) {
    fail("AWS_DB_HANDOFF_IDENTIFIER", `${path} must be an identifier`);
  }
  return result;
}

function dnsLabel(value: unknown, path: string): string {
  const result = bounded(value, path, 63);
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(result)) {
    fail("AWS_DB_HANDOFF_DNS_LABEL", `${path} must be a DNS label`);
  }
  return result;
}

function digest(value: unknown, path: string): string {
  const result = bounded(value, path, 64);
  if (!/^[a-f0-9]{64}$/.test(result)) {
    fail("AWS_DB_HANDOFF_DIGEST", `${path} must be a SHA-256 digest`);
  }
  return result;
}

function opaque(value: unknown, path: string): string {
  const result = bounded(value, path, 512);
  if (!/^[A-Za-z0-9._:/=-]+$/.test(result)) {
    fail("AWS_DB_HANDOFF_OPAQUE", `${path} must be one opaque identifier`);
  }
  return result;
}

function assertPlainJson(
  value: unknown,
  path: string,
  seen = new WeakSet<object>(),
): void {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("AWS_DB_HANDOFF_JSON_DOMAIN", `${path} must be a finite number`);
    }
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) {
      fail("AWS_DB_HANDOFF_JSON_DOMAIN", `${path} must not be cyclic`);
    }
    seen.add(value);
    value.forEach((entry, index) =>
      assertPlainJson(entry, `${path}[${index}]`, seen),
    );
    seen.delete(value);
    return;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("AWS_DB_HANDOFF_JSON_DOMAIN", `${path} must be a plain JSON object`);
    }
    if (seen.has(value)) {
      fail("AWS_DB_HANDOFF_JSON_DOMAIN", `${path} must not be cyclic`);
    }
    seen.add(value);
    for (const [key, entry] of Object.entries(value)) {
      assertPlainJson(entry, `${path}.${key}`, seen);
    }
    seen.delete(value);
    return;
  }
  fail(
    "AWS_DB_HANDOFF_JSON_DOMAIN",
    `${path} contains a non-JSON ${typeof value} value`,
  );
}

function handoffDigest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
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

function fail(code: string, message: string): never {
  throw new Error(`${code}: ${message}`);
}
