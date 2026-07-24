import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import {
  assertCloudContextCatalog,
  type CloudContext,
  type CloudContextCatalog,
  type CloudContextPlacement,
  type CloudManagedPostgresBinding,
} from "./cloudContext";

export const CLOUD_CONTEXT_OBSERVATION_API_VERSION =
  "evidence.security.deus.dev/cloud-context-observation/v1alpha1" as const;

export type CloudDependencyKind =
  | "context"
  | "runtime"
  | "network"
  | "registry"
  | "identity"
  | "observability"
  | "dns"
  | "resource-binding";

export type CloudReferencePurpose =
  | "provider-boundary"
  | "runtime-target"
  | "network-boundary"
  | "registry-target"
  | "identity-binding"
  | "dns-zone"
  | "audit-sink"
  | "logs-sink"
  | "metrics-sink"
  | "traces-sink"
  | "provider-resource"
  | "postgres-endpoint"
  | "postgres-ca-bundle"
  | "postgres-runtime-identity"
  | "postgres-migration-identity";

export type CloudReferenceConfidentiality =
  | "public-metadata"
  | "confidential-reference";

export type CloudReferenceProjection =
  | "control-plane-only"
  | "workload-reference";

export type CloudReferenceOutputType =
  | "provider-boundary-id"
  | "runtime-target-reference"
  | "network-boundary-id"
  | "registry-reference"
  | "workload-identity-reference"
  | "dns-zone-reference"
  | "audit-sink-reference"
  | "telemetry-sink-reference"
  | "provider-resource-id"
  | "postgres-endpoint-reference"
  | "ca-bundle-reference";

export interface CloudContextPlacementSelection {
  organizationId: string;
  platformTenantId: string;
  applicationId: string;
  componentId: string;
  requestDigest: string;
}

export interface CloudReferenceRequest {
  catalogDesiredStateDigest: string;
  placementDigest: string;
  organizationId: string;
  platformTenantId: string;
  environment: CloudContextCatalog["environment"];
  applicationId: string;
  componentId: string;
  admissionRequestDigest: string;
  contextId: string;
  dependencyKey: string;
  dependencyKind: CloudDependencyKind;
  dependencyId: string;
  dependencySubjectDigest: string;
  generation: number;
  uri: string;
  scheme: string;
  purpose: CloudReferencePurpose;
  confidentiality: CloudReferenceConfidentiality;
  projection: CloudReferenceProjection;
  expectedOutputType: CloudReferenceOutputType;
  requestDigest: string;
}

export interface CloudReferenceResolution {
  requestDigest: string;
  resolverId: string;
  resolverVersion: string;
  owner: string;
  providerResourceUid: string;
  providerResourceVersion: string;
  outputDigest: string;
  resolvedAt: string;
  expiresAt: string;
}

export interface CloudReferenceResolver {
  scheme: string;
  resolverId: string;
  resolverVersion: string;
  owner: string;
  allowedPurposes: readonly CloudReferencePurpose[];
  allowedConfidentialities: readonly CloudReferenceConfidentiality[];
  allowedProjections: readonly CloudReferenceProjection[];
  allowedOutputTypes: readonly CloudReferenceOutputType[];
  allowedEnvironments: readonly CloudContextCatalog["environment"][];
  allowedOrganizations: readonly string[];
  allowedPlatformTenants: readonly string[];
  allowedContextIds: readonly string[];
  maxResolutionTtlSeconds: number;
  acceptsProviderCredentials: false;
  serializesResolvedValues: false;
  resolve(
    request: CloudReferenceRequest,
    resolvedAt: string,
  ): CloudReferenceResolution;
}

export interface CloudReferenceResolverRegistry {
  readonly resolvers: ReadonlyMap<string, CloudReferenceResolver>;
  readonly digest: string;
}

export interface CloudContextDependency {
  key: string;
  kind: CloudDependencyKind;
  contextId: string;
  id: string;
  generation: number;
  required: true;
  subjectDigest: string;
  references: readonly CloudReferenceRequest[];
}

export interface CloudDependencyObservation {
  dependencyKey: string;
  dependencyKind: CloudDependencyKind;
  contextId: string;
  dependencyId: string;
  generation: number;
  subjectDigest: string;
  phase: "ready";
  previousObservationDigest: string | null;
  resolutions: readonly CloudReferenceResolution[];
}

export interface CloudContextObservationEvidenceUnsigned {
  apiVersion: typeof CLOUD_CONTEXT_OBSERVATION_API_VERSION;
  kind: "CloudContextObservationEvidence";
  evidenceId: string;
  organizationId: string;
  platformTenantId: string;
  environment: CloudContextCatalog["environment"];
  applicationId: string;
  componentId: string;
  requestDigest: string;
  catalogDesiredStateDigest: string;
  placementDigest: string;
  dependencyClosureDigest: string;
  resolverRegistryDigest: string;
  admissionPolicyDigest: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  verifier: {
    id: string;
    version: string;
    keyId: string;
  };
  observations: readonly CloudDependencyObservation[];
}

export interface CloudContextObservationEvidence extends CloudContextObservationEvidenceUnsigned {
  signature: {
    algorithm: "Ed25519";
    value: string;
  };
}

export interface CloudContextObservationSigner {
  verifierId: string;
  verifierVersion: string;
  keyId: string;
  privateKeyPem: string;
}

export interface TrustedCloudContextObservationVerifier {
  verifierId: string;
  verifierVersion: string;
  keyId: string;
  publicKeyPem: string;
  allowedOrganizations: readonly string[];
  allowedPlatformTenants: readonly string[];
  allowedEnvironments: readonly CloudContextCatalog["environment"][];
  maxEvidenceTtlSeconds: number;
}

export interface CloudContextObservationRevocations {
  revokedEvidenceIds: ReadonlySet<string>;
  revokedNonces: ReadonlySet<string>;
  revokedKeyIds: ReadonlySet<string>;
}

export interface CloudContextObservationReplayStore {
  redeem(input: {
    evidenceId: string;
    nonce: string;
    requestDigest: string;
    evidenceDigest: string;
    expiresAt: string;
  }): boolean;
}

export interface VerifiedCloudContextPlacement {
  organizationId: string;
  platformTenantId: string;
  environment: CloudContextCatalog["environment"];
  applicationId: string;
  componentId: string;
  placement: CloudContextPlacement;
  dependencies: readonly CloudContextDependency[];
  catalogDesiredStateDigest: string;
  placementDigest: string;
  dependencyClosureDigest: string;
  evidenceDigest: string;
  evidenceId: string;
  requestDigest: string;
  resolverRegistryDigest: string;
  admissionPolicyDigest: string;
  evaluatedAt: string;
  decisionDigest: string;
  expiresAt: string;
}

const authenticCloudContextPlacements = new WeakSet<object>();

interface DependencyInput {
  key: string;
  kind: CloudDependencyKind;
  contextId: string;
  id: string;
  generation: number;
  definition: unknown;
  references: readonly {
    uri: string;
    purpose: CloudReferencePurpose;
    confidentiality: CloudReferenceConfidentiality;
    projection: CloudReferenceProjection;
    expectedOutputType: CloudReferenceOutputType;
  }[];
}

const dependencyKinds: readonly CloudDependencyKind[] = [
  "context",
  "runtime",
  "network",
  "registry",
  "identity",
  "observability",
  "dns",
  "resource-binding",
];

const referencePurposes: readonly CloudReferencePurpose[] = [
  "provider-boundary",
  "runtime-target",
  "network-boundary",
  "registry-target",
  "identity-binding",
  "dns-zone",
  "audit-sink",
  "logs-sink",
  "metrics-sink",
  "traces-sink",
  "provider-resource",
  "postgres-endpoint",
  "postgres-ca-bundle",
  "postgres-runtime-identity",
  "postgres-migration-identity",
];

const referenceConfidentialities: readonly CloudReferenceConfidentiality[] = [
  "public-metadata",
  "confidential-reference",
];

const referenceProjections: readonly CloudReferenceProjection[] = [
  "control-plane-only",
  "workload-reference",
];

const referenceOutputTypes: readonly CloudReferenceOutputType[] = [
  "provider-boundary-id",
  "runtime-target-reference",
  "network-boundary-id",
  "registry-reference",
  "workload-identity-reference",
  "dns-zone-reference",
  "audit-sink-reference",
  "telemetry-sink-reference",
  "provider-resource-id",
  "postgres-endpoint-reference",
  "ca-bundle-reference",
];

const environments: readonly CloudContextCatalog["environment"][] = [
  "development",
  "staging",
  "production",
];

export function createCloudReferenceResolverRegistry(
  resolvers: readonly CloudReferenceResolver[],
): CloudReferenceResolverRegistry {
  const result = new Map<string, CloudReferenceResolver>();
  for (const resolver of resolvers) {
    const scheme = schemeValue(resolver.scheme, "resolver.scheme");
    identifier(resolver.resolverId, "resolver.resolverId");
    version(resolver.resolverVersion, "resolver.resolverVersion");
    identifier(resolver.owner, "resolver.owner");
    exactEnumSet(
      resolver.allowedPurposes,
      referencePurposes,
      "resolver.allowedPurposes",
      false,
    );
    exactEnumSet(
      resolver.allowedProjections,
      referenceProjections,
      "resolver.allowedProjections",
      false,
    );
    exactEnumSet(
      resolver.allowedOutputTypes,
      referenceOutputTypes,
      "resolver.allowedOutputTypes",
      false,
    );
    exactEnumSet(
      resolver.allowedConfidentialities,
      referenceConfidentialities,
      "resolver.allowedConfidentialities",
      false,
    );
    exactEnumSet(
      resolver.allowedEnvironments,
      environments,
      "resolver.allowedEnvironments",
      false,
    );
    for (const [path, values] of [
      ["resolver.allowedOrganizations", resolver.allowedOrganizations],
      ["resolver.allowedPlatformTenants", resolver.allowedPlatformTenants],
      ["resolver.allowedContextIds", resolver.allowedContextIds],
    ] as const) {
      unique(values, path);
      if (values.length === 0) {
        fail("CLOUD_REF_RESOLVER_SCOPE", `${path} must not be empty`);
      }
      for (const value of values) identifier(value, path);
    }
    integer(
      resolver.maxResolutionTtlSeconds,
      "resolver.maxResolutionTtlSeconds",
      1,
      86_400,
    );
    if (
      resolver.acceptsProviderCredentials !== false ||
      resolver.serializesResolvedValues !== false
    ) {
      fail(
        "CLOUD_REF_RESOLVER_AUTHORITY",
        `resolver '${scheme}' must be credential-free and reference-only`,
      );
    }
    if (result.has(scheme)) {
      fail(
        "CLOUD_REF_RESOLVER_DUPLICATE",
        `reference scheme '${scheme}' has more than one resolver`,
      );
    }
    result.set(scheme, resolver);
  }
  if (result.size === 0) {
    fail(
      "CLOUD_REF_RESOLVER_EMPTY",
      "at least one typed reference resolver is required",
    );
  }
  return {
    resolvers: result,
    digest: digest(
      [...result.values()]
        .map((resolver) => ({
          scheme: resolver.scheme,
          resolverId: resolver.resolverId,
          resolverVersion: resolver.resolverVersion,
          owner: resolver.owner,
          allowedPurposes: [...resolver.allowedPurposes].sort(),
          allowedConfidentialities: [
            ...resolver.allowedConfidentialities,
          ].sort(),
          allowedProjections: [...resolver.allowedProjections].sort(),
          allowedOutputTypes: [...resolver.allowedOutputTypes].sort(),
          allowedEnvironments: [...resolver.allowedEnvironments].sort(),
          allowedOrganizations: [...resolver.allowedOrganizations].sort(),
          allowedPlatformTenants: [...resolver.allowedPlatformTenants].sort(),
          allowedContextIds: [...resolver.allowedContextIds].sort(),
          maxResolutionTtlSeconds: resolver.maxResolutionTtlSeconds,
          acceptsProviderCredentials: resolver.acceptsProviderCredentials,
          serializesResolvedValues: resolver.serializesResolvedValues,
        }))
        .sort((left, right) => left.scheme.localeCompare(right.scheme)),
    ),
  };
}

export function deriveCloudContextPlacementDependencies(
  catalog: CloudContextCatalog,
  selection: CloudContextPlacementSelection,
): readonly CloudContextDependency[] {
  assertCloudContextCatalog(catalog);
  assertSelection(selection);
  const placement = selectedPlacement(catalog, selection);
  const catalogDesiredStateDigest =
    cloudContextCatalogDesiredStateDigest(catalog);
  const placementDigest = digest(placement);
  const contexts = new Map(
    catalog.contexts.map((context) => [context.id, context]),
  );
  const primaryContext = contexts.get(placement.contextId)!;
  const inputs: DependencyInput[] = [];
  addContextDependency(inputs, primaryContext);
  addCapabilityDependency(
    inputs,
    primaryContext,
    "runtime",
    placement.runtimeCapabilityId,
  );
  addCapabilityDependency(
    inputs,
    primaryContext,
    "network",
    placement.networkCapabilityId,
  );
  addCapabilityDependency(
    inputs,
    primaryContext,
    "registry",
    placement.registryCapabilityId,
  );
  addCapabilityDependency(
    inputs,
    primaryContext,
    "identity",
    placement.identityCapabilityId,
  );
  addCapabilityDependency(
    inputs,
    primaryContext,
    "observability",
    placement.observabilityCapabilityId,
  );
  for (const dnsId of placement.dnsCapabilityIds) {
    addCapabilityDependency(inputs, primaryContext, "dns", dnsId);
  }
  for (const bindingId of placement.resourceBindingIds) {
    const located = locateBinding(catalog, bindingId);
    if (located.context.id !== placement.contextId) {
      fail(
        "CLOUD_DEPENDENCY_CONTEXT_ESCAPE",
        `resource binding '${bindingId}' is outside selected context '${placement.contextId}'`,
      );
    }
    addBindingDependency(inputs, located.context, located.binding);
  }
  for (const delegated of placement.delegatedRuntimes) {
    const context = contexts.get(delegated.contextId)!;
    addContextDependency(inputs, context);
    addCapabilityDependency(
      inputs,
      context,
      "runtime",
      delegated.runtimeCapabilityId,
    );
  }

  const dependencies = new Map<string, CloudContextDependency>();
  for (const input of inputs) {
    if (dependencies.has(input.key)) continue;
    const subjectDigest = digest({
      kind: input.kind,
      contextId: input.contextId,
      id: input.id,
      generation: input.generation,
      definition: input.definition,
      consumer: selection,
    });
    const references = input.references
      .map((reference) => {
        const uri = canonicalReferenceUri(reference.uri);
        const scheme = referenceScheme(uri);
        const request = {
          catalogDesiredStateDigest,
          placementDigest,
          organizationId: selection.organizationId,
          platformTenantId: selection.platformTenantId,
          environment: catalog.environment,
          applicationId: selection.applicationId,
          componentId: selection.componentId,
          admissionRequestDigest: selection.requestDigest,
          contextId: input.contextId,
          dependencyKey: input.key,
          dependencyKind: input.kind,
          dependencyId: input.id,
          dependencySubjectDigest: subjectDigest,
          generation: input.generation,
          uri,
          scheme,
          purpose: reference.purpose,
          confidentiality: reference.confidentiality,
          projection: reference.projection,
          expectedOutputType: reference.expectedOutputType,
        };
        return {
          ...request,
          requestDigest: digest(request),
        } satisfies CloudReferenceRequest;
      })
      .sort((left, right) =>
        left.requestDigest.localeCompare(right.requestDigest),
      );
    dependencies.set(input.key, {
      key: input.key,
      kind: input.kind,
      contextId: input.contextId,
      id: input.id,
      generation: input.generation,
      required: true,
      subjectDigest,
      references,
    });
  }
  return [...dependencies.values()].sort((left, right) =>
    left.key.localeCompare(right.key),
  );
}

export function cloudContextCatalogDesiredStateDigest(
  catalog: CloudContextCatalog,
): string {
  assertCloudContextCatalog(catalog);
  return digest({
    apiVersion: catalog.apiVersion,
    kind: catalog.kind,
    name: catalog.name,
    environment: catalog.environment,
    contexts: catalog.contexts.map((context) => {
      const { status: _status, resourceBindings, ...desiredContext } = context;
      return {
        ...desiredContext,
        resourceBindings: resourceBindings.map((binding) => {
          const { status: _bindingStatus, ...desiredBinding } = binding;
          return desiredBinding;
        }),
      };
    }),
    placements: catalog.placements,
  });
}

export function cloudContextDependencyClosureDigest(
  dependencies: readonly CloudContextDependency[],
): string {
  return digest(
    dependencies
      .map((dependency) => ({
        key: dependency.key,
        subjectDigest: dependency.subjectDigest,
        referenceRequestDigests: dependency.references.map(
          (reference) => reference.requestDigest,
        ),
      }))
      .sort((left, right) => left.key.localeCompare(right.key)),
  );
}

export function createCloudContextObservationEvidence(args: {
  catalog: CloudContextCatalog;
  selection: CloudContextPlacementSelection;
  resolverRegistry: CloudReferenceResolverRegistry;
  signer: CloudContextObservationSigner;
  evidenceId: string;
  nonce: string;
  issuedAt: string;
  ttlSeconds: number;
  admissionPolicyDigest: string;
  previousObservationDigests?: Readonly<Record<string, string | null>>;
}): CloudContextObservationEvidence {
  identifier(args.evidenceId, "evidenceId");
  nonce(args.nonce, "nonce");
  timestamp(args.issuedAt, "issuedAt");
  integer(args.ttlSeconds, "ttlSeconds", 1, 3600);
  digestValue(args.admissionPolicyDigest, "admissionPolicyDigest");
  identifier(args.signer.verifierId, "signer.verifierId");
  version(args.signer.verifierVersion, "signer.verifierVersion");
  keyId(args.signer.keyId, "signer.keyId");
  const issuedAtMs = Date.parse(args.issuedAt);
  const expiresAt = new Date(issuedAtMs + args.ttlSeconds * 1000).toISOString();
  const dependencies = deriveCloudContextPlacementDependencies(
    args.catalog,
    args.selection,
  );
  if (args.previousObservationDigests) {
    const dependencyKeys = new Set(
      dependencies.map((dependency) => dependency.key),
    );
    for (const [dependencyKey, previousDigest] of Object.entries(
      args.previousObservationDigests,
    )) {
      if (!dependencyKeys.has(dependencyKey)) {
        fail(
          "CLOUD_OBSERVATION_PREVIOUS_LINK",
          `previous observation references unknown dependency '${dependencyKey}'`,
        );
      }
      if (previousDigest !== null) {
        digestValue(
          previousDigest,
          `previousObservationDigests.${dependencyKey}`,
        );
      }
    }
  }
  // Authorize the complete dispatch set before invoking any resolver. A later
  // invalid reference therefore cannot cause earlier resolver side effects.
  for (const dependency of dependencies) {
    for (const request of dependency.references) {
      requiredResolver(request, args.resolverRegistry);
    }
  }
  const placement = selectedPlacement(args.catalog, args.selection);
  const observations = dependencies.map((dependency) => ({
    dependencyKey: dependency.key,
    dependencyKind: dependency.kind,
    contextId: dependency.contextId,
    dependencyId: dependency.id,
    generation: dependency.generation,
    subjectDigest: dependency.subjectDigest,
    phase: "ready" as const,
    previousObservationDigest:
      args.previousObservationDigests?.[dependency.key] ?? null,
    resolutions: dependency.references.map((request) =>
      resolveReference(
        request,
        args.resolverRegistry,
        args.issuedAt,
        expiresAt,
      ),
    ),
  }));
  const unsigned: CloudContextObservationEvidenceUnsigned = {
    apiVersion: CLOUD_CONTEXT_OBSERVATION_API_VERSION,
    kind: "CloudContextObservationEvidence",
    evidenceId: args.evidenceId,
    organizationId: args.selection.organizationId,
    platformTenantId: args.selection.platformTenantId,
    environment: args.catalog.environment,
    applicationId: args.selection.applicationId,
    componentId: args.selection.componentId,
    requestDigest: args.selection.requestDigest,
    catalogDesiredStateDigest: cloudContextCatalogDesiredStateDigest(
      args.catalog,
    ),
    placementDigest: digest(placement),
    dependencyClosureDigest: cloudContextDependencyClosureDigest(dependencies),
    resolverRegistryDigest: args.resolverRegistry.digest,
    admissionPolicyDigest: args.admissionPolicyDigest,
    issuedAt: args.issuedAt,
    expiresAt,
    nonce: args.nonce,
    verifier: {
      id: args.signer.verifierId,
      version: args.signer.verifierVersion,
      keyId: args.signer.keyId,
    },
    observations,
  };
  let signature: Buffer;
  try {
    signature = signBytes(
      null,
      signaturePayload(unsigned),
      createPrivateKey(args.signer.privateKeyPem),
    );
  } catch (error) {
    fail(
      "CLOUD_OBSERVATION_SIGNING_KEY",
      `observation signing failed: ${errorMessage(error)}`,
    );
  }
  return {
    ...unsigned,
    signature: {
      algorithm: "Ed25519",
      value: signature.toString("base64url"),
    },
  };
}

export function parseCloudContextObservationEvidence(
  value: unknown,
): CloudContextObservationEvidence {
  const input = exactObject(value, "evidence", [
    "apiVersion",
    "kind",
    "evidenceId",
    "organizationId",
    "platformTenantId",
    "environment",
    "applicationId",
    "componentId",
    "requestDigest",
    "catalogDesiredStateDigest",
    "placementDigest",
    "dependencyClosureDigest",
    "resolverRegistryDigest",
    "admissionPolicyDigest",
    "issuedAt",
    "expiresAt",
    "nonce",
    "verifier",
    "observations",
    "signature",
  ]);
  const verifier = exactObject(input.verifier, "evidence.verifier", [
    "id",
    "version",
    "keyId",
  ]);
  const signature = exactObject(input.signature, "evidence.signature", [
    "algorithm",
    "value",
  ]);
  const evidence: CloudContextObservationEvidence = {
    apiVersion: literal(
      input.apiVersion,
      "evidence.apiVersion",
      CLOUD_CONTEXT_OBSERVATION_API_VERSION,
    ),
    kind: literal(
      input.kind,
      "evidence.kind",
      "CloudContextObservationEvidence",
    ),
    evidenceId: identifier(input.evidenceId, "evidence.evidenceId"),
    organizationId: identifier(input.organizationId, "evidence.organizationId"),
    platformTenantId: identifier(
      input.platformTenantId,
      "evidence.platformTenantId",
    ),
    environment: enumValue(
      input.environment,
      "evidence.environment",
      environments,
    ),
    applicationId: identifier(input.applicationId, "evidence.applicationId"),
    componentId: identifier(input.componentId, "evidence.componentId"),
    requestDigest: digestValue(input.requestDigest, "evidence.requestDigest"),
    catalogDesiredStateDigest: digestValue(
      input.catalogDesiredStateDigest,
      "evidence.catalogDesiredStateDigest",
    ),
    placementDigest: digestValue(
      input.placementDigest,
      "evidence.placementDigest",
    ),
    dependencyClosureDigest: digestValue(
      input.dependencyClosureDigest,
      "evidence.dependencyClosureDigest",
    ),
    resolverRegistryDigest: digestValue(
      input.resolverRegistryDigest,
      "evidence.resolverRegistryDigest",
    ),
    admissionPolicyDigest: digestValue(
      input.admissionPolicyDigest,
      "evidence.admissionPolicyDigest",
    ),
    issuedAt: timestamp(input.issuedAt, "evidence.issuedAt"),
    expiresAt: timestamp(input.expiresAt, "evidence.expiresAt"),
    nonce: nonce(input.nonce, "evidence.nonce"),
    verifier: {
      id: identifier(verifier.id, "evidence.verifier.id"),
      version: version(verifier.version, "evidence.verifier.version"),
      keyId: keyId(verifier.keyId, "evidence.verifier.keyId"),
    },
    observations: array(
      input.observations,
      "evidence.observations",
      parseObservation,
    ),
    signature: {
      algorithm: literal(
        signature.algorithm,
        "evidence.signature.algorithm",
        "Ed25519",
      ),
      value: signatureValue(signature.value, "evidence.signature.value"),
    },
  };
  if (evidence.observations.length === 0) {
    fail(
      "CLOUD_OBSERVATION_EMPTY",
      "evidence must contain at least one dependency observation",
    );
  }
  unique(
    evidence.observations.map((entry) => entry.dependencyKey),
    "observation",
  );
  return evidence;
}

export function assertDeployableCloudContextPlacement(args: {
  catalog: CloudContextCatalog;
  selection: CloudContextPlacementSelection;
  evidence: unknown;
  resolverRegistry: CloudReferenceResolverRegistry;
  trustedVerifiers: readonly TrustedCloudContextObservationVerifier[];
  revocations: CloudContextObservationRevocations;
  replayStore: CloudContextObservationReplayStore;
  expectedEvidenceDigest: string;
  admissionPolicyDigest: string;
  expectedPreviousObservationDigests: Readonly<Record<string, string | null>>;
  now: string;
}): VerifiedCloudContextPlacement {
  timestamp(args.now, "now");
  digestValue(args.expectedEvidenceDigest, "expectedEvidenceDigest");
  digestValue(args.admissionPolicyDigest, "admissionPolicyDigest");
  assertSelection(args.selection);
  const evidence = parseCloudContextObservationEvidence(args.evidence);
  const placement = selectedPlacement(args.catalog, args.selection);
  const dependencies = deriveCloudContextPlacementDependencies(
    args.catalog,
    args.selection,
  );
  const catalogDesiredStateDigest = cloudContextCatalogDesiredStateDigest(
    args.catalog,
  );
  const placementDigest = digest(placement);
  const dependencyClosureDigest =
    cloudContextDependencyClosureDigest(dependencies);
  const evidenceDigest = digest(evidence);
  if (evidenceDigest !== args.expectedEvidenceDigest) {
    fail(
      "CLOUD_OBSERVATION_CONTENT_ADDRESS",
      "observation content does not match its expected digest",
    );
  }
  const trust = uniqueTrustedVerifier(args.trustedVerifiers, evidence);
  if (
    args.revocations.revokedEvidenceIds.has(evidence.evidenceId) ||
    args.revocations.revokedNonces.has(evidence.nonce) ||
    args.revocations.revokedKeyIds.has(evidence.verifier.keyId)
  ) {
    fail("CLOUD_OBSERVATION_REVOKED", "observation or signing key is revoked");
  }
  const nowMs = Date.parse(args.now);
  const issuedAtMs = Date.parse(evidence.issuedAt);
  const expiresAtMs = Date.parse(evidence.expiresAt);
  if (issuedAtMs > nowMs) {
    fail("CLOUD_OBSERVATION_NOT_YET_VALID", "observation is future-dated");
  }
  if (expiresAtMs <= nowMs) {
    fail("CLOUD_OBSERVATION_EXPIRED", "observation has expired");
  }
  if (
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > trust.maxEvidenceTtlSeconds * 1000
  ) {
    fail(
      "CLOUD_OBSERVATION_TTL",
      "observation lifetime exceeds the trusted verifier limit",
    );
  }
  const unsigned = unsignedEvidence(evidence);
  let signatureValid = false;
  try {
    signatureValid = verifyBytes(
      null,
      signaturePayload(unsigned),
      createPublicKey(trust.publicKeyPem),
      Buffer.from(evidence.signature.value, "base64url"),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    fail(
      "CLOUD_OBSERVATION_SIGNATURE",
      "observation signature verification failed",
    );
  }
  if (
    evidence.organizationId !== args.selection.organizationId ||
    evidence.platformTenantId !== args.selection.platformTenantId ||
    evidence.applicationId !== args.selection.applicationId ||
    evidence.componentId !== args.selection.componentId ||
    evidence.requestDigest !== args.selection.requestDigest ||
    evidence.environment !== args.catalog.environment
  ) {
    fail(
      "CLOUD_OBSERVATION_SUBJECT_MISMATCH",
      "observation evidence does not match the selected organization, tenant, environment, application, and component",
    );
  }
  if (
    !trust.allowedOrganizations.includes(evidence.organizationId) ||
    !trust.allowedPlatformTenants.includes(evidence.platformTenantId) ||
    !trust.allowedEnvironments.includes(evidence.environment)
  ) {
    fail(
      "CLOUD_OBSERVATION_VERIFIER_SCOPE",
      "observation verifier is not trusted for this subject",
    );
  }
  if (
    evidence.catalogDesiredStateDigest !== catalogDesiredStateDigest ||
    evidence.placementDigest !== placementDigest ||
    evidence.dependencyClosureDigest !== dependencyClosureDigest
  ) {
    fail(
      "CLOUD_OBSERVATION_DIGEST_MISMATCH",
      "observation evidence does not match the catalog, placement, and dependency closure",
    );
  }
  if (
    evidence.resolverRegistryDigest !== args.resolverRegistry.digest ||
    evidence.admissionPolicyDigest !== args.admissionPolicyDigest
  ) {
    fail(
      "CLOUD_OBSERVATION_POLICY_MISMATCH",
      "observation does not match the trusted resolver registry and admission policy",
    );
  }
  const expectedDependencyKeys = dependencies.map(
    (dependency) => dependency.key,
  );
  const previousKeys = Object.keys(
    args.expectedPreviousObservationDigests,
  ).sort();
  if (
    JSON.stringify(previousKeys) !==
    JSON.stringify([...expectedDependencyKeys].sort())
  ) {
    fail(
      "CLOUD_OBSERVATION_PREVIOUS_LINK",
      "expected previous-observation lineage must exactly cover the dependency closure",
    );
  }
  for (const [dependencyKey, previousDigest] of Object.entries(
    args.expectedPreviousObservationDigests,
  )) {
    if (previousDigest !== null) {
      digestValue(
        previousDigest,
        `expectedPreviousObservationDigests.${dependencyKey}`,
      );
    }
  }
  for (const observation of evidence.observations) {
    if (
      observation.previousObservationDigest !==
      args.expectedPreviousObservationDigests[observation.dependencyKey]
    ) {
      fail(
        "CLOUD_OBSERVATION_PREVIOUS_LINK",
        `observation '${observation.dependencyKey}' breaks its evidence lineage`,
      );
    }
  }
  verifyObservations(evidence, dependencies, args.resolverRegistry);
  if (
    !args.replayStore.redeem({
      evidenceId: evidence.evidenceId,
      nonce: evidence.nonce,
      requestDigest: evidence.requestDigest,
      evidenceDigest,
      expiresAt: evidence.expiresAt,
    })
  ) {
    fail(
      "CLOUD_OBSERVATION_REPLAY",
      "observation evidence has already been redeemed",
    );
  }
  const decisionSubject = {
    organizationId: evidence.organizationId,
    platformTenantId: evidence.platformTenantId,
    environment: evidence.environment,
    applicationId: evidence.applicationId,
    componentId: evidence.componentId,
    requestDigest: evidence.requestDigest,
    placementDigest,
    dependencyClosureDigest,
    evidenceDigest,
    resolverRegistryDigest: evidence.resolverRegistryDigest,
    admissionPolicyDigest: evidence.admissionPolicyDigest,
    evaluatedAt: args.now,
    expiresAt: evidence.expiresAt,
  };
  const verified = {
    organizationId: evidence.organizationId,
    platformTenantId: evidence.platformTenantId,
    environment: evidence.environment,
    applicationId: evidence.applicationId,
    componentId: evidence.componentId,
    placement,
    dependencies,
    catalogDesiredStateDigest,
    placementDigest,
    dependencyClosureDigest,
    evidenceDigest,
    evidenceId: evidence.evidenceId,
    requestDigest: evidence.requestDigest,
    resolverRegistryDigest: evidence.resolverRegistryDigest,
    admissionPolicyDigest: evidence.admissionPolicyDigest,
    evaluatedAt: args.now,
    expiresAt: evidence.expiresAt,
    decisionDigest: digest({
      ...decisionSubject,
      placement,
      dependencies,
      catalogDesiredStateDigest,
      evidenceId: evidence.evidenceId,
    }),
  };
  authenticCloudContextPlacements.add(verified);
  return verified;
}

export function assertAuthenticVerifiedCloudContextPlacement(
  decision: VerifiedCloudContextPlacement,
): void {
  const { decisionDigest, ...subject } = decision;
  if (
    !authenticCloudContextPlacements.has(decision) ||
    digest(subject) !== decisionDigest
  ) {
    fail(
      "CLOUD_PLACEMENT_DECISION_UNTRUSTED",
      "cloud-context placement must be the unchanged in-process result of authenticated observation verification",
    );
  }
}

export function cloudContextObservationEvidenceDigest(value: unknown): string {
  return digest(parseCloudContextObservationEvidence(value));
}

function verifyObservations(
  evidence: CloudContextObservationEvidence,
  dependencies: readonly CloudContextDependency[],
  registry: CloudReferenceResolverRegistry,
) {
  const expected = new Map(
    dependencies.map((dependency) => [dependency.key, dependency]),
  );
  if (
    expected.size !== evidence.observations.length ||
    evidence.observations.some(
      (observation) => !expected.has(observation.dependencyKey),
    )
  ) {
    fail(
      "CLOUD_OBSERVATION_DEPENDENCY_SET",
      "observation set does not exactly match the selected dependency closure",
    );
  }
  for (const observation of evidence.observations) {
    const dependency = expected.get(observation.dependencyKey)!;
    if (
      observation.phase !== "ready" ||
      observation.dependencyKind !== dependency.kind ||
      observation.contextId !== dependency.contextId ||
      observation.dependencyId !== dependency.id ||
      observation.generation !== dependency.generation ||
      observation.subjectDigest !== dependency.subjectDigest
    ) {
      fail(
        "CLOUD_OBSERVATION_DEPENDENCY_MISMATCH",
        `observation '${observation.dependencyKey}' does not match its required dependency`,
      );
    }
    const requests = new Map(
      dependency.references.map((request) => [request.requestDigest, request]),
    );
    if (
      requests.size !== observation.resolutions.length ||
      observation.resolutions.some(
        (resolution) => !requests.has(resolution.requestDigest),
      )
    ) {
      fail(
        "CLOUD_OBSERVATION_RESOLUTION_SET",
        `observation '${observation.dependencyKey}' does not contain the exact reference resolution set`,
      );
    }
    for (const resolution of observation.resolutions) {
      const request = requests.get(resolution.requestDigest)!;
      verifyResolution(request, resolution, registry, evidence);
    }
  }
}

function resolveReference(
  request: CloudReferenceRequest,
  registry: CloudReferenceResolverRegistry,
  resolvedAt: string,
  evidenceExpiresAt: string,
): CloudReferenceResolution {
  const resolver = requiredResolver(request, registry);
  let resolution: CloudReferenceResolution;
  try {
    resolution = normalizeResolution(
      resolver.resolve(structuredClone(request), resolvedAt),
      `resolution '${request.requestDigest}'`,
    );
  } catch (error) {
    fail(
      "CLOUD_REF_RESOLUTION_FAILED",
      `resolver '${resolver.resolverId}' failed: ${errorMessage(error)}`,
    );
  }
  if (
    resolution.requestDigest !== request.requestDigest ||
    resolution.resolverId !== resolver.resolverId ||
    resolution.resolverVersion !== resolver.resolverVersion ||
    resolution.owner !== resolver.owner
  ) {
    fail(
      "CLOUD_REF_RESOLUTION_SUBSTITUTION",
      `resolver '${resolver.resolverId}' returned a substituted resolution`,
    );
  }
  assertResolutionLifetime(resolution, resolver, resolvedAt, evidenceExpiresAt);
  return resolution;
}

function verifyResolution(
  request: CloudReferenceRequest,
  resolution: CloudReferenceResolution,
  registry: CloudReferenceResolverRegistry,
  evidence: CloudContextObservationEvidence,
) {
  const resolver = requiredResolver(request, registry);
  if (
    resolution.requestDigest !== request.requestDigest ||
    resolution.resolverId !== resolver.resolverId ||
    resolution.resolverVersion !== resolver.resolverVersion ||
    resolution.owner !== resolver.owner
  ) {
    fail(
      "CLOUD_REF_RESOLUTION_SUBSTITUTION",
      `resolution '${resolution.requestDigest}' does not match its resolver and request`,
    );
  }
  assertResolutionLifetime(
    resolution,
    resolver,
    evidence.issuedAt,
    evidence.expiresAt,
  );
}

function requiredResolver(
  request: CloudReferenceRequest,
  registry: CloudReferenceResolverRegistry,
): CloudReferenceResolver {
  const resolver = registry.resolvers.get(request.scheme);
  if (!resolver) {
    fail(
      "CLOUD_REF_SCHEME_UNKNOWN",
      `reference scheme '${request.scheme}' has no registered resolver`,
    );
  }
  if (
    !resolver.allowedPurposes.includes(request.purpose) ||
    !resolver.allowedConfidentialities.includes(request.confidentiality) ||
    !resolver.allowedProjections.includes(request.projection) ||
    !resolver.allowedOutputTypes.includes(request.expectedOutputType) ||
    !resolver.allowedEnvironments.includes(request.environment) ||
    !resolver.allowedOrganizations.includes(request.organizationId) ||
    !resolver.allowedPlatformTenants.includes(request.platformTenantId) ||
    !resolver.allowedContextIds.includes(request.contextId)
  ) {
    fail(
      "CLOUD_REF_RESOLVER_SCOPE",
      `resolver '${resolver.resolverId}' is not authorized for '${request.purpose}' in '${request.environment}'`,
    );
  }
  return resolver;
}

function assertResolutionLifetime(
  resolution: CloudReferenceResolution,
  resolver: CloudReferenceResolver,
  evidenceIssuedAt: string,
  evidenceExpiresAt: string,
) {
  const resolvedAt = Date.parse(resolution.resolvedAt);
  const resolutionExpiresAt = Date.parse(resolution.expiresAt);
  if (
    resolvedAt > Date.parse(evidenceIssuedAt) ||
    resolutionExpiresAt < Date.parse(evidenceExpiresAt) ||
    resolutionExpiresAt <= resolvedAt ||
    resolutionExpiresAt - resolvedAt > resolver.maxResolutionTtlSeconds * 1000
  ) {
    fail(
      "CLOUD_REF_RESOLUTION_TTL",
      `resolution '${resolution.requestDigest}' is stale or exceeds its resolver TTL`,
    );
  }
}

function normalizeResolution(
  value: unknown,
  path: string,
): CloudReferenceResolution {
  const input = exactObject(value, path, [
    "requestDigest",
    "resolverId",
    "resolverVersion",
    "owner",
    "providerResourceUid",
    "providerResourceVersion",
    "outputDigest",
    "resolvedAt",
    "expiresAt",
  ]);
  return {
    requestDigest: digestValue(input.requestDigest, `${path}.requestDigest`),
    resolverId: identifier(input.resolverId, `${path}.resolverId`),
    resolverVersion: version(input.resolverVersion, `${path}.resolverVersion`),
    owner: identifier(input.owner, `${path}.owner`),
    providerResourceUid: exactAuthority(
      input.providerResourceUid,
      `${path}.providerResourceUid`,
    ),
    providerResourceVersion: exactAuthority(
      input.providerResourceVersion,
      `${path}.providerResourceVersion`,
    ),
    outputDigest: digestValue(input.outputDigest, `${path}.outputDigest`),
    resolvedAt: timestamp(input.resolvedAt, `${path}.resolvedAt`),
    expiresAt: timestamp(input.expiresAt, `${path}.expiresAt`),
  };
}

function parseObservation(
  value: unknown,
  path: string,
): CloudDependencyObservation {
  const input = exactObject(value, path, [
    "dependencyKey",
    "dependencyKind",
    "contextId",
    "dependencyId",
    "generation",
    "subjectDigest",
    "phase",
    "previousObservationDigest",
    "resolutions",
  ]);
  return {
    dependencyKey: dependencyKey(input.dependencyKey, `${path}.dependencyKey`),
    dependencyKind: enumValue(
      input.dependencyKind,
      `${path}.dependencyKind`,
      dependencyKinds,
    ),
    contextId: identifier(input.contextId, `${path}.contextId`),
    dependencyId: identifier(input.dependencyId, `${path}.dependencyId`),
    generation: integer(input.generation, `${path}.generation`, 1, 1_000_000),
    subjectDigest: digestValue(input.subjectDigest, `${path}.subjectDigest`),
    phase: literal(input.phase, `${path}.phase`, "ready"),
    previousObservationDigest:
      input.previousObservationDigest === null
        ? null
        : digestValue(
            input.previousObservationDigest,
            `${path}.previousObservationDigest`,
          ),
    resolutions: array(
      input.resolutions,
      `${path}.resolutions`,
      normalizeResolution,
    ),
  };
}

function addContextDependency(
  inputs: DependencyInput[],
  context: CloudContext,
) {
  inputs.push({
    key: dependencyKeyFor(context.id, "context", context.id),
    kind: "context",
    contextId: context.id,
    id: context.id,
    generation: context.status.generation,
    definition: {
      environment: context.environment,
      provider: context.provider,
      provisioning: context.provisioning,
      posture: context.posture,
    },
    references: [
      {
        uri: context.provider.boundaryRef,
        purpose: "provider-boundary",
        confidentiality: "public-metadata",
        projection: "control-plane-only",
        expectedOutputType: "provider-boundary-id",
      },
    ],
  });
}

function addCapabilityDependency(
  inputs: DependencyInput[],
  context: CloudContext,
  kind: Exclude<CloudDependencyKind, "context" | "resource-binding">,
  id: string,
) {
  const capabilities = capabilityList(context, kind);
  const capability = capabilities.find((candidate) => candidate.id === id);
  if (!capability) {
    fail(
      "CLOUD_DEPENDENCY_UNKNOWN",
      `capability '${context.id}/${kind}/${id}' does not exist`,
    );
  }
  inputs.push({
    key: dependencyKeyFor(context.id, kind, id),
    kind,
    contextId: context.id,
    id,
    generation: context.status.generation,
    definition: capability,
    references: capabilityReferences(kind, capability),
  });
}

function addBindingDependency(
  inputs: DependencyInput[],
  context: CloudContext,
  binding: CloudManagedPostgresBinding,
) {
  inputs.push({
    key: dependencyKeyFor(context.id, "resource-binding", binding.id),
    kind: "resource-binding",
    contextId: context.id,
    id: binding.id,
    generation: binding.status.generation,
    definition: {
      ...binding,
      status: undefined,
    },
    references: [
      {
        uri: binding.providerResourceRef,
        purpose: "provider-resource",
        confidentiality: "public-metadata",
        projection: "control-plane-only",
        expectedOutputType: "provider-resource-id",
      },
      {
        uri: binding.outputs.endpointRef,
        purpose: "postgres-endpoint",
        confidentiality: "confidential-reference",
        projection: "workload-reference",
        expectedOutputType: "postgres-endpoint-reference",
      },
      {
        uri: binding.outputs.caBundleRef,
        purpose: "postgres-ca-bundle",
        confidentiality: "public-metadata",
        projection: "workload-reference",
        expectedOutputType: "ca-bundle-reference",
      },
      {
        uri: binding.outputs.runtimeIdentityRef,
        purpose: "postgres-runtime-identity",
        confidentiality: "confidential-reference",
        projection: "workload-reference",
        expectedOutputType: "workload-identity-reference",
      },
      {
        uri: binding.outputs.migrationIdentityRef,
        purpose: "postgres-migration-identity",
        confidentiality: "confidential-reference",
        projection: "control-plane-only",
        expectedOutputType: "workload-identity-reference",
      },
    ],
  });
}

function capabilityList(
  context: CloudContext,
  kind: Exclude<CloudDependencyKind, "context" | "resource-binding">,
): readonly { id: string }[] {
  switch (kind) {
    case "runtime":
      return context.capabilities.runtimes;
    case "network":
      return context.capabilities.networks;
    case "registry":
      return context.capabilities.registries;
    case "identity":
      return context.capabilities.identities;
    case "observability":
      return context.capabilities.observability;
    case "dns":
      return context.capabilities.dns;
  }
}

function capabilityReferences(
  kind: Exclude<CloudDependencyKind, "context" | "resource-binding">,
  capability: { id: string },
): DependencyInput["references"] {
  if (kind === "observability") {
    const value =
      capability as CloudContext["capabilities"]["observability"][number];
    return [
      {
        uri: value.auditRef,
        purpose: "audit-sink",
        confidentiality: "confidential-reference",
        projection: "control-plane-only",
        expectedOutputType: "audit-sink-reference",
      },
      {
        uri: value.logsRef,
        purpose: "logs-sink",
        confidentiality: "confidential-reference",
        projection: "workload-reference",
        expectedOutputType: "telemetry-sink-reference",
      },
      {
        uri: value.metricsRef,
        purpose: "metrics-sink",
        confidentiality: "confidential-reference",
        projection: "workload-reference",
        expectedOutputType: "telemetry-sink-reference",
      },
      {
        uri: value.tracesRef,
        purpose: "traces-sink",
        confidentiality: "confidential-reference",
        projection: "workload-reference",
        expectedOutputType: "telemetry-sink-reference",
      },
    ];
  }
  const value = capability as { id: string; reference: string };
  const purpose: Record<
    Exclude<
      CloudDependencyKind,
      "context" | "resource-binding" | "observability"
    >,
    CloudReferencePurpose
  > = {
    runtime: "runtime-target",
    network: "network-boundary",
    registry: "registry-target",
    identity: "identity-binding",
    dns: "dns-zone",
  };
  const outputType: Record<keyof typeof purpose, CloudReferenceOutputType> = {
    runtime: "runtime-target-reference",
    network: "network-boundary-id",
    registry: "registry-reference",
    identity: "workload-identity-reference",
    dns: "dns-zone-reference",
  };
  return [
    {
      uri: value.reference,
      purpose: purpose[kind as keyof typeof purpose],
      confidentiality:
        kind === "identity" ? "confidential-reference" : "public-metadata",
      projection:
        kind === "network" || kind === "runtime"
          ? "control-plane-only"
          : "workload-reference",
      expectedOutputType: outputType[kind as keyof typeof outputType],
    },
  ];
}

function locateBinding(catalog: CloudContextCatalog, id: string) {
  for (const context of catalog.contexts) {
    const binding = context.resourceBindings.find(
      (candidate) => candidate.id === id,
    );
    if (binding) return { context, binding };
  }
  fail("CLOUD_DEPENDENCY_UNKNOWN", `resource binding '${id}' does not exist`);
}

function selectedPlacement(
  catalog: CloudContextCatalog,
  selection: CloudContextPlacementSelection,
): CloudContextPlacement {
  assertCloudContextCatalog(catalog);
  const placement = catalog.placements.find(
    (candidate) =>
      candidate.applicationId === selection.applicationId &&
      candidate.componentId === selection.componentId,
  );
  if (!placement) {
    fail(
      "CLOUD_PLACEMENT_UNKNOWN",
      `placement '${selection.applicationId}/${selection.componentId}' does not exist`,
    );
  }
  return placement;
}

function uniqueTrustedVerifier(
  trusts: readonly TrustedCloudContextObservationVerifier[],
  evidence: CloudContextObservationEvidence,
) {
  const matches = trusts.filter(
    (trust) =>
      trust.verifierId === evidence.verifier.id &&
      trust.verifierVersion === evidence.verifier.version &&
      trust.keyId === evidence.verifier.keyId,
  );
  if (matches.length !== 1) {
    fail(
      "CLOUD_OBSERVATION_VERIFIER_UNKNOWN",
      "observation verifier identity/version/key is not uniquely trusted",
    );
  }
  const trust = matches[0];
  identifier(trust.verifierId, "trust.verifierId");
  version(trust.verifierVersion, "trust.verifierVersion");
  keyId(trust.keyId, "trust.keyId");
  exactEnumSet(
    trust.allowedEnvironments,
    environments,
    "trust.allowedEnvironments",
    false,
  );
  unique(trust.allowedOrganizations, "trusted organization");
  unique(trust.allowedPlatformTenants, "trusted platform tenant");
  for (const organization of trust.allowedOrganizations) {
    identifier(organization, "trust.allowedOrganizations");
  }
  for (const tenant of trust.allowedPlatformTenants) {
    identifier(tenant, "trust.allowedPlatformTenants");
  }
  integer(trust.maxEvidenceTtlSeconds, "trust.maxEvidenceTtlSeconds", 1, 3600);
  return trust;
}

function unsignedEvidence(
  evidence: CloudContextObservationEvidence,
): CloudContextObservationEvidenceUnsigned {
  const { signature: _signature, ...unsigned } = evidence;
  return unsigned;
}

function signaturePayload(
  evidence: CloudContextObservationEvidenceUnsigned,
): Buffer {
  return Buffer.from(
    `DEUS_CLOUD_CONTEXT_OBSERVATION_V1\0${stableJson(evidence)}`,
  );
}

function dependencyKeyFor(
  contextId: string,
  kind: CloudDependencyKind,
  id: string,
) {
  return `${contextId}/${kind}/${id}`;
}

function referenceScheme(uri: string): string {
  const match = /^([a-z][a-z0-9+.-]*):\/\//.exec(uri);
  if (!match) {
    fail("CLOUD_REF_URI_INVALID", `reference '${uri}' has no exact scheme`);
  }
  return match[1];
}

function canonicalReferenceUri(uri: string): string {
  const match = /^([a-z][a-z0-9+.-]*):\/\/([A-Za-z0-9._~:/-]+)$/.exec(uri);
  if (!match) {
    fail("CLOUD_REF_URI_INVALID", `reference '${uri}' is not canonical`);
  }
  const body = match[2];
  if (
    body.startsWith("/") ||
    body.endsWith("/") ||
    body.includes("//") ||
    body.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    fail(
      "CLOUD_REF_URI_NON_CANONICAL",
      `reference '${uri}' contains an empty or dot segment`,
    );
  }
  return uri;
}

function assertSelection(selection: CloudContextPlacementSelection) {
  identifier(selection.organizationId, "selection.organizationId");
  identifier(selection.platformTenantId, "selection.platformTenantId");
  identifier(selection.applicationId, "selection.applicationId");
  identifier(selection.componentId, "selection.componentId");
  digestValue(selection.requestDigest, "selection.requestDigest");
}

function exactObject(
  value: unknown,
  path: string,
  fields: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("CLOUD_OBSERVATION_SHAPE", `${path} must be an object`);
  }
  const result = value as Record<string, unknown>;
  const keys = Object.keys(result).sort();
  const expected = [...fields].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    fail(
      "CLOUD_OBSERVATION_SHAPE",
      `${path} fields must exactly match [${expected.join(", ")}]`,
    );
  }
  return result;
}

function array<T>(
  value: unknown,
  path: string,
  parser: (value: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) {
    fail("CLOUD_OBSERVATION_SHAPE", `${path} must be an array`);
  }
  return value.map((entry, index) => parser(entry, `${path}[${index}]`));
}

function literal<T extends string>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) {
    fail("CLOUD_OBSERVATION_VALUE", `${path} must be '${expected}'`);
  }
  return expected;
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    fail(
      "CLOUD_OBSERVATION_VALUE",
      `${path} must be one of: ${allowed.join(", ")}`,
    );
  }
  return value as T;
}

function identifier(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/.test(value)
  ) {
    fail("CLOUD_OBSERVATION_IDENTIFIER", `${path} is not an exact identifier`);
  }
  return value;
}

function dependencyKey(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*\/(?:context|runtime|network|registry|identity|observability|dns|resource-binding)\/[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/.test(
      value,
    )
  ) {
    fail("CLOUD_OBSERVATION_DEPENDENCY_KEY", `${path} is not exact`);
  }
  return value;
}

function schemeValue(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-z][a-z0-9+.-]{0,31}$/.test(value)) {
    fail("CLOUD_REF_SCHEME_INVALID", `${path} is not a valid URI scheme`);
  }
  return value;
}

function version(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(value)) {
    fail("CLOUD_OBSERVATION_VERSION", `${path} must be an exact semver`);
  }
  return value;
}

function keyId(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  ) {
    fail("CLOUD_OBSERVATION_KEY_ID", `${path} must be an exact key identifier`);
  }
  return value;
}

function nonce(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length < 32 ||
    value.length > 128 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    fail(
      "CLOUD_OBSERVATION_NONCE",
      `${path} must have 32-128 base64url characters`,
    );
  }
  return value;
}

function signatureValue(value: unknown, path: string): string {
  const decoded =
    typeof value === "string" ? Buffer.from(value, "base64url") : undefined;
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9_-]{86}$/.test(value) ||
    decoded?.length !== 64 ||
    decoded.toString("base64url") !== value
  ) {
    fail("CLOUD_OBSERVATION_SIGNATURE", `${path} is not an Ed25519 signature`);
  }
  return value;
}

function digestValue(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    fail("CLOUD_OBSERVATION_DIGEST", `${path} must be a SHA-256 digest`);
  }
  return value;
}

function timestamp(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    fail(
      "CLOUD_OBSERVATION_TIMESTAMP",
      `${path} must be an ISO-8601 UTC timestamp`,
    );
  }
  const canonical = new Date(Date.parse(value)).toISOString();
  if (value !== canonical && value !== canonical.replace(".000Z", "Z")) {
    fail(
      "CLOUD_OBSERVATION_TIMESTAMP",
      `${path} must be a canonical calendar timestamp`,
    );
  }
  return value;
}

function exactAuthority(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 512 ||
    /[*?\s@#]/.test(value) ||
    /(?:password|secret|credential|access[_-]?key|session[_-]?token)/i.test(
      value,
    )
  ) {
    fail(
      "CLOUD_REF_AUTHORITY_INVALID",
      `${path} is not an exact safe authority`,
    );
  }
  return value;
}

function integer(
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
    fail(
      "CLOUD_OBSERVATION_INTEGER",
      `${path} must be an integer from ${minimum} to ${maximum}`,
    );
  }
  return value as number;
}

function exactEnumSet<T extends string>(
  values: readonly T[],
  allowed: readonly T[],
  path: string,
  requireAll: boolean,
) {
  if (!Array.isArray(values) || values.length === 0) {
    fail("CLOUD_OBSERVATION_SET", `${path} must be a non-empty array`);
  }
  unique(values, path);
  if (
    values.some((value) => !allowed.includes(value)) ||
    (requireAll && values.length !== allowed.length)
  ) {
    fail("CLOUD_OBSERVATION_SET", `${path} contains an unsupported value`);
  }
}

function unique(values: readonly unknown[], path: string) {
  if (
    values.some((value) => typeof value !== "string") ||
    new Set(values).size !== values.length
  ) {
    fail("CLOUD_OBSERVATION_SET", `${path} values must be unique strings`);
  }
}

function digest(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function stableJson(value: unknown): string {
  if (value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function fail(code: string, message: string): never {
  throw new Error(`${code}: ${message}`);
}
