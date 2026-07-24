import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import type {
  PostgresAccessClass,
  PostgresAccessProfile,
} from "./postgresAccessProfile";
import {
  parseAwsDatabaseInfrastructureHandoff,
  type ParsedAwsDatabaseInfrastructureHandoff,
} from "./awsDatabaseInfrastructureHandoff";
import { assertCredentialFreeJson } from "./credentialFree";

export const POSTGRES_ACCESS_OBSERVATION_API_VERSION =
  "evidence.security.deus.dev/postgres-access-observation/v1alpha1" as const;

export const POSTGRES_ACCESS_OBSERVATION_KEYS = [
  "namespace",
  "serviceAccount",
  "admissionPolicy",
  "applicationNetworkPolicy",
  "nodeClass",
  "nodePool",
  "podIdentityAssociation",
] as const;

export type PostgresAccessObservationKey =
  (typeof POSTGRES_ACCESS_OBSERVATION_KEYS)[number];

const observationKinds: Readonly<Record<PostgresAccessObservationKey, string>> =
  {
    namespace: "Namespace",
    serviceAccount: "ServiceAccount",
    admissionPolicy: "ClusterPolicy",
    applicationNetworkPolicy: "ApplicationNetworkPolicy",
    nodeClass: "NodeClass",
    nodePool: "NodePool",
    podIdentityAssociation: "EksPodIdentityAssociation",
  };

const observationApiVersions: Readonly<
  Record<PostgresAccessObservationKey, string>
> = {
  namespace: "v1",
  serviceAccount: "v1",
  admissionPolicy: "kyverno.io/v1",
  applicationNetworkPolicy: "networking.k8s.aws/v1alpha1",
  nodeClass: "eks.amazonaws.com/v1",
  nodePool: "karpenter.sh/v1",
  podIdentityAssociation: "eks.amazonaws.com/v1",
};

const observationReadyStates: Readonly<
  Record<PostgresAccessObservationKey, string>
> = {
  namespace: "Active",
  serviceAccount: "Observed",
  admissionPolicy: "Enforced",
  applicationNetworkPolicy: "Enforced",
  nodeClass: "Ready",
  nodePool: "Ready",
  podIdentityAssociation: "Active",
};

export interface PostgresAccessResourceObservation {
  apiVersion: string;
  kind: string;
  name: string;
  namespace: string | null;
  uid: string;
  resourceVersion: string;
  specDigest: string;
  status: {
    state: string;
    observedGeneration: number;
    conditionDigest: string;
    rawEvidenceDigest: string;
  };
  observedAt: string;
}

export interface PostgresAccessObservationSubject {
  apiVersion: string;
  kind: string;
  name: string;
  namespace: string | null;
  specDigest: string;
}

export interface PostgresAccessObservationEvidenceUnsigned {
  apiVersion: typeof POSTGRES_ACCESS_OBSERVATION_API_VERSION;
  kind: "PostgresAccessObservationEvidence";
  evidenceId: string;
  profile: {
    id: string;
    bindingId: string;
    accessClass: PostgresAccessClass;
    profileSpecDigest: string;
    bindingDigest: string;
    workloadBundleDigest: string;
    handoffSpecDigest: string;
  };
  observedGeneration: number;
  previousEvidenceDigest: string | null;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  verifier: {
    id: string;
    version: string;
    keyId: string;
    binaryDigest: string;
    policyDigest: string;
    schemaDigest: string;
    rawReportDigest: string;
  };
  observations: Readonly<
    Record<PostgresAccessObservationKey, PostgresAccessResourceObservation>
  >;
  deploymentAuthority: {
    controllerServiceAccountSubject: string;
    sourceRepository: string;
    sourceRevision: string;
    sourcePath: string;
    allowedWorkloadKind: "Deployment" | "Job";
    rbacDenialMatrixDigest: string;
    directPodDenialDigest: string;
  };
  postgresBootstrap: {
    markerDigest: string;
    rolePolicyDigest: string;
    extensionsDigest: string;
    activationGeneration: number;
    associationId: string;
    activationActorSubject: string;
    bootstrapJobUid: string;
    activatedAt: string;
    completedAt: string;
    removedAt: string;
    finalAssociationAbsenceDigest: string;
    secretAccessAuditDigest: string;
  };
  runtimeProbes: {
    podIdentityStsDigest: string;
    podSecurityGroupAttachmentDigest: string;
    applicationNetworkPolicyDenialDigest: string;
    rdsProxyIamTlsDigest: string;
    rdsProxyTargetHealthDigest: string;
  };
}

export interface PostgresAccessObservationEvidence extends PostgresAccessObservationEvidenceUnsigned {
  signature: {
    algorithm: "Ed25519";
    value: string;
  };
}

export interface PostgresAccessObservationSigner {
  verifierId: string;
  verifierVersion: string;
  keyId: string;
  privateKeyPem: string;
}

export interface TrustedPostgresAccessObservationVerifier {
  verifierId: string;
  verifierVersion: string;
  keyId: string;
  publicKeyPem: string;
  allowedBindingIds: readonly string[];
  allowedAccessClasses: readonly PostgresAccessClass[];
  maxEvidenceTtlSeconds: number;
  maxObservationAgeSeconds: number;
  maxBootstrapActivationSeconds: number;
  binaryDigest: string;
  policyDigest: string;
  schemaDigest: string;
}

export interface PostgresAccessObservationRevocations {
  revokedEvidenceIds: ReadonlySet<string>;
  revokedNonces: ReadonlySet<string>;
  revokedKeyIds: ReadonlySet<string>;
}

export interface PostgresAccessObservationReplayStore {
  redeem(input: {
    evidenceId: string;
    nonce: string;
    profileSpecDigest: string;
    evidenceDigest: string;
    expiresAt: string;
  }): boolean;
}

export interface VerifiedPostgresAccessDecision {
  state: "ready";
  ready: true;
  profileId: string;
  bindingId: string;
  accessClass: PostgresAccessClass;
  profileSpecDigest: string;
  handoffSpecDigest: string;
  evidenceId: string;
  evidenceDigest: string;
  observedGeneration: number;
  evaluatedAt: string;
  expiresAt: string;
  decisionDigest: string;
}

const authenticPostgresAccessDecisions = new WeakSet<object>();

export function signPostgresAccessObservationEvidence(
  value: PostgresAccessObservationEvidenceUnsigned,
  signer: PostgresAccessObservationSigner,
): PostgresAccessObservationEvidence {
  if (
    value.verifier.id !== signer.verifierId ||
    value.verifier.version !== signer.verifierVersion ||
    value.verifier.keyId !== signer.keyId
  ) {
    fail(
      "POSTGRES_OBSERVATION_SIGNER_MISMATCH",
      "signer identity must exactly match the unsigned evidence verifier",
    );
  }
  const unsigned = parseUnsigned(value);
  let signature: Buffer;
  try {
    signature = signBytes(
      null,
      signaturePayload(unsigned),
      createPrivateKey(signer.privateKeyPem),
    );
  } catch {
    fail(
      "POSTGRES_OBSERVATION_SIGNING_FAILED",
      "observation evidence could not be signed with the configured Ed25519 key",
    );
  }
  return parsePostgresAccessObservationEvidence({
    ...unsigned,
    signature: {
      algorithm: "Ed25519",
      value: signature.toString("base64url"),
    },
  });
}

export function parsePostgresAccessObservationEvidence(
  value: unknown,
): PostgresAccessObservationEvidence {
  assertCredentialFreeJson(value, {
    code: "POSTGRES_OBSERVATION_CREDENTIAL_MATERIAL",
    path: "postgresAccessObservation",
  });
  const input = exactObject(value, "evidence", [
    "apiVersion",
    "kind",
    "evidenceId",
    "profile",
    "observedGeneration",
    "previousEvidenceDigest",
    "issuedAt",
    "expiresAt",
    "nonce",
    "verifier",
    "observations",
    "deploymentAuthority",
    "postgresBootstrap",
    "runtimeProbes",
    "signature",
  ]);
  const signature = exactObject(input.signature, "evidence.signature", [
    "algorithm",
    "value",
  ]);
  const { signature: _signature, ...unsigned } = input;
  return {
    ...parseUnsigned(unsigned),
    signature: {
      algorithm: exact(
        signature.algorithm,
        "evidence.signature.algorithm",
        "Ed25519",
      ),
      value: signatureValue(signature.value, "evidence.signature.value"),
    },
  };
}

function parseUnsigned(
  value: unknown,
): PostgresAccessObservationEvidenceUnsigned {
  const input = exactObject(value, "evidence", [
    "apiVersion",
    "kind",
    "evidenceId",
    "profile",
    "observedGeneration",
    "previousEvidenceDigest",
    "issuedAt",
    "expiresAt",
    "nonce",
    "verifier",
    "observations",
    "deploymentAuthority",
    "postgresBootstrap",
    "runtimeProbes",
  ]);
  const profile = exactObject(input.profile, "evidence.profile", [
    "id",
    "bindingId",
    "accessClass",
    "profileSpecDigest",
    "bindingDigest",
    "workloadBundleDigest",
    "handoffSpecDigest",
  ]);
  const verifier = exactObject(input.verifier, "evidence.verifier", [
    "id",
    "version",
    "keyId",
    "binaryDigest",
    "policyDigest",
    "schemaDigest",
    "rawReportDigest",
  ]);
  const authority = exactObject(
    input.deploymentAuthority,
    "evidence.deploymentAuthority",
    [
      "controllerServiceAccountSubject",
      "sourceRepository",
      "sourceRevision",
      "sourcePath",
      "allowedWorkloadKind",
      "rbacDenialMatrixDigest",
      "directPodDenialDigest",
    ],
  );
  const bootstrap = exactObject(
    input.postgresBootstrap,
    "evidence.postgresBootstrap",
    [
      "markerDigest",
      "rolePolicyDigest",
      "extensionsDigest",
      "activationGeneration",
      "associationId",
      "activationActorSubject",
      "bootstrapJobUid",
      "activatedAt",
      "completedAt",
      "removedAt",
      "finalAssociationAbsenceDigest",
      "secretAccessAuditDigest",
    ],
  );
  const runtimeProbes = exactObject(
    input.runtimeProbes,
    "evidence.runtimeProbes",
    [
      "podIdentityStsDigest",
      "podSecurityGroupAttachmentDigest",
      "applicationNetworkPolicyDenialDigest",
      "rdsProxyIamTlsDigest",
      "rdsProxyTargetHealthDigest",
    ],
  );
  const accessClass = oneOf(
    profile.accessClass,
    "evidence.profile.accessClass",
    ["runtime", "migration"] as const,
  );
  const issuedAt = timestamp(input.issuedAt, "evidence.issuedAt");
  const expiresAt = timestamp(input.expiresAt, "evidence.expiresAt");
  const completedAt = timestamp(
    bootstrap.completedAt,
    "evidence.postgresBootstrap.completedAt",
  );
  const activatedAt = timestamp(
    bootstrap.activatedAt,
    "evidence.postgresBootstrap.activatedAt",
  );
  const removedAt = timestamp(
    bootstrap.removedAt,
    "evidence.postgresBootstrap.removedAt",
  );
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    fail(
      "POSTGRES_OBSERVATION_TIME_ORDER",
      "evidence.expiresAt must be later than issuedAt",
    );
  }
  if (Date.parse(completedAt) > Date.parse(issuedAt)) {
    fail(
      "POSTGRES_OBSERVATION_BOOTSTRAP_TIME",
      "PostgreSQL bootstrap completion must not be later than evidence issuance",
    );
  }
  if (
    Date.parse(activatedAt) >= Date.parse(completedAt) ||
    Date.parse(completedAt) > Date.parse(removedAt) ||
    Date.parse(removedAt) > Date.parse(issuedAt)
  ) {
    fail(
      "POSTGRES_OBSERVATION_BOOTSTRAP_LIFECYCLE",
      "bootstrap activation, SQL completion, association removal, and evidence issuance must be strictly ordered",
    );
  }
  const allowedWorkloadKind = oneOf(
    authority.allowedWorkloadKind,
    "evidence.deploymentAuthority.allowedWorkloadKind",
    ["Deployment", "Job"] as const,
  );
  if (
    allowedWorkloadKind !== (accessClass === "runtime" ? "Deployment" : "Job")
  ) {
    fail(
      "POSTGRES_OBSERVATION_WORKLOAD_KIND",
      "allowed workload kind must match the exact database access class",
    );
  }
  return {
    apiVersion: exact(
      input.apiVersion,
      "evidence.apiVersion",
      POSTGRES_ACCESS_OBSERVATION_API_VERSION,
    ),
    kind: exact(
      input.kind,
      "evidence.kind",
      "PostgresAccessObservationEvidence",
    ),
    evidenceId: identifier(input.evidenceId, "evidence.evidenceId"),
    profile: {
      id: identifier(profile.id, "evidence.profile.id"),
      bindingId: identifier(profile.bindingId, "evidence.profile.bindingId"),
      accessClass,
      profileSpecDigest: digest(
        profile.profileSpecDigest,
        "evidence.profile.profileSpecDigest",
      ),
      bindingDigest: digest(
        profile.bindingDigest,
        "evidence.profile.bindingDigest",
      ),
      workloadBundleDigest: digest(
        profile.workloadBundleDigest,
        "evidence.profile.workloadBundleDigest",
      ),
      handoffSpecDigest: digest(
        profile.handoffSpecDigest,
        "evidence.profile.handoffSpecDigest",
      ),
    },
    observedGeneration: integer(
      input.observedGeneration,
      "evidence.observedGeneration",
      1,
      1_000_000,
    ),
    previousEvidenceDigest:
      input.previousEvidenceDigest === null
        ? null
        : digest(
            input.previousEvidenceDigest,
            "evidence.previousEvidenceDigest",
          ),
    issuedAt,
    expiresAt,
    nonce: nonce(input.nonce, "evidence.nonce"),
    verifier: {
      id: identifier(verifier.id, "evidence.verifier.id"),
      version: version(verifier.version, "evidence.verifier.version"),
      keyId: keyId(verifier.keyId, "evidence.verifier.keyId"),
      binaryDigest: digest(
        verifier.binaryDigest,
        "evidence.verifier.binaryDigest",
      ),
      policyDigest: digest(
        verifier.policyDigest,
        "evidence.verifier.policyDigest",
      ),
      schemaDigest: digest(
        verifier.schemaDigest,
        "evidence.verifier.schemaDigest",
      ),
      rawReportDigest: digest(
        verifier.rawReportDigest,
        "evidence.verifier.rawReportDigest",
      ),
    },
    observations: parseObservations(input.observations, issuedAt),
    deploymentAuthority: {
      controllerServiceAccountSubject: serviceAccountSubject(
        authority.controllerServiceAccountSubject,
      ),
      sourceRepository: repository(authority.sourceRepository),
      sourceRevision: revision(authority.sourceRevision),
      sourcePath: relativePath(authority.sourcePath),
      allowedWorkloadKind,
      rbacDenialMatrixDigest: digest(
        authority.rbacDenialMatrixDigest,
        "evidence.deploymentAuthority.rbacDenialMatrixDigest",
      ),
      directPodDenialDigest: digest(
        authority.directPodDenialDigest,
        "evidence.deploymentAuthority.directPodDenialDigest",
      ),
    },
    postgresBootstrap: {
      markerDigest: digest(
        bootstrap.markerDigest,
        "evidence.postgresBootstrap.markerDigest",
      ),
      rolePolicyDigest: digest(
        bootstrap.rolePolicyDigest,
        "evidence.postgresBootstrap.rolePolicyDigest",
      ),
      extensionsDigest: digest(
        bootstrap.extensionsDigest,
        "evidence.postgresBootstrap.extensionsDigest",
      ),
      activationGeneration: integer(
        bootstrap.activationGeneration,
        "evidence.postgresBootstrap.activationGeneration",
        1,
        1_000_000,
      ),
      associationId: opaque(
        bootstrap.associationId,
        "evidence.postgresBootstrap.associationId",
      ),
      activationActorSubject: serviceAccountSubjectAt(
        bootstrap.activationActorSubject,
        "evidence.postgresBootstrap.activationActorSubject",
      ),
      bootstrapJobUid: opaque(
        bootstrap.bootstrapJobUid,
        "evidence.postgresBootstrap.bootstrapJobUid",
      ),
      activatedAt,
      completedAt,
      removedAt,
      finalAssociationAbsenceDigest: digest(
        bootstrap.finalAssociationAbsenceDigest,
        "evidence.postgresBootstrap.finalAssociationAbsenceDigest",
      ),
      secretAccessAuditDigest: digest(
        bootstrap.secretAccessAuditDigest,
        "evidence.postgresBootstrap.secretAccessAuditDigest",
      ),
    },
    runtimeProbes: {
      podIdentityStsDigest: digest(
        runtimeProbes.podIdentityStsDigest,
        "evidence.runtimeProbes.podIdentityStsDigest",
      ),
      podSecurityGroupAttachmentDigest: digest(
        runtimeProbes.podSecurityGroupAttachmentDigest,
        "evidence.runtimeProbes.podSecurityGroupAttachmentDigest",
      ),
      applicationNetworkPolicyDenialDigest: digest(
        runtimeProbes.applicationNetworkPolicyDenialDigest,
        "evidence.runtimeProbes.applicationNetworkPolicyDenialDigest",
      ),
      rdsProxyIamTlsDigest: digest(
        runtimeProbes.rdsProxyIamTlsDigest,
        "evidence.runtimeProbes.rdsProxyIamTlsDigest",
      ),
      rdsProxyTargetHealthDigest: digest(
        runtimeProbes.rdsProxyTargetHealthDigest,
        "evidence.runtimeProbes.rdsProxyTargetHealthDigest",
      ),
    },
  };
}

export function derivePostgresAccessObservationSubjects(
  handoffValue: unknown,
  accessClass: PostgresAccessClass,
): {
  handoff: ParsedAwsDatabaseInfrastructureHandoff;
  subjects: Readonly<
    Record<PostgresAccessObservationKey, PostgresAccessObservationSubject>
  >;
} {
  const handoff = parseAwsDatabaseInfrastructureHandoff(handoffValue);
  const access = handoff.accessClasses[accessClass];
  const manifest = (
    key:
      | "namespace"
      | "serviceAccount"
      | "admissionPolicy"
      | "applicationNetworkPolicy"
      | "nodeClass"
      | "nodePool",
  ) => requiredRecord(access.manifests[key], `handoff.${accessClass}.${key}`);
  const subject = (
    key: Exclude<PostgresAccessObservationKey, "podIdentityAssociation">,
    namespaced: boolean,
  ): PostgresAccessObservationSubject => {
    const resource = manifest(key);
    const metadata = requiredRecord(
      resource.metadata,
      `handoff.${accessClass}.${key}.metadata`,
    );
    return {
      apiVersion: exact(
        resource.apiVersion,
        `handoff.${accessClass}.${key}.apiVersion`,
        observationApiVersions[key],
      ),
      kind: exact(
        resource.kind,
        `handoff.${accessClass}.${key}.kind`,
        observationKinds[key],
      ),
      name: dnsLabel(metadata.name, `handoff.${accessClass}.${key}.name`),
      namespace: namespaced
        ? exact(
            metadata.namespace,
            `handoff.${accessClass}.${key}.namespace`,
            access.namespace,
          )
        : null,
      specDigest: sha256(canonicalJson(resource)),
    };
  };
  const associationId = access.podIdentityAssociationId;
  if (!associationId) {
    fail(
      "POSTGRES_OBSERVATION_HANDOFF_ASSOCIATION",
      `${accessClass} requires a persistent Pod Identity association`,
    );
  }
  return {
    handoff,
    subjects: {
      namespace: subject("namespace", false),
      serviceAccount: subject("serviceAccount", true),
      admissionPolicy: subject("admissionPolicy", false),
      applicationNetworkPolicy: subject("applicationNetworkPolicy", true),
      nodeClass: subject("nodeClass", false),
      nodePool: subject("nodePool", false),
      podIdentityAssociation: {
        apiVersion: observationApiVersions.podIdentityAssociation,
        kind: observationKinds.podIdentityAssociation,
        name: associationId,
        namespace: null,
        specDigest: sha256(
          canonicalJson({
            associationId,
            namespace: access.namespace,
            serviceAccount: access.serviceAccount,
          }),
        ),
      },
    },
  };
}

export function verifyPostgresAccessObservationEvidence(args: {
  profile: PostgresAccessProfile;
  handoff: unknown;
  evidence: unknown;
  expectedEvidenceDigest: string;
  expectedObservedGeneration: number;
  expectedPreviousEvidenceDigest: string | null;
  expectedDeploymentAuthority: PostgresAccessObservationEvidence["deploymentAuthority"];
  expectedPostgresBootstrap: PostgresAccessObservationEvidence["postgresBootstrap"];
  expectedRuntimeProbes: PostgresAccessObservationEvidence["runtimeProbes"];
  trustedVerifiers: readonly TrustedPostgresAccessObservationVerifier[];
  revocations: PostgresAccessObservationRevocations;
  replayStore: PostgresAccessObservationReplayStore;
  now: string;
}): VerifiedPostgresAccessDecision {
  const evidence = parsePostgresAccessObservationEvidence(args.evidence);
  const expected = derivePostgresAccessObservationSubjects(
    args.handoff,
    args.profile.accessClass,
  );
  const handoffAccess =
    expected.handoff.accessClasses[args.profile.accessClass];
  const now = timestamp(args.now, "now");
  const expectedEvidenceDigest = digest(
    args.expectedEvidenceDigest,
    "expectedEvidenceDigest",
  );
  if (
    evidence.profile.id !== args.profile.id ||
    evidence.profile.bindingId !== args.profile.bindingId ||
    evidence.profile.accessClass !== args.profile.accessClass ||
    evidence.profile.profileSpecDigest !== args.profile.profileSpecDigest ||
    evidence.profile.bindingDigest !== args.profile.enforcement.bindingDigest ||
    evidence.profile.workloadBundleDigest !==
      args.profile.enforcement.workloadBundleDigest ||
    evidence.profile.handoffSpecDigest !== expected.handoff.handoffSpecDigest ||
    handoffAccess.namespace !== args.profile.identity.namespace ||
    handoffAccess.serviceAccount !== args.profile.identity.serviceAccount ||
    handoffAccess.podIdentityAssociationId !==
      args.profile.identity.podIdentityAssociationId ||
    handoffAccess.bindingDigest !== args.profile.enforcement.bindingDigest ||
    handoffAccess.workloadBundleDigest !==
      args.profile.enforcement.workloadBundleDigest
  ) {
    fail(
      "POSTGRES_OBSERVATION_SUBJECT_MISMATCH",
      "observation evidence does not bind the exact access profile and infrastructure handoff",
    );
  }
  if (evidence.observedGeneration !== args.expectedObservedGeneration) {
    fail(
      "POSTGRES_OBSERVATION_GENERATION_MISMATCH",
      "observation generation does not match the expected reconciliation generation",
    );
  }
  if (evidence.previousEvidenceDigest !== args.expectedPreviousEvidenceDigest) {
    fail(
      "POSTGRES_OBSERVATION_PREVIOUS_LINK",
      "observation evidence breaks the expected monotonic lineage",
    );
  }
  const evidenceDigest = postgresAccessObservationEvidenceDigest(evidence);
  if (evidenceDigest !== expectedEvidenceDigest) {
    fail(
      "POSTGRES_OBSERVATION_CONTENT_ADDRESS",
      "observation content does not match its expected digest",
    );
  }
  const trust = uniqueTrustedVerifier(args.trustedVerifiers, evidence);
  if (
    evidence.verifier.binaryDigest !== trust.binaryDigest ||
    evidence.verifier.policyDigest !== trust.policyDigest ||
    evidence.verifier.schemaDigest !== trust.schemaDigest
  ) {
    fail(
      "POSTGRES_OBSERVATION_VERIFIER_PROVENANCE",
      "observation verifier binary, policy, and schema digests must match the trusted verifier configuration",
    );
  }
  if (
    args.revocations.revokedEvidenceIds.has(evidence.evidenceId) ||
    args.revocations.revokedNonces.has(evidence.nonce) ||
    args.revocations.revokedKeyIds.has(evidence.verifier.keyId)
  ) {
    fail(
      "POSTGRES_OBSERVATION_REVOKED",
      "observation evidence, nonce, or signing key is revoked",
    );
  }
  if (
    !trust.allowedBindingIds.includes(evidence.profile.bindingId) ||
    !trust.allowedAccessClasses.includes(evidence.profile.accessClass)
  ) {
    fail(
      "POSTGRES_OBSERVATION_VERIFIER_SCOPE",
      "observation verifier is not trusted for this binding and access class",
    );
  }
  const nowMs = Date.parse(now);
  const issuedAtMs = Date.parse(evidence.issuedAt);
  const expiresAtMs = Date.parse(evidence.expiresAt);
  if (issuedAtMs > nowMs) {
    fail(
      "POSTGRES_OBSERVATION_NOT_YET_VALID",
      "observation evidence is future-dated",
    );
  }
  if (expiresAtMs <= nowMs) {
    fail("POSTGRES_OBSERVATION_EXPIRED", "observation evidence has expired");
  }
  if (expiresAtMs - issuedAtMs > trust.maxEvidenceTtlSeconds * 1000) {
    fail(
      "POSTGRES_OBSERVATION_TTL",
      "observation evidence lifetime exceeds the trusted verifier limit",
    );
  }
  for (const key of POSTGRES_ACCESS_OBSERVATION_KEYS) {
    const observation = evidence.observations[key];
    const subject = expected.subjects[key];
    if (
      observation.apiVersion !== subject.apiVersion ||
      observation.kind !== subject.kind ||
      observation.name !== subject.name ||
      observation.namespace !== subject.namespace ||
      observation.specDigest !== subject.specDigest
    ) {
      fail(
        "POSTGRES_OBSERVATION_RESOURCE_MISMATCH",
        `observation '${key}' does not match the exact handoff-derived resource identity and specification`,
      );
    }
    if (
      nowMs - Date.parse(observation.observedAt) >
      trust.maxObservationAgeSeconds * 1000
    ) {
      fail(
        "POSTGRES_OBSERVATION_STALE",
        `observation '${key}' exceeds the trusted observation age`,
      );
    }
  }
  if (
    canonicalJson(evidence.deploymentAuthority) !==
    canonicalJson(args.expectedDeploymentAuthority)
  ) {
    fail(
      "POSTGRES_OBSERVATION_AUTHORITY_MISMATCH",
      "deployment authority evidence does not match the exact trusted controller and source",
    );
  }
  if (
    canonicalJson(evidence.postgresBootstrap) !==
    canonicalJson(args.expectedPostgresBootstrap)
  ) {
    fail(
      "POSTGRES_OBSERVATION_BOOTSTRAP_MISMATCH",
      "PostgreSQL bootstrap proof does not match the expected role, extension, and marker state",
    );
  }
  if (
    Date.parse(evidence.postgresBootstrap.removedAt) -
      Date.parse(evidence.postgresBootstrap.activatedAt) >
    trust.maxBootstrapActivationSeconds * 1000
  ) {
    fail(
      "POSTGRES_OBSERVATION_BOOTSTRAP_TTL",
      "bootstrap Pod Identity activation exceeded the trusted maximum duration",
    );
  }
  if (
    canonicalJson(evidence.runtimeProbes) !==
    canonicalJson(args.expectedRuntimeProbes)
  ) {
    fail(
      "POSTGRES_OBSERVATION_RUNTIME_PROBE_MISMATCH",
      "AWS runtime probe evidence does not match the independently expected proof digests",
    );
  }
  let signatureValid = false;
  try {
    signatureValid = verifyBytes(
      null,
      signaturePayload(unsignedEvidence(evidence)),
      createPublicKey(trust.publicKeyPem),
      Buffer.from(evidence.signature.value, "base64url"),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    fail(
      "POSTGRES_OBSERVATION_SIGNATURE",
      "observation signature verification failed",
    );
  }
  if (
    !args.replayStore.redeem({
      evidenceId: evidence.evidenceId,
      nonce: evidence.nonce,
      profileSpecDigest: evidence.profile.profileSpecDigest,
      evidenceDigest,
      expiresAt: evidence.expiresAt,
    })
  ) {
    fail(
      "POSTGRES_OBSERVATION_REPLAY",
      "observation evidence has already been redeemed",
    );
  }
  const decisionSubject = {
    state: "ready" as const,
    ready: true as const,
    profileId: evidence.profile.id,
    bindingId: evidence.profile.bindingId,
    accessClass: evidence.profile.accessClass,
    profileSpecDigest: evidence.profile.profileSpecDigest,
    handoffSpecDigest: evidence.profile.handoffSpecDigest,
    evidenceId: evidence.evidenceId,
    evidenceDigest,
    observedGeneration: evidence.observedGeneration,
    evaluatedAt: now,
    expiresAt: evidence.expiresAt,
  };
  const verified = {
    ...decisionSubject,
    decisionDigest: sha256(canonicalJson(decisionSubject)),
  };
  authenticPostgresAccessDecisions.add(verified);
  return verified;
}

export function assertAuthenticVerifiedPostgresAccessDecision(
  decision: VerifiedPostgresAccessDecision,
): void {
  const { decisionDigest, ...subject } = decision;
  if (
    !authenticPostgresAccessDecisions.has(decision) ||
    sha256(canonicalJson(subject)) !== decisionDigest
  ) {
    fail(
      "POSTGRES_ACCESS_DECISION_UNTRUSTED",
      "PostgreSQL access decision must be the unchanged in-process result of authenticated observation verification",
    );
  }
}

export function postgresAccessObservationEvidenceDigest(
  value: unknown,
): string {
  return sha256(canonicalJson(parsePostgresAccessObservationEvidence(value)));
}

function parseObservations(
  value: unknown,
  issuedAt: string,
): Record<PostgresAccessObservationKey, PostgresAccessResourceObservation> {
  const input = exactObject(
    value,
    "evidence.observations",
    POSTGRES_ACCESS_OBSERVATION_KEYS,
  );
  return Object.fromEntries(
    POSTGRES_ACCESS_OBSERVATION_KEYS.map((key) => {
      const path = `evidence.observations.${key}`;
      const observation = exactObject(input[key], path, [
        "apiVersion",
        "kind",
        "name",
        "namespace",
        "uid",
        "resourceVersion",
        "specDigest",
        "status",
        "observedAt",
      ]);
      const status = exactObject(observation.status, `${path}.status`, [
        "state",
        "observedGeneration",
        "conditionDigest",
        "rawEvidenceDigest",
      ]);
      const observedAt = timestamp(
        observation.observedAt,
        `${path}.observedAt`,
      );
      if (Date.parse(observedAt) > Date.parse(issuedAt)) {
        fail(
          "POSTGRES_OBSERVATION_RESOURCE_TIME",
          `${path} must not be observed after evidence issuance`,
        );
      }
      return [
        key,
        {
          apiVersion: exact(
            observation.apiVersion,
            `${path}.apiVersion`,
            observationApiVersions[key],
          ),
          kind: exact(observation.kind, `${path}.kind`, observationKinds[key]),
          name: dnsLabelOrOpaque(observation.name, `${path}.name`, key),
          namespace:
            observation.namespace === null
              ? null
              : dnsLabel(observation.namespace, `${path}.namespace`),
          uid: opaque(observation.uid, `${path}.uid`),
          resourceVersion: opaque(
            observation.resourceVersion,
            `${path}.resourceVersion`,
          ),
          specDigest: digest(observation.specDigest, `${path}.specDigest`),
          status: {
            state: exact(
              status.state,
              `${path}.status.state`,
              observationReadyStates[key],
            ),
            observedGeneration: integer(
              status.observedGeneration,
              `${path}.status.observedGeneration`,
              1,
              1_000_000,
            ),
            conditionDigest: digest(
              status.conditionDigest,
              `${path}.status.conditionDigest`,
            ),
            rawEvidenceDigest: digest(
              status.rawEvidenceDigest,
              `${path}.status.rawEvidenceDigest`,
            ),
          },
          observedAt,
        },
      ];
    }),
  ) as Record<PostgresAccessObservationKey, PostgresAccessResourceObservation>;
}

function uniqueTrustedVerifier(
  verifiers: readonly TrustedPostgresAccessObservationVerifier[],
  evidence: PostgresAccessObservationEvidence,
): TrustedPostgresAccessObservationVerifier {
  const matches = verifiers.filter(
    (candidate) =>
      candidate.verifierId === evidence.verifier.id &&
      candidate.verifierVersion === evidence.verifier.version &&
      candidate.keyId === evidence.verifier.keyId,
  );
  if (matches.length !== 1) {
    fail(
      "POSTGRES_OBSERVATION_VERIFIER_TRUST",
      "observation evidence requires exactly one trusted verifier",
    );
  }
  const trust = matches[0];
  integer(
    trust.maxEvidenceTtlSeconds,
    "verifier.maxEvidenceTtlSeconds",
    1,
    3600,
  );
  integer(
    trust.maxBootstrapActivationSeconds,
    "verifier.maxBootstrapActivationSeconds",
    1,
    3600,
  );
  digest(trust.binaryDigest, "verifier.binaryDigest");
  digest(trust.policyDigest, "verifier.policyDigest");
  digest(trust.schemaDigest, "verifier.schemaDigest");
  integer(
    trust.maxObservationAgeSeconds,
    "verifier.maxObservationAgeSeconds",
    1,
    86_400,
  );
  return trust;
}

function unsignedEvidence(
  evidence: PostgresAccessObservationEvidence,
): PostgresAccessObservationEvidenceUnsigned {
  const { signature: _signature, ...unsigned } = evidence;
  return unsigned;
}

function signaturePayload(
  unsigned: PostgresAccessObservationEvidenceUnsigned,
): Buffer {
  return Buffer.from(
    `postgres-access-observation-v1alpha1\n${canonicalJson(unsigned)}`,
    "utf8",
  );
}

function exactObject(value: unknown, path: string, keys: readonly string[]) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail("POSTGRES_OBSERVATION_OBJECT", `${path} must be an object`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      "POSTGRES_OBSERVATION_FIELDS",
      `${path} must have exactly: ${expected.join(", ")}`,
    );
  }
  return record;
}

function requiredRecord(value: unknown, path: string): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length === 0
  ) {
    fail("POSTGRES_OBSERVATION_OBJECT", `${path} must be a non-empty object`);
  }
  return value as Record<string, unknown>;
}

function exact<T>(value: unknown, path: string, expected: T): T {
  if (value !== expected) {
    fail(
      "POSTGRES_OBSERVATION_LITERAL",
      `${path} must equal ${String(expected)}`,
    );
  }
  return expected;
}

function oneOf<const T extends readonly string[]>(
  value: unknown,
  path: string,
  choices: T,
): T[number] {
  if (typeof value !== "string" || !choices.includes(value)) {
    fail(
      "POSTGRES_OBSERVATION_ENUM",
      `${path} must be one of ${choices.join(", ")}`,
    );
  }
  return value as T[number];
}

function bounded(value: unknown, path: string, maxLength = 512): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    fail(
      "POSTGRES_OBSERVATION_STRING",
      `${path} must be a non-empty bounded string`,
    );
  }
  return value;
}

function identifier(value: unknown, path: string): string {
  const result = bounded(value, path, 128);
  if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(result)) {
    fail("POSTGRES_OBSERVATION_IDENTIFIER", `${path} is not an identifier`);
  }
  return result;
}

function dnsLabel(value: unknown, path: string): string {
  const result = bounded(value, path, 63);
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(result)) {
    fail("POSTGRES_OBSERVATION_DNS_LABEL", `${path} is not a DNS label`);
  }
  return result;
}

function dnsLabelOrOpaque(
  value: unknown,
  path: string,
  key: PostgresAccessObservationKey,
): string {
  return key === "podIdentityAssociation"
    ? opaque(value, path)
    : dnsLabel(value, path);
}

function version(value: unknown, path: string): string {
  const result = bounded(value, path, 64);
  if (!/^\d+\.\d+\.\d+$/.test(result)) {
    fail("POSTGRES_OBSERVATION_VERSION", `${path} is not a version`);
  }
  return result;
}

function keyId(value: unknown, path: string): string {
  const result = bounded(value, path, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) {
    fail("POSTGRES_OBSERVATION_KEY_ID", `${path} is not a key ID`);
  }
  return result;
}

function digest(value: unknown, path: string): string {
  const result = bounded(value, path, 64);
  if (!/^[a-f0-9]{64}$/.test(result)) {
    fail("POSTGRES_OBSERVATION_DIGEST", `${path} is not a SHA-256 digest`);
  }
  return result;
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
      "POSTGRES_OBSERVATION_INTEGER",
      `${path} must be an integer from ${minimum} through ${maximum}`,
    );
  }
  return value as number;
}

function timestamp(value: unknown, path: string): string {
  const result = bounded(value, path, 32);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(result) ||
    !Number.isFinite(Date.parse(result))
  ) {
    fail("POSTGRES_OBSERVATION_TIMESTAMP", `${path} is not a UTC timestamp`);
  }
  const canonical = new Date(Date.parse(result)).toISOString();
  if (result !== canonical && result !== canonical.replace(".000Z", "Z")) {
    fail(
      "POSTGRES_OBSERVATION_TIMESTAMP",
      `${path} is not a canonical calendar timestamp`,
    );
  }
  return result;
}

function nonce(value: unknown, path: string): string {
  const result = bounded(value, path, 128);
  if (result.length < 32 || !/^[A-Za-z0-9_-]+$/.test(result)) {
    fail("POSTGRES_OBSERVATION_NONCE", `${path} is not a secure nonce`);
  }
  return result;
}

function signatureValue(value: unknown, path: string): string {
  const result = bounded(value, path, 86);
  if (!/^[A-Za-z0-9_-]{86}$/.test(result)) {
    fail(
      "POSTGRES_OBSERVATION_SIGNATURE",
      `${path} is not an Ed25519 signature`,
    );
  }
  const decoded = Buffer.from(result, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== result) {
    fail(
      "POSTGRES_OBSERVATION_SIGNATURE",
      `${path} is not a canonical Ed25519 signature encoding`,
    );
  }
  return result;
}

function opaque(value: unknown, path: string): string {
  const result = bounded(value, path, 512);
  if (
    !/^[A-Za-z0-9._:/=-]+$/.test(result) ||
    /password|secret|credential|access[_-]?key|session[_-]?token/i.test(result)
  ) {
    fail(
      "POSTGRES_OBSERVATION_OPAQUE_VALUE",
      `${path} is not a safe opaque provider identifier`,
    );
  }
  return result;
}

function serviceAccountSubject(value: unknown): string {
  return serviceAccountSubjectAt(
    value,
    "evidence.deploymentAuthority.controllerServiceAccountSubject",
  );
}

function serviceAccountSubjectAt(value: unknown, path: string): string {
  const result = bounded(value, path, 253);
  if (
    !/^system:serviceaccount:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(
      result,
    )
  ) {
    fail(
      "POSTGRES_OBSERVATION_CONTROLLER_SUBJECT",
      `${path} must be one exact Kubernetes ServiceAccount subject`,
    );
  }
  return result;
}

function repository(value: unknown): string {
  const result = bounded(
    value,
    "evidence.deploymentAuthority.sourceRepository",
    512,
  );
  if (
    !/^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(?:\.git)?$/.test(
      result,
    )
  ) {
    fail(
      "POSTGRES_OBSERVATION_SOURCE_REPOSITORY",
      "sourceRepository must be one credential-free HTTPS Git repository",
    );
  }
  return result;
}

function revision(value: unknown): string {
  const result = bounded(
    value,
    "evidence.deploymentAuthority.sourceRevision",
    40,
  );
  if (!/^[a-f0-9]{40}$/.test(result)) {
    fail(
      "POSTGRES_OBSERVATION_SOURCE_REVISION",
      "sourceRevision must be one full Git revision",
    );
  }
  return result;
}

function relativePath(value: unknown): string {
  const result = bounded(value, "evidence.deploymentAuthority.sourcePath", 512);
  if (
    result.startsWith("/") ||
    result.includes("\\") ||
    result.split("/").some((segment) => segment === ".." || segment === "") ||
    !/^[A-Za-z0-9._/-]+$/.test(result)
  ) {
    fail(
      "POSTGRES_OBSERVATION_SOURCE_PATH",
      "sourcePath must be one normalized repository-relative path",
    );
  }
  return result;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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

function fail(code: string, message: string): never {
  throw new Error(`${code}: ${message}`);
}
