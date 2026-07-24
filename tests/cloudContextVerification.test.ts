import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  compileAwsCloudContextCatalog,
  type AwsCloudContextExtensions,
} from "../src/adapters/aws";
import {
  assertDeployableCloudContextPlacement,
  assertRuntimeDeploymentAdmission,
  cloudContextCatalogDesiredStateDigest,
  cloudContextObservationEvidenceDigest,
  createCloudContextObservationEvidence,
  createCloudReferenceResolverRegistry,
  createWardenMindBlueprint,
  deriveCloudContextPlacementDependencies,
  parseCloudContextObservationEvidence,
  parseManagedPostgresIntent,
  parsePostgresAccessProfile,
  postgresAccessObservationEvidenceDigest,
  signPostgresAccessObservationEvidence,
  verifyPostgresAccessObservationEvidence,
  type CloudContextCatalog,
  type CloudContextObservationReplayStore,
  type CloudContextPlacementSelection,
  type CloudReferenceResolver,
  type PostgresAccessObservationEvidence,
  type PostgresAccessObservationEvidenceUnsigned,
  type PostgresAccessObservationReplayStore,
} from "../src/core";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = {
  verifierId: "cloud-context-observer",
  verifierVersion: "1.0.0",
  keyId: "cloud-context-observer-2026-07",
  privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};
const admissionPolicyDigest = "ab".repeat(32);
const postgresKeys = generateKeyPairSync("ed25519");
const postgresSigner = {
  verifierId: "aws-dev-postgres-observer",
  verifierVersion: "1.0.0",
  keyId: "aws-dev-postgres-observer-2026-07",
  privateKeyPem: postgresKeys.privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString(),
};

function setup() {
  const blueprint = createWardenMindBlueprint({
    networkCidrs: {
      "egress-net": "10.0.0.0/16",
      "control-net": "10.10.0.0/16",
      "execution-shared-net": "10.20.0.0/16",
      "data-shared-net": "10.30.0.0/16",
    },
  });
  const postgres = parseManagedPostgresIntent(
    JSON.parse(
      readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
    ),
    "development",
    blueprint,
  );
  const extensions: AwsCloudContextExtensions = {
    partition: "aws",
    platformAccountId: "111111111111",
    executionAccountId: "222222222222",
    region: "us-east-1",
    applicationContextId: "platform-aws",
    executionContextId: "execution-aws",
    platformStackRef: "deus/secure-saas-infra/platform-dev",
    executionStackRef: "deus/secure-saas-infra/execution-dev",
    registryRef: "provider-reference://aws/ecr/platform",
    publicDnsRef: "provider-reference://aws/route53/public",
    privateDnsRef: "provider-reference://aws/route53/private",
    platformIdentityRef: "identity://platform-workloads",
    executionIdentityRef: "identity://execution-workloads",
    auditRef: "stack-output://deus/secure-saas-infra/audit",
    logsRef: "stack-output://deus/secure-saas-infra/logs",
    metricsRef: "stack-output://deus/secure-saas-infra/metrics",
    tracesRef: "stack-output://deus/secure-saas-infra/traces",
  };
  const catalog = compileAwsCloudContextCatalog(
    blueprint,
    postgres,
    extensions,
  );
  const placement = catalog.placements.find((candidate) =>
    candidate.resourceBindingIds.includes("warden-saas-postgres"),
  )!;
  const selection: CloudContextPlacementSelection = {
    organizationId: "deus",
    platformTenantId: "tenant-warden",
    applicationId: placement.applicationId,
    componentId: placement.componentId,
    requestDigest: "cd".repeat(32),
  };
  return { catalog, selection };
}

function resolverRegistry(
  catalog: CloudContextCatalog,
  selection: CloudContextPlacementSelection,
  calls: string[] = [],
  omitScheme?: string,
) {
  const requests = deriveCloudContextPlacementDependencies(
    catalog,
    selection,
  ).flatMap((dependency) => dependency.references);
  const schemes = [...new Set(requests.map((request) => request.scheme))];
  const resolvers = schemes
    .filter((scheme) => scheme !== omitScheme)
    .map((scheme): CloudReferenceResolver => {
      const scoped = requests.filter((request) => request.scheme === scheme);
      return {
        scheme,
        resolverId: `${scheme.replace(/[^a-z0-9]+/g, "-")}-resolver`,
        resolverVersion: "1.0.0",
        owner: "secure-saas-infra",
        allowedPurposes: [...new Set(scoped.map((entry) => entry.purpose))],
        allowedConfidentialities: [
          ...new Set(scoped.map((entry) => entry.confidentiality)),
        ],
        allowedProjections: [
          ...new Set(scoped.map((entry) => entry.projection)),
        ],
        allowedOutputTypes: [
          ...new Set(scoped.map((entry) => entry.expectedOutputType)),
        ],
        allowedEnvironments: [catalog.environment],
        allowedOrganizations: [selection.organizationId],
        allowedPlatformTenants: [selection.platformTenantId],
        allowedContextIds: [...new Set(scoped.map((entry) => entry.contextId))],
        maxResolutionTtlSeconds: 600,
        acceptsProviderCredentials: false,
        serializesResolvedValues: false,
        resolve(request, resolvedAt) {
          calls.push(request.requestDigest);
          return {
            requestDigest: request.requestDigest,
            resolverId: `${scheme.replace(/[^a-z0-9]+/g, "-")}-resolver`,
            resolverVersion: "1.0.0",
            owner: "secure-saas-infra",
            providerResourceUid: `${scheme.replace(/[^a-z0-9]+/g, "-")}-uid`,
            providerResourceVersion: "version-1",
            outputDigest: request.requestDigest,
            resolvedAt,
            expiresAt: "2026-07-18T12:05:00.000Z",
          };
        },
      };
    });
  return createCloudReferenceResolverRegistry(resolvers);
}

function replayStore(): CloudContextObservationReplayStore {
  const redeemed = new Set<string>();
  return {
    redeem(input) {
      const key = `${input.evidenceId}:${input.nonce}:${input.requestDigest}:${input.evidenceDigest}`;
      if (redeemed.has(key)) return false;
      redeemed.add(key);
      return true;
    },
  };
}

function evidenceFor(
  catalog: CloudContextCatalog,
  selection: CloudContextPlacementSelection,
  registry = resolverRegistry(catalog, selection),
) {
  return createCloudContextObservationEvidence({
    catalog,
    selection,
    resolverRegistry: registry,
    signer,
    evidenceId: "warden-cloud-context-observation-1",
    nonce: "0123456789abcdef0123456789abcdef",
    issuedAt: "2026-07-18T12:00:00.000Z",
    ttlSeconds: 300,
    admissionPolicyDigest,
  });
}

function verifyArgs(
  catalog: CloudContextCatalog,
  selection: CloudContextPlacementSelection,
  evidence: ReturnType<typeof evidenceFor>,
  registry = resolverRegistry(catalog, selection),
  store = replayStore(),
) {
  const dependencies = deriveCloudContextPlacementDependencies(
    catalog,
    selection,
  );
  return {
    catalog,
    selection,
    evidence,
    resolverRegistry: registry,
    trustedVerifiers: [
      {
        verifierId: signer.verifierId,
        verifierVersion: signer.verifierVersion,
        keyId: signer.keyId,
        publicKeyPem: publicKey
          .export({ type: "spki", format: "pem" })
          .toString(),
        allowedOrganizations: [selection.organizationId],
        allowedPlatformTenants: [selection.platformTenantId],
        allowedEnvironments: [catalog.environment],
        maxEvidenceTtlSeconds: 600,
      },
    ],
    revocations: {
      revokedEvidenceIds: new Set<string>(),
      revokedNonces: new Set<string>(),
      revokedKeyIds: new Set<string>(),
    },
    replayStore: store,
    expectedEvidenceDigest: cloudContextObservationEvidenceDigest(evidence),
    admissionPolicyDigest,
    expectedPreviousObservationDigests: Object.fromEntries(
      dependencies.map((dependency) => [dependency.key, null]),
    ),
    now: "2026-07-18T12:01:00.000Z",
  };
}

function verifiedPostgresRuntimeDecision() {
  const profile = parsePostgresAccessProfile(
    JSON.parse(
      readFileSync("contracts/postgres-access-profile-v1alpha1.json", "utf8"),
    ),
  );
  const checked = JSON.parse(
    readFileSync("contracts/postgres-access-observation-v1alpha1.json", "utf8"),
  ) as PostgresAccessObservationEvidence;
  const { signature: _signature, ...unsigned } = checked;
  const evidence = signPostgresAccessObservationEvidence(
    unsigned as PostgresAccessObservationEvidenceUnsigned,
    postgresSigner,
  );
  const redeemed = new Set<string>();
  const store: PostgresAccessObservationReplayStore = {
    redeem(input) {
      const key = `${input.evidenceId}:${input.nonce}:${input.profileSpecDigest}:${input.evidenceDigest}`;
      if (redeemed.has(key)) return false;
      redeemed.add(key);
      return true;
    },
  };
  return verifyPostgresAccessObservationEvidence({
    profile,
    handoff: JSON.parse(
      readFileSync(
        "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
        "utf8",
      ),
    ),
    evidence,
    expectedEvidenceDigest: postgresAccessObservationEvidenceDigest(evidence),
    expectedObservedGeneration: 1,
    expectedPreviousEvidenceDigest: null,
    expectedDeploymentAuthority: {
      controllerServiceAccountSubject:
        "system:serviceaccount:argocd-database:database-infrastructure-application-controller",
      sourceRepository: "https://github.com/codefly-dev/secure-saas-infra.git",
      sourceRevision: "a".repeat(40),
      sourcePath: "gitops/generated/database/warden-saas-postgres/runtime",
      allowedWorkloadKind: "Deployment",
      rbacDenialMatrixDigest: "c".repeat(64),
      directPodDenialDigest: "d".repeat(64),
    },
    expectedPostgresBootstrap: {
      markerDigest: "e".repeat(64),
      rolePolicyDigest: "f".repeat(64),
      extensionsDigest:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      activationGeneration: 1,
      associationId: "a-bootstrap-jit-0123456789",
      activationActorSubject:
        "system:serviceaccount:codefly-system:codefly-database-operator",
      bootstrapJobUid: "uid-postgres-bootstrap-job-1",
      activatedAt: "2026-07-18T11:55:00.000Z",
      completedAt: "2026-07-18T11:58:00.000Z",
      removedAt: "2026-07-18T11:59:00.000Z",
      finalAssociationAbsenceDigest: "13".repeat(32),
      secretAccessAuditDigest: "14".repeat(32),
    },
    expectedRuntimeProbes: {
      podIdentityStsDigest: "15".repeat(32),
      podSecurityGroupAttachmentDigest: "16".repeat(32),
      applicationNetworkPolicyDenialDigest: "17".repeat(32),
      rdsProxyIamTlsDigest: "18".repeat(32),
      rdsProxyTargetHealthDigest: "19".repeat(32),
    },
    trustedVerifiers: [
      {
        verifierId: postgresSigner.verifierId,
        verifierVersion: postgresSigner.verifierVersion,
        keyId: postgresSigner.keyId,
        publicKeyPem: postgresKeys.publicKey
          .export({ type: "spki", format: "pem" })
          .toString(),
        allowedBindingIds: [profile.bindingId],
        allowedAccessClasses: ["runtime"],
        maxEvidenceTtlSeconds: 600,
        maxObservationAgeSeconds: 600,
        maxBootstrapActivationSeconds: 600,
        binaryDigest: "10".repeat(32),
        policyDigest: "20".repeat(32),
        schemaDigest: "30".repeat(32),
      },
    ],
    revocations: {
      revokedEvidenceIds: new Set<string>(),
      revokedNonces: new Set<string>(),
      revokedKeyIds: new Set<string>(),
    },
    replayStore: store,
    now: "2026-07-18T12:01:00.000Z",
  });
}

test("cloud-context evidence deterministically authenticates an exact placement closure", () => {
  const { catalog, selection } = setup();
  const registry = resolverRegistry(catalog, selection);
  const first = evidenceFor(catalog, selection, registry);
  const second = evidenceFor(catalog, selection, registry);
  assert.deepEqual(first, second);
  const decision = assertDeployableCloudContextPlacement(
    verifyArgs(catalog, selection, first, registry),
  );
  assert.equal(decision.placement.applicationId, selection.applicationId);
  assert.match(decision.decisionDigest, /^[a-f0-9]{64}$/);

  const statusOnly = structuredClone(catalog);
  statusOnly.contexts[1].status.phase = "degraded";
  statusOnly.contexts[1].status.observedGeneration = 1;
  statusOnly.contexts[1].status.verifiedAt = "2026-07-18T12:00:00.000Z";
  statusOnly.contexts[1].status.evidenceRef =
    "evidence://cloud-context/unused-degraded-context";
  assert.equal(
    cloudContextCatalogDesiredStateDigest(statusOnly),
    cloudContextCatalogDesiredStateDigest(catalog),
  );
});

test("runtime deployment admission joins exact CloudContext and PostgreSQL readiness", () => {
  const { catalog, selection } = setup();
  const registry = resolverRegistry(catalog, selection);
  const cloudEvidence = evidenceFor(catalog, selection, registry);
  const cloud = assertDeployableCloudContextPlacement(
    verifyArgs(catalog, selection, cloudEvidence, registry),
  );
  const postgres = verifiedPostgresRuntimeDecision();
  const admission = assertRuntimeDeploymentAdmission({
    cloudContext: cloud,
    postgres: [postgres],
    now: "2026-07-18T12:01:30.000Z",
  });
  assert.equal(admission.state, "admitted");
  assert.equal(admission.applicationId, selection.applicationId);
  assert.equal(admission.componentId, selection.componentId);
  assert.deepEqual(
    admission.resources.map((resource) => resource.bindingId),
    cloud.placement.resourceBindingIds,
  );
  assert.match(admission.decisionDigest, /^[a-f0-9]{64}$/);

  assert.throws(
    () =>
      assertRuntimeDeploymentAdmission({
        cloudContext: cloud,
        postgres: [],
        now: "2026-07-18T12:01:30.000Z",
      }),
    /DEPLOYMENT_ADMISSION_RESOURCE_SET_MISMATCH/,
  );

  const serializedCloud = structuredClone(cloud);
  assert.throws(
    () =>
      assertRuntimeDeploymentAdmission({
        cloudContext: serializedCloud,
        postgres: [postgres],
        now: "2026-07-18T12:01:30.000Z",
      }),
    /CLOUD_PLACEMENT_DECISION_UNTRUSTED/,
  );

  const substitutedPostgres = structuredClone(postgres);
  substitutedPostgres.bindingId = "other-postgres";
  assert.throws(
    () =>
      assertRuntimeDeploymentAdmission({
        cloudContext: cloud,
        postgres: [substitutedPostgres],
        now: "2026-07-18T12:01:30.000Z",
      }),
    /POSTGRES_ACCESS_DECISION_UNTRUSTED/,
  );

  assert.throws(
    () =>
      assertRuntimeDeploymentAdmission({
        cloudContext: cloud,
        postgres: [postgres],
        now: "2026-07-18T12:06:00.000Z",
      }),
    /DEPLOYMENT_ADMISSION_EXPIRED_DECISION/,
  );
});

test("cloud-context resolver dispatch is fully authorized before any resolver side effect", () => {
  const { catalog, selection } = setup();
  const dependencies = deriveCloudContextPlacementDependencies(
    catalog,
    selection,
  );
  const omitted = dependencies
    .flatMap((entry) => entry.references)
    .at(-1)!.scheme;
  const calls: string[] = [];
  const registry = resolverRegistry(catalog, selection, calls, omitted);
  assert.throws(
    () => evidenceFor(catalog, selection, registry),
    /CLOUD_REF_SCHEME_UNKNOWN/,
  );
  assert.deepEqual(calls, []);
});

test("cloud-context verification rejects signature, subject, policy, revocation, replay, and stale evidence", () => {
  const { catalog, selection } = setup();
  const registry = resolverRegistry(catalog, selection);
  const evidence = evidenceFor(catalog, selection, registry);

  const signature = structuredClone(evidence);
  signature.signature.value = `${signature.signature.value.slice(0, -1)}B`;
  assert.throws(
    () =>
      assertDeployableCloudContextPlacement(
        verifyArgs(catalog, selection, signature, registry),
      ),
    /CLOUD_OBSERVATION_(SIGNATURE|CONTENT_ADDRESS)/,
  );

  assert.throws(
    () =>
      assertDeployableCloudContextPlacement({
        ...verifyArgs(catalog, selection, evidence, registry),
        admissionPolicyDigest: "0".repeat(64),
      }),
    /CLOUD_OBSERVATION_POLICY_MISMATCH/,
  );

  const wrongSubject = { ...selection, platformTenantId: "other-tenant" };
  assert.throws(
    () =>
      assertDeployableCloudContextPlacement(
        verifyArgs(catalog, wrongSubject, evidence, registry),
      ),
    /CLOUD_OBSERVATION_(SUBJECT_MISMATCH|POLICY_MISMATCH|DIGEST_MISMATCH)/,
  );

  const revoked = verifyArgs(catalog, selection, evidence, registry);
  revoked.revocations.revokedEvidenceIds.add(evidence.evidenceId);
  assert.throws(
    () => assertDeployableCloudContextPlacement(revoked),
    /CLOUD_OBSERVATION_REVOKED/,
  );

  assert.throws(
    () =>
      assertDeployableCloudContextPlacement({
        ...verifyArgs(catalog, selection, evidence, registry),
        now: "2026-07-18T12:06:00.000Z",
      }),
    /CLOUD_OBSERVATION_EXPIRED/,
  );

  const store = replayStore();
  assert.doesNotThrow(() =>
    assertDeployableCloudContextPlacement(
      verifyArgs(catalog, selection, evidence, registry, store),
    ),
  );
  assert.throws(
    () =>
      assertDeployableCloudContextPlacement(
        verifyArgs(catalog, selection, evidence, registry, store),
      ),
    /CLOUD_OBSERVATION_REPLAY/,
  );
});

test("cloud-context binding context and provider reference substitution fail closed", () => {
  const { catalog, selection } = setup();
  const registry = resolverRegistry(catalog, selection);
  const evidence = evidenceFor(catalog, selection, registry);

  const substituted = structuredClone(catalog);
  const selectedContext = substituted.contexts.find(
    (context) =>
      context.id ===
      substituted.placements.find(
        (placement) =>
          placement.applicationId === selection.applicationId &&
          placement.componentId === selection.componentId,
      )!.contextId,
  )!;
  selectedContext.resourceBindings[0].outputs.endpointRef =
    "stack-output://deus/secure-saas-infra/substituted-endpoint";
  assert.throws(
    () =>
      assertDeployableCloudContextPlacement(
        verifyArgs(substituted, selection, evidence),
      ),
    /CLOUD_OBSERVATION_(DIGEST_MISMATCH|CONTENT_ADDRESS)/,
  );

  const escaped = structuredClone(catalog);
  const source = escaped.contexts.find(
    (context) => context.id === selectedContext.id,
  )!;
  const target = escaped.contexts.find(
    (context) => context.id !== selectedContext.id,
  )!;
  (target.resourceBindings as any[]).push(
    (source.resourceBindings as any[]).shift()!,
  );
  assert.throws(
    () => deriveCloudContextPlacementDependencies(escaped, selection),
    /CLOUD_(BINDING_CONTEXT_MISMATCH|DEPENDENCY_CONTEXT_ESCAPE)/,
  );
});

test("checked cloud-context observation parser rejects noncanonical encodings and impossible dates", () => {
  const checked = JSON.parse(
    readFileSync("contracts/cloud-context-observation-v1alpha1.json", "utf8"),
  );
  assert.doesNotThrow(() => parseCloudContextObservationEvidence(checked));
  checked.signature.value = `${checked.signature.value.slice(0, -1)}B`;
  assert.throws(
    () => parseCloudContextObservationEvidence(checked),
    /CLOUD_OBSERVATION_SIGNATURE/,
  );
  const invalidDate = JSON.parse(
    readFileSync("contracts/cloud-context-observation-v1alpha1.json", "utf8"),
  );
  invalidDate.issuedAt = "2026-02-30T12:00:00.000Z";
  assert.throws(
    () => parseCloudContextObservationEvidence(invalidDate),
    /canonical calendar timestamp/,
  );
});
