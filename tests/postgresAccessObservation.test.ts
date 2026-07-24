import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  derivePostgresAccessObservationSubjects,
  parsePostgresAccessObservationEvidence,
  parsePostgresAccessProfile,
  postgresAccessObservationEvidenceDigest,
  signPostgresAccessObservationEvidence,
  verifyPostgresAccessObservationEvidence,
  type PostgresAccessObservationEvidence,
  type PostgresAccessObservationEvidenceUnsigned,
  type PostgresAccessObservationReplayStore,
  type TrustedPostgresAccessObservationVerifier,
} from "../src/core";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signer = {
  verifierId: "aws-dev-postgres-observer",
  verifierVersion: "1.0.0",
  keyId: "aws-dev-postgres-observer-2026-07",
  privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};

function fixture(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

function profile() {
  return parsePostgresAccessProfile(
    fixture("contracts/postgres-access-profile-v1alpha1.json"),
  );
}

function unsignedEvidence(): PostgresAccessObservationEvidenceUnsigned {
  const source = fixture(
    "contracts/postgres-access-observation-v1alpha1.json",
  ) as PostgresAccessObservationEvidence;
  const { signature: _signature, ...unsigned } = source;
  return unsigned;
}

function signedEvidence(
  mutate?: (value: PostgresAccessObservationEvidenceUnsigned) => void,
): PostgresAccessObservationEvidence {
  const value = structuredClone(unsignedEvidence());
  mutate?.(value);
  return signPostgresAccessObservationEvidence(value, signer);
}

function trust(): TrustedPostgresAccessObservationVerifier {
  return {
    verifierId: signer.verifierId,
    verifierVersion: signer.verifierVersion,
    keyId: signer.keyId,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    allowedBindingIds: [profile().bindingId],
    allowedAccessClasses: [profile().accessClass],
    maxEvidenceTtlSeconds: 600,
    maxObservationAgeSeconds: 600,
    maxBootstrapActivationSeconds: 600,
    binaryDigest: "10".repeat(32),
    policyDigest: "20".repeat(32),
    schemaDigest: "30".repeat(32),
  };
}

function replayStore(): PostgresAccessObservationReplayStore {
  const redeemed = new Set<string>();
  return {
    redeem(input) {
      const key = `${input.evidenceId}:${input.nonce}:${input.profileSpecDigest}:${input.evidenceDigest}`;
      if (redeemed.has(key)) return false;
      redeemed.add(key);
      return true;
    },
  };
}

function verificationArgs(
  evidence: PostgresAccessObservationEvidence,
  store = replayStore(),
) {
  return {
    profile: profile(),
    handoff: fixture(
      "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
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
      allowedWorkloadKind: "Deployment" as const,
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
    trustedVerifiers: [trust()],
    revocations: {
      revokedEvidenceIds: new Set<string>(),
      revokedNonces: new Set<string>(),
      revokedKeyIds: new Set<string>(),
    },
    replayStore: store,
    now: "2026-07-18T12:01:00.000Z",
  };
}

test("checked PostgreSQL access observation is strict and credential-free", () => {
  const parsed = parsePostgresAccessObservationEvidence(
    fixture("contracts/postgres-access-observation-v1alpha1.json"),
  );
  assert.equal(parsed.profile.accessClass, "runtime");
  assert.equal(parsed.deploymentAuthority.allowedWorkloadKind, "Deployment");
  assert.equal(Object.keys(parsed.observations).length, 7);
  assert.throws(
    () =>
      parsePostgresAccessObservationEvidence({
        ...parsed,
        password: "forbidden",
      }),
    /forbidden credential material/,
  );
  const nonCanonicalSignature = structuredClone(parsed);
  nonCanonicalSignature.signature.value = `${parsed.signature.value.slice(0, -1)}B`;
  assert.throws(
    () => parsePostgresAccessObservationEvidence(nonCanonicalSignature),
    /canonical Ed25519 signature encoding/,
  );
  const invalidCalendar = structuredClone(parsed);
  invalidCalendar.issuedAt = "2026-02-30T12:00:00.000Z";
  assert.throws(
    () => parsePostgresAccessObservationEvidence(invalidCalendar),
    /canonical calendar timestamp/,
  );
});

test("PostgreSQL profile, infrastructure handoff, and observation fixtures form one coherent family", () => {
  const accessProfile = profile();
  const handoff = fixture(
    "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
  );
  const evidence = parsePostgresAccessObservationEvidence(
    fixture("contracts/postgres-access-observation-v1alpha1.json"),
  );
  const derived = derivePostgresAccessObservationSubjects(
    handoff,
    accessProfile.accessClass,
  );
  const access = derived.handoff.accessClasses[accessProfile.accessClass];
  assert.equal(access.bindingDigest, accessProfile.enforcement.bindingDigest);
  assert.equal(
    access.workloadBundleDigest,
    accessProfile.enforcement.workloadBundleDigest,
  );
  assert.equal(access.namespace, accessProfile.identity.namespace);
  assert.equal(access.serviceAccount, accessProfile.identity.serviceAccount);
  assert.equal(
    access.podIdentityAssociationId,
    accessProfile.identity.podIdentityAssociationId,
  );
  assert.deepEqual(evidence.profile, {
    id: accessProfile.id,
    bindingId: accessProfile.bindingId,
    accessClass: accessProfile.accessClass,
    profileSpecDigest: accessProfile.profileSpecDigest,
    bindingDigest: accessProfile.enforcement.bindingDigest,
    workloadBundleDigest: accessProfile.enforcement.workloadBundleDigest,
    handoffSpecDigest: derived.handoff.handoffSpecDigest,
  });
  for (const key of Object.keys(derived.subjects) as Array<
    keyof typeof derived.subjects
  >) {
    assert.deepEqual(
      {
        apiVersion: evidence.observations[key].apiVersion,
        kind: evidence.observations[key].kind,
        name: evidence.observations[key].name,
        namespace: evidence.observations[key].namespace,
        specDigest: evidence.observations[key].specDigest,
      },
      derived.subjects[key],
      key,
    );
  }
});

test("signed PostgreSQL observation produces a separate expiring ready decision", () => {
  const evidence = signedEvidence();
  const decision = verifyPostgresAccessObservationEvidence(
    verificationArgs(evidence),
  );
  assert.equal(decision.state, "ready");
  assert.equal(decision.ready, true);
  assert.equal(decision.profileSpecDigest, profile().profileSpecDigest);
  assert.equal(
    decision.handoffSpecDigest,
    fixture("contracts/aws-database-infrastructure-handoff-v1alpha1.json")
      .handoffSpecDigest,
  );
  assert.match(decision.decisionDigest, /^[a-f0-9]{64}$/);
  assert.equal(
    profile().readiness.state,
    "pending-infrastructure",
    "observation must not mutate or forge the immutable pending profile",
  );
});

test("PostgreSQL observation rejects signature, subject, resource, lineage, expiry, and replay substitutions", () => {
  const signed = signedEvidence();
  const forgedSignature = structuredClone(signed);
  forgedSignature.signature.value = `${forgedSignature.signature.value.slice(0, -1)}${forgedSignature.signature.value.endsWith("A") ? "B" : "A"}`;
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(
        verificationArgs(forgedSignature),
      ),
    /SIGNATURE/,
  );

  const wrongHandoff = signedEvidence((value) => {
    value.profile.handoffSpecDigest = "0".repeat(64);
  });
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(verificationArgs(wrongHandoff)),
    /SUBJECT_MISMATCH/,
  );

  const wrongResource = signedEvidence((value) => {
    value.observations.nodePool.specDigest = "0".repeat(64);
  });
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(verificationArgs(wrongResource)),
    /RESOURCE_MISMATCH/,
  );

  const wrongIdentity = signedEvidence((value) => {
    value.observations.serviceAccount.name = "wrong-service-account";
  });
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(verificationArgs(wrongIdentity)),
    /RESOURCE_MISMATCH/,
  );

  const wrongProbe = signedEvidence((value) => {
    value.runtimeProbes.rdsProxyIamTlsDigest = "0".repeat(64);
  });
  assert.throws(
    () => verifyPostgresAccessObservationEvidence(verificationArgs(wrongProbe)),
    /RUNTIME_PROBE_MISMATCH/,
  );

  const wrongBootstrapCleanup = signedEvidence((value) => {
    value.postgresBootstrap.finalAssociationAbsenceDigest = "0".repeat(64);
  });
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(
        verificationArgs(wrongBootstrapCleanup),
      ),
    /BOOTSTRAP_MISMATCH/,
  );

  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence({
        ...verificationArgs(signed),
        expectedPreviousEvidenceDigest: "f".repeat(64),
      }),
    /PREVIOUS_LINK/,
  );
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence({
        ...verificationArgs(signed),
        now: "2026-07-18T12:06:00.000Z",
      }),
    /EXPIRED/,
  );

  const store = replayStore();
  assert.doesNotThrow(() =>
    verifyPostgresAccessObservationEvidence(verificationArgs(signed, store)),
  );
  assert.throws(
    () =>
      verifyPostgresAccessObservationEvidence(verificationArgs(signed, store)),
    /REPLAY/,
  );
});
