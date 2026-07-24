import { canonicalJson, sha256 } from "./management-seed-scope.mjs";
import { verifyManagementSeedOrganizationStateAttestation } from "./management-seed-organization-state.mjs";

export const ORGANIZATION_RECOVERY_REASON =
  "post-apply-attestation-convergence";

export function createManagementSeedOrganizationRecoveryReceipt({
  bootstrapCandidateDigest,
  generatedAt = new Date().toISOString(),
  managementAccountId,
  observedBaselineState,
  plan,
  planManifestDigest,
  reviewedStandaloneState,
  sourceRevision,
}) {
  if (
    !/^[a-f0-9]{40}$/.test(sourceRevision ?? "") ||
    !/^[a-f0-9]{64}$/.test(planManifestDigest ?? "") ||
    !/^[a-f0-9]{64}$/.test(plan?.sha256 ?? "") ||
    plan?.stack !== "management" ||
    plan?.planFile !== "management.plan.json"
  ) {
    throw new Error(
      "organization recovery source and reviewed plan binding is invalid",
    );
  }
  const reviewed = verifyManagementSeedOrganizationStateAttestation(
    reviewedStandaloneState,
    { managementAccountId, bootstrapCandidateDigest },
  );
  const observed = verifyManagementSeedOrganizationStateAttestation(
    observedBaselineState,
    { managementAccountId, bootstrapCandidateDigest },
  );
  if (
    reviewed.expectedState !== "standalone" ||
    reviewed.organizationPresent !== false ||
    observed.expectedState !== "organization-baseline" ||
    observed.organizationPresent !== true ||
    reviewed.configurationDigest !== observed.configurationDigest ||
    observed.fullAwsAccessTargetId !== observed.rootId ||
    observed.managementAccount?.id !== managementAccountId ||
    observed.pass !== true ||
    reviewed.pass !== true
  ) {
    throw new Error("organization recovery transition is not exact");
  }
  const subject = {
    apiVersion:
      "security.deus.dev/management-seed-organization-recovery-receipt/v1",
    kind: "ManagementSeedOrganizationRecoveryReceipt",
    generatedAt,
    recoveryReason: ORGANIZATION_RECOVERY_REASON,
    sourceRevision,
    managementAccountId,
    bootstrapCandidateDigest,
    planManifestDigest,
    plan: {
      stack: plan.stack,
      planFile: plan.planFile,
      sha256: plan.sha256,
    },
    reviewedStandaloneState: reviewed,
    observedBaselineState: observed,
    pulumiInvoked: false,
    cloudMutationPerformed: false,
  };
  return { ...subject, receiptDigest: sha256(canonicalJson(subject)) };
}

export function verifyManagementSeedOrganizationRecoveryReceipt(
  receipt,
  {
    bootstrapCandidateDigest,
    managementAccountId,
    planManifestDigest,
    sourceRevision,
  },
) {
  const { receiptDigest, ...subject } = receipt ?? {};
  if (
    !/^[a-f0-9]{64}$/.test(receiptDigest ?? "") ||
    receiptDigest !== sha256(canonicalJson(subject)) ||
    receipt.apiVersion !==
      "security.deus.dev/management-seed-organization-recovery-receipt/v1" ||
    receipt.kind !== "ManagementSeedOrganizationRecoveryReceipt" ||
    receipt.sourceRevision !== sourceRevision ||
    receipt.managementAccountId !== managementAccountId ||
    receipt.bootstrapCandidateDigest !== bootstrapCandidateDigest ||
    receipt.planManifestDigest !== planManifestDigest ||
    receipt.recoveryReason !== ORGANIZATION_RECOVERY_REASON ||
    receipt.pulumiInvoked !== false ||
    receipt.cloudMutationPerformed !== false
  ) {
    throw new Error("organization recovery receipt binding is invalid");
  }
  createManagementSeedOrganizationRecoveryReceipt({
    bootstrapCandidateDigest,
    generatedAt: receipt.generatedAt,
    managementAccountId,
    observedBaselineState: receipt.observedBaselineState,
    plan: receipt.plan,
    planManifestDigest,
    reviewedStandaloneState: receipt.reviewedStandaloneState,
    sourceRevision,
  });
  return receipt;
}
