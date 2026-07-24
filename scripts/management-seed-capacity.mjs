import { canonicalJson, sha256 } from "./management-seed-scope.mjs";

const ACCOUNT_QUOTA_NAME = "Maximum number of accounts";

export function attestManagementSeedAccountCapacity(
  organization,
  onboarding,
  awsJson,
  seedWave,
  binding,
) {
  const managementAccountId = onboarding?.managementAccountId;
  const bootstrapCandidateDigest = binding?.bootstrapCandidateDigest;
  if (!/^[0-9]{12}$/.test(managementAccountId ?? "")) {
    throw new Error("capacity attestation requires the management account ID");
  }
  if (!/^[a-f0-9]{64}$/.test(bootstrapCandidateDigest ?? "")) {
    throw new Error(
      "capacity attestation requires the exact bootstrap candidate digest",
    );
  }
  const configurationDigest = sha256(
    canonicalJson({ managementAccountId, organization, seedWave }),
  );
  if (seedWave === "organization-only") {
    const subject = {
      apiVersion: "security.deus.dev/management-seed-account-capacity/v1",
      wave: seedWave,
      managementAccountId,
      bootstrapCandidateDigest,
      configurationDigest,
      requiredAccounts: 1,
      observationRequired: false,
      pass: true,
    };
    return {
      ...subject,
      attestationDigest: sha256(canonicalJson(subject)),
    };
  }
  if (seedWave !== "full" || typeof awsJson !== "function") {
    throw new Error("full management seed requires an AWS observation adapter");
  }
  const desiredMembers = new Map(
    organization.accounts
      .filter((account) => account.create !== false)
      .map((account) => [String(account.email).toLowerCase(), account.name]),
  );
  const requiredAccounts = desiredMembers.size + 1;
  if (requiredAccounts !== 9) {
    throw new Error(
      "full management seed must require exactly nine AWS accounts",
    );
  }

  const quotas = awsJson([
    "service-quotas",
    "list-service-quotas",
    "--service-code",
    "organizations",
    "--region",
    "us-east-1",
  ]).Quotas;
  const accountQuotas = Array.isArray(quotas)
    ? quotas.filter((quota) => quota?.QuotaName === ACCOUNT_QUOTA_NAME)
    : [];
  if (
    accountQuotas.length !== 1 ||
    accountQuotas[0].Adjustable !== true ||
    !Number.isInteger(accountQuotas[0].Value) ||
    accountQuotas[0].Value < requiredAccounts
  ) {
    throw new Error(
      `Organizations account quota must be observed in us-east-1 at or above ${requiredAccounts}`,
    );
  }

  const accounts = awsJson(["organizations", "list-accounts"]).Accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error("Organizations account inventory is unavailable");
  }
  let managementSeen = false;
  const observedMembers = [];
  for (const account of accounts) {
    const state = account?.State ?? account?.Status;
    if (state !== "ACTIVE") {
      throw new Error(
        "Organizations account inventory contains a non-active account",
      );
    }
    if (account.Id === onboarding.managementAccountId) {
      if (managementSeen)
        throw new Error("management account appears more than once");
      managementSeen = true;
      continue;
    }
    const email = String(account?.Email ?? "").toLowerCase();
    const expectedName = desiredMembers.get(email);
    if (!expectedName || account.Name !== expectedName) {
      throw new Error(
        "Organizations contains an account outside the reviewed seed",
      );
    }
    observedMembers.push({ id: account.Id, email, name: account.Name });
  }
  if (!managementSeen || accounts.length > requiredAccounts) {
    throw new Error(
      "Organizations account inventory exceeds the reviewed seed",
    );
  }

  const pending = awsJson([
    "organizations",
    "list-create-account-status",
    "--states",
    "IN_PROGRESS",
  ]).CreateAccountStatuses;
  if (!Array.isArray(pending) || pending.length !== 0) {
    throw new Error("concurrent Organizations account creation is forbidden");
  }
  const handshakes = awsJson([
    "organizations",
    "list-handshakes-for-organization",
    "--filter",
    "ActionType=INVITE",
  ]).Handshakes;
  const terminalInvitationStates = new Set([
    "ACCEPTED",
    "CANCELED",
    "DECLINED",
    "EXPIRED",
  ]);
  if (
    !Array.isArray(handshakes) ||
    handshakes.some(
      (handshake) => !terminalInvitationStates.has(handshake?.State),
    )
  ) {
    throw new Error(
      "a pending or unknown Organizations account invitation consumes quota",
    );
  }

  const subject = {
    apiVersion: "security.deus.dev/management-seed-account-capacity/v1",
    wave: seedWave,
    managementAccountId,
    bootstrapCandidateDigest,
    configurationDigest,
    observationRequired: true,
    quotaRegion: "us-east-1",
    quotaName: ACCOUNT_QUOTA_NAME,
    quotaValue: accountQuotas[0].Value,
    requiredAccounts,
    observedAccountCount: accounts.length,
    observedMembers: observedMembers.sort((left, right) =>
      left.email.localeCompare(right.email),
    ),
    openInvitations: 0,
    pendingAccountCreations: 0,
    pass: true,
  };
  return { ...subject, attestationDigest: sha256(canonicalJson(subject)) };
}

export function verifyManagementSeedAccountCapacityAttestation(
  value,
  { managementAccountId, bootstrapCandidateDigest },
) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("reviewed capacity/state attestation is not an object");
  }
  const { attestationDigest, ...subject } = value;
  if (
    !/^[a-f0-9]{64}$/.test(attestationDigest ?? "") ||
    sha256(canonicalJson(subject)) !== attestationDigest
  ) {
    throw new Error("reviewed capacity/state attestation digest is invalid");
  }
  if (
    value.managementAccountId !== managementAccountId ||
    value.bootstrapCandidateDigest !== bootstrapCandidateDigest
  ) {
    throw new Error(
      "reviewed capacity/state attestation is not bound to this management account and bootstrap candidate",
    );
  }
  return value;
}
