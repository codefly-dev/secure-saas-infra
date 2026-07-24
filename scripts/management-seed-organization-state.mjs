import { canonicalJson, sha256 } from "./management-seed-scope.mjs";

export const ORGANIZATION_STATE_API_VERSION =
  "security.deus.dev/management-seed-organization-state/v1";

const REGION = "us-east-1";
const ENABLED_POLICY_TYPES = ["S3_POLICY", "SERVICE_CONTROL_POLICY"];

export function attestManagementSeedOrganizationState(
  organization,
  onboarding,
  awsObservation,
  expectedState,
  binding,
) {
  const managementAccountId = onboarding?.managementAccountId;
  const bootstrapCandidateDigest = binding?.bootstrapCandidateDigest;
  if (!/^[0-9]{12}$/.test(managementAccountId ?? "")) {
    throw new Error(
      "organization-state attestation requires the management account ID",
    );
  }
  if (!/^[a-f0-9]{64}$/.test(bootstrapCandidateDigest ?? "")) {
    throw new Error(
      "organization-state attestation requires the exact bootstrap candidate digest",
    );
  }
  if (typeof awsObservation !== "function") {
    throw new Error(
      "organization-state attestation requires an AWS observation adapter",
    );
  }
  if (
    expectedState !== "standalone" &&
    expectedState !== "organization-baseline"
  ) {
    throw new Error("organization-state attestation expected state is invalid");
  }

  const configurationDigest = sha256(
    canonicalJson({ managementAccountId, organization }),
  );
  const described = observe(
    awsObservation,
    ["organizations", "describe-organization", "--region", REGION],
    "organization",
  );
  if (expectedState === "standalone") {
    if (
      described.ok !== false ||
      described.errorCode !== "AWSOrganizationsNotInUseException"
    ) {
      throw new Error(
        "standalone precondition requires AWSOrganizationsNotInUseException",
      );
    }
    return digest({
      apiVersion: ORGANIZATION_STATE_API_VERSION,
      expectedState,
      managementAccountId,
      bootstrapCandidateDigest,
      configurationDigest,
      observationRegion: REGION,
      organizationPresent: false,
      pass: true,
    });
  }

  const organizationValue = requireRecord(
    requireSuccess(described, "organization").Organization,
    "organization",
  );
  const organizationId = exactString(
    organizationValue.Id,
    /^o-[a-z0-9]{10,32}$/,
    "organization ID",
  );
  assertEqual(organizationValue.FeatureSet, "ALL", "organization feature set");
  assertEqual(
    organizationValue.ManagementAccountId ?? organizationValue.MasterAccountId,
    managementAccountId,
    "organization management account",
  );
  assertEqual(
    organizationValue.Arn,
    `arn:aws:organizations::${managementAccountId}:organization/${organizationId}`,
    "organization ARN",
  );

  const roots = requireArray(
    successValue(
      awsObservation,
      ["organizations", "list-roots", "--region", REGION],
      "roots",
    ).Roots,
    "roots",
  );
  if (roots.length !== 1)
    throw new Error("organization must contain exactly one root");
  const root = requireRecord(roots[0], "organization root");
  const rootId = exactString(root.Id, /^r-[0-9a-z]{4,32}$/, "root ID");
  assertEqual(root.Name, "Root", "root name");
  assertEqual(
    root.Arn,
    `arn:aws:organizations::${managementAccountId}:root/${organizationId}/${rootId}`,
    "root ARN",
  );
  const policyTypes = requireArray(root.PolicyTypes, "root policy types")
    .map((entry) => {
      const policyType = requireRecord(entry, "root policy type");
      assertEqual(policyType.Status, "ENABLED", "root policy type status");
      return exactString(
        policyType.Type,
        /^(?:S3_POLICY|SERVICE_CONTROL_POLICY)$/,
        "root policy type",
      );
    })
    .sort();
  assertCanonicalEqual(policyTypes, ENABLED_POLICY_TYPES, "root policy types");
  const rootTags = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-tags-for-resource",
        "--resource-id",
        rootId,
        "--region",
        REGION,
      ],
      "root tags",
    ).Tags,
    "root tags",
  );
  assertEmpty(rootTags, "organization baseline root tags");

  const accounts = requireArray(
    successValue(
      awsObservation,
      ["organizations", "list-accounts", "--region", REGION],
      "accounts",
    ).Accounts,
    "accounts",
  );
  if (accounts.length !== 1) {
    throw new Error(
      "organization baseline must contain only the management account",
    );
  }
  const managementAccount = requireRecord(accounts[0], "management account");
  assertEqual(
    managementAccount.Id,
    managementAccountId,
    "management account ID",
  );
  assertEqual(
    managementAccount.State ?? managementAccount.Status,
    "ACTIVE",
    "management account state",
  );
  const managementAccountName = exactString(
    managementAccount.Name,
    /^.{1,50}$/u,
    "management account name",
  );
  const managementAccountEmail = exactString(
    String(managementAccount.Email ?? "").toLowerCase(),
    /^[^\s@]+@[^\s@]+$/u,
    "management account email",
  );
  const managementAccountTags = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-tags-for-resource",
        "--resource-id",
        managementAccountId,
        "--region",
        REGION,
      ],
      "management account tags",
    ).Tags,
    "management account tags",
  );
  assertEmpty(
    managementAccountTags,
    "organization baseline management account tags",
  );

  const ous = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-organizational-units-for-parent",
        "--parent-id",
        rootId,
        "--region",
        REGION,
      ],
      "organizational units",
    ).OrganizationalUnits,
    "organizational units",
  );
  assertEmpty(ous, "organization baseline organizational units");

  const enabledServices = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-aws-service-access-for-organization",
        "--region",
        REGION,
      ],
      "trusted service access",
    ).EnabledServicePrincipals,
    "trusted service access",
  );
  assertEmpty(enabledServices, "organization baseline trusted service access");

  const delegatedAdministrators = requireArray(
    successValue(
      awsObservation,
      ["organizations", "list-delegated-administrators", "--region", REGION],
      "delegated administrators",
    ).DelegatedAdministrators,
    "delegated administrators",
  );
  assertEmpty(
    delegatedAdministrators,
    "organization baseline delegated administrators",
  );

  const resourcePolicy = observe(
    awsObservation,
    ["organizations", "describe-resource-policy", "--region", REGION],
    "organization resource policy",
  );
  if (
    resourcePolicy.ok !== false ||
    resourcePolicy.errorCode !== "ResourcePolicyNotFoundException"
  ) {
    throw new Error("organization baseline must not contain a resource policy");
  }

  const serviceControlPolicies = policies(
    awsObservation,
    "SERVICE_CONTROL_POLICY",
  );
  if (serviceControlPolicies.length !== 1) {
    throw new Error("organization baseline must contain only FullAWSAccess");
  }
  const fullAccess = requireRecord(
    serviceControlPolicies[0],
    "FullAWSAccess policy",
  );
  assertEqual(fullAccess.Id, "p-FullAWSAccess", "FullAWSAccess policy ID");
  assertEqual(fullAccess.Name, "FullAWSAccess", "FullAWSAccess policy name");
  assertEqual(
    fullAccess.Type,
    "SERVICE_CONTROL_POLICY",
    "FullAWSAccess policy type",
  );
  assertEqual(fullAccess.AwsManaged, true, "FullAWSAccess AWS-managed marker");
  assertEqual(
    fullAccess.Arn,
    "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
    "FullAWSAccess policy ARN",
  );
  const s3Policies = policies(awsObservation, "S3_POLICY");
  assertEmpty(s3Policies, "organization baseline S3 policies");
  const fullAccessTargets = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-targets-for-policy",
        "--policy-id",
        "p-FullAWSAccess",
        "--region",
        REGION,
      ],
      "FullAWSAccess targets",
    ).Targets,
    "FullAWSAccess targets",
  );
  if (fullAccessTargets.length !== 1) {
    throw new Error("FullAWSAccess must be attached only to the root");
  }
  const fullAccessTarget = requireRecord(
    fullAccessTargets[0],
    "FullAWSAccess target",
  );
  assertEqual(fullAccessTarget.TargetId, rootId, "FullAWSAccess root target");
  assertEqual(fullAccessTarget.Type, "ROOT", "FullAWSAccess target type");

  const pending = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-create-account-status",
        "--states",
        "IN_PROGRESS",
        "--region",
        REGION,
      ],
      "pending account creation",
    ).CreateAccountStatuses,
    "pending account creation",
  );
  assertEmpty(pending, "organization baseline pending account creation");
  const handshakes = requireArray(
    successValue(
      awsObservation,
      [
        "organizations",
        "list-handshakes-for-organization",
        "--filter",
        "ActionType=INVITE",
        "--region",
        REGION,
      ],
      "organization invitations",
    ).Handshakes,
    "organization invitations",
  );
  const terminalInvitationStates = new Set([
    "ACCEPTED",
    "CANCELED",
    "DECLINED",
    "EXPIRED",
  ]);
  if (handshakes.some((entry) => !terminalInvitationStates.has(entry?.State))) {
    throw new Error(
      "organization baseline contains a pending or unknown invitation",
    );
  }

  return digest({
    apiVersion: ORGANIZATION_STATE_API_VERSION,
    expectedState,
    managementAccountId,
    bootstrapCandidateDigest,
    configurationDigest,
    observationRegion: REGION,
    organizationPresent: true,
    organizationId,
    organizationArn: organizationValue.Arn,
    featureSet: "ALL",
    rootId,
    rootArn: root.Arn,
    rootPolicyTypes: policyTypes,
    rootTags: [],
    managementAccount: {
      id: managementAccountId,
      name: managementAccountName,
      email: managementAccountEmail,
      state: "ACTIVE",
      tags: [],
    },
    organizationalUnits: [],
    trustedServicePrincipals: [],
    delegatedAdministrators: [],
    resourcePolicyPresent: false,
    customerPolicies: [],
    fullAwsAccessTargetId: rootId,
    openInvitations: 0,
    pendingAccountCreations: 0,
    pass: true,
  });
}

export function verifyManagementSeedOrganizationStateAttestation(
  value,
  { managementAccountId, bootstrapCandidateDigest },
) {
  const record = requireRecord(
    value,
    "reviewed organization-state attestation",
  );
  const { attestationDigest, ...subject } = record;
  if (
    !/^[a-f0-9]{64}$/.test(attestationDigest ?? "") ||
    sha256(canonicalJson(subject)) !== attestationDigest
  ) {
    throw new Error(
      "reviewed organization-state attestation digest is invalid",
    );
  }
  if (
    record.apiVersion !== ORGANIZATION_STATE_API_VERSION ||
    record.managementAccountId !== managementAccountId ||
    record.bootstrapCandidateDigest !== bootstrapCandidateDigest
  ) {
    throw new Error(
      "reviewed organization-state attestation is not bound to this management account and bootstrap candidate",
    );
  }
  return record;
}

function policies(awsObservation, type) {
  return requireArray(
    successValue(
      awsObservation,
      ["organizations", "list-policies", "--filter", type, "--region", REGION],
      `${type} policies`,
    ).Policies,
    `${type} policies`,
  );
}

function successValue(awsObservation, args, label) {
  return requireSuccess(observe(awsObservation, args, label), label);
}

function observe(awsObservation, args, label) {
  const result = awsObservation(args);
  if (result === null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${label} observation result is invalid`);
  }
  if (result.ok !== true && result.ok !== false) {
    throw new Error(
      `${label} observation must report an explicit success status`,
    );
  }
  return result;
}

function requireSuccess(result, label) {
  if (result.ok !== true) throw new Error(`${label} observation failed closed`);
  return requireRecord(result.value, `${label} response`);
}

function digest(subject) {
  return { ...subject, attestationDigest: sha256(canonicalJson(subject)) };
}

function requireRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} inventory is invalid`);
  return value;
}

function exactString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} is not exact`);
}

function assertCanonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label} inventory is not exact`);
  }
}

function assertEmpty(value, label) {
  if (value.length !== 0) throw new Error(`${label} must be empty`);
}
