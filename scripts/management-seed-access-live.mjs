import path from "node:path";
import {
  APPLY_ROLE_NAME,
  PREVIEW_ROLE_NAME,
  createManagementSeedAccessBundle,
} from "./management-seed-access.mjs";
import { canonicalJson, sha256 } from "./management-seed-scope.mjs";

const ACCESS_MODES = {
  preview: {
    roleName: PREVIEW_ROLE_NAME,
    roleLogicalId: "PreviewRole",
    boundaryLogicalId: "PreviewPermissionsBoundary",
    policyLogicalId: "PreviewRolePolicy",
  },
  apply: {
    roleName: APPLY_ROLE_NAME,
    roleLogicalId: "ApplyRole",
    boundaryLogicalId: "ApplyPermissionsBoundary",
    policyLogicalId: "ApplyRolePolicy",
  },
};

export function attestManagementSeedAccessDeployment(
  root,
  onboarding,
  awsJson,
  { requireProvisionerRetired = true } = {},
) {
  if (typeof awsJson !== "function") {
    throw new Error("AWS observation adapter is required");
  }
  const bundle = createManagementSeedAccessBundle(root, onboarding);
  const observations = {
    bootstrapSamlProvider: attestBootstrapSamlProvider(bundle, awsJson),
    targetRoles: {},
    sourceRoles: {},
  };
  for (const [mode, expected] of Object.entries(ACCESS_MODES)) {
    observations.targetRoles[mode] = attestTargetRole(
      bundle,
      mode,
      expected,
      awsJson,
    );
    observations.sourceRoles[mode] = attestSourceRole(bundle, mode, awsJson);
  }
  observations.retirementAuthority = attestRetirementAuthority(bundle, awsJson);
  observations.provisionerRetirement = requireProvisionerRetired
    ? attestRetiredProvisioner(bundle, awsJson)
    : attestActiveProvisioner(bundle, awsJson);
  const subject = {
    apiVersion: "security.deus.dev/management-seed-access-live-attestation/v1",
    managementAccountId: bundle.managementAccountId,
    awsPartition: bundle.awsPartition,
    managementAccessRegion: bundle.provisioning.region,
    bundleDigest: bundle.bundleDigest,
    observations,
    pass: true,
  };
  return { ...subject, attestationDigest: sha256(canonicalJson(subject)) };
}

export function attestManagementSeedAccessFoundation(
  root,
  onboarding,
  awsJson,
) {
  if (typeof awsJson !== "function") {
    throw new Error("AWS observation adapter is required");
  }
  const bundle = createManagementSeedAccessBundle(root, onboarding);
  const observations = {
    bootstrapSamlProvider: attestBootstrapSamlProvider(bundle, awsJson),
    targetRoles: {},
    sourceRoles: {},
  };
  for (const [mode, expected] of Object.entries(ACCESS_MODES)) {
    observations.targetRoles[mode] = attestTargetRole(
      bundle,
      mode,
      expected,
      awsJson,
      { requireInlinePolicy: false },
    );
    observations.sourceRoles[mode] = attestSourceRole(bundle, mode, awsJson);
  }
  const subject = {
    apiVersion:
      "security.deus.dev/management-seed-access-foundation-attestation/v1",
    managementAccountId: bundle.managementAccountId,
    awsPartition: bundle.awsPartition,
    managementAccessRegion: bundle.provisioning.region,
    bundleDigest: bundle.bundleDigest,
    observations,
    pass: true,
  };
  return { ...subject, attestationDigest: sha256(canonicalJson(subject)) };
}

export function attestManagementSeedAccessInstallationProgress(
  root,
  onboarding,
  awsJson,
) {
  try {
    const attestation = attestManagementSeedAccessFoundation(
      root,
      onboarding,
      awsJson,
    );
    return installationProgress("foundation", attestation);
  } catch (foundationError) {
    try {
      const attestation = attestManagementSeedAccessDeployment(
        root,
        onboarding,
        awsJson,
        { requireProvisionerRetired: false },
      );
      return installationProgress("deployed", attestation);
    } catch (deployedError) {
      throw new Error(
        `management-seed access is neither an exact empty foundation nor an exact deployment: foundation=${foundationError.message}; deployed=${deployedError.message}`,
      );
    }
  }
}

function installationProgress(state, attestation) {
  const subject = {
    state,
    bundleDigest: attestation.bundleDigest,
    attestationDigest: attestation.attestationDigest,
  };
  return { ...subject, progressDigest: sha256(canonicalJson(subject)) };
}

export function attestActiveProvisioner(bundle, awsJson) {
  const active = bundle.provisioning.active;
  const sourceArn = bundle.provisioning.principalArn;
  const roleName = path.posix.basename(sourceArn);
  const expectedPath = `/${sourceArn.split(":role/")[1].slice(0, -roleName.length)}`;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", roleName]).Role,
    "active provisioner role",
  );
  assertEqual(role.RoleName, roleName, "active provisioner role name");
  assertEqual(role.Arn, sourceArn, "active provisioner role ARN");
  assertEqual(role.Path, expectedPath, "active provisioner role path");
  assertEqual(
    role.MaxSessionDuration,
    3600,
    "active provisioner session duration",
  );
  assertCanonicalEqual(
    policyDocument(role.AssumeRolePolicyDocument, "active provisioner trust"),
    bundle.bootstrapSourceTrustPolicy,
    "active provisioner SAML-only trust",
  );
  if (role.PermissionsBoundary !== undefined) {
    throw new Error(
      "active provisioner has an unreviewed permissions boundary",
    );
  }
  assertCanonicalEqual(
    normalizeTags(role.Tags),
    normalizeTags(active.requiredRoleTags),
    "active provisioner role tags",
  );
  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames,
    "active provisioner inline policy names",
  ).sort();
  assertCanonicalEqual(
    inlineNames,
    [active.inlinePolicyName],
    "active provisioner inline policy inventory",
  );
  const inline = awsJson([
    "iam",
    "get-role-policy",
    "--role-name",
    roleName,
    "--policy-name",
    active.inlinePolicyName,
  ]);
  assertCanonicalEqual(
    policyDocument(inline.PolicyDocument, "active provisioner inline policy"),
    active.inlinePolicyDocument,
    "active provisioner inline policy",
  );
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 0) {
    throw new Error("active provisioner has attached policies");
  }
  const bootstrapSamlProvider = attestBootstrapSamlProvider(bundle, awsJson);
  const retirementBoundary = attestProvisionerRetirementBoundary(
    bundle.provisioning.retirement,
    awsJson,
    0,
  );
  return {
    required: false,
    observed: true,
    state: "active",
    roleArn: sourceArn,
    policyDigest: sha256(canonicalJson(active.inlinePolicyDocument)),
    bootstrapSamlProvider,
    retirementBoundary,
  };
}

export function attestRetirementAuthority(bundle, awsJson) {
  const retirement = bundle.provisioning.retirement;
  const sourceArn = retirement.principalArn;
  const roleName = path.posix.basename(sourceArn);
  const expectedPath = `/${sourceArn.split(":role/")[1].slice(0, -roleName.length)}`;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", roleName]).Role,
    "retirement authority role",
  );
  assertEqual(role.RoleName, roleName, "retirement authority role name");
  assertEqual(role.Arn, sourceArn, "retirement authority role ARN");
  assertEqual(role.Path, expectedPath, "retirement authority role path");
  assertEqual(
    role.MaxSessionDuration,
    3600,
    "retirement authority session duration",
  );
  assertCanonicalEqual(
    policyDocument(role.AssumeRolePolicyDocument, "retirement authority trust"),
    bundle.bootstrapSourceTrustPolicy,
    "retirement authority SAML-only trust",
  );
  if (role.PermissionsBoundary !== undefined) {
    throw new Error(
      "retirement authority has an unreviewed permissions boundary",
    );
  }
  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames,
    "retirement authority inline policy names",
  ).sort();
  assertCanonicalEqual(
    inlineNames,
    [retirement.principalInlinePolicyName],
    "retirement authority inline policy inventory",
  );
  const inline = awsJson([
    "iam",
    "get-role-policy",
    "--role-name",
    roleName,
    "--policy-name",
    retirement.principalInlinePolicyName,
  ]);
  assertCanonicalEqual(
    policyDocument(inline.PolicyDocument, "retirement authority inline policy"),
    retirement.principalPolicyDocument,
    "retirement authority inline policy",
  );
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 0) {
    throw new Error("retirement authority has attached policies");
  }
  return {
    roleArn: sourceArn,
    policyDigest: sha256(canonicalJson(retirement.principalPolicyDocument)),
    bootstrapSamlProvider: attestBootstrapSamlProvider(bundle, awsJson),
  };
}

export function attestBootstrapSamlProvider(bundle, awsJson) {
  const expected = bundle.bootstrapSamlProvider;
  const provider = requireRecord(
    awsJson(["iam", "get-saml-provider", "--saml-provider-arn", expected.arn]),
    "bootstrap SAML provider",
  );
  if (
    typeof provider.SAMLMetadataDocument !== "string" ||
    provider.SAMLMetadataDocument.length === 0
  ) {
    throw new Error("bootstrap SAML provider metadata is absent or invalid");
  }
  const metadataSha256 = sha256(
    Buffer.from(provider.SAMLMetadataDocument, "utf8"),
  );
  assertEqual(
    metadataSha256,
    expected.metadataSha256,
    "bootstrap SAML provider metadata SHA-256",
  );
  assertEqual(
    provider.AssertionEncryptionMode,
    expected.assertionEncryptionMode,
    "bootstrap SAML provider assertion encryption mode",
  );
  const privateKeys = provider.PrivateKeyList ?? [];
  if (
    !Array.isArray(privateKeys) ||
    privateKeys.some(
      (entry) =>
        entry === null ||
        typeof entry !== "object" ||
        typeof entry.KeyId !== "string",
    )
  ) {
    throw new Error("bootstrap SAML provider private key inventory is invalid");
  }
  const privateKeyIds = privateKeys.map((entry) => entry.KeyId).sort();
  assertCanonicalEqual(
    privateKeyIds,
    expected.requiredPrivateKeyIds,
    "bootstrap SAML provider private key inventory",
  );
  assertCanonicalEqual(
    normalizeTags(provider.Tags ?? []),
    normalizeTags(expected.requiredTags),
    "bootstrap SAML provider tags",
  );
  return {
    arn: expected.arn,
    assertionEncryptionMode: expected.assertionEncryptionMode,
    metadataSha256,
    requiredPrivateKeyIds: expected.requiredPrivateKeyIds,
    requiredTags: expected.requiredTags,
  };
}

export function attestProvisionerRetirementProgress(bundle, awsJson) {
  const sourceArn = bundle.provisioning.principalArn;
  const active = bundle.provisioning.active;
  const retirement = bundle.provisioning.retirement;
  const roleName = path.posix.basename(sourceArn);
  const expectedPath = `/${sourceArn.split(":role/")[1].slice(0, -roleName.length)}`;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", roleName]).Role,
    "provisioner retirement progress role",
  );
  assertEqual(role.RoleName, roleName, "provisioner retirement role name");
  assertEqual(role.Arn, sourceArn, "provisioner retirement role ARN");
  assertEqual(role.Path, expectedPath, "provisioner retirement role path");
  assertEqual(
    role.MaxSessionDuration,
    3600,
    "provisioner retirement session duration",
  );
  assertCanonicalEqual(
    policyDocument(
      role.AssumeRolePolicyDocument,
      "provisioner retirement trust",
    ),
    bundle.bootstrapSourceTrustPolicy,
    "provisioner retirement SAML-only trust",
  );

  const tags = normalizeTags(role.Tags);
  const activeTags = normalizeTags(active.requiredRoleTags);
  const retiredTags = normalizeTags(retirement.requiredRoleTags);
  const hasActiveTags = canonicalJson(tags) === canonicalJson(activeTags);
  const hasRetiredTags = canonicalJson(tags) === canonicalJson(retiredTags);
  if (!hasActiveTags && !hasRetiredTags) {
    throw new Error(
      "provisioner retirement tags are not an exact monotonic state",
    );
  }

  const boundaryArn = role.PermissionsBoundary?.PermissionsBoundaryArn;
  const boundaryType = role.PermissionsBoundary?.PermissionsBoundaryType;
  const hasBoundary = boundaryArn !== undefined || boundaryType !== undefined;
  if (
    hasBoundary &&
    (boundaryArn !== retirement.permissionsBoundaryArn ||
      boundaryType !== "Policy")
  ) {
    throw new Error(
      "provisioner retirement boundary is not the exact deny-all boundary",
    );
  }
  attestProvisionerRetirementBoundary(retirement, awsJson, hasBoundary ? 1 : 0);

  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames,
    "provisioner retirement inline policy names",
  ).sort();
  const hasActivePolicy =
    canonicalJson(inlineNames) === canonicalJson([active.inlinePolicyName]);
  const hasNoPolicy = inlineNames.length === 0;
  if (!hasActivePolicy && !hasNoPolicy) {
    throw new Error(
      "provisioner retirement inline policy inventory is not monotonic",
    );
  }
  if (hasActivePolicy) {
    const inline = awsJson([
      "iam",
      "get-role-policy",
      "--role-name",
      roleName,
      "--policy-name",
      active.inlinePolicyName,
    ]);
    assertCanonicalEqual(
      policyDocument(
        inline.PolicyDocument,
        "provisioner retirement active policy",
      ),
      active.inlinePolicyDocument,
      "provisioner retirement active policy",
    );
  }
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 0) {
    throw new Error("provisioner retirement role has attached policies");
  }

  let state;
  let completedOperations;
  if (hasActiveTags && !hasBoundary && hasActivePolicy) {
    state = "active";
    completedOperations = [];
  } else if (hasActiveTags && hasBoundary && hasActivePolicy) {
    state = "bounded";
    completedOperations = ["iam:PutRolePermissionsBoundary"];
  } else if (hasActiveTags && hasBoundary && hasNoPolicy) {
    state = "stripped";
    completedOperations = [
      "iam:PutRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
    ];
  } else if (hasRetiredTags && hasBoundary && hasNoPolicy) {
    state = "retired";
    completedOperations = [
      "iam:PutRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
      "iam:TagRole",
    ];
  } else {
    throw new Error(
      "provisioner retirement state is not an exact monotonic prefix",
    );
  }
  const subject = {
    required: state === "retired",
    observed: true,
    state,
    roleArn: sourceArn,
    boundaryArn: retirement.permissionsBoundaryArn,
    completedOperations,
  };
  return { ...subject, progressDigest: sha256(canonicalJson(subject)) };
}

function attestRetiredProvisioner(bundle, awsJson) {
  const progress = attestProvisionerRetirementProgress(bundle, awsJson);
  if (progress.state !== "retired") {
    throw new Error("provisioner has not reached the exact retired state");
  }
  const detail = verifyExactRetiredProvisioner(bundle, awsJson);
  return {
    ...detail,
    state: "retired",
    completedOperations: progress.completedOperations,
  };
}

function verifyExactRetiredProvisioner(bundle, awsJson) {
  const sourceArn = bundle.provisioning.principalArn;
  const retirement = bundle.provisioning.retirement;
  const roleName = path.posix.basename(sourceArn);
  const expectedPath = `/${sourceArn.split(":role/")[1].slice(0, -roleName.length)}`;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", roleName]).Role,
    "retired provisioner role",
  );
  assertEqual(role.RoleName, roleName, "retired provisioner role name");
  assertEqual(role.Arn, sourceArn, "retired provisioner role ARN");
  assertEqual(role.Path, expectedPath, "retired provisioner role path");
  assertEqual(
    role.MaxSessionDuration,
    3600,
    "retired provisioner session duration",
  );
  assertCanonicalEqual(
    policyDocument(role.AssumeRolePolicyDocument, "retired provisioner trust"),
    bundle.bootstrapSourceTrustPolicy,
    "retired provisioner SAML-only trust",
  );
  assertEqual(
    role.PermissionsBoundary?.PermissionsBoundaryArn,
    retirement.permissionsBoundaryArn,
    "retired provisioner deny-all boundary ARN",
  );
  assertEqual(
    role.PermissionsBoundary?.PermissionsBoundaryType,
    "Policy",
    "retired provisioner deny-all boundary type",
  );
  assertCanonicalEqual(
    normalizeTags(role.Tags),
    normalizeTags(retirement.requiredRoleTags),
    "retired provisioner role tags",
  );

  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames,
    "retired provisioner inline policy names",
  ).sort();
  assertCanonicalEqual(
    inlineNames,
    retirement.requiredInlinePolicyNames,
    "retired provisioner inline policy inventory",
  );
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached)) {
    throw new Error("retired provisioner attached policy inventory is invalid");
  }
  assertCanonicalEqual(
    attached.map((entry) => entry?.PolicyArn).sort(),
    retirement.requiredAttachedPolicyArns,
    "retired provisioner attached policy inventory",
  );

  const boundary = requireRecord(
    awsJson([
      "iam",
      "get-policy",
      "--policy-arn",
      retirement.permissionsBoundaryArn,
    ]).Policy,
    "retired provisioner deny-all boundary",
  );
  assertEqual(
    boundary.Arn,
    retirement.permissionsBoundaryArn,
    "retired provisioner boundary ARN",
  );
  assertEqual(
    boundary.PolicyName,
    retirement.permissionsBoundaryName,
    "retired provisioner boundary name",
  );
  assertEqual(
    boundary.Path,
    retirement.permissionsBoundaryPath,
    "retired provisioner boundary path",
  );
  assertEqual(
    boundary.IsAttachable,
    true,
    "retired provisioner boundary attachability",
  );
  assertEqual(
    boundary.AttachmentCount,
    0,
    "retired provisioner boundary attachment count",
  );
  assertEqual(
    boundary.PermissionsBoundaryUsageCount,
    1,
    "retired provisioner boundary usage count",
  );
  if (typeof boundary.DefaultVersionId !== "string") {
    throw new Error("retired provisioner boundary has no default version");
  }
  const versions = awsJson([
    "iam",
    "list-policy-versions",
    "--policy-arn",
    retirement.permissionsBoundaryArn,
  ]).Versions;
  if (
    !Array.isArray(versions) ||
    versions.length !== 1 ||
    versions[0]?.VersionId !== boundary.DefaultVersionId ||
    versions[0]?.IsDefaultVersion !== true
  ) {
    throw new Error(
      "retired provisioner boundary version inventory is not exact",
    );
  }
  const version = requireRecord(
    awsJson([
      "iam",
      "get-policy-version",
      "--policy-arn",
      retirement.permissionsBoundaryArn,
      "--version-id",
      boundary.DefaultVersionId,
    ]).PolicyVersion,
    "retired provisioner boundary default version",
  );
  assertEqual(
    version.VersionId,
    boundary.DefaultVersionId,
    "retired provisioner boundary default version ID",
  );
  assertEqual(
    version.IsDefaultVersion,
    true,
    "retired provisioner boundary default marker",
  );
  assertCanonicalEqual(
    policyDocument(version.Document, "retired provisioner boundary document"),
    retirement.permissionsBoundaryDocument,
    "retired provisioner deny-all boundary document",
  );
  return {
    required: true,
    observed: true,
    roleArn: sourceArn,
    boundaryArn: retirement.permissionsBoundaryArn,
    retirementDigest: sha256(
      canonicalJson({
        trust: bundle.bootstrapSourceTrustPolicy,
        tags: retirement.requiredRoleTags,
        boundary: retirement.permissionsBoundaryDocument,
        inlinePolicies: retirement.requiredInlinePolicyNames,
        attachedPolicies: retirement.requiredAttachedPolicyArns,
      }),
    ),
  };
}

function attestProvisionerRetirementBoundary(
  retirement,
  awsJson,
  expectedUsageCount,
) {
  const boundary = requireRecord(
    awsJson([
      "iam",
      "get-policy",
      "--policy-arn",
      retirement.permissionsBoundaryArn,
    ]).Policy,
    "provisioner retirement deny-all boundary",
  );
  assertEqual(
    boundary.Arn,
    retirement.permissionsBoundaryArn,
    "provisioner retirement boundary ARN",
  );
  assertEqual(
    boundary.PolicyName,
    retirement.permissionsBoundaryName,
    "provisioner retirement boundary name",
  );
  assertEqual(
    boundary.Path,
    retirement.permissionsBoundaryPath,
    "provisioner retirement boundary path",
  );
  assertEqual(
    boundary.IsAttachable,
    true,
    "provisioner retirement boundary attachability",
  );
  assertEqual(
    boundary.AttachmentCount,
    0,
    "provisioner retirement boundary attachment count",
  );
  assertEqual(
    boundary.PermissionsBoundaryUsageCount,
    expectedUsageCount,
    "provisioner retirement boundary usage count",
  );
  if (typeof boundary.DefaultVersionId !== "string") {
    throw new Error("provisioner retirement boundary has no default version");
  }
  const versions = awsJson([
    "iam",
    "list-policy-versions",
    "--policy-arn",
    retirement.permissionsBoundaryArn,
  ]).Versions;
  if (
    !Array.isArray(versions) ||
    versions.length !== 1 ||
    versions[0]?.VersionId !== boundary.DefaultVersionId ||
    versions[0]?.IsDefaultVersion !== true
  ) {
    throw new Error(
      "provisioner retirement boundary version inventory is not exact",
    );
  }
  const version = requireRecord(
    awsJson([
      "iam",
      "get-policy-version",
      "--policy-arn",
      retirement.permissionsBoundaryArn,
      "--version-id",
      boundary.DefaultVersionId,
    ]).PolicyVersion,
    "provisioner retirement boundary default version",
  );
  assertEqual(
    version.VersionId,
    boundary.DefaultVersionId,
    "provisioner retirement boundary version ID",
  );
  assertEqual(
    version.IsDefaultVersion,
    true,
    "provisioner retirement boundary default marker",
  );
  assertCanonicalEqual(
    policyDocument(
      version.Document,
      "provisioner retirement boundary document",
    ),
    retirement.permissionsBoundaryDocument,
    "provisioner retirement deny-all boundary document",
  );
  return {
    boundaryArn: retirement.permissionsBoundaryArn,
    boundaryDigest: sha256(
      canonicalJson(retirement.permissionsBoundaryDocument),
    ),
  };
}

function attestTargetRole(
  bundle,
  mode,
  expected,
  awsJson,
  { requireInlinePolicy = true } = {},
) {
  const roleResource =
    bundle.precreatedFoundation[expected.roleLogicalId].Properties;
  const boundaryResource =
    bundle.precreatedFoundation[expected.boundaryLogicalId].Properties;
  const expectedInline =
    bundle.cloudFormationTemplate.Resources[expected.policyLogicalId]
      .Properties;
  const expectedRoleArn = bundle.targetRoles[mode];
  const expectedBoundaryArn = roleResource.PermissionsBoundary;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", expected.roleName]).Role,
    `${mode} target role`,
  );
  assertEqual(role.RoleName, expected.roleName, `${mode} target role name`);
  assertEqual(role.Arn, expectedRoleArn, `${mode} target role ARN`);
  assertEqual(role.Path, roleResource.Path, `${mode} target role path`);
  assertEqual(
    role.MaxSessionDuration,
    roleResource.MaxSessionDuration,
    `${mode} target session duration`,
  );
  assertEqual(
    role.PermissionsBoundary?.PermissionsBoundaryArn,
    expectedBoundaryArn,
    `${mode} permissions boundary ARN`,
  );
  assertEqual(
    role.PermissionsBoundary?.PermissionsBoundaryType,
    "Policy",
    `${mode} permissions boundary type`,
  );
  assertCanonicalEqual(
    policyDocument(role.AssumeRolePolicyDocument, `${mode} target trust`),
    roleResource.AssumeRolePolicyDocument,
    `${mode} target trust`,
  );
  assertCanonicalEqual(
    normalizeTags(role.Tags),
    normalizeTags(roleResource.Tags),
    `${mode} target tags`,
  );

  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", expected.roleName])
      .PolicyNames,
    `${mode} inline policy names`,
  ).sort();
  assertCanonicalEqual(
    inlineNames,
    requireInlinePolicy ? [expectedInline.PolicyName] : [],
    `${mode} target inline policy inventory`,
  );
  if (requireInlinePolicy) {
    const inline = awsJson([
      "iam",
      "get-role-policy",
      "--role-name",
      expected.roleName,
      "--policy-name",
      expectedInline.PolicyName,
    ]);
    assertCanonicalEqual(
      policyDocument(inline.PolicyDocument, `${mode} inline policy`),
      expectedInline.PolicyDocument,
      `${mode} target inline policy`,
    );
  }
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    expected.roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 0) {
    throw new Error(`${mode} target role has attached policies`);
  }

  const policy = requireRecord(
    awsJson(["iam", "get-policy", "--policy-arn", expectedBoundaryArn]).Policy,
    `${mode} boundary`,
  );
  assertEqual(policy.Arn, expectedBoundaryArn, `${mode} boundary ARN`);
  assertEqual(
    policy.PolicyName,
    boundaryResource.ManagedPolicyName,
    `${mode} boundary name`,
  );
  assertEqual(policy.Path, boundaryResource.Path, `${mode} boundary path`);
  assertEqual(policy.IsAttachable, true, `${mode} boundary attachability`);
  assertEqual(policy.AttachmentCount, 0, `${mode} boundary attachment count`);
  assertEqual(
    policy.PermissionsBoundaryUsageCount,
    1,
    `${mode} boundary usage count`,
  );
  if (typeof policy.DefaultVersionId !== "string") {
    throw new Error(`${mode} boundary has no default version`);
  }
  const versions = awsJson([
    "iam",
    "list-policy-versions",
    "--policy-arn",
    expectedBoundaryArn,
  ]).Versions;
  if (
    !Array.isArray(versions) ||
    versions.length !== 1 ||
    versions[0]?.VersionId !== policy.DefaultVersionId ||
    versions[0]?.IsDefaultVersion !== true
  ) {
    throw new Error(`${mode} boundary version inventory is not exact`);
  }
  const version = requireRecord(
    awsJson([
      "iam",
      "get-policy-version",
      "--policy-arn",
      expectedBoundaryArn,
      "--version-id",
      policy.DefaultVersionId,
    ]).PolicyVersion,
    `${mode} boundary default version`,
  );
  assertEqual(
    version.VersionId,
    policy.DefaultVersionId,
    `${mode} boundary default version ID`,
  );
  assertEqual(
    version.IsDefaultVersion,
    true,
    `${mode} boundary default marker`,
  );
  assertCanonicalEqual(
    policyDocument(version.Document, `${mode} boundary document`),
    boundaryResource.PolicyDocument,
    `${mode} boundary policy document`,
  );
  return {
    roleArn: expectedRoleArn,
    boundaryArn: expectedBoundaryArn,
    inlinePolicyInstalled: requireInlinePolicy,
    boundaryVersionId: policy.DefaultVersionId,
    roleDigest: sha256(
      canonicalJson({
        trust: roleResource.AssumeRolePolicyDocument,
        inline: expectedInline.PolicyDocument,
        boundary: boundaryResource.PolicyDocument,
        tags: normalizeTags(roleResource.Tags),
      }),
    ),
  };
}

function attestSourceRole(bundle, mode, awsJson) {
  const sourceArn = bundle.trustedPrincipals[mode];
  const roleName = path.posix.basename(sourceArn);
  const expectedPath = `/${sourceArn.split(":role/")[1].slice(0, -roleName.length)}`;
  const role = requireRecord(
    awsJson(["iam", "get-role", "--role-name", roleName]).Role,
    `${mode} source role`,
  );
  assertEqual(role.RoleName, roleName, `${mode} source role name`);
  assertEqual(role.Arn, sourceArn, `${mode} source role ARN`);
  assertEqual(role.Path, expectedPath, `${mode} source role path`);
  assertEqual(role.MaxSessionDuration, 3600, `${mode} source session duration`);
  const sourceTrust = policyDocument(
    role.AssumeRolePolicyDocument,
    `${mode} source trust`,
  );
  assertCanonicalEqual(
    sourceTrust,
    bundle.bootstrapSourceTrustPolicy,
    `${mode} pre-organization source SAML-only trust`,
  );
  if (role.PermissionsBoundary !== undefined) {
    throw new Error(
      `${mode} source role has an unreviewed permissions boundary`,
    );
  }
  const inlineNames = requireStringArray(
    awsJson(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames,
    `${mode} source inline policy names`,
  );
  if (inlineNames.length !== 1) {
    throw new Error(`${mode} source role must have exactly one inline policy`);
  }
  const inline = awsJson([
    "iam",
    "get-role-policy",
    "--role-name",
    roleName,
    "--policy-name",
    inlineNames[0],
  ]);
  assertCanonicalEqual(
    policyDocument(inline.PolicyDocument, `${mode} source policy`),
    bundle.trustedPrincipalAssumeRolePolicies[mode],
    `${mode} source assume-role policy`,
  );
  const attached = awsJson([
    "iam",
    "list-attached-role-policies",
    "--role-name",
    roleName,
  ]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 0) {
    throw new Error(`${mode} source role has attached policies`);
  }
  return {
    roleArn: sourceArn,
    trustDigest: sha256(canonicalJson(sourceTrust)),
    policyDigest: sha256(
      canonicalJson(bundle.trustedPrincipalAssumeRolePolicies[mode]),
    ),
  };
}

function policyDocument(value, label) {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const decoded = decodeURIComponent(value.replace(/\+/g, "%20"));
      return requireRecord(JSON.parse(decoded), label);
    } catch (error) {
      throw new Error(
        `${label} is not a valid encoded IAM policy: ${error.message}`,
      );
    }
  }
  throw new Error(`${label} is not an IAM policy document`);
}

function normalizeTags(tags) {
  if (!Array.isArray(tags)) throw new Error("role tags are not an array");
  return tags
    .map((tag) => ({ Key: tag?.Key, Value: tag?.Value }))
    .sort((left, right) => left.Key.localeCompare(right.Key));
}

function requireRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value;
}

function requireStringArray(value, label) {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string")
  ) {
    throw new Error(`${label} is not a string array`);
  }
  return value;
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} does not match the governed access bundle`);
  }
}

function assertCanonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label} does not match the governed access bundle`);
  }
}
