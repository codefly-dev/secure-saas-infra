import { readFileSync } from "node:fs";
import path from "node:path";
import { canonicalJson, safeFile, sha256 } from "./management-seed-scope.mjs";

export const ACCESS_BUNDLE_API_VERSION =
  "security.deus.dev/management-seed-access-bundle/v1";
export const ACCESS_BUNDLE_KIND = "ManagementSeedAccessBundle";
export const PREVIEW_ROLE_NAME = "OrganizationSeedPreview";
export const APPLY_ROLE_NAME = "OrganizationSeedApply";
export const RETIRED_PROVISIONER_BOUNDARY_NAME =
  "DeusManagementSeedProvisionerRetiredBoundary";
export const PROVISIONER_POLICY_NAME = "ManagementSeedAccessProvisioner";
export const RETIREMENT_POLICY_NAME = "ManagementSeedProvisionerRetirement";
export const RETIREMENT_ROLE_NAME = "ManagementSeedRetirement";

const KNOWN_EXAMPLE_ACCOUNT_IDS = new Set([
  "111111111111",
  "111122223333",
  "123456789012",
]);
const ROLE_ARN = /^arn:(aws):iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]+)$/;
const SAML_PROVIDER_ARN =
  /^arn:(aws):iam::([0-9]{12}):saml-provider\/(DeusBootstrap)$/;
const BOOTSTRAP_SOURCE_ROLE_PATHS = Object.freeze({
  managementPreviewTrustedPrincipalArn:
    "deus/bootstrap-source/ManagementSeedPreview",
  managementApplyTrustedPrincipalArn:
    "deus/bootstrap-source/ManagementSeedApply",
  managementProvisionerPrincipalArn:
    "deus/bootstrap-source/ManagementSeedProvisioner",
});

export function managementSeedAccessConfigurationFailures(onboarding) {
  const failures = [];
  if (!isRecord(onboarding)) return ["onboarding must be an object"];

  const accountId = onboarding.managementAccountId;
  if (!/^[0-9]{12}$/.test(accountId ?? "")) {
    failures.push("managementAccountId must be exactly 12 digits");
  } else if (KNOWN_EXAMPLE_ACCOUNT_IDS.has(accountId)) {
    failures.push("managementAccountId is still an example value");
  }
  if (
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(
      onboarding.managementAccessRegion ?? "",
    )
  ) {
    failures.push("managementAccessRegion must be one exact AWS region");
  }

  const targetRoles = [
    ["managementPreviewRoleArn", PREVIEW_ROLE_NAME],
    ["managementApplyRoleArn", APPLY_ROLE_NAME],
  ];
  const trustedPrincipals = [
    "managementPreviewTrustedPrincipalArn",
    "managementApplyTrustedPrincipalArn",
  ];
  const provisionerKey = "managementProvisionerPrincipalArn";
  const samlProviderKey = "managementBootstrapSamlProviderArn";
  const samlMetadataDigestKey = "managementBootstrapSamlMetadataSha256";
  const parsedArns = new Map();

  for (const [key, expectedName] of targetRoles) {
    const parsed = parseManagementRoleArn(onboarding[key], accountId);
    if (!parsed || parsed.rolePath !== expectedName) {
      failures.push(
        `${key} must equal arn:aws:iam::managementAccountId:role/${expectedName}`,
      );
    } else {
      parsedArns.set(key, parsed);
    }
  }

  for (const key of trustedPrincipals) {
    const parsed = parseManagementRoleArn(onboarding[key], accountId);
    if (!parsed || parsed.rolePath !== BOOTSTRAP_SOURCE_ROLE_PATHS[key]) {
      failures.push(
        `${key} must be the exact pre-organization SAML source role in managementAccountId`,
      );
    } else {
      parsedArns.set(key, parsed);
    }
  }
  const provisioner = parseManagementRoleArn(
    onboarding[provisionerKey],
    accountId,
  );
  if (
    !provisioner ||
    provisioner.rolePath !== BOOTSTRAP_SOURCE_ROLE_PATHS[provisionerKey]
  ) {
    failures.push(
      `${provisionerKey} must be the exact pre-organization SAML provisioner role in managementAccountId`,
    );
  } else {
    parsedArns.set(provisionerKey, provisioner);
  }
  const samlProvider = parseSamlProviderArn(
    onboarding[samlProviderKey],
    accountId,
  );
  if (!samlProvider) {
    failures.push(
      `${samlProviderKey} must be the exact same-account DeusBootstrap SAML provider ARN in managementAccountId`,
    );
  } else {
    parsedArns.set(samlProviderKey, samlProvider);
  }
  if (
    !/^[a-f0-9]{64}$/.test(onboarding[samlMetadataDigestKey] ?? "") ||
    /^0{64}$/.test(onboarding[samlMetadataDigestKey] ?? "")
  ) {
    failures.push(
      `${samlMetadataDigestKey} must be the non-placeholder lowercase SHA-256 of the exact AWS-returned SAML metadata UTF-8 bytes`,
    );
  }

  const exactValues = [
    ...targetRoles.map(([key]) => onboarding[key]),
    ...trustedPrincipals.map((key) => onboarding[key]),
    onboarding[provisionerKey],
  ];
  if (new Set(exactValues).size !== exactValues.length) {
    failures.push(
      "management preview/apply roles, trusted principals, and JIT provisioner must all be distinct",
    );
  }

  if (
    [...parsedArns.values()].some((entry) => entry.partition !== "aws") ||
    (typeof onboarding.managementAccessRegion === "string" &&
      !partitionAcceptsRegion("aws", onboarding.managementAccessRegion))
  ) {
    failures.push(
      "this management-seed release supports only the commercial aws partition and one of its regions",
    );
  }

  return [...new Set(failures)];
}

export function assertManagementSeedAccessConfiguration(onboarding) {
  const failures = managementSeedAccessConfigurationFailures(onboarding);
  if (failures.length > 0) {
    throw new Error(
      `Management-seed access configuration denied: ${failures.join("; ")}.`,
    );
  }
}

export function createManagementSeedAccessBundle(root, onboarding) {
  assertManagementSeedAccessConfiguration(onboarding);
  const repositoryRoot = path.resolve(root);
  const partition = parseManagementRoleArn(
    onboarding.managementPreviewRoleArn,
    onboarding.managementAccountId,
  ).partition;
  const previewPolicy = readPolicy(
    repositoryRoot,
    "security/aws-management-seed-preview-policy.json",
    onboarding.managementAccountId,
  );
  const applyPolicy = readPolicy(
    repositoryRoot,
    "security/aws-management-seed-apply-policy.json",
    onboarding.managementAccountId,
  );
  const accountPrincipal = `arn:${partition}:iam::${onboarding.managementAccountId}:root`;
  const previewBoundary = managedPolicyResource(
    "DeusOrganizationSeedPreviewBoundary",
    "Maximum permissions for management-seed preview sessions.",
    previewPolicy.document,
  );
  const applyBoundary = managedPolicyResource(
    "DeusOrganizationSeedApplyBoundary",
    "Maximum permissions for create-only management-seed apply sessions.",
    applyPolicy.document,
  );
  const previewBoundaryArn = `arn:${partition}:iam::${onboarding.managementAccountId}:policy/deus/bootstrap/${previewBoundary.Properties.ManagedPolicyName}`;
  const applyBoundaryArn = `arn:${partition}:iam::${onboarding.managementAccountId}:policy/deus/bootstrap/${applyBoundary.Properties.ManagedPolicyName}`;
  const previewRole = roleResource({
    accountId: onboarding.managementAccountId,
    accountPrincipal,
    trustedPrincipalArn: onboarding.managementPreviewTrustedPrincipalArn,
    roleName: PREVIEW_ROLE_NAME,
    boundaryArn: previewBoundaryArn,
    accessMode: "preview",
  });
  const applyRole = roleResource({
    accountId: onboarding.managementAccountId,
    accountPrincipal,
    trustedPrincipalArn: onboarding.managementApplyTrustedPrincipalArn,
    roleName: APPLY_ROLE_NAME,
    boundaryArn: applyBoundaryArn,
    accessMode: "apply",
  });
  const precreatedFoundation = {
    PreviewPermissionsBoundary: previewBoundary,
    ApplyPermissionsBoundary: applyBoundary,
    PreviewRole: previewRole,
    ApplyRole: applyRole,
  };
  const template = {
    AWSTemplateFormatVersion: "2010-09-09",
    Description:
      "Install only the bounded AWS Organizations management-seed inline policies into precreated roles.",
    Metadata: {
      Deus: {
        ApiVersion: ACCESS_BUNDLE_API_VERSION,
        AuthorizationModel: "separate-preorganization-saml-principals",
        CloudMutationPerformedByRenderer: false,
      },
    },
    Conditions: {
      ExpectedManagementAccountPartitionAndRegion: {
        "Fn::And": [
          {
            "Fn::Equals": [
              { Ref: "AWS::AccountId" },
              onboarding.managementAccountId,
            ],
          },
          { "Fn::Equals": [{ Ref: "AWS::Partition" }, partition] },
          {
            "Fn::Equals": [
              { Ref: "AWS::Region" },
              onboarding.managementAccessRegion,
            ],
          },
        ],
      },
    },
    Resources: {
      PreviewRolePolicy: rolePolicyResource(
        PREVIEW_ROLE_NAME,
        "OrganizationSeedPreviewPermissions",
        previewPolicy.document,
      ),
      ApplyRolePolicy: rolePolicyResource(
        APPLY_ROLE_NAME,
        "OrganizationSeedApplyPermissions",
        applyPolicy.document,
      ),
    },
    Outputs: {
      PreviewRoleArn: {
        Condition: "ExpectedManagementAccountPartitionAndRegion",
        Value: onboarding.managementPreviewRoleArn,
      },
      ApplyRoleArn: {
        Condition: "ExpectedManagementAccountPartitionAndRegion",
        Value: onboarding.managementApplyRoleArn,
      },
      PreviewPermissionsBoundaryArn: {
        Condition: "ExpectedManagementAccountPartitionAndRegion",
        Value: previewBoundaryArn,
      },
      ApplyPermissionsBoundaryArn: {
        Condition: "ExpectedManagementAccountPartitionAndRegion",
        Value: applyBoundaryArn,
      },
    },
  };
  const subject = {
    apiVersion: ACCESS_BUNDLE_API_VERSION,
    kind: ACCESS_BUNDLE_KIND,
    cloudMutationPerformed: false,
    managementAccountId: onboarding.managementAccountId,
    awsPartition: partition,
    authorizationModel: "separate-preorganization-saml-principals",
    bootstrapSamlProvider: {
      arn: onboarding.managementBootstrapSamlProviderArn,
      assertionEncryptionMode: "Allowed",
      metadataSha256: onboarding.managementBootstrapSamlMetadataSha256,
      requiredPrivateKeyIds: [],
      requiredTags: [],
    },
    bootstrapSourceTrustPolicy: bootstrapSourceTrustPolicy(
      partition,
      onboarding.managementBootstrapSamlProviderArn,
    ),
    provisioning: {
      model: "preorganization-saml-administrator",
      principalArn: onboarding.managementProvisionerPrincipalArn,
      active: {
        inlinePolicyName: PROVISIONER_POLICY_NAME,
        inlinePolicyDocument: activeProvisionerPolicy(onboarding, partition),
        requiredRoleTags: provisionerTags("active"),
        requiredAttachedPolicyArns: [],
        permissionsBoundaryRequired: false,
      },
      cloudFormationStackName: "deus-management-seed-access",
      region: onboarding.managementAccessRegion,
      standingAssignmentAllowed: false,
      retirementRequiredBeforeSeedPreview: true,
      retirement: {
        principalArn: `arn:${partition}:iam::${onboarding.managementAccountId}:role/deus/bootstrap-source/${RETIREMENT_ROLE_NAME}`,
        principalInlinePolicyName: RETIREMENT_POLICY_NAME,
        principalPolicyDocument: provisionerRetirementPolicy(
          onboarding,
          partition,
        ),
        permissionsBoundaryArn: `arn:aws:iam::${onboarding.managementAccountId}:policy/deus/bootstrap/${RETIRED_PROVISIONER_BOUNDARY_NAME}`,
        permissionsBoundaryName: RETIRED_PROVISIONER_BOUNDARY_NAME,
        permissionsBoundaryPath: "/deus/bootstrap/",
        permissionsBoundaryDocument: retiredProvisionerBoundaryPolicy(),
        requiredRoleTags: provisionerTags("retired"),
        requiredInlinePolicyNames: [],
        requiredAttachedPolicyArns: [],
        upstreamIdpAssignmentRetirementExternallyRequired: true,
      },
    },
    trustedPrincipals: {
      preview: onboarding.managementPreviewTrustedPrincipalArn,
      apply: onboarding.managementApplyTrustedPrincipalArn,
    },
    targetRoles: {
      preview: onboarding.managementPreviewRoleArn,
      apply: onboarding.managementApplyRoleArn,
    },
    precreatedFoundation,
    trustedPrincipalAssumeRolePolicies: {
      preview: assumeExactRolePolicy(onboarding.managementPreviewRoleArn),
      apply: assumeExactRolePolicy(onboarding.managementApplyRoleArn),
    },
    sourcePolicies: {
      preview: {
        path: previewPolicy.path,
        sha256: previewPolicy.sha256,
      },
      apply: { path: applyPolicy.path, sha256: applyPolicy.sha256 },
    },
    cloudFormationTemplate: template,
    cloudFormationTemplateCanonicalSha256: sha256(canonicalJson(template)),
    cloudFormationTemplateFileSha256: sha256(
      renderManagementSeedAccessTemplate(template),
    ),
  };
  return { ...subject, bundleDigest: sha256(canonicalJson(subject)) };
}

export function renderManagementSeedAccessTemplate(template) {
  return `${JSON.stringify(template, null, 2)}\n`;
}

function parseManagementRoleArn(value, expectedAccountId) {
  if (typeof value !== "string" || value.includes("*")) return null;
  const match = ROLE_ARN.exec(value);
  if (!match || match[2] !== expectedAccountId) return null;
  return { partition: match[1], accountId: match[2], rolePath: match[3] };
}

function parseSamlProviderArn(value, expectedAccountId) {
  if (typeof value !== "string" || value.includes("*")) return null;
  const match = SAML_PROVIDER_ARN.exec(value);
  if (!match || match[2] !== expectedAccountId) return null;
  return { partition: match[1], accountId: match[2], providerName: match[3] };
}

function partitionAcceptsRegion(partition, region) {
  return (
    partition === "aws" &&
    /^[a-z]{2}-[a-z]+-\d$/.test(region) &&
    !region.startsWith("cn-") &&
    !region.startsWith("us-gov-")
  );
}

function readPolicy(root, relativePath, managementAccountId) {
  const file = safeFile(root, relativePath);
  const source = readFileSync(file);
  let document;
  try {
    document = JSON.parse(source.toString("utf8"));
  } catch (error) {
    throw new Error(`${relativePath} is not valid JSON: ${error.message}`);
  }
  if (
    !isRecord(document) ||
    document.Version !== "2012-10-17" ||
    !Array.isArray(document.Statement) ||
    document.Statement.length === 0
  ) {
    throw new Error(`${relativePath} is not a valid IAM policy document.`);
  }
  return {
    path: relativePath,
    document: bindManagementAccountId(document, managementAccountId),
    sha256: sha256(source),
  };
}

function bindManagementAccountId(value, managementAccountId) {
  const placeholder = "__DEUS_MANAGEMENT_ACCOUNT_ID__";
  if (typeof value === "string") {
    return value.replaceAll(placeholder, managementAccountId);
  }
  if (Array.isArray(value)) {
    return value.map((entry) =>
      bindManagementAccountId(entry, managementAccountId),
    );
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        bindManagementAccountId(entry, managementAccountId),
      ]),
    );
  }
  return value;
}

function managedPolicyResource(name, description, policyDocument) {
  return {
    Type: "AWS::IAM::ManagedPolicy",
    Condition: "ExpectedManagementAccountPartitionAndRegion",
    DeletionPolicy: "Retain",
    UpdateReplacePolicy: "Retain",
    Properties: {
      ManagedPolicyName: name,
      Path: "/deus/bootstrap/",
      Description: description,
      PolicyDocument: policyDocument,
    },
  };
}

function rolePolicyResource(roleName, policyName, policyDocument) {
  return {
    Type: "AWS::IAM::RolePolicy",
    Condition: "ExpectedManagementAccountPartitionAndRegion",
    DeletionPolicy: "Retain",
    UpdateReplacePolicy: "Retain",
    Properties: {
      RoleName: roleName,
      PolicyName: policyName,
      PolicyDocument: policyDocument,
    },
  };
}

function assumeExactRolePolicy(targetRoleArn) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AssumeExactManagementSeedRole",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Resource: targetRoleArn,
      },
      {
        Sid: "DenyAssumingAnyOtherRole",
        Effect: "Deny",
        Action: "sts:AssumeRole",
        NotResource: targetRoleArn,
      },
      {
        Sid: "DenyEveryOtherSourceAction",
        Effect: "Deny",
        NotAction: "sts:AssumeRole",
        Resource: "*",
      },
    ],
  };
}

function bootstrapSourceTrustPolicy(partition, samlProviderArn) {
  if (partition !== "aws") {
    throw new Error("bootstrap source trust supports only commercial AWS");
  }
  const audience = "https://signin.aws.amazon.com/saml";
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Federated: samlProviderArn },
        Action: ["sts:AssumeRoleWithSAML", "sts:TagSession"],
        Condition: {
          StringEquals: {
            "SAML:aud": audience,
          },
        },
      },
    ],
  };
}

function retiredProvisionerBoundaryPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyAllRetiredProvisionerActions",
        Effect: "Deny",
        Action: "*",
        Resource: "*",
      },
    ],
  };
}

function provisionerTags(state) {
  return [
    { Key: "DeusManagedBy", Value: "secure-saas-infra" },
    { Key: "DeusPurpose", Value: "management-seed-provisioner" },
    { Key: "DeusState", Value: state },
  ];
}

function activeProvisionerPolicy(onboarding, partition) {
  const accountId = onboarding.managementAccountId;
  const region = onboarding.managementAccessRegion;
  const stackArn = `arn:${partition}:cloudformation:${region}:${accountId}:stack/deus-management-seed-access/*`;
  const changeSetArn = `arn:${partition}:cloudformation:${region}:${accountId}:changeSet/deus-management-seed-access-*/*`;
  const roleArns = [
    onboarding.managementProvisionerPrincipalArn,
    `arn:${partition}:iam::${accountId}:role/deus/bootstrap-source/${RETIREMENT_ROLE_NAME}`,
    onboarding.managementPreviewTrustedPrincipalArn,
    onboarding.managementApplyTrustedPrincipalArn,
    onboarding.managementPreviewRoleArn,
    onboarding.managementApplyRoleArn,
  ];
  const boundaryArns = [
    `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/DeusOrganizationSeedPreviewBoundary`,
    `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/DeusOrganizationSeedApplyBoundary`,
    `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/${RETIRED_PROVISIONER_BOUNDARY_NAME}`,
  ];
  const allowed = [
    "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStacks",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:GetTemplate",
    "cloudformation:ValidateTemplate",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:GetSAMLProvider",
    "iam:ListAttachedRolePolicies",
    "iam:ListPolicyVersions",
    "iam:ListRolePolicies",
    "iam:PutRolePolicy",
    "sts:GetCallerIdentity",
  ];
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ValidateExactAccessTemplate",
        Effect: "Allow",
        Action: "cloudformation:ValidateTemplate",
        Resource: "*",
      },
      {
        Sid: "OperateExactAccessStack",
        Effect: "Allow",
        Action: [
          "cloudformation:CreateChangeSet",
          "cloudformation:DescribeChangeSet",
          "cloudformation:DescribeStacks",
          "cloudformation:ExecuteChangeSet",
          "cloudformation:GetTemplate",
        ],
        Resource: [changeSetArn, stackArn],
      },
      {
        Sid: "InstallExactBoundedAccessPolicies",
        Effect: "Allow",
        Action: "iam:PutRolePolicy",
        Resource: [
          onboarding.managementApplyRoleArn,
          onboarding.managementPreviewRoleArn,
        ],
      },
      {
        Sid: "ReadExactBootstrapAccessResources",
        Effect: "Allow",
        Action: [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:GetSAMLProvider",
          "iam:ListAttachedRolePolicies",
          "iam:ListPolicyVersions",
          "iam:ListRolePolicies",
        ],
        Resource: [
          ...boundaryArns,
          ...roleArns,
          onboarding.managementBootstrapSamlProviderArn,
        ],
      },
      {
        Sid: "IdentifyProvisionerSession",
        Effect: "Allow",
        Action: "sts:GetCallerIdentity",
        Resource: "*",
      },
      {
        Sid: "DenyEveryOtherProvisionerAction",
        Effect: "Deny",
        NotAction: allowed,
        Resource: "*",
      },
    ],
  };
}

function provisionerRetirementPolicy(onboarding, partition) {
  const accountId = onboarding.managementAccountId;
  const provisionerArn = onboarding.managementProvisionerPrincipalArn;
  const retirementArn = `arn:${partition}:iam::${accountId}:role/deus/bootstrap-source/${RETIREMENT_ROLE_NAME}`;
  const boundaryArn = `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/${RETIRED_PROVISIONER_BOUNDARY_NAME}`;
  const observedRoles = [
    provisionerArn,
    retirementArn,
    onboarding.managementPreviewTrustedPrincipalArn,
    onboarding.managementApplyTrustedPrincipalArn,
    onboarding.managementPreviewRoleArn,
    onboarding.managementApplyRoleArn,
  ];
  const observedPolicies = [
    boundaryArn,
    `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/DeusOrganizationSeedPreviewBoundary`,
    `arn:${partition}:iam::${accountId}:policy/deus/bootstrap/DeusOrganizationSeedApplyBoundary`,
  ];
  const samlProviderArn = onboarding.managementBootstrapSamlProviderArn;
  const allowed = [
    "iam:DeleteRolePolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:GetSAMLProvider",
    "iam:ListAttachedRolePolicies",
    "iam:ListPolicyVersions",
    "iam:ListRolePolicies",
    "iam:PutRolePermissionsBoundary",
    "iam:TagRole",
    "sts:GetCallerIdentity",
  ];
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadExactBootstrapAccessResources",
        Effect: "Allow",
        Action: [
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:GetSAMLProvider",
          "iam:ListAttachedRolePolicies",
          "iam:ListPolicyVersions",
          "iam:ListRolePolicies",
        ],
        Resource: [...observedPolicies, ...observedRoles, samlProviderArn],
      },
      {
        Sid: "TagExactProvisionerRetired",
        Effect: "Allow",
        Action: "iam:TagRole",
        Resource: provisionerArn,
        Condition: {
          StringEquals: {
            "aws:RequestTag/DeusManagedBy": "secure-saas-infra",
            "aws:RequestTag/DeusPurpose": "management-seed-provisioner",
            "aws:RequestTag/DeusState": "retired",
          },
          "ForAllValues:StringEquals": {
            "aws:TagKeys": ["DeusManagedBy", "DeusPurpose", "DeusState"],
          },
        },
      },
      {
        Sid: "AttachExactRetirementBoundary",
        Effect: "Allow",
        Action: "iam:PutRolePermissionsBoundary",
        Resource: provisionerArn,
        Condition: {
          StringEquals: { "iam:PermissionsBoundary": boundaryArn },
        },
      },
      {
        Sid: "DeleteSoleProvisionerGrant",
        Effect: "Allow",
        Action: "iam:DeleteRolePolicy",
        Resource: provisionerArn,
      },
      {
        Sid: "IdentifyRetirementSession",
        Effect: "Allow",
        Action: "sts:GetCallerIdentity",
        Resource: "*",
      },
      {
        Sid: "DenyEveryOtherRetirementAction",
        Effect: "Deny",
        NotAction: allowed,
        Resource: "*",
      },
    ],
  };
}

function roleResource({
  accountId,
  accountPrincipal,
  trustedPrincipalArn,
  roleName,
  boundaryArn,
  accessMode,
}) {
  return {
    Type: "AWS::IAM::Role",
    Condition: "ExpectedManagementAccountPartitionAndRegion",
    DeletionPolicy: "Retain",
    UpdateReplacePolicy: "Retain",
    Properties: {
      RoleName: roleName,
      Path: "/",
      Description: `Human-federated ${accessMode} access for the AWS Organizations management seed.`,
      MaxSessionDuration: 3600,
      PermissionsBoundary: boundaryArn,
      AssumeRolePolicyDocument: {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "TrustOneExactFederatedRole",
            Effect: "Allow",
            Principal: { AWS: accountPrincipal },
            Action: "sts:AssumeRole",
            Condition: {
              ArnEquals: { "aws:PrincipalArn": trustedPrincipalArn },
              StringEquals: { "aws:PrincipalAccount": accountId },
            },
          },
        ],
      },
      Policies: [],
      Tags: [
        { Key: "AccessMode", Value: accessMode },
        { Key: "ManagedBy", Value: "secure-saas-infra" },
        { Key: "Purpose", Value: "organizations-management-seed" },
      ],
    },
  };
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
