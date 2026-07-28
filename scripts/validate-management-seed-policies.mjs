#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const EXPECTED_POLICY_CANONICAL_SHA256 = Object.freeze({
  preview: "79dd219d31923bc7367697aed1d1304274763cf5d6e1baf8ab0d7f8cfb3fa06b",
  apply: "b7ecb27ff21e27055b26566c97e873dd215abcf48d38e95db613ef7b275b9bae",
});

const EXPECTED_PREVIEW_ACTIONS = Object.freeze([
  "account:GetAlternateContact",
  "account:GetContactInformation",
  "cloudtrail:LookupEvents",
  "ec2:DescribeRegions",
  "guardduty:ListOrganizationAdminAccounts",
  "iam:GetAccountSummary",
  "iam:GetPolicy",
  "iam:GetPolicyVersion",
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:GetSAMLProvider",
  "iam:ListAttachedRolePolicies",
  "iam:ListPolicyVersions",
  "iam:ListRolePolicies",
  "inspector2:ListDelegatedAdminAccounts",
  "organizations:DescribeAccount",
  "organizations:DescribeCreateAccountStatus",
  "organizations:DescribeEffectivePolicy",
  "organizations:DescribeOrganization",
  "organizations:DescribeOrganizationalUnit",
  "organizations:DescribePolicy",
  "organizations:DescribeResourcePolicy",
  "organizations:ListAWSServiceAccessForOrganization",
  "organizations:ListAccounts",
  "organizations:ListAccountsForParent",
  "organizations:ListChildren",
  "organizations:ListCreateAccountStatus",
  "organizations:ListDelegatedAdministrators",
  "organizations:ListDelegatedServicesForAccount",
  "organizations:ListHandshakesForOrganization",
  "organizations:ListOrganizationalUnitsForParent",
  "organizations:ListParents",
  "organizations:ListPolicies",
  "organizations:ListPoliciesForTarget",
  "organizations:ListRoots",
  "organizations:ListTagsForResource",
  "organizations:ListTargetsForPolicy",
  "securityhub:ListOrganizationAdminAccounts",
  "servicequotas:ListServiceQuotas",
  "sts:GetCallerIdentity",
]);
const EXPECTED_APPLY_ACTIONS = Object.freeze([
  ...EXPECTED_PREVIEW_ACTIONS,
  "iam:CreateServiceLinkedRole",
  "organizations:CreateOrganization",
  "organizations:EnablePolicyType",
]);
const MANAGEMENT_ACCOUNT_PLACEHOLDER = "__DEUS_MANAGEMENT_ACCOUNT_ID__";
const EXPECTED_BOOTSTRAP_ROLE_RESOURCES = Object.freeze([
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/OrganizationSeedPreview`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/OrganizationSeedApply`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/deus/bootstrap-source/ManagementSeedPreview`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/deus/bootstrap-source/ManagementSeedApply`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/deus/bootstrap-source/ManagementSeedProvisioner`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:role/deus/bootstrap-source/ManagementSeedRetirement`,
]);
const EXPECTED_BOOTSTRAP_BOUNDARY_RESOURCES = Object.freeze([
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:policy/deus/bootstrap/DeusOrganizationSeedPreviewBoundary`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:policy/deus/bootstrap/DeusOrganizationSeedApplyBoundary`,
  `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:policy/deus/bootstrap/DeusManagementSeedProvisionerRetiredBoundary`,
]);
const EXPECTED_BOOTSTRAP_SAML_PROVIDER_RESOURCE = `arn:aws:iam::${MANAGEMENT_ACCOUNT_PLACEHOLDER}:saml-provider/DeusBootstrap`;

const preview = load("security/aws-management-seed-preview-policy.json");
const apply = load("security/aws-management-seed-apply-policy.json");
const previewAllows = allowedActions(preview);
const applyAllows = allowedActions(apply);
const applyDenies = deniedActions(apply);

assertExactActionSet("preview allow", previewAllows, EXPECTED_PREVIEW_ACTIONS);
assertExactActionSet("apply allow", applyAllows, EXPECTED_APPLY_ACTIONS);

for (const [name, policy] of [
  ["preview", preview],
  ["apply", apply],
]) {
  if (policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) {
    fail(`${name} policy is not an IAM policy document`);
  }
  if (Buffer.byteLength(JSON.stringify(policy), "utf8") > 6_144) {
    fail(`${name} policy exceeds the IAM managed-policy size limit`);
  }
  for (const statement of policy.Statement) {
    if (statement.Principal || statement.NotResource) {
      fail(`${name} policy uses a forbidden principal or NotResource`);
    }
    if (
      statement.NotAction !== undefined &&
      (statement.Effect !== "Deny" ||
        statement.Sid !==
          `DenyUnreviewed${name === "preview" ? "Preview" : "Apply"}Actions` ||
        statement.Action !== undefined ||
        statement.Resource !== "*" ||
        statement.Condition !== undefined)
    ) {
      fail(`${name} policy uses an unreviewed NotAction cap`);
    }
    if (statement.Resource === undefined)
      fail(`${name} policy statement '${statement.Sid}' omits Resource`);
    for (const action of statement.Action === undefined
      ? []
      : array(statement.Action)) {
      if (action.includes("*"))
        fail(`${name} policy contains wildcard action '${action}'`);
    }
  }
  assertAbsoluteActionCap(name, policy, allowedActions(policy));
  assertExactIamReadScope(name, policy);
  if (
    createHash("sha256").update(canonicalJson(policy)).digest("hex") !==
    EXPECTED_POLICY_CANONICAL_SHA256[name]
  ) {
    fail(`${name} policy statement structure drifted from its exact review`);
  }
}

for (const action of previewAllows) {
  if (
    !/:(?:Describe|Get|List)/.test(action) &&
    action !== "cloudtrail:LookupEvents"
  )
    fail(`preview policy contains mutation '${action}'`);
}
for (const action of previewAllows) {
  if (!applyAllows.has(action))
    fail(`apply policy omits preview read '${action}'`);
}
for (const action of [
  "organizations:CreateOrganization",
  "organizations:EnablePolicyType",
]) {
  if (!applyAllows.has(action))
    fail(`apply policy omits required seed action '${action}'`);
}
for (const action of [
  "organizations:CloseAccount",
  "organizations:DeleteOrganization",
  "organizations:DeleteOrganizationalUnit",
  "organizations:DeletePolicy",
  "organizations:DetachPolicy",
  "organizations:RemoveAccountFromOrganization",
  "organizations:DisableAWSServiceAccess",
  "organizations:DeregisterDelegatedAdministrator",
  "organizations:RegisterDelegatedAdministrator",
  "organizations:UntagResource",
  "organizations:UpdateOrganizationalUnit",
  "organizations:UpdatePolicy",
  "guardduty:DisableOrganizationAdminAccount",
  "securityhub:DisableOrganizationAdminAccount",
  "inspector2:DisableDelegatedAdminAccount",
]) {
  if (applyAllows.has(action) || !applyDenies.has(action)) {
    fail(`apply policy does not explicitly deny '${action}'`);
  }
}

for (const action of [
  "organizations:RegisterDelegatedAdministrator",
  "organizations:UntagResource",
  "organizations:UpdateOrganizationalUnit",
  "organizations:UpdatePolicy",
]) {
  if (applyAllows.has(action))
    fail(`create-only apply policy permits post-seed mutation '${action}'`);
}

assertInverseDeny(
  ["organizations:EnablePolicyType"],
  "StringNotEquals",
  "organizations:PolicyType",
  ["S3_POLICY", "SERVICE_CONTROL_POLICY"],
);
assertInverseDeny(
  ["iam:CreateServiceLinkedRole"],
  "StringNotEquals",
  "iam:AWSServiceName",
  ["organizations.amazonaws.com"],
);

process.stdout.write(
  `Management seed policies validated (${previewAllows.size} preview actions; ${applyAllows.size} apply actions; ${applyDenies.size} explicit denies).\n`,
);

function load(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${file} is invalid: ${error.message}`);
  }
}

function allowedActions(policy) {
  return actions(policy, "Allow");
}

function deniedActions(policy) {
  return actions(policy, "Deny");
}

function actions(policy, effect) {
  return new Set(
    policy.Statement.filter((statement) => statement.Effect === effect).flatMap(
      (statement) =>
        statement.Action === undefined ? [] : array(statement.Action),
    ),
  );
}

function assertAbsoluteActionCap(name, policy, allowed) {
  const sid = `DenyUnreviewed${name === "preview" ? "Preview" : "Apply"}Actions`;
  const caps = policy.Statement.filter((statement) => statement.Sid === sid);
  if (caps.length !== 1) fail(`${name} policy must contain one absolute cap`);
  const actual = [...array(caps[0].NotAction)].sort();
  const expected = [...allowed].sort();
  if (
    new Set(actual).size !== actual.length ||
    JSON.stringify(actual) !== JSON.stringify(expected)
  ) {
    fail(`${name} absolute NotAction cap must exactly equal allowed actions`);
  }
}

function assertExactActionSet(label, actual, expected) {
  const actualValues = [...actual].sort();
  const expectedValues = [...expected].sort();
  if (
    actual.size !== actualValues.length ||
    new Set(expectedValues).size !== expectedValues.length ||
    JSON.stringify(actualValues) !== JSON.stringify(expectedValues)
  ) {
    const unexpected = actualValues.filter(
      (action) => !expectedValues.includes(action),
    );
    const missing = expectedValues.filter(
      (action) => !actualValues.includes(action),
    );
    fail(
      `${label} action inventory drifted (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"})`,
    );
  }
}

function assertExactIamReadScope(name, policy) {
  const expected = [
    [
      "ReadAccountAuditPosture",
      [
        "account:GetAlternateContact",
        "account:GetContactInformation",
        "cloudtrail:LookupEvents",
        "iam:GetAccountSummary",
      ],
      ["*"],
    ],
    [
      "ReadExactBootstrapRoles",
      [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
      ],
      EXPECTED_BOOTSTRAP_ROLE_RESOURCES,
    ],
    [
      "ReadExactBootstrapBoundaries",
      ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"],
      EXPECTED_BOOTSTRAP_BOUNDARY_RESOURCES,
    ],
    [
      "ReadExactBootstrapSamlProvider",
      ["iam:GetSAMLProvider"],
      [EXPECTED_BOOTSTRAP_SAML_PROVIDER_RESOURCE],
    ],
  ];
  for (const [sid, actions, resources] of expected) {
    const statements = policy.Statement.filter(
      (statement) => statement.Sid === sid,
    );
    if (statements.length !== 1) {
      fail(`${name} policy must contain exactly one '${sid}' statement`);
    }
    const statement = statements[0];
    if (
      statement.Effect !== "Allow" ||
      statement.Condition !== undefined ||
      statement.NotAction !== undefined ||
      statement.NotResource !== undefined ||
      JSON.stringify([...array(statement.Action)].sort()) !==
        JSON.stringify([...actions].sort()) ||
      JSON.stringify([...array(statement.Resource)].sort()) !==
        JSON.stringify([...resources].sort())
    ) {
      fail(`${name} policy '${sid}' IAM read scope drifted`);
    }
  }
  for (const statement of policy.Statement) {
    const iamReadActions = array(statement.Action ?? []).filter((action) =>
      /^iam:(?:Get|List)/.test(action),
    );
    if (
      statement.Effect === "Allow" &&
      iamReadActions.length > 0 &&
      statement.Resource === "*" &&
      !(
        statement.Sid === "ReadAccountAuditPosture" &&
        JSON.stringify(iamReadActions) ===
          JSON.stringify(["iam:GetAccountSummary"])
      )
    ) {
      fail(
        `${name} policy allow statement '${statement.Sid}' grants account-wide IAM access`,
      );
    }
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function array(value) {
  return Array.isArray(value) ? value : [value];
}

function assertInverseDeny(actions, operator, key, expected) {
  const wantedActions = [...actions].sort();
  const statement = apply.Statement.find(
    (entry) =>
      entry.Effect === "Deny" &&
      JSON.stringify([...array(entry.Action)].sort()) ===
        JSON.stringify(wantedActions),
  );
  const actual = [...array(statement?.Condition?.[operator]?.[key])].sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(
      `${wantedActions.join(",")} does not have the exact inverse ${operator}/${key} deny`,
    );
  }
}

function fail(message) {
  process.stderr.write(`MANAGEMENT_SEED_POLICY_DENIED: ${message}.\n`);
  process.exit(1);
}
