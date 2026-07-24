#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const EXPECTED_POLICY_CANONICAL_SHA256 = Object.freeze({
  preview: "40a7dfa77d1ef7ed4e9b99ad34a1f9a8daca30abc0b3979428c430f77f2f81fe",
  apply: "f834c4de591cbabdcd668d1e8d452ca569acc74583b2fe23d00fb996ebeb67c4",
});

const EXPECTED_PREVIEW_ACTIONS = Object.freeze([
  "ec2:DescribeRegions",
  "guardduty:ListOrganizationAdminAccounts",
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
  if (
    createHash("sha256").update(canonicalJson(policy)).digest("hex") !==
    EXPECTED_POLICY_CANONICAL_SHA256[name]
  ) {
    fail(`${name} policy statement structure drifted from its exact review`);
  }
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
}

for (const action of previewAllows) {
  if (!/:(?:Describe|Get|List)/.test(action))
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
  const actual = array(caps[0].NotAction).sort();
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
      JSON.stringify(array(entry.Action).sort()) ===
        JSON.stringify(wantedActions),
  );
  const actual = array(statement?.Condition?.[operator]?.[key]).sort();
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
