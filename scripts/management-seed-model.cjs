"use strict";

const ACCOUNT_ROLE = "DeusOrganizationBootstrap";
const SERVICE_ACCESS_PRINCIPALS = Object.freeze([
  "cloudtrail.amazonaws.com",
  "config.amazonaws.com",
  "config-multiaccountsetup.amazonaws.com",
  "guardduty.amazonaws.com",
  "securityhub.amazonaws.com",
  "inspector2.amazonaws.com",
]);
const POLICY_TYPES = Object.freeze(["SERVICE_CONTROL_POLICY", "S3_POLICY"]);
const ORGANIZATIONAL_UNITS = Object.freeze([
  Object.freeze({ name: "Security" }),
  Object.freeze({ name: "Infrastructure" }),
  Object.freeze({ name: "Workloads" }),
  Object.freeze({ name: "NonProd", parent: "Workloads" }),
  Object.freeze({ name: "PreProd", parent: "Workloads" }),
  Object.freeze({ name: "Prod", parent: "Workloads" }),
  Object.freeze({ name: "Suspended" }),
]);
const ACCOUNT_BASELINE = Object.freeze([
  Object.freeze({ name: "security-tooling", ou: "Security", kind: "security" }),
  Object.freeze({ name: "log-archive", ou: "Security", kind: "log-archive" }),
  Object.freeze({ name: "network", ou: "Infrastructure", kind: "network" }),
  Object.freeze({
    name: "shared-services",
    ou: "Infrastructure",
    kind: "shared-services",
  }),
  Object.freeze({ name: "platform-dev", ou: "NonProd", kind: "workload" }),
  Object.freeze({ name: "execution-dev", ou: "NonProd", kind: "execution" }),
  Object.freeze({
    name: "platform-staging",
    ou: "PreProd",
    kind: "workload",
    modular: true,
  }),
  Object.freeze({
    name: "execution-staging",
    ou: "PreProd",
    kind: "execution",
    modular: true,
  }),
  Object.freeze({ name: "platform-prod", ou: "Prod", kind: "workload" }),
  Object.freeze({ name: "execution-prod", ou: "Prod", kind: "execution" }),
]);
const GUARDRAIL_TARGETS = Object.freeze([
  "Security",
  "Infrastructure",
  "Workloads",
]);
const ORGANIZATION_FIELDS = Object.freeze([
  "accounts",
  "createOrganization",
  "defaultAccountRoleName",
  "enableRamSharing",
  "enableSecurityDelegatedAdmin",
  "enabledPolicyTypes",
  "guardrailScpsEnabled",
  "guardrailTargetOuNames",
  "organizationalUnits",
  "serviceAccessPrincipals",
]);
const ACCOUNT_FIELDS = new Set([
  "closeOnDeletion",
  "create",
  "email",
  "kind",
  "name",
  "ou",
  "roleName",
]);

function managementSeedOrganizationFailures(
  organization,
  { accountEmailDomain } = {},
) {
  const failures = [];
  if (!isRecord(organization)) {
    return ["secure-saas-infra:organization must be an object"];
  }
  expectExactObjectKeys(
    organization,
    ORGANIZATION_FIELDS,
    "organization",
    failures,
  );
  expectExact(
    organization.createOrganization,
    true,
    "organization.createOrganization",
    failures,
  );
  expectExact(
    organization.defaultAccountRoleName,
    ACCOUNT_ROLE,
    "organization.defaultAccountRoleName",
    failures,
  );
  expectExact(
    organization.enableRamSharing,
    true,
    "organization.enableRamSharing",
    failures,
  );
  expectExact(
    organization.enableSecurityDelegatedAdmin,
    false,
    "organization.enableSecurityDelegatedAdmin",
    failures,
  );
  expectExactSequence(
    organization.serviceAccessPrincipals,
    SERVICE_ACCESS_PRINCIPALS,
    "organization.serviceAccessPrincipals",
    failures,
  );
  expectExactSequence(
    organization.enabledPolicyTypes,
    POLICY_TYPES,
    "organization.enabledPolicyTypes",
    failures,
  );
  expectExact(
    organization.guardrailScpsEnabled,
    true,
    "organization.guardrailScpsEnabled",
    failures,
  );
  expectExactSequence(
    organization.guardrailTargetOuNames,
    GUARDRAIL_TARGETS,
    "organization.guardrailTargetOuNames",
    failures,
  );
  validateOrganizationalUnits(organization.organizationalUnits, failures);
  validateAccounts(organization.accounts, accountEmailDomain, failures);
  validateGuardrailCoverage(organization, failures);
  return unique(failures);
}

function managementSeedConfigurationValuesFailures(config, onboarding) {
  const failures = [];
  if (!isRecord(config)) return ["Pulumi management config must be an object"];
  expectExact(
    config["secure-saas-infra:stackKind"],
    "management",
    "secure-saas-infra:stackKind",
    failures,
  );
  expectExact(
    config["secure-saas-infra:deploymentMode"],
    "organization",
    "secure-saas-infra:deploymentMode",
    failures,
  );
  expectExact(
    config["secure-saas-infra:environment"],
    "management",
    "secure-saas-infra:environment",
    failures,
  );
  if (
    config["secure-saas-infra:seedWave"] !== "organization-only" &&
    config["secure-saas-infra:seedWave"] !== "full"
  ) {
    failures.push(
      "secure-saas-infra:seedWave must equal organization-only or full",
    );
  }
  const organizationName = config["secure-saas-infra:organizationName"];
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(organizationName ?? "")) {
    failures.push(
      "secure-saas-infra:organizationName must be a safe exact name",
    );
  }
  if (
    typeof onboarding?.organizationName === "string" &&
    organizationName !== onboarding.organizationName
  ) {
    failures.push(
      "secure-saas-infra:organizationName must equal onboarding.organizationName",
    );
  }
  failures.push(
    ...managementSeedOrganizationFailures(
      config["secure-saas-infra:organization"],
      { accountEmailDomain: onboarding?.accountEmailDomain },
    ),
  );
  return unique(failures);
}

function validateOrganizationalUnits(units, failures) {
  if (!Array.isArray(units)) {
    failures.push("organization.organizationalUnits must be an array");
    return;
  }
  if (units.length !== ORGANIZATIONAL_UNITS.length) {
    failures.push(
      `organization.organizationalUnits must contain exactly ${ORGANIZATIONAL_UNITS.length} baseline OUs`,
    );
  }
  const names = new Set();
  const slugs = new Set();
  for (const [index, unit] of units.entries()) {
    if (!isRecord(unit)) {
      failures.push(
        `organization.organizationalUnits[${index}] must be an object`,
      );
      continue;
    }
    const expected = ORGANIZATIONAL_UNITS[index];
    expectExactObjectKeys(
      unit,
      expected ? Object.keys(expected) : ["name"],
      `organization.organizationalUnits[${index}]`,
      failures,
    );
    if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}$/.test(unit.name ?? "")) {
      failures.push(
        `organization.organizationalUnits[${index}].name is invalid`,
      );
    }
    if (names.has(unit.name)) failures.push(`duplicate OU name '${unit.name}'`);
    names.add(unit.name);
    const unitSlug = slug(unit.name ?? "");
    if (!unitSlug || slugs.has(unitSlug)) {
      failures.push(
        `OU '${unit.name}' has an empty or duplicate resource slug`,
      );
    }
    slugs.add(unitSlug);
    if (unit.parent !== undefined && !names.has(unit.parent)) {
      failures.push(
        `OU '${unit.name}' references unknown or later parent OU '${unit.parent}'`,
      );
    }
    if (
      expected &&
      (unit.name !== expected.name || unit.parent !== expected.parent)
    ) {
      failures.push(
        `organization.organizationalUnits[${index}] must equal the reviewed ${expected.name} baseline OU`,
      );
    }
  }
}

function validateAccounts(accounts, accountEmailDomain, failures) {
  if (!Array.isArray(accounts)) {
    failures.push("organization.accounts must be an array");
    return;
  }
  if (accounts.length !== ACCOUNT_BASELINE.length) {
    failures.push(
      `organization.accounts must contain exactly ${ACCOUNT_BASELINE.length} baseline accounts`,
    );
  }
  const names = new Set();
  const emails = new Set();
  const slugs = new Set();
  for (const [index, account] of accounts.entries()) {
    if (!isRecord(account)) {
      failures.push(`organization.accounts[${index}] must be an object`);
      continue;
    }
    const extra = Object.keys(account)
      .filter((key) => !ACCOUNT_FIELDS.has(key))
      .sort();
    if (extra.length > 0) {
      failures.push(
        `organization.accounts[${index}] contains unknown fields: ${extra.join(", ")}`,
      );
    }
    const expected = ACCOUNT_BASELINE[index];
    if (
      !expected ||
      account.name !== expected.name ||
      account.ou !== expected.ou ||
      account.kind !== expected.kind
    ) {
      failures.push(
        `organization.accounts[${index}] must equal the reviewed ${expected?.name ?? "baseline"} identity, kind, and OU`,
      );
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,49}$/.test(account.name ?? "")) {
      failures.push(`organization.accounts[${index}].name is invalid`);
    }
    if (names.has(account.name)) {
      failures.push(`duplicate account name '${account.name}'`);
    }
    names.add(account.name);
    const accountSlug = slug(account.name ?? "");
    if (!accountSlug || slugs.has(accountSlug)) {
      failures.push(
        `account '${account.name}' has an empty or duplicate resource slug`,
      );
    }
    slugs.add(accountSlug);
    const email = String(account.email ?? "").toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(email)) {
      failures.push(`account '${account.name}' email is invalid`);
    }
    if (emails.has(email)) failures.push(`duplicate account email '${email}'`);
    emails.add(email);
    if (
      typeof accountEmailDomain === "string" &&
      !email.endsWith(`@${accountEmailDomain.toLowerCase()}`)
    ) {
      failures.push(
        `account '${account.name}' email is outside onboarding.accountEmailDomain`,
      );
    }
    if (account.roleName !== undefined && account.roleName !== ACCOUNT_ROLE) {
      failures.push(
        `account '${account.name}' roleName must equal ${ACCOUNT_ROLE}`,
      );
    }
    if (
      account.closeOnDeletion !== undefined &&
      account.closeOnDeletion !== false
    ) {
      failures.push(`account '${account.name}' closeOnDeletion must be false`);
    }
    if (account.create !== undefined && typeof account.create !== "boolean") {
      failures.push(`account '${account.name}' create must be boolean`);
    }
    if (!expected?.modular && account.create === false) {
      failures.push(`baseline account '${account.name}' cannot be disabled`);
    }
    if (expected?.modular && account.create !== false) {
      failures.push(
        `staging account '${account.name}' must remain disabled until quota evidence is governed`,
      );
    }
  }
}

function validateGuardrailCoverage(organization, failures) {
  if (
    !Array.isArray(organization.organizationalUnits) ||
    !Array.isArray(organization.accounts) ||
    !Array.isArray(organization.guardrailTargetOuNames)
  ) {
    return;
  }
  const parents = new Map(
    organization.organizationalUnits
      .filter(isRecord)
      .map((unit) => [unit.name, unit.parent]),
  );
  const targets = new Set(organization.guardrailTargetOuNames);
  for (const account of organization.accounts.filter(isRecord)) {
    if (account.create === false) continue;
    let current = account.ou;
    let covered = false;
    const seen = new Set();
    while (typeof current === "string" && !seen.has(current)) {
      if (targets.has(current)) {
        covered = true;
        break;
      }
      seen.add(current);
      current = parents.get(current);
    }
    if (!covered) {
      failures.push(
        `active account '${account.name}' does not inherit every seed guardrail policy`,
      );
    }
  }
}

function expectExact(actual, expected, label, failures) {
  if (actual !== expected) failures.push(`${label} must equal ${expected}`);
}

function expectExactSequence(actual, expected, label, failures) {
  if (
    !Array.isArray(actual) ||
    JSON.stringify(actual) !== JSON.stringify(expected)
  ) {
    failures.push(`${label} must exactly equal: ${expected.join(", ")}`);
  }
}

function expectExactObjectKeys(value, expected, label, failures) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    failures.push(`${label} fields must exactly equal: ${wanted.join(", ")}`);
  }
}

function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function unique(values) {
  return [...new Set(values)];
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

module.exports = Object.freeze({
  ACCOUNT_BASELINE,
  ACCOUNT_ROLE,
  GUARDRAIL_TARGETS,
  ORGANIZATIONAL_UNITS,
  POLICY_TYPES,
  SERVICE_ACCESS_PRINCIPALS,
  managementSeedConfigurationValuesFailures,
  managementSeedOrganizationFailures,
});
