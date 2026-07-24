import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import seedModel from "./management-seed-model.cjs";

const { managementSeedConfigurationValuesFailures } = seedModel;
const allowedManagementConfigKeys = new Set([
  "aws:allowedAccountIds",
  "aws:region",
  "secure-saas-infra:deploymentMode",
  "secure-saas-infra:environment",
  "secure-saas-infra:organization",
  "secure-saas-infra:organizationName",
  "secure-saas-infra:seedWave",
  "secure-saas-infra:stackKind",
]);

export function managementSeedConfigurationFailures(root, onboarding) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const stack = readDirectYaml(
    path.join(repositoryRoot, "Pulumi.management.yaml"),
    "Pulumi.management.yaml",
  );
  if (stack.failure) return [stack.failure];
  const failures = managementSeedConfigurationDocumentFailures(
    stack.document,
    onboarding,
  );
  const project = readDirectYaml(
    path.join(repositoryRoot, "Pulumi.yaml"),
    "Pulumi.yaml",
  );
  if (project.failure) {
    failures.push(project.failure);
  } else if (
    project.document?.name !== onboarding?.pulumiProject ||
    project.document?.name !== "secure-saas-infra"
  ) {
    failures.push(
      "Pulumi.yaml name, onboarding.pulumiProject, and secure-saas-infra must match",
    );
  }
  return [...new Set(failures)];
}

export function managementSeedConfigurationDocumentFailures(
  document,
  onboarding,
) {
  const failures = [];
  if (!isRecord(document) || !isRecord(document.config)) {
    return ["Pulumi.management.yaml must contain a config object"];
  }
  if (Object.hasOwn(document, "environment")) {
    failures.push(
      "management seed must not import Pulumi ESC environments or provider-bearing environment configuration",
    );
  }
  const documentKeys = Object.keys(document).sort();
  if (JSON.stringify(documentKeys) !== '["config"]') {
    failures.push("Pulumi.management.yaml may contain only the config field");
  }

  const config = document.config;
  const unexpectedKeys = Object.keys(config)
    .filter((key) => !allowedManagementConfigKeys.has(key))
    .sort();
  if (unexpectedKeys.length > 0) {
    failures.push(
      `management seed contains non-allowlisted configuration: ${unexpectedKeys.join(", ")}`,
    );
  }
  const allowedAccounts = config["aws:allowedAccountIds"];
  if (
    !Array.isArray(allowedAccounts) ||
    allowedAccounts.length !== 1 ||
    allowedAccounts[0] !== onboarding?.managementAccountId
  ) {
    failures.push(
      "aws:allowedAccountIds must contain only onboarding.managementAccountId",
    );
  }
  const region = config["aws:region"];
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region ?? "")) {
    failures.push("aws:region must be one exact AWS region");
  } else if (region !== onboarding?.managementAccessRegion) {
    failures.push(
      "aws:region must equal onboarding.managementAccessRegion for the bootstrap handoff",
    );
  }
  failures.push(
    ...managementSeedConfigurationValuesFailures(config, onboarding),
  );
  return [...new Set(failures)];
}

export function assertManagementSeedConfiguration(root, onboarding) {
  const failures = managementSeedConfigurationFailures(root, onboarding);
  if (failures.length > 0) {
    throw new Error(
      `Management seed configuration denied: ${failures.join("; ")}.`,
    );
  }
}

export function assertManagementSeedConfigurationDocument(
  document,
  onboarding,
) {
  const failures = managementSeedConfigurationDocumentFailures(
    document,
    onboarding,
  );
  if (failures.length > 0) {
    throw new Error(
      `Management seed configuration denied: ${failures.join("; ")}.`,
    );
  }
}

export function assertManagementSeedWaveOperation(seedWave, operation) {
  if (seedWave !== "organization-only" && seedWave !== "full") {
    throw new Error(
      "Management seed execution denied: seedWave must be organization-only or full.",
    );
  }
  if (operation !== "preview" && operation !== "apply") {
    throw new Error(
      "Management seed execution denied: operation must be preview or apply.",
    );
  }
  if (seedWave === "full" && operation === "apply") {
    throw new Error(
      "Management seed full apply is blocked until a separately qualified member-access installation and immediate DeusOrganizationBootstrap retirement wave exists; use organization-only for apply.",
    );
  }
}

function readDirectYaml(file, label) {
  if (!existsSync(file)) return { failure: `${label} is missing` };
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(file) !== file) {
    return { failure: `${label} must be a direct regular file` };
  }
  try {
    return { document: parse(readFileSync(file, "utf8")) };
  } catch (error) {
    return { failure: `${label} is invalid YAML: ${error.message}` };
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
