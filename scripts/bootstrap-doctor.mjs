#!/usr/bin/env node

import { createHash, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { managementSeedAccessConfigurationFailures } from "./management-seed-access.mjs";
import { managementSeedConfigurationFailures } from "./management-seed-contract.mjs";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";
import { runReadOnlyGit } from "./safe-git.mjs";

const REPORT_API_VERSION =
  "security.deus.dev/bootstrap-readiness-report/v1alpha1";

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(`error: ${error.message}`);
  printUsage();
  process.exit(2);
}

if (args.help) {
  printUsage();
  process.exit(0);
}

const root = realpathSync(resolve(args.root ?? process.cwd()));
const configPath = resolve(args.config ?? join(root, "onboarding.local.json"));
const strict = args.strict === true;
const checkAwsSession = strict || args.checkAwsSession === true;
const checkPulumiLogin = strict || args.checkPulumiLogin === true;
const checks = [];
let onboarding = null;

checkNode();
checkCommand("npm", ["--version"], true);
checkCommand("aws", ["--version"], strict || checkAwsSession);
checkCommand("pulumi", ["version"], strict || checkPulumiLogin);
checkOnboarding();
checkManagementStack();
checkCredentialEnvironment();
checkQualificationTrust();
const cleanReleaseWorktree = checkReleaseWorktree();
checkReviewDisposition(cleanReleaseWorktree);
checkProductionQualificationHost();

if (checkAwsSession) checkAwsCaller();
if (checkPulumiLogin) checkPulumiIdentity();

const summary = {
  passed: checks.filter((check) => check.status === "pass").length,
  warnings: checks.filter((check) => check.status === "warning").length,
  failures: checks.filter((check) => check.status === "failure").length,
};
const report = {
  apiVersion: REPORT_API_VERSION,
  kind: "BootstrapReadinessReport",
  offline: !checkAwsSession && !checkPulumiLogin,
  cloudMutation: false,
  root,
  configPath,
  decisions: onboarding
    ? {
        landingZoneOwner: onboarding.landingZoneOwner ?? null,
        pulumiBackend: onboarding.pulumiBackend ?? null,
        pulumiOrganization: onboarding.pulumiOrg ?? null,
        managementAccountId: onboarding.managementAccountId ?? null,
      }
    : null,
  summary,
  checks,
};

if (args.json) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  printReport(report);
}

if (summary.failures > 0) process.exitCode = 1;

function checkNode() {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (major === 24) {
    add("tool.node", "pass", `Node ${process.versions.node}`);
  } else {
    add("tool.node", "failure", "Pinned Node 24 is required.");
  }
}

function checkCommand(command, commandArgs, required) {
  const result = spawnSync(command, commandArgs, {
    encoding: "utf8",
    env: safeProcessEnvironment(),
  });
  if (result.error?.code === "ENOENT") {
    add(
      `tool.${command}`,
      required ? "failure" : "warning",
      `${command} is not installed or not available on PATH.`,
    );
    return;
  }
  if (result.status !== 0) {
    add(
      `tool.${command}`,
      required ? "failure" : "warning",
      `${command} version check failed.`,
    );
    return;
  }
  const version = `${result.stdout ?? ""} ${result.stderr ?? ""}`
    .trim()
    .split(/\r?\n/)[0];
  add(`tool.${command}`, "pass", version || `${command} is available.`);
}

function checkOnboarding() {
  if (!existsSync(configPath)) {
    add(
      "config.onboarding",
      "failure",
      `Missing onboarding configuration at ${configPath}.`,
    );
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf8"));
  } catch {
    add("config.onboarding", "failure", "Onboarding config is not valid JSON.");
    return;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    add("config.onboarding", "failure", "Onboarding config must be an object.");
    return;
  }
  onboarding = parsed;
  const failures = [];
  const warnings = [];
  const allowedKeys = [
    "accountEmailDomain",
    "landingZoneOwner",
    "managementAccessRegion",
    "managementAccountId",
    "managementApplyRoleArn",
    "managementApplyTrustedPrincipalArn",
    "managementBootstrapSamlMetadataSha256",
    "managementBootstrapSamlProviderArn",
    "managementPreviewRoleArn",
    "managementPreviewTrustedPrincipalArn",
    "managementProvisionerPrincipalArn",
    "organizationName",
    "pulumiBackend",
    "pulumiBackendUrl",
    "pulumiOrg",
    "pulumiProject",
  ];
  const actualKeys = Object.keys(parsed).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(allowedKeys)) {
    failures.push(
      `onboarding fields must exactly equal: ${allowedKeys.join(", ")}`,
    );
  }

  if (!/^[A-Za-z0-9_.-]+$/.test(parsed.pulumiOrg ?? "")) {
    failures.push("pulumiOrg must be an exact Pulumi organization slug");
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(parsed.pulumiProject ?? "")) {
    failures.push("pulumiProject must be an exact Pulumi project name");
  }
  if (!/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(parsed.accountEmailDomain ?? "")) {
    failures.push("accountEmailDomain must be a DNS-like domain");
  } else if (/\.example\.(com|org|net)$/i.test(parsed.accountEmailDomain)) {
    failures.push("accountEmailDomain is still an example domain");
  }
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(parsed.organizationName ?? "")) {
    failures.push("organizationName must be a safe exact name");
  }
  if (!/^(organizations|control-tower)$/.test(parsed.landingZoneOwner ?? "")) {
    failures.push("landingZoneOwner must be organizations or control-tower");
  }
  if (parsed.pulumiBackend !== "pulumi-cloud") {
    failures.push(
      "management seed currently requires pulumiBackend=pulumi-cloud; self-managed backend selection is deferred until it has a signed credentialed channel",
    );
  }
  failures.push(...managementSeedAccessConfigurationFailures(parsed));
  validateBackendUrl(parsed, failures);

  if (parsed.landingZoneOwner === "control-tower") {
    failures.push(
      "landingZoneOwner=control-tower is not implemented; use organizations or add the discovery/import adapter before qualification",
    );
  }

  if (failures.length > 0) {
    add("config.onboarding", "failure", failures.join("; "));
  } else {
    add(
      "config.onboarding",
      "pass",
      "Onboarding decisions are complete and contain no known example value.",
    );
  }
  for (const warning of warnings) {
    add("config.landing-zone-owner", "warning", warning);
  }
}

function validateBackendUrl(parsed, failures) {
  if (parsed.pulumiBackendUrl !== "https://api.pulumi.com") {
    failures.push(
      "management seed requires pulumiBackendUrl=https://api.pulumi.com",
    );
  }
}

function checkManagementStack() {
  const stackPath = join(root, "Pulumi.management.yaml");
  if (!existsSync(stackPath)) {
    add(
      "config.management-stack",
      strict ? "failure" : "warning",
      "Pulumi.management.yaml does not exist; example files are never executable configuration.",
    );
    return;
  }
  const body = readFileSync(stackPath, "utf8");
  const emails = [...body.matchAll(/^\s*email:\s*([^\s#]+)\s*$/gm)].map(
    (match) => match[1].toLowerCase(),
  );
  const failures = managementSeedConfigurationFailures(root, onboarding ?? {});
  if (emails.length === 0) failures.push("no account email entries found");
  if (new Set(emails).size !== emails.length) {
    failures.push("account emails are not unique");
  }
  for (const email of emails) {
    if (!/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(email)) {
      failures.push(`invalid account email ${email}`);
    }
    if (/example\.(com|org|net)$/i.test(email)) {
      failures.push("account emails still use an example domain");
      break;
    }
    if (
      onboarding?.accountEmailDomain &&
      !email.endsWith(`@${onboarding.accountEmailDomain.toLowerCase()}`)
    ) {
      failures.push(`account email ${email} is outside accountEmailDomain`);
    }
  }
  if (failures.length > 0) {
    add(
      "config.management-stack",
      "failure",
      [...new Set(failures)].join("; "),
    );
  } else {
    add(
      "config.management-stack",
      "pass",
      `${emails.length} unique account emails are configured. Global availability still requires AWS verification.`,
    );
  }
}

function checkCredentialEnvironment() {
  if (process.env.AWS_ACCESS_KEY_ID && !process.env.AWS_SESSION_TOKEN) {
    add(
      "aws.credential-mode",
      "failure",
      "Long-lived AWS access-key environment detected; use AWS SSO/OIDC/STS temporary credentials.",
    );
    return;
  }
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SESSION_TOKEN) {
    add(
      "aws.credential-mode",
      "pass",
      "Temporary AWS session environment detected; secret values were not inspected or emitted.",
    );
    return;
  }
  add(
    "aws.credential-mode",
    "pass",
    "No long-lived AWS access-key environment detected.",
  );
}

function checkQualificationTrust() {
  const trustPath = join(
    root,
    "security",
    "bootstrap-qualification-trust.json",
  );
  if (!existsSync(trustPath)) {
    add(
      "release.signer-trust",
      strict ? "failure" : "warning",
      "Independent Ed25519 qualification trust is not present.",
    );
    return;
  }
  let trust;
  try {
    trust = readDirectJson(trustPath, "qualification trust root");
  } catch (error) {
    add("release.signer-trust", "failure", error.message);
    return;
  }
  if (trust.configured !== true) {
    add(
      "release.signer-trust",
      "failure",
      "Independent Ed25519 qualification trust is not configured.",
    );
    return;
  }
  const expectedKeys = [
    "algorithm",
    "apiVersion",
    "configured",
    "keyId",
    "publicKeySpki",
  ];
  if (
    trust.apiVersion !== "security.deus.dev/bootstrap-qualification-trust/v1" ||
    trust.algorithm !== "Ed25519" ||
    JSON.stringify(Object.keys(trust).sort()) !==
      JSON.stringify(expectedKeys) ||
    typeof trust.publicKeySpki !== "string" ||
    !/^[A-Za-z0-9_-]{59}$/.test(trust.publicKeySpki) ||
    !/^[a-f0-9]{64}$/.test(trust.keyId ?? "")
  ) {
    add(
      "release.signer-trust",
      "failure",
      "Qualification trust does not match the exact Ed25519 public trust contract.",
    );
    return;
  }
  const publicDer = Buffer.from(trust.publicKeySpki, "base64url");
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: publicDer,
      format: "der",
      type: "spki",
    });
  } catch {
    add(
      "release.signer-trust",
      "failure",
      "Qualification trust is not a valid Ed25519 SPKI public key.",
    );
    return;
  }
  if (
    publicDer.toString("base64url") !== trust.publicKeySpki ||
    publicKey.asymmetricKeyType !== "ed25519" ||
    createHash("sha256").update(publicDer).digest("hex") !== trust.keyId
  ) {
    add(
      "release.signer-trust",
      "failure",
      "Qualification trust key ID or canonical public-key encoding is invalid.",
    );
    return;
  }
  add(
    "release.signer-trust",
    "pass",
    `Pinned independent Ed25519 public trust ${trust.keyId}.`,
  );
}

function checkReleaseWorktree() {
  let status;
  try {
    status = runReadOnlyGit(root, [
      "status",
      "--porcelain",
      "--untracked-files=all",
    ]).trim();
  } catch {
    add(
      "release.worktree",
      strict ? "failure" : "warning",
      "Exact clean Git worktree state is unavailable.",
    );
    return false;
  }
  if (status) {
    add(
      "release.worktree",
      "failure",
      "Release preparation requires a clean committed exact source tree.",
    );
    return false;
  }
  add("release.worktree", "pass", "Git worktree is clean and committed.");
  return true;
}

function checkReviewDisposition(cleanWorktree) {
  const reviewPath = join(
    root,
    "security",
    "adversarial-review-disposition.json",
  );
  if (!existsSync(reviewPath)) {
    add(
      "release.adversarial-review",
      strict ? "failure" : "warning",
      "Exact-tree architecture, security, and validation dispositions are not present.",
    );
    return;
  }
  let disposition;
  try {
    disposition = readDirectJson(reviewPath, "adversarial review disposition");
  } catch (error) {
    add("release.adversarial-review", "failure", error.message);
    return;
  }
  if (
    disposition.approvedForLocalQualification !== true ||
    disposition.approvedForAwsMutation !== false ||
    !Array.isArray(disposition.reviews) ||
    disposition.reviews.length !== 3 ||
    disposition.reviews.some((review) => review.localFindings !== "resolved")
  ) {
    add(
      "release.adversarial-review",
      "failure",
      "Exact-tree architecture, security, and validation findings remain unresolved.",
    );
    return;
  }
  if (!cleanWorktree) {
    add(
      "release.adversarial-review",
      "failure",
      "Review disposition cannot be authenticated until the exact worktree is clean.",
    );
    return;
  }
  try {
    validateAdversarialReviewDisposition(root);
  } catch (error) {
    add("release.adversarial-review", "failure", error.message);
    return;
  }
  add(
    "release.adversarial-review",
    "pass",
    "Fresh exact-tree architecture, security, and validation dispositions are authenticated.",
  );
}

function checkProductionQualificationHost() {
  const supportedArchitecture = ["x64", "arm64"].includes(process.arch);
  if (process.platform !== "linux" || !supportedArchitecture) {
    add(
      "release.production-host",
      strict ? "failure" : "warning",
      `Sealed production qualification requires native Linux x64/arm64; current host is ${process.platform}/${process.arch}.`,
    );
    return;
  }
  add(
    "release.production-host",
    "pass",
    `Native Linux ${process.arch} can attempt sealed-host qualification; both architectures still require release evidence.`,
  );
}

function checkAwsCaller() {
  if (!onboarding?.managementAccountId) {
    add(
      "aws.caller",
      "failure",
      "Cannot verify AWS caller without a valid managementAccountId.",
    );
    return;
  }
  const result = spawnSync(
    "aws",
    ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"],
    {
      encoding: "utf8",
      env: { ...safeProcessEnvironment(), AWS_PAGER: "" },
    },
  );
  if (result.status !== 0) {
    add(
      "aws.caller",
      "failure",
      "AWS caller identity is unavailable; authenticate with aws configure sso/aws sso login.",
    );
    return;
  }
  let identity;
  try {
    identity = JSON.parse(result.stdout);
  } catch {
    add("aws.caller", "failure", "AWS caller identity response is invalid.");
    return;
  }
  if (identity.Account !== onboarding.managementAccountId) {
    add(
      "aws.caller",
      "failure",
      `AWS caller account ${identity.Account ?? "unknown"} does not match the configured management account.`,
    );
    return;
  }
  if (/^arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:root$/.test(identity.Arn ?? "")) {
    add("aws.caller", "failure", "AWS root credentials are forbidden.");
    return;
  }
  if (/^arn:aws(?:-[a-z]+)?:iam::[0-9]{12}:user\//.test(identity.Arn ?? "")) {
    add(
      "aws.caller",
      "failure",
      "IAM user caller is forbidden; use a federated or assumed role with temporary credentials.",
    );
    return;
  }
  const expectedPrefixes = [
    onboarding.managementPreviewRoleArn,
    onboarding.managementApplyRoleArn,
  ]
    .filter(Boolean)
    .map((role) =>
      String(role)
        .replace(":iam:", ":sts:")
        .replace(":role/", ":assumed-role/"),
    );
  if (
    expectedPrefixes.length !== 2 ||
    typeof identity.Arn !== "string" ||
    !expectedPrefixes.some(
      (prefix) =>
        identity.Arn.startsWith(`${prefix}/`) &&
        !identity.Arn.slice(prefix.length + 1).includes("/"),
    )
  ) {
    add(
      "aws.caller",
      "failure",
      "AWS caller is not one of the exact configured management seed assumed roles.",
    );
    return;
  }
  add(
    "aws.caller",
    "pass",
    `Verified temporary caller ${identity.Arn} in the exact management account.`,
  );
}

function checkPulumiIdentity() {
  const result = spawnSync("pulumi", ["whoami", "--json", "--verbose"], {
    encoding: "utf8",
    env: safeProcessEnvironment(),
  });
  if (result.status !== 0) {
    add(
      "pulumi.identity",
      "failure",
      "Pulumi login is unavailable; authenticate to the selected backend.",
    );
    return;
  }
  let identity;
  try {
    identity = JSON.parse(result.stdout);
  } catch {
    add("pulumi.identity", "failure", "Pulumi identity response is invalid.");
    return;
  }
  const organizations = Array.isArray(identity.organizations)
    ? identity.organizations
    : [];
  if (
    typeof identity.url !== "string" ||
    normalizeBackendUrl(identity.url) !==
      normalizeBackendUrl(onboarding?.pulumiBackendUrl)
  ) {
    add(
      "pulumi.identity",
      "failure",
      "Pulumi identity is logged into a backend different from pulumiBackendUrl.",
    );
    return;
  }
  if (
    onboarding?.pulumiOrg &&
    !organizations.includes(onboarding.pulumiOrg) &&
    identity.user !== onboarding.pulumiOrg
  ) {
    add(
      "pulumi.identity",
      "failure",
      `Pulumi identity is not a member of ${onboarding.pulumiOrg}.`,
    );
    return;
  }
  add(
    "pulumi.identity",
    "pass",
    `Pulumi backend identity is available${identity.user ? ` as ${identity.user}` : ""}.`,
  );
}

function normalizeBackendUrl(value) {
  return typeof value === "string" ? value.replace(/\/+$/, "") : "";
}

function readDirectJson(file, label) {
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || realpathSync(file) !== file) {
    throw new Error(`${label} must be a direct regular file.`);
  }
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
}

function safeProcessEnvironment() {
  return {
    ...process.env,
    NO_COLOR: "1",
    PAGER: "cat",
  };
}

function add(id, status, message) {
  checks.push({ id, status, message });
}

function printReport(report) {
  console.log("Bootstrap readiness doctor");
  console.log(`  offline:        ${report.offline}`);
  console.log("  cloud mutation: disabled");
  console.log(`  root:           ${report.root}`);
  console.log(`  config:         ${report.configPath}`);
  console.log("");
  for (const check of report.checks) {
    console.log(`${check.status.padEnd(7)} ${check.id}: ${check.message}`);
  }
  console.log("");
  console.log(
    `Summary: ${report.summary.passed} passed, ${report.summary.warnings} warnings, ${report.summary.failures} failures.`,
  );
  if (report.offline) {
    console.log(
      "No AWS or Pulumi backend request was made. Use --strict only after short-lived sessions are configured.",
    );
  }
}

function parseArgs(values) {
  const parsed = {};
  const valueArgs = new Set(["root", "config"]);
  const flagArgs = new Set([
    "help",
    "json",
    "strict",
    "check-aws-session",
    "check-pulumi-login",
  ]);
  for (let index = 0; index < values.length; index += 1) {
    const raw = values[index];
    if (!raw.startsWith("--")) throw new Error(`Invalid argument '${raw}'.`);
    const name = raw.slice(2);
    if (flagArgs.has(name)) {
      parsed[toCamelCase(name)] = true;
      continue;
    }
    if (!valueArgs.has(name)) throw new Error(`Unknown argument '--${name}'.`);
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`--${name} requires a value.`);
    }
    parsed[toCamelCase(name)] = value;
    index += 1;
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

function printUsage() {
  console.log(`Usage: npm run bootstrap:doctor -- [options]

Non-mutating bootstrap readiness checks. Offline by default.

Options:
  --root <path>              Repository root. Default: current directory.
  --config <path>            Onboarding JSON. Default: onboarding.local.json.
  --json                     Emit a credential-free JSON report.
  --check-aws-session        Call only STS GetCallerIdentity and reject root/IAM users.
  --check-pulumi-login       Check the selected Pulumi backend identity.
  --strict                   Require real stack config, Pulumi, AWS session, and backend login.
  --help                     Show this help.

The doctor never writes files and never performs AWS or Pulumi mutations.`);
}
