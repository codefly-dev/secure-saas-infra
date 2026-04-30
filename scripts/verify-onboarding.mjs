#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

let rawArgs;
try {
  rawArgs = parseArgs(process.argv.slice(2));
} catch (error) {
  console.error(`error: ${error.message}`);
  console.error("");
  printUsage();
  process.exit(1);
}

if (rawArgs.help) {
  printUsage();
  process.exit(0);
}

const configArgs = rawArgs.config ? readConfig(rawArgs.config) : {};
const args = { ...configArgs, ...rawArgs };
const root = resolve(args.root ?? process.cwd());

const githubOrg = args.githubOrg;
const pulumiOrg = args.pulumiOrg;
const accountEmailDomain = args.accountEmailDomain;
const repo = args.repo ?? "secure-saas-infra";
const pulumiProject = args.pulumiProject ?? "secure-saas-infra";
const organizationName = args.organizationName ?? "deus";
const codeownersTeam = args.codeownersTeam ?? "platform-security";
const awsEmailPrefix = args.awsEmailPrefix ?? "aws";
const managementAccountId = args.managementAccountId;
const deployerPolicyAccountId =
  args.deployerPolicyAccountId ?? managementAccountId;

const failures = validateInputs();

if (failures.length === 0) {
  verifyRequiredFiles();
  verifyPlaceholders();
  verifyGithubGovernance();
  verifyGithubOidc();
  verifyManagementAccounts();
  verifyStackRefs();
  verifyCodeowners();
  verifyGitopsRepoUrls();
  verifyGeneratedSummary();
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`error: ${failure}`);
  }
  process.exit(1);
}

console.log("Onboarding verification passed.");

function validateInputs() {
  const errors = [];

  if (!githubOrg)
    errors.push("--github-org is required or missing from config");
  if (!pulumiOrg)
    errors.push("--pulumi-org is required or missing from config");
  if (!accountEmailDomain) {
    errors.push("--account-email-domain is required or missing from config");
  }

  if (managementAccountId && !/^[0-9]{12}$/.test(managementAccountId)) {
    errors.push("--management-account-id must be a 12 digit AWS account ID");
  }

  if (deployerPolicyAccountId && !/^[0-9]{12}$/.test(deployerPolicyAccountId)) {
    errors.push(
      "--deployer-policy-account-id must be a 12 digit AWS account ID",
    );
  }

  return errors;
}

function verifyRequiredFiles() {
  for (const file of requiredGeneratedFiles()) {
    if (!existsSync(join(root, file))) {
      failures.push(`missing generated file: ${file}`);
    }
  }
}

function verifyPlaceholders() {
  for (const file of requiredGeneratedFiles()) {
    const path = join(root, file);
    if (!existsSync(path)) continue;

    const body = readFileSync(path, "utf8");
    for (const placeholder of placeholderMatches(body)) {
      failures.push(`${file} still contains placeholder '${placeholder}'`);
    }
  }
}

function verifyGithubGovernance() {
  const file = "Pulumi.github-governance.yaml";
  const body = read(file);
  if (!body) return;

  mustContain(file, body, `github:owner: ${githubOrg}`);
  mustContain(file, body, `owner: ${githubOrg}`);
  mustContain(file, body, `repository: ${repo}`);
  mustContain(file, body, "requireShaPinnedActions: true");
  mustContain(file, body, "requireCodeOwnerReview: true");
  mustContain(file, body, "requireSignedCommits: true");
  mustContain(file, body, "codeScanningTool: CodeQL");
}

function verifyGithubOidc() {
  const file = "Pulumi.github-oidc.yaml";
  const body = read(file);
  if (!body) return;

  mustContain(file, body, `owner: ${githubOrg}`);
  mustContain(file, body, `repo: ${repo}`);

  if (deployerPolicyAccountId) {
    mustContain(file, body, `arn:aws:iam::${deployerPolicyAccountId}:policy/`);
  }
}

function verifyManagementAccounts() {
  const file = "Pulumi.management.yaml";
  const body = read(file);
  if (!body) return;

  const emails = [...body.matchAll(/^\s*email:\s*([^\s]+)\s*$/gm)].map(
    (match) => match[1],
  );
  if (emails.length === 0) {
    failures.push(`${file} has no account email entries`);
    return;
  }

  const uniqueEmails = new Set(emails);
  if (uniqueEmails.size !== emails.length) {
    failures.push(`${file} has duplicate account email entries`);
  }

  for (const email of emails) {
    if (!email.endsWith(`@${accountEmailDomain}`)) {
      failures.push(
        `${file} account email '${email}' does not use @${accountEmailDomain}`,
      );
    }
    if (!email.startsWith(`${awsEmailPrefix}+`)) {
      failures.push(
        `${file} account email '${email}' does not use ${awsEmailPrefix}+ prefix`,
      );
    }
  }
}

function verifyStackRefs() {
  const expectedPrefix = `${pulumiOrg}/${pulumiProject}/`;

  for (const file of requiredStackFiles()) {
    const body = read(file);
    if (!body) continue;

    let inStackRefList = false;
    let listIndent = 0;
    for (const [lineNumber, line] of body.split(/\r?\n/).entries()) {
      const singular = line.match(
        /^(\s*)(networkStackRef|organizationStackRef|logArchiveStackRef):\s*(\S+)\s*$/,
      );
      if (singular) {
        verifyStackRefValue(file, lineNumber + 1, singular[3], expectedPrefix);
        continue;
      }

      const listStart = line.match(/^(\s*)spokeStackRefs:\s*$/);
      if (listStart) {
        inStackRefList = true;
        listIndent = listStart[1].length;
        continue;
      }

      if (!inStackRefList) {
        continue;
      }

      const entry = line.match(/^(\s*)-\s+(\S+)\s*$/);
      if (entry && entry[1].length > listIndent) {
        verifyStackRefValue(file, lineNumber + 1, entry[2], expectedPrefix);
        continue;
      }

      if (line.trim() !== "" && line.search(/\S/) <= listIndent) {
        inStackRefList = false;
      }
    }
  }
}

function verifyStackRefValue(file, lineNumber, value, expectedPrefix) {
  if (value.includes("/") && !value.includes(expectedPrefix)) {
    failures.push(
      `${file}:${lineNumber} stack reference does not use ${expectedPrefix}`,
    );
  }
}

function verifyCodeowners() {
  const file = ".github/CODEOWNERS";
  const body = read(file);
  if (!body) return;

  mustContain(file, body, `@${githubOrg}/${codeownersTeam}`);
}

function verifyGitopsRepoUrls() {
  for (const file of [
    "gitops/bootstrap/argocd/base/platform-cluster-baseline.application.yaml",
    "gitops/bootstrap/argocd/base/execution-cluster-baseline.application.yaml",
  ]) {
    const body = read(file);
    if (!body) continue;
    mustContain(file, body, `https://github.com/${githubOrg}/${repo}.git`);
  }
}

function verifyGeneratedSummary() {
  const file = "ONBOARDING.generated.md";
  const body = read(file);
  if (!body) return;

  mustContain(file, body, `GitHub organization: ${githubOrg}`);
  mustContain(
    file,
    body,
    `Pulumi stack prefix: ${pulumiOrg}/${pulumiProject}/`,
  );
}

function mustContain(file, body, expected) {
  if (!body.includes(expected)) {
    failures.push(`${file} does not contain '${expected}'`);
  }
}

function read(file) {
  const path = join(root, file);
  if (!existsSync(path)) return undefined;
  return readFileSync(path, "utf8");
}

function requiredGeneratedFiles() {
  return [
    ...requiredStackFiles(),
    ".github/CODEOWNERS",
    "gitops/bootstrap/argocd/base/platform-cluster-baseline.application.yaml",
    "gitops/bootstrap/argocd/base/execution-cluster-baseline.application.yaml",
    "ONBOARDING.generated.md",
  ];
}

function requiredStackFiles() {
  return [
    "Pulumi.dev.yaml",
    "Pulumi.execution-dev.yaml",
    "Pulumi.execution-prod.yaml",
    "Pulumi.execution-staging.yaml",
    "Pulumi.github-governance.yaml",
    "Pulumi.github-oidc.yaml",
    "Pulumi.identity.yaml",
    "Pulumi.log-archive.yaml",
    "Pulumi.management.yaml",
    "Pulumi.network-routing.yaml",
    "Pulumi.network.yaml",
    "Pulumi.organization-audit.yaml",
    "Pulumi.platform-dev.yaml",
    "Pulumi.platform-prod.yaml",
    "Pulumi.platform-staging.yaml",
    "Pulumi.security-tooling.yaml",
    "Pulumi.shared-services.yaml",
  ];
}

function placeholderMatches(body) {
  const placeholders = [];
  const patterns = [
    /your-github-org/g,
    /your-pulumi-org/g,
    /your-org\/secure-saas-infra\.git/g,
    /aws\+[^@\s]+@example\.com/g,
    /security@example\.com/g,
    /111111111111/g,
    /123456789012/g,
  ];

  for (const pattern of patterns) {
    for (const match of body.matchAll(pattern)) {
      placeholders.push(match[0]);
    }
  }

  return placeholders;
}

function readConfig(path) {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8"));
  return Object.fromEntries(
    Object.entries(raw).map(([key, value]) => [toCamel(key), value]),
  );
}

function parseArgs(argv) {
  const parsed = {};

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      throw new Error(`Unexpected argument: ${arg}`);
    }

    const [rawKey, inlineValue] = arg.slice(2).split("=", 2);
    const key = toCamel(rawKey);

    if (["help"].includes(key)) {
      parsed[key] = true;
      continue;
    }

    const value = inlineValue ?? argv[++index];
    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${rawKey}`);
    }

    parsed[key] = value;
  }

  return parsed;
}

function toCamel(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

function printUsage() {
  console.log(`Usage:
  npm run verify:onboarding -- --config onboarding.local.json

Options:
  --config <path>                 JSON config generated from onboarding.config.example.json.
  --root <path>                   Directory containing generated files. Default: current directory.
  --github-org <org>              Overrides config.
  --pulumi-org <org>              Overrides config.
  --account-email-domain <domain> Overrides config.
  --repo <name>                   Default: secure-saas-infra.
  --pulumi-project <name>         Default: secure-saas-infra.
  --organization-name <name>      Default: deus.
  --codeowners-team <team>        Default: platform-security.
  --aws-email-prefix <prefix>     Default: aws.
  --management-account-id <id>    Expected AWS management account ID.
  --deployer-policy-account-id <id>
                                  Expected deployer policy ARN account ID.`);
}
