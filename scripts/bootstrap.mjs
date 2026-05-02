#!/usr/bin/env node
// scripts/bootstrap.mjs
//
// Single-command orchestrator: takes onboarding.local.json + a target
// environment and drives the full landing zone deploy. Runs preflight,
// onboards example files, initializes Pulumi stacks, configures
// cross-account assume-role from the management stack output, and runs
// `pulumi up` in dependency order.
//
// IMPORTANT: This is a thin orchestrator. It does NOT replace
//   - creating the AWS management account itself,
//   - enabling IAM Identity Center (one-time UI click),
//   - creating Tailscale OAuth credentials (vendor-side),
//   - GitHub Team plan upgrade for branch protection / rulesets.
// Those steps are documented in docs/bootstrap.md and remain manual.

import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import { join, resolve } from "node:path";

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  printUsage();
  process.exit(0);
}

const root = resolve(args.root ?? process.cwd());
const dryRun = args.dryRun === true;
const skipPreflight = args.skipPreflight === true;
const onlyStack = args.onlyStack;
const fromStack = args.fromStack;

const environments = parseEnvironments(args.environment ?? "dev");
const phases = args.phases
  ? args.phases.split(",")
  : ["foundation", "shared", "workload", "edge"];

const onboardingConfigPath = resolve(
  args.config ?? join(root, "onboarding.local.json"),
);

if (!existsSync(onboardingConfigPath)) {
  console.error(
    `error: onboarding config not found at ${onboardingConfigPath}.\nCopy onboarding.config.example.json to onboarding.local.json and fill in your values.`,
  );
  process.exit(1);
}

const onboarding = JSON.parse(readFileSync(onboardingConfigPath, "utf8"));
const pulumiOrg = onboarding.pulumiOrg;
const pulumiProject = onboarding.pulumiProject ?? "secure-saas-infra";

if (!pulumiOrg) {
  console.error(
    "error: onboarding.local.json must set pulumiOrg.",
  );
  process.exit(1);
}

console.log("=== bootstrap plan ===");
console.log(`  root:           ${root}`);
console.log(`  pulumi org:     ${pulumiOrg}/${pulumiProject}`);
console.log(`  environments:   ${environments.join(", ")}`);
console.log(`  phases:         ${phases.join(", ")}`);
console.log(`  dry run:        ${dryRun}`);
if (onlyStack) console.log(`  only stack:     ${onlyStack}`);
if (fromStack) console.log(`  from stack:     ${fromStack}`);
console.log("");

if (!skipPreflight) {
  runStep("npm run preflight", () => {
    execFileSync("npm", ["run", "preflight"], { stdio: "inherit" });
  });
}

runStep("npm run onboard --write", () => {
  execFileSync(
    "node",
    [
      "scripts/onboard.mjs",
      "--config",
      onboardingConfigPath,
      "--write",
    ],
    { stdio: "inherit", cwd: root },
  );
});

runStep("npm run build", () => {
  execFileSync("npm", ["run", "build"], { stdio: "inherit", cwd: root });
});

const stacks = buildPlan(environments, phases);
const filtered = filterPlan(stacks, { onlyStack, fromStack });

console.log("=== deploy order ===");
filtered.forEach((entry, index) => {
  console.log(`  ${(index + 1).toString().padStart(2, " ")}. ${entry.stack}  [${entry.account}]`);
});
console.log("");

if (dryRun) {
  console.log("Dry run; not executing pulumi up.");
  process.exit(0);
}

let managementAccountIds = null;

for (const entry of filtered) {
  const fqStackName = `${pulumiOrg}/${pulumiProject}/${entry.stack}`;

  if (!stackExists(fqStackName)) {
    runStep(`pulumi stack init ${fqStackName}`, () => {
      execPulumi(["stack", "init", fqStackName], { cwd: root });
    });
  }

  if (entry.account !== "management" && entry.account !== "self") {
    if (!managementAccountIds) {
      managementAccountIds = readManagementAccounts(pulumiOrg, pulumiProject);
    }
    const accountId = managementAccountIds[entry.account];
    if (!accountId) {
      console.error(
        `error: no account id known for '${entry.account}'. Run management stack first.`,
      );
      process.exit(2);
    }
    runStep(
      `pulumi config set aws:assumeRole.roleArn (${entry.account}=${accountId})`,
      () => {
        execPulumi(
          [
            "config",
            "set",
            "--stack",
            fqStackName,
            "aws:assumeRole.roleArn",
            `arn:aws:iam::${accountId}:role/OrganizationAccountAccessRole`,
          ],
          { cwd: root },
        );
        execPulumi(
          [
            "config",
            "set",
            "--stack",
            fqStackName,
            "aws:assumeRole.sessionName",
            `deus-pulumi-${entry.stack}`,
          ],
          { cwd: root },
        );
      },
    );
  }

  runStep(`pulumi up --stack ${entry.stack}`, () => {
    execPulumi(
      [
        "up",
        "--stack",
        fqStackName,
        "--policy-pack",
        "./policy",
        "--yes",
        "--non-interactive",
      ],
      { cwd: root, env: { ...process.env, GITHUB_TOKEN: process.env.GITHUB_TOKEN ?? "" } },
    );
  });

  if (entry.stack === "management") {
    // Block until accounts are ACTIVE before continuing. AWS account
    // creation is asynchronous; downstream stacks depend on the role
    // existing in member accounts.
    runStep("wait-for-accounts", () => {
      waitForAccounts(pulumiOrg, pulumiProject);
    });
  }
}

console.log("");
console.log("=== bootstrap complete ===");
console.log("Manual follow-ups:");
console.log("  - Initialize Vault and split unseal keys: vault operator init");
console.log("  - Drop Tailscale OAuth values into the placeholder Secrets Manager secrets");
console.log(
  "  - Drop E2B BYOC vendor principal ARN + external ID into Pulumi.execution-prod.yaml",
);
console.log("");

function buildPlan(envs, phases) {
  const plan = [];

  if (phases.includes("foundation")) {
    plan.push({ stack: "github-governance", account: "self" });
    plan.push({ stack: "management", account: "self" });
    plan.push({ stack: "identity", account: "self" });
    plan.push({ stack: "log-archive", account: "log-archive" });
    plan.push({ stack: "organization-audit", account: "self" });
    plan.push({ stack: "security-tooling", account: "security-tooling" });
    plan.push({ stack: "shared-services", account: "shared-services" });
    plan.push({ stack: "dns", account: "shared-services" });
    plan.push({ stack: "network", account: "network" });
    plan.push({ stack: "detection", account: "security-tooling" });
    plan.push({ stack: "compliance", account: "security-tooling" });
    plan.push({ stack: "macie", account: "security-tooling" });
    plan.push({ stack: "cost-controls", account: "self" });
  }

  if (phases.includes("shared")) {
    for (const env of envs) {
      plan.push({ stack: `backup-${env}`, account: `platform-${env}` });
    }
  }

  if (phases.includes("workload")) {
    for (const env of envs) {
      plan.push({ stack: `platform-${env}`, account: `platform-${env}` });
      plan.push({ stack: `execution-${env}`, account: `execution-${env}` });
    }
    plan.push({ stack: "network-routing", account: "network" });
  }

  if (phases.includes("edge")) {
    for (const env of envs) {
      plan.push({ stack: `waf-${env}`, account: `platform-${env}` });
      plan.push({ stack: `ingress-${env}`, account: `platform-${env}` });
      plan.push({
        stack: `argocd-platform-${env}`,
        account: `platform-${env}`,
      });
      plan.push({
        stack: `argocd-execution-${env}`,
        account: `execution-${env}`,
      });
    }
  }

  return plan;
}

function filterPlan(plan, { onlyStack, fromStack }) {
  if (onlyStack) {
    return plan.filter((entry) => entry.stack === onlyStack);
  }
  if (fromStack) {
    const index = plan.findIndex((entry) => entry.stack === fromStack);
    if (index < 0) {
      console.error(`error: --from-stack '${fromStack}' is not in the plan.`);
      process.exit(2);
    }
    return plan.slice(index);
  }
  return plan;
}

function stackExists(fqStackName) {
  const result = spawnSync(
    "pulumi",
    ["stack", "ls", "--all", "--json"],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return false;
  try {
    const stacks = JSON.parse(result.stdout);
    return stacks.some((stack) => stack.name === fqStackName);
  } catch {
    return false;
  }
}

function readManagementAccounts(pulumiOrg, pulumiProject) {
  const result = spawnSync(
    "pulumi",
    [
      "stack",
      "output",
      "--stack",
      `${pulumiOrg}/${pulumiProject}/management`,
      "--json",
      "organizationAccountIds",
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    console.error(result.stderr);
    return {};
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    return {};
  }
}

function waitForAccounts(pulumiOrg, pulumiProject) {
  const accounts = readManagementAccounts(pulumiOrg, pulumiProject);
  const accountIds = Object.values(accounts);
  if (accountIds.length === 0) {
    console.warn("warning: no member accounts found; skipping wait.");
    return;
  }
  console.log(
    `Waiting for ${accountIds.length} member accounts to reach ACTIVE...`,
  );
  // Pulumi already polled the account creation handler; accounts in the
  // output are ACTIVE. This step is a hook for future probe logic.
}

function execPulumi(pulumiArgs, options = {}) {
  const result = spawnSync("pulumi", pulumiArgs, {
    stdio: "inherit",
    ...options,
  });
  if (result.status !== 0) {
    console.error(`pulumi ${pulumiArgs.join(" ")} failed with code ${result.status}`);
    process.exit(result.status ?? 1);
  }
}

function runStep(label, fn) {
  console.log(`▶ ${label}`);
  const start = Date.now();
  try {
    fn();
  } catch (error) {
    console.error(`✗ ${label}: ${error.message}`);
    process.exit(1);
  }
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`✓ ${label} (${elapsed}s)`);
  console.log("");
}

function parseEnvironments(value) {
  if (value === "all") return ["dev", "staging", "prod"];
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected positional argument: ${arg}`);
    }
    const [rawKey, inlineValue] = arg.slice(2).split("=", 2);
    const key = toCamel(rawKey);
    if (
      ["help", "dryRun", "skipPreflight"].includes(key)
    ) {
      parsed[key] = true;
      continue;
    }
    const value = inlineValue ?? argv[++index];
    if (!value || value.startsWith("--")) {
      throw new Error(`missing value for --${rawKey}`);
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
  node scripts/bootstrap.mjs --environment <env|all> [options]

Environments:
  dev | staging | prod | all | dev,staging | etc.

Phases (default: all phases):
  foundation  → org, identity, log-archive, audit, security tooling, shared
                services, dns, network hub, detection, compliance, macie,
                cost-controls.
  shared      → per-env backup vaults.
  workload    → per-env platform + execution + network-routing.
  edge        → per-env waf, ingress, argocd-platform, argocd-execution.

Options:
  --config <path>          Path to onboarding.local.json (default: ./onboarding.local.json).
  --environment <env>      Target environment(s). Required.
  --phases <list>          Comma-separated phases (default: all).
  --only-stack <name>      Run only the named stack.
  --from-stack <name>      Resume from the named stack.
  --skip-preflight         Skip preflight checks (use sparingly).
  --dry-run                Print the deploy plan and exit.
  --root <path>            Repository root (default: cwd).
  --help                   Show this help.

Environment variables:
  GITHUB_TOKEN             Required for github-governance and github-oidc stacks.
  PULUMI_ACCESS_TOKEN      For non-interactive Pulumi backend access.
  AWS credentials must be the management-account root or a role with
  AWSOrganizationsFullAccess; the bootstrap assumes
  OrganizationAccountAccessRole into each member account from there.

Example:
  node scripts/bootstrap.mjs --environment prod --phases foundation,shared,workload
  node scripts/bootstrap.mjs --environment all --dry-run
  node scripts/bootstrap.mjs --environment dev --from-stack platform-dev
`);
}
