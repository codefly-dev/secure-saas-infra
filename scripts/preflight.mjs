#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const args = new Set(process.argv.slice(2));
const root = process.cwd();
const requireStackFiles = args.has("--require-stack-files");
const strictPlaceholders = args.has("--strict-placeholders");

const failures = [];
const warnings = [];

const requiredFiles = [
  ".github/CODEOWNERS",
  ".github/dependabot.yml",
  ".github/pull_request_template.md",
  ".github/workflows/infra-ci.yml",
  ".github/workflows/release.yml",
  "scripts/onboard.mjs",
  "scripts/verify-onboarding.mjs",
  "onboarding.config.example.json",
  "Pulumi.github-governance.yaml.example",
  "Pulumi.github-oidc.yaml.example",
  "Pulumi.backup.yaml.example",
  "Pulumi.detection.yaml.example",
  "Pulumi.compliance.yaml.example",
  "Pulumi.cost-controls.yaml.example",
  "Pulumi.macie.yaml.example",
  "Pulumi.waf.yaml.example",
  "docs/onboarding.md",
  "docs/github-security.md",
  "docs/deploy-runbook.md",
  "docs/mind-server-security.md",
  "docs/e2b-byoc.md",
  "docs/customer-data.md",
  "docs/disaster-recovery.md",
  "docs/database.md",
  "docs/agentic-ai.md",
  "docs/runtime-security.md",
  "docs/compliance.md",
  "docs/cost-controls.md",
  "docs/waf.md",
  "policy/index.ts",
  "gitops/base/kyverno/require-execution-sandbox.yaml",
  "gitops/base/kyverno/verify-signed-provenance.yaml",
  "gitops/base/kyverno/require-agent-audit.yaml",
  "gitops/bootstrap/argocd/base/apps/vault.application.yaml",
  "gitops/bootstrap/argocd/base/apps/falco.application.yaml",
];

for (const file of requiredFiles) {
  if (!existsSync(join(root, file))) {
    failures.push(`missing required file: ${file}`);
  }
}

checkPackageScripts();
checkPinnedWorkflowActions();
checkPulumiStacks();
checkStrictPlaceholders();

if (warnings.length > 0) {
  for (const warning of warnings) {
    console.warn(`warning: ${warning}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`error: ${failure}`);
  }
  process.exitCode = 1;
} else {
  console.log("Preflight passed.");
}

function checkPackageScripts() {
  const packagePath = join(root, "package.json");
  if (!existsSync(packagePath)) {
    failures.push("missing package.json");
    return;
  }

  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
  for (const scriptName of [
    "test",
    "validate",
    "policy:build",
    "validate:gitops",
    "onboard",
    "verify:onboarding",
    "preflight",
    "preflight:strict",
  ]) {
    if (!packageJson.scripts?.[scriptName]) {
      failures.push(`package.json is missing script '${scriptName}'`);
    }
  }
}

function checkPinnedWorkflowActions() {
  const workflowsDir = join(root, ".github", "workflows");
  if (!existsSync(workflowsDir)) {
    failures.push("missing .github/workflows");
    return;
  }

  // SLSA Level 3 reusable workflows must be referenced by versioned tag — the
  // slsa-verifier validates the workflow ref against allowed semver tags from
  // the slsa-framework org, and SHA pinning would defeat the trust check.
  const slsaSemverExceptions = [/^slsa-framework\/[^@]+@v\d+\.\d+\.\d+$/];

  for (const file of walk(workflowsDir).filter((path) =>
    /\.(ya?ml)$/.test(path),
  )) {
    const body = readFileSync(file, "utf8");
    for (const [index, line] of body.split(/\r?\n/).entries()) {
      const match = line.match(/^\s*uses:\s*([^#\s]+)/);
      if (!match) continue;

      const reference = match[1];
      if (reference.startsWith("./") || reference.startsWith("../")) {
        continue;
      }

      if (slsaSemverExceptions.some((pattern) => pattern.test(reference))) {
        continue;
      }

      const atIndex = reference.lastIndexOf("@");
      const ref = atIndex >= 0 ? reference.slice(atIndex + 1) : "";
      if (!/^[a-f0-9]{40}$/i.test(ref)) {
        failures.push(
          `${relative(root, file)}:${index + 1} uses '${reference}' without a full commit SHA`,
        );
      }
    }
  }
}

function checkPulumiStacks() {
  const actualStackFiles = readdirSync(root)
    .filter((file) => /^Pulumi\..+\.ya?ml$/.test(file))
    .filter((file) => file !== "Pulumi.yaml" && !file.endsWith(".example"));

  if (requireStackFiles && actualStackFiles.length === 0) {
    failures.push(
      "no real Pulumi stack files found; copy and fill the .example files first",
    );
  }

  for (const file of actualStackFiles) {
    const body = readFileSync(join(root, file), "utf8");
    for (const placeholder of placeholderMatches(body)) {
      failures.push(`${file} still contains placeholder '${placeholder}'`);
    }
  }
}

function checkStrictPlaceholders() {
  const files = strictPlaceholders
    ? [
        ".github/CODEOWNERS",
        "Pulumi.github-governance.yaml",
        "Pulumi.github-oidc.yaml",
        "Pulumi.management.yaml",
        "Pulumi.log-archive.yaml",
        "gitops/bootstrap/argocd/base/platform-cluster-baseline.application.yaml",
        "gitops/bootstrap/argocd/base/execution-cluster-baseline.application.yaml",
      ]
    : [
        ".github/CODEOWNERS",
        "Pulumi.github-governance.yaml.example",
        "Pulumi.github-oidc.yaml.example",
        "Pulumi.management.yaml.example",
        "Pulumi.log-archive.yaml.example",
      ];

  for (const file of files) {
    if (!existsSync(join(root, file))) continue;

    const body = readFileSync(join(root, file), "utf8");
    const matches = placeholderMatches(body);
    if (matches.length === 0) continue;

    const message = `${file} contains placeholder values: ${[...new Set(matches)].join(", ")}`;
    if (strictPlaceholders) {
      failures.push(message);
    } else {
      warnings.push(
        `${message}; run npm run preflight:strict after copying real stack files`,
      );
    }
  }
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

function walk(path) {
  const stat = statSync(path);
  if (!stat.isDirectory()) {
    return [path];
  }

  return readdirSync(path).flatMap((entry) => walk(join(path, entry)));
}
