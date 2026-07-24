#!/usr/bin/env node
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

let args;
try {
  const rawArgs = parseArgs(process.argv.slice(2));
  if (rawArgs.help) {
    printUsage();
    process.exit(0);
  }
  const configArgs = rawArgs.config ? readConfig(rawArgs.config) : {};
  args = { ...configArgs, ...rawArgs };
} catch (error) {
  console.error(`error: ${error.message}`);
  console.error("");
  printUsage();
  process.exit(1);
}

const write = args.write === true;
const force = args.force === true;
const root = resolve(args.root ?? process.cwd());
const outDir = resolve(args.outDir ?? root);

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

const errors = validateInputs();
if (errors.length > 0) {
  for (const error of errors) console.error(`error: ${error}`);
  console.error("");
  printUsage();
  process.exit(1);
}

const operations = [];

for (const file of stackExampleFiles()) {
  const target = file.replace(/\.example$/, "");
  planTransformedFile(file, target, { overwriteExisting: false });
}

planTransformedFile(".github/CODEOWNERS", ".github/CODEOWNERS", {
  overwriteExisting: true,
  onlyWhenPlaceholdersRemain: true,
});

for (const file of [
  "gitops/bootstrap/argocd/base/projects.appproject.yaml",
  "gitops/bootstrap/argocd/base/platform-cluster-baseline.application.yaml",
  "gitops/bootstrap/argocd/base/execution-cluster-baseline.application.yaml",
  "gitops/base/kyverno/verify-signed-provenance.yaml",
]) {
  planTransformedFile(file, file, {
    overwriteExisting: true,
    onlyWhenPlaceholdersRemain: true,
  });
}

planGeneratedFile("ONBOARDING.generated.md", renderSummary());

if (operations.length === 0) {
  console.log("No onboarding changes needed.");
} else {
  for (const operation of operations) {
    console.log(`${write ? "wrote" : "would write"} ${operation}`);
  }
}

if (!write) {
  console.log("");
  console.log("Dry run only. Add --write to create or update files.");
}

if (!managementAccountId) {
  console.log("");
  console.log(
    "warning: management account ID was not provided; account-id placeholders remain in generated files.",
  );
}

console.log("");
console.log("Next checks:");
console.log("  npm run bootstrap:doctor -- --config onboarding.local.json");
console.log("  npm run validate:local");

function validateInputs() {
  const failures = [];

  if (!githubOrg) failures.push("--github-org is required");
  if (!pulumiOrg) failures.push("--pulumi-org is required");
  if (!accountEmailDomain) failures.push("--account-email-domain is required");

  if (
    githubOrg &&
    !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(githubOrg)
  ) {
    failures.push("--github-org must be a valid GitHub organization slug");
  }

  if (pulumiOrg && !/^[A-Za-z0-9_.-]+$/.test(pulumiOrg)) {
    failures.push("--pulumi-org must be a Pulumi organization slug");
  }

  if (repo && !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    failures.push("--repo must be a repository name, not owner/repo");
  }

  if (pulumiProject && !/^[A-Za-z0-9_.-]+$/.test(pulumiProject)) {
    failures.push("--pulumi-project must be a Pulumi project name");
  }

  if (
    accountEmailDomain &&
    !/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(accountEmailDomain)
  ) {
    failures.push("--account-email-domain must be a DNS-like domain");
  }

  if (managementAccountId && !/^[0-9]{12}$/.test(managementAccountId)) {
    failures.push("--management-account-id must be a 12 digit AWS account ID");
  }

  if (deployerPolicyAccountId && !/^[0-9]{12}$/.test(deployerPolicyAccountId)) {
    failures.push(
      "--deployer-policy-account-id must be a 12 digit AWS account ID",
    );
  }

  if (!existsSync(root) || !statSync(root).isDirectory()) {
    failures.push(`--root does not exist or is not a directory: ${root}`);
  }

  return failures;
}

function stackExampleFiles() {
  return readdirSync(root)
    .filter((file) => /^Pulumi\..+\.ya?ml\.example$/.test(file))
    .sort();
}

function planTransformedFile(sourceRel, targetRel, options) {
  const source = join(root, sourceRel);
  const target = join(outDir, targetRel);

  if (!existsSync(source)) {
    return;
  }

  const original = readFileSync(source, "utf8");
  const transformed = transform(original);
  const targetExists = existsSync(target);

  if (targetExists && !force) {
    const current = readFileSync(target, "utf8");
    const shouldUpdate =
      options.overwriteExisting &&
      current !== transformed &&
      (!options.onlyWhenPlaceholdersRemain || hasKnownPlaceholder(current));

    if (!shouldUpdate) {
      return;
    }
  }

  operations.push(relative(process.cwd(), target));

  if (!write) {
    return;
  }

  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, transformed);
}

function planGeneratedFile(targetRel, body) {
  const target = join(outDir, targetRel);
  const targetExists = existsSync(target);

  if (targetExists && !force) {
    const current = readFileSync(target, "utf8");
    if (current === body) {
      return;
    }
  }

  operations.push(relative(process.cwd(), target));

  if (!write) {
    return;
  }

  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, body);
}

function renderSummary() {
  const stackPrefix = `${pulumiOrg}/${pulumiProject}/`;
  const managementId = managementAccountId ?? "<set-management-account-id>";

  return `# Generated Onboarding Plan

GitHub organization: ${githubOrg}
GitHub repository: ${repo}
Pulumi organization: ${pulumiOrg}
Pulumi project: ${pulumiProject}
Pulumi stack prefix: ${stackPrefix}
AWS account email domain: ${accountEmailDomain}
AWS management account ID: ${managementId}

## Verify

\`\`\`sh
npm run bootstrap:doctor -- --config onboarding.local.json
npm run validate:local
\`\`\`

## First Commands

\`\`\`sh
npm run bootstrap:doctor
# Initialize backend stacks without AWS credentials, commit the reviewed
# source, publish/authenticate the host kit, then prepare the fixed Linux root
# exactly as documented in docs/management-seed-runbook.md.
sudo -iu deus-qualify sh -c 'cd /usr/local/lib/deus-bootstrap/execution && ./scripts/credential-free-qualification --config onboarding.local.json'
# Transfer only artifacts/bootstrap-signing-review-bundle.json to the
# independently controlled signer. Return only its raw detached signature.
sudo -iu deus-qualify sh -c 'cd /usr/local/lib/deus-bootstrap/execution && npm run bootstrap:finalize -- --signature /trusted-transfer/bootstrap-candidate.sig'
\`\`\`

## Remaining Manual Inputs

- Confirm each account email in Pulumi.management.yaml is globally unique.
- Set account-local deployer policy ARNs in Pulumi.github-oidc.yaml.
- Add EKS admin role ARNs to platform and execution stacks.
- Fill E2B BYOC vendor principal ARNs and external ID after vendor onboarding.
`;
}

function transform(body) {
  let next = body;

  next = next.replace(
    /@your-github-org\/platform-security/g,
    `@${githubOrg}/${codeownersTeam}`,
  );
  next = next.replace(
    /(?:your-github-org|codefly-dev)\/secure-saas-infra/g,
    `${githubOrg}/${repo}`,
  );
  next = next.replace(/your-github-org/g, githubOrg);
  next = next.replace(
    /(?:your-org|codefly-dev)\/secure-saas-infra\.git/g,
    `${githubOrg}/${repo}.git`,
  );
  next = next.replace(
    /your-pulumi-org\/secure-saas-infra/g,
    `${pulumiOrg}/${pulumiProject}`,
  );
  next = next.replace(/your-pulumi-org/g, pulumiOrg);
  next = next.replace(/repository: secure-saas-infra/g, `repository: ${repo}`);
  next = next.replace(/repo: secure-saas-infra/g, `repo: ${repo}`);
  next = next.replace(
    /secure-saas-infra:organizationName: deus/g,
    `secure-saas-infra:organizationName: ${organizationName}`,
  );
  next = next.replace(
    /aws\+([a-z0-9-]+)@example\.com/g,
    `${awsEmailPrefix}+$1@${accountEmailDomain}`,
  );
  next = next.replace(
    /security@example\.com/g,
    `security@${accountEmailDomain}`,
  );

  if (managementAccountId) {
    next = next.replace(/111111111111/g, managementAccountId);
  }

  if (deployerPolicyAccountId) {
    next = next.replace(/123456789012/g, deployerPolicyAccountId);
  }

  return next;
}

function hasKnownPlaceholder(body) {
  return /your-github-org|your-pulumi-org|(?:your-org|codefly-dev)\/secure-saas-infra\.git|aws\+[^@\s]+@example\.com|security@example\.com|111111111111|123456789012/.test(
    body,
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

    if (["write", "force", "help"].includes(key)) {
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

function readConfig(path) {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8"));
  return Object.fromEntries(
    Object.entries(raw).map(([key, value]) => [toCamel(key), value]),
  );
}

function toCamel(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

function printUsage() {
  console.log(`Usage:
  npm run onboard -- --github-org <org> --pulumi-org <org> --account-email-domain <domain> [options]

Options:
  --config <path>                 JSON config generated from onboarding.config.example.json.
  --write                         Create/update files. Without this, only prints the plan.
  --force                         Overwrite existing generated stack files.
  --repo <name>                   GitHub repository name. Default: secure-saas-infra.
  --pulumi-project <name>         Pulumi project name. Default: secure-saas-infra.
  --organization-name <name>      secure-saas-infra organizationName. Default: deus.
  --codeowners-team <team>        GitHub team slug. Default: platform-security.
  --aws-email-prefix <prefix>     Account email local-part prefix. Default: aws.
  --management-account-id <id>    Replaces management account ID placeholders.
  --deployer-policy-account-id <id>
                                  Replaces example deployer policy ARN account ID.
  --out-dir <path>                Write generated files somewhere else for review.
  --root <path>                   Repository root. Default: current directory.

Example:
  cp onboarding.config.example.json onboarding.local.json
  npm run onboard -- --config onboarding.local.json --write`);
}
