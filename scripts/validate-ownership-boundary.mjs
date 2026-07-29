#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

// The single repository that Codefly's promotion driver publishes reviewed
// application commits into and that owns Argo application reconciliation. Cloud
// IaC ends at infrastructure facts and this repository is the only first-party
// Argo source the platform tree may reference.
const PROTECTED_PLATFORM_REPOSITORY =
  "https://github.com/codefly-dev/secure-saas-infra.git";
const FIRST_PARTY_SOURCE_PATTERN =
  /https:\/\/github\.com\/codefly-dev\/[A-Za-z0-9._/-]+/g;

const HANDOFF_CONTRACT =
  "contracts/aws-database-infrastructure-handoff-v1alpha1.json";
const PLATFORM_TREE = "gitops";
const PROMOTION_DRIVER = "scripts/verify-review-promotion.mjs";
const PROMOTION_WORKFLOW = ".github/workflows/review-promotion.yml";
const QUALIFICATION_ENTRYPOINT = "scripts/credential-free-qualification";
const SEED_SCOPE = "security/management-seed-qualification-scope.json";

// Argo application-reconciliation objects and application source-binding keys.
// The handoff carries infrastructure admission manifests (namespaces, service
// accounts, network/node policy) but never an Argo Application or an
// application source binding/revision.
const APPLICATION_PAYLOAD_KINDS = new Set(["Application", "AppProject"]);
const APPLICATION_PAYLOAD_KEYS = new Set(["repoURL", "targetRevision"]);

// Publishing application Git commits or Argo Applications is the promotion
// driver's responsibility; no cloud-IaC command or governed script may do it.
const APPLICATION_PUBLICATION_PATTERN =
  /argocd\s+app\s+(?:create|set|sync)|git\s+push|git\s+commit/;

export function validateOwnershipBoundary(root = process.cwd()) {
  return {
    handoff: assertHandoffIsInfrastructureOnly(readHandoff(root)),
    platformRepository: assertProtectedPlatformRepositoryIsSoleFirstPartySource(
      collectFirstPartyRepositoryReferences(root),
    ),
    promotion: assertApplicationPublicationDelegated(root),
    paths: assertCloudIacDoesNotOwnPlatformTree(readSeedScope(root)),
    credentials: assertQualificationStripsProviderCredentials(root),
  };
}

function assertHandoffIsInfrastructureOnly(handoff) {
  if (handoff.owner !== "external-iac") {
    deny("cloud IaC handoff must declare owner 'external-iac'");
  }
  if (handoff.authorizedConsumer !== "infrastructure-controller") {
    deny("cloud IaC handoff must be consumed by the infrastructure controller");
  }
  if (handoff.applicationMutationAllowed !== false) {
    deny("cloud IaC handoff must forbid application mutation");
  }
  scanForApplicationPayload(handoff, "handoff");
  return { owner: handoff.owner, applicationMutationAllowed: false };
}

function assertProtectedPlatformRepositoryIsSoleFirstPartySource(references) {
  for (const reference of references) {
    if (reference !== PROTECTED_PLATFORM_REPOSITORY) {
      deny(
        `plugin-owned repository source binding '${reference}' is not the protected platform repository`,
      );
    }
  }
  if (!references.includes(PROTECTED_PLATFORM_REPOSITORY)) {
    deny(
      "the protected platform repository must own the first-party Argo source",
    );
  }
  return { protectedPlatformRepository: PROTECTED_PLATFORM_REPOSITORY };
}

function assertApplicationPublicationDelegated(root) {
  if (!existsSync(join(root, PROMOTION_DRIVER))) {
    deny("the promotion driver entrypoint is missing");
  }
  const workflow = readText(root, PROMOTION_WORKFLOW);
  if (!workflow.includes("verify-review-promotion.mjs")) {
    deny("the promotion workflow must delegate to the promotion driver");
  }
  const scripts = JSON.parse(readText(root, "package.json")).scripts ?? {};
  for (const [name, body] of Object.entries(scripts)) {
    if (APPLICATION_PUBLICATION_PATTERN.test(body)) {
      deny(`cloud IaC command '${name}' must not publish application commits`);
    }
  }
  // Beyond package.json command bodies, a publish can hide inside an invoked
  // governed script. Contiguous shell-form invocations are matched here;
  // programmatic array-argument git calls in .mjs are indistinguishable from
  // Array.push by text and are instead constrained by the read-only
  // scripts/safe-git.mjs wrapper that governed scripts route git through.
  for (const file of governedScripts(root)) {
    if (APPLICATION_PUBLICATION_PATTERN.test(readText(root, file))) {
      deny(`cloud IaC script '${file}' must not publish application commits`);
    }
  }
  return { promotionDriver: PROMOTION_DRIVER };
}

function assertCloudIacDoesNotOwnPlatformTree(seedScope) {
  const owned = [
    ...seedScope.sourceFiles,
    ...seedScope.tests.included,
    ...seedScope.tests.quarantined,
    ...seedScope.contracts.includedChecked.map((entry) => entry.contract),
  ];
  const platform = owned.filter((entry) => /^gitops\//.test(entry));
  if (platform.length > 0) {
    deny(
      `cloud IaC inventory must not own the platform tree ('${platform[0]}')`,
    );
  }
  return { cloudIacOwnsPlatformTree: false };
}

function assertQualificationStripsProviderCredentials(root) {
  const source = readText(root, QUALIFICATION_ENTRYPOINT);
  const stripped = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PULUMI_ACCESS_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
  ];
  for (const variable of stripped) {
    if (!source.includes(variable)) {
      deny(
        `credential-free qualification must reject '${variable}' before rendering`,
      );
    }
  }
  return { providerCredentialsStripped: true };
}

function scanForApplicationPayload(value, location) {
  if (Array.isArray(value)) {
    for (const entry of value) scanForApplicationPayload(entry, location);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (APPLICATION_PAYLOAD_KINDS.has(value.kind)) {
    deny(`${location} must not embed an Argo ${value.kind} resource`);
  }
  for (const [key, entry] of Object.entries(value)) {
    if (APPLICATION_PAYLOAD_KEYS.has(key)) {
      deny(`${location} must not carry application payload key '${key}'`);
    }
    scanForApplicationPayload(entry, location);
  }
}

// Every first-party repository reference anywhere Argo reconciles from — base
// AppProjects, environment/role overlay patches, and Application sources — not
// just the static base project file.
function collectFirstPartyRepositoryReferences(root) {
  const references = new Set();
  for (const file of listYamlFiles(join(root, PLATFORM_TREE))) {
    const matches = readFileSync(file, "utf8").match(FIRST_PARTY_SOURCE_PATTERN);
    for (const match of matches ?? []) references.add(match);
  }
  return [...references];
}

function listYamlFiles(directory) {
  return readdirSync(directory, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".yaml"))
    .map((entry) => path.join(entry.parentPath, entry.name));
}

function governedScripts(root) {
  return readSeedScope(root).sourceFiles.filter((entry) =>
    /^scripts\//.test(entry),
  );
}

function readHandoff(root) {
  return JSON.parse(readText(root, HANDOFF_CONTRACT));
}

function readSeedScope(root) {
  return JSON.parse(readText(root, SEED_SCOPE));
}

function readText(root, relative) {
  return readFileSync(join(root, relative), "utf8");
}

function join(root, relative) {
  return path.resolve(root, relative);
}

function deny(message) {
  throw new Error(`OWNERSHIP_BOUNDARY_DENIED: ${message}`);
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  try {
    const root = argument("--root") ?? process.cwd();
    validateOwnershipBoundary(root);
    process.stdout.write(
      "Ownership boundary holds: cloud IaC, the manifest producer, the promotion driver, and the protected platform repository own disjoint paths and responsibilities.\n",
    );
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a path.`);
  }
  return value;
}
