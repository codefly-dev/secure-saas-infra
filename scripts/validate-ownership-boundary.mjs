#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseAllDocuments } from "yaml";

// The single repository that Codefly's promotion driver publishes reviewed
// application commits into and that owns Argo application reconciliation. Cloud
// IaC ends at infrastructure facts and this repository is the only first-party
// Argo source it may reference.
const PROTECTED_PLATFORM_REPOSITORY =
  "https://github.com/codefly-dev/secure-saas-infra.git";
const FIRST_PARTY_SOURCE_PREFIX = "https://github.com/codefly-dev/";

const HANDOFF_CONTRACT =
  "contracts/aws-database-infrastructure-handoff-v1alpha1.json";
const APPPROJECTS = "gitops/bootstrap/argocd/base/projects.appproject.yaml";
const PROMOTION_DRIVER = "scripts/verify-review-promotion.mjs";
const PROMOTION_WORKFLOW = ".github/workflows/review-promotion.yml";
const QUALIFICATION_ENTRYPOINT = "scripts/credential-free-qualification";
const SEED_SCOPE = "security/management-seed-qualification-scope.json";

// Argo application-reconciliation and application-source payload markers. The
// handoff carries infrastructure admission manifests (namespaces, service
// accounts, network/node policy) but never an application source binding,
// revision, or container image.
const APPLICATION_PAYLOAD_KINDS = new Set(["Application", "AppProject"]);
const APPLICATION_PAYLOAD_KEYS = new Set([
  "repoURL",
  "targetRevision",
  "image",
  "images",
  "chart",
]);

export function validateOwnershipBoundary(root = process.cwd()) {
  return {
    handoff: assertHandoffIsInfrastructureOnly(readHandoff(root)),
    platformRepository: assertProtectedPlatformRepositoryIsSoleFirstPartySource(
      collectSourceRepositories(root),
    ),
    promotion: assertApplicationPublicationDelegated(root),
    paths: assertCloudIacDoesNotOwnPlatformTree(readSeedScope(root)),
    credentials: assertQualificationStripsProviderCredentials(root),
  };
}

export function assertHandoffIsInfrastructureOnly(handoff) {
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

export function assertProtectedPlatformRepositoryIsSoleFirstPartySource(
  repositories,
) {
  const firstParty = repositories.filter((repository) =>
    repository.startsWith(FIRST_PARTY_SOURCE_PREFIX),
  );
  for (const repository of firstParty) {
    if (repository !== PROTECTED_PLATFORM_REPOSITORY) {
      deny(
        `plugin-owned repository source binding '${repository}' is not the protected platform repository`,
      );
    }
  }
  if (!firstParty.includes(PROTECTED_PLATFORM_REPOSITORY)) {
    deny("the protected platform repository must own the first-party Argo source");
  }
  return { protectedPlatformRepository: PROTECTED_PLATFORM_REPOSITORY };
}

export function assertApplicationPublicationDelegated(root) {
  if (!existsSync(join(root, PROMOTION_DRIVER))) {
    deny("the promotion driver entrypoint is missing");
  }
  const workflow = readText(root, PROMOTION_WORKFLOW);
  if (!workflow.includes("verify-review-promotion.mjs")) {
    deny("the promotion workflow must delegate to the promotion driver");
  }
  const scripts = JSON.parse(readText(root, "package.json")).scripts ?? {};
  for (const [name, body] of Object.entries(scripts)) {
    if (/argocd\s+app\s+create|git\s+push|git\s+commit/.test(body)) {
      deny(`cloud IaC script '${name}' must not publish application commits`);
    }
  }
  return { promotionDriver: PROMOTION_DRIVER };
}

export function assertCloudIacDoesNotOwnPlatformTree(seedScope) {
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

export function assertQualificationStripsProviderCredentials(root) {
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

function collectSourceRepositories(root) {
  const documents = parseAllDocuments(readText(root, APPPROJECTS))
    .map((document) => document.toJSON())
    .filter(Boolean);
  const repositories = new Set();
  for (const document of documents) {
    for (const repository of document.spec?.sourceRepos ?? []) {
      repositories.add(repository);
    }
  }
  return [...repositories];
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

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
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
