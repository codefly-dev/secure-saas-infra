#!/usr/bin/env node
// scripts/bootstrap-main.mjs
//
// Single-command orchestrator: takes onboarding.local.json + a target
// environment and drives a pre-qualified landing-zone preview or update.
// Credential-free onboarding, stack initialization, build, tests, policy
// checks, and evidence qualification must already be complete.
//
// IMPORTANT: This is a thin orchestrator. It does NOT replace
//   - creating the AWS management account itself,
//   - the separately audited initial management-account SAML federation,
//   - creating Tailscale OAuth credentials (vendor-side),
//   - GitHub Team plan upgrade for branch protection / rulesets.
// Those steps are documented in docs/bootstrap.md and remain manual.

import { spawnSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  existsSync,
  chmodSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, relative as pathRelative, resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";
import { managementSeedAccessConfigurationFailures } from "./management-seed-access.mjs";
import { attestManagementSeedAccessDeployment } from "./management-seed-access-live.mjs";
import {
  attestManagementSeedAccountCapacity,
  verifyManagementSeedAccountCapacityAttestation,
} from "./management-seed-capacity.mjs";
import {
  attestManagementSeedOrganizationState,
  verifyManagementSeedOrganizationStateAttestation,
} from "./management-seed-organization-state.mjs";
import { createManagementSeedOrganizationRecoveryReceipt } from "./management-seed-organization-recovery.mjs";
import {
  assertManagementSeedConfiguration,
  assertManagementSeedWaveOperation,
} from "./management-seed-contract.mjs";
import {
  assertBootstrapRuntime,
  assertExportedAwsSession,
  assertSafeBootstrapEnvironment,
  assertSafeCredentialTransportEnvironment,
  runtimeExecutable,
} from "./bootstrap-runtime-integrity.mjs";
import { closeVerifiedPlan, openVerifiedPlan } from "./immutable-plan.mjs";
import { managementSeedTreeDigest } from "./management-seed-scope.mjs";
import {
  retryExactAttestation,
  runAttestedPulumiLifecycle,
} from "./pulumi-lifecycle.mjs";

const args = parseArgs(process.argv.slice(2));
const CREDENTIAL_CAPABILITY = Symbol.for(
  "security.deus.dev/credentialed-stage1/v1",
);
const CANDIDATE_MAX_AGE_MS = 24 * 60 * 60 * 1_000;

if (args.help) {
  printUsage();
  process.exit(0);
}

const root = realpathSync(resolve(args.root ?? process.cwd()));
assertSafeBootstrapEnvironment(process.env, "credentialed bootstrap");
if (
  [args.apply, args.preview, args.recoverOrganizationState].filter(
    (value) => value === true,
  ).length > 1
) {
  throw new Error(
    "Choose exactly one of --preview, --apply, or --recover-organization-state.",
  );
}
if (args.recoverOrganizationState === true && args.dryRun === true) {
  throw new Error(
    "--recover-organization-state cannot be combined with --dry-run.",
  );
}
const apply = args.apply === true && args.dryRun !== true;
const preview = args.preview === true && args.dryRun !== true;
const recoverOrganizationState = args.recoverOrganizationState === true;
const credentialed = apply || preview || recoverOrganizationState;
const dryRun = !credentialed;
const credentialCapability = credentialed
  ? assertCredentialCapability("bootstrap")
  : null;
let brokeredPulumiEnvironment = {};
if (credentialed) {
  assertSafeCredentialTransportEnvironment(process.env);
  assertExportedAwsSession(process.env);
}
if (apply || preview) {
  brokeredPulumiEnvironment = await readBrokeredPulumiEnvironment(
    credentialCapability.pulumiBrokerToken,
  );
}
const onlyStack = args.onlyStack;
const fromStack = args.fromStack;
const planDirectory = resolve(
  args.planDirectory ?? join(root, "artifacts", "pulumi-plans"),
);

const environments = parseEnvironments(
  args.environment ?? "dev",
  args.enablePreprod === true,
  args.enableProduction === true,
);
const phases = parsePhases(args.phases);
if (credentialed) {
  assertSelectedAuthorities(
    recoverOrganizationState
      ? "organization recovery"
      : preview
        ? "preview"
        : "apply",
  );
}

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
const pulumiBackend = onboarding.pulumiBackend;
const pulumiBackendUrl = onboarding.pulumiBackendUrl;
const managementAccountId = onboarding.managementAccountId;
const managementRoleArn =
  preview || recoverOrganizationState
    ? onboarding.managementPreviewRoleArn
    : apply
      ? onboarding.managementApplyRoleArn
      : null;
let bootstrapCandidate = null;
let bootstrapCandidatePath = null;

if (!pulumiOrg) {
  console.error("error: onboarding.local.json must set pulumiOrg.");
  process.exit(1);
}

if (credentialed) {
  if (!args.candidate) {
    console.error(
      "error: credentialed preview/apply/recovery requires --candidate from npm run bootstrap:finalize.",
    );
    process.exit(1);
  }
  bootstrapCandidatePath = safeCandidatePath(args.candidate);
  bootstrapCandidate = loadBootstrapCandidate(bootstrapCandidatePath);
  if (
    credentialCapability.candidateDigest !== bootstrapCandidate.candidateDigest
  ) {
    throw new Error(
      "Credentialed preview/apply/recovery requires the builtins-only signed-runtime stage 1.",
    );
  }
  if (!/^[0-9]{12}$/.test(managementAccountId ?? "")) {
    console.error(
      "error: credentialed preview/apply/recovery requires a 12-digit managementAccountId in onboarding.local.json.",
    );
    process.exit(1);
  }
  if (args.confirmManagementAccountId !== managementAccountId) {
    console.error(
      "error: credentialed preview/apply/recovery requires --confirm-management-account-id matching onboarding.local.json.",
    );
    process.exit(1);
  }
  assertManagementRoleArn();
  verifyBootstrapCandidate();
  assertManagementSeedConfiguration(root, onboarding);
  const preparedSeedDocument = parseYaml(
    readFileSync(join(root, "Pulumi.management.yaml"), "utf8"),
  );
  assertManagementSeedWaveOperation(
    preparedSeedDocument.config["secure-saas-infra:seedWave"],
    recoverOrganizationState ? "preview" : preview ? "preview" : "apply",
  );
  if (
    recoverOrganizationState &&
    preparedSeedDocument.config["secure-saas-infra:seedWave"] !==
      "organization-only"
  ) {
    throw new Error(
      "organization recovery admits only the organization-only seed wave",
    );
  }
  assertSafePlanDirectory();
  assertManagementCaller(managementAccountId, managementRoleArn);
  assertManagementAccessDeployment(
    recoverOrganizationState
      ? "before read-only organization recovery"
      : "before Pulumi backend verification",
  );
  if (!recoverOrganizationState) assertPulumiBackendIdentity();
}

if (recoverOrganizationState) {
  recoverManagementSeedOrganizationState();
  process.exit(0);
}

console.log("=== bootstrap plan ===");
console.log(`  root:           ${root}`);
console.log(`  pulumi org:     ${pulumiOrg}/${pulumiProject}`);
console.log(`  environments:   ${environments.join(", ")}`);
console.log(`  phases:         ${phases.join(", ")}`);
console.log(`  dry run:        ${dryRun}`);
console.log(
  `  AWS mutation:   ${apply ? "AUTHORIZED" : preview ? "preview only" : "disabled"}`,
);
if (preview || apply) console.log(`  plan directory:  ${planDirectory}`);
if (onlyStack) console.log(`  only stack:     ${onlyStack}`);
if (fromStack) console.log(`  from stack:     ${fromStack}`);
console.log("");

const stacks = buildPlan(environments, phases);
const filtered = filterPlan(stacks, { onlyStack, fromStack });
if (filtered.length === 0) {
  console.error("error: the requested bootstrap selection contains no stacks.");
  process.exit(2);
}

console.log("=== deploy order ===");
filtered.forEach((entry, index) => {
  console.log(
    `  ${(index + 1).toString().padStart(2, " ")}. ${entry.stack}  [${entry.account}]`,
  );
});
console.log("");

if (dryRun) {
  console.log(
    "Orchestration plan only; pass --preview to create policy-checked Pulumi update plans.",
  );
  process.exit(0);
}

console.log(`  qualified candidate: ${bootstrapCandidate.candidateDigest}`);
verifyBootstrapCandidate();

let managementAccountIds = null;
let managementCapacityAttestation = null;
let managementOrganizationStateAttestation = null;
const previewRecords = [];
const reviewedManifest = apply ? loadReviewedPlanManifest() : null;

if (preview && !existsSync(planDirectory)) {
  throw new Error(
    `plan directory must be created during credential-free preparation: ${planDirectory}`,
  );
}

for (const entry of filtered) {
  const fqStackName = `${pulumiOrg}/${pulumiProject}/${entry.stack}`;
  let observeManagementCapacity = null;
  let observeManagementOrganizationState = null;
  let lifecycleCapacityAttestation = null;
  const lifecycleOrganizationStateAttestations = new Map();
  let managementDocument = null;

  if (entry.stack === "management") {
    assertManagementSeedConfiguration(root, onboarding);
    managementDocument = parseYaml(
      readFileSync(join(root, "Pulumi.management.yaml"), "utf8"),
    );
    observeManagementCapacity = () =>
      attestManagementSeedAccountCapacity(
        managementDocument.config["secure-saas-infra:organization"],
        onboarding,
        awsJson,
        managementDocument.config["secure-saas-infra:seedWave"],
        { bootstrapCandidateDigest: bootstrapCandidate.candidateDigest },
      );
    observeManagementOrganizationState = (expectedState) =>
      attestManagementSeedOrganizationState(
        managementDocument.config["secure-saas-infra:organization"],
        onboarding,
        awsObservation,
        expectedState,
        { bootstrapCandidateDigest: bootstrapCandidate.candidateDigest },
      );
  }

  if (!stackExists(fqStackName)) {
    throw new Error(
      `Pulumi stack '${fqStackName}' is not initialized. Initialize backend stacks before assuming AWS credentials, then re-qualify the candidate.`,
    );
  }

  if (entry.stack === "management") {
    assertPreparedManagementStack(fqStackName, managementDocument.config);
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
    assertPreparedMemberStack(fqStackName, entry, accountId);
  }

  const planPath = join(planDirectory, `${entry.stack}.plan.json`);
  runStep(`pulumi ${preview ? "preview" : "up"} --stack ${entry.stack}`, () => {
    const reviewedPlan = apply
      ? verifyReviewedPlan(reviewedManifest, entry.stack, planPath)
      : null;
    runAttestedPulumiLifecycle({
      beforeLabel: `before Pulumi ${preview ? "preview" : "apply"}`,
      afterLabel: `after Pulumi ${preview ? "preview" : "apply"}`,
      attest: (stage) => {
        assertManagementAccessDeployment(stage);
        if (!observeManagementCapacity) return;
        const expectedOrganizationState = expectedOrganizationStateForLifecycle(
          managementDocument.config["secure-saas-infra:seedWave"],
          preview ? "preview" : "apply",
          stage,
        );
        const observeExactOrganizationState = () =>
          observeManagementOrganizationState(expectedOrganizationState);
        const observedOrganizationState =
          apply &&
          expectedOrganizationState === "organization-baseline" &&
          stage.startsWith("after ")
            ? retryExactAttestation(observeExactOrganizationState, {
                label: "management-seed post-apply organization baseline",
              })
            : observeExactOrganizationState();
        const priorOrganizationState =
          lifecycleOrganizationStateAttestations.get(expectedOrganizationState);
        if (
          priorOrganizationState?.attestationDigest &&
          observedOrganizationState.attestationDigest !==
            priorOrganizationState.attestationDigest
        ) {
          throw new Error(
            `management-seed ${expectedOrganizationState} state changed during the Pulumi lifecycle`,
          );
        }
        if (
          reviewedManifest?.managementSeedOrganizationState &&
          stage.startsWith("before ") &&
          observedOrganizationState.attestationDigest !==
            reviewedManifest.managementSeedOrganizationState.attestationDigest
        ) {
          throw new Error(
            "live management-seed organization state no longer matches the reviewed plan manifest",
          );
        }
        lifecycleOrganizationStateAttestations.set(
          expectedOrganizationState,
          observedOrganizationState,
        );
        managementOrganizationStateAttestation = observedOrganizationState;
        console.log(
          `  management organization-state attestation (${stage}): ${observedOrganizationState.attestationDigest}`,
        );
        const observed = observeManagementCapacity();
        if (
          reviewedManifest?.managementSeedCapacity?.attestationDigest &&
          observed.attestationDigest !==
            reviewedManifest.managementSeedCapacity.attestationDigest
        ) {
          throw new Error(
            "live management-seed capacity/state no longer matches the reviewed plan manifest",
          );
        }
        if (
          lifecycleCapacityAttestation?.attestationDigest &&
          observed.attestationDigest !==
            lifecycleCapacityAttestation.attestationDigest
        ) {
          throw new Error(
            "management-seed capacity/state changed during the Pulumi lifecycle",
          );
        }
        lifecycleCapacityAttestation = observed;
        managementCapacityAttestation = observed;
        console.log(
          `  management capacity/state attestation (${stage}): ${observed.attestationDigest}`,
        );
      },
      invoke: () =>
        execPulumi(
          preview
            ? [
                "preview",
                "--stack",
                fqStackName,
                "--policy-pack",
                "./policy",
                "--diff",
                "--save-plan",
                planPath,
                "--suppress-outputs",
                "--non-interactive",
              ]
            : [
                "up",
                "--stack",
                fqStackName,
                "--policy-pack",
                "./policy",
                "--plan",
                reviewedPlan.childPath,
                "--yes",
                "--non-interactive",
              ],
          {
            cwd: root,
            env: bootstrapChildEnvironment({ PULUMI_EXPERIMENTAL: "true" }),
            inheritedPlanFd: reviewedPlan?.fd,
          },
        ),
      reviewedPlan,
      closePlan: closeVerifiedPlan,
    });
    if (preview) {
      assertRegularPlanFile(planPath);
      chmodSync(planPath, 0o600);
      previewRecords.push({
        stack: entry.stack,
        planFile: `${entry.stack}.plan.json`,
        sha256: hashFile(planPath),
      });
    }
  });

  if (apply && entry.stack === "management") {
    // Block until accounts are ACTIVE before continuing. AWS account
    // creation is asynchronous; downstream stacks depend on the role
    // existing in member accounts.
    runStep("wait-for-accounts", () => {
      waitForAccounts(pulumiOrg, pulumiProject);
    });
  }
}

if (preview) {
  writePlanManifest(
    previewRecords,
    managementCapacityAttestation,
    managementOrganizationStateAttestation,
  );
}

console.log("");
console.log("=== bootstrap complete ===");
console.log("Manual follow-ups:");
console.log("  - Initialize Vault and split unseal keys: vault operator init");
console.log(
  "  - Drop Tailscale OAuth values into the placeholder Secrets Manager secrets",
);
console.log(
  "  - Drop E2B BYOC vendor principal ARN + external ID into Pulumi.execution-prod.yaml",
);
console.log("");

function assertSelectedAuthorities(mode) {
  if (phases.length !== 1 || phases[0] !== "seed") {
    throw new Error(
      `${mode} currently admits only '--phases seed'. Later waves require real management-stack account outputs, a reviewed account-access plan, and exact scoped Pulumi provider bindings; the broad member handoff role is not an escape hatch.`,
    );
  }
}

function writePlanManifest(
  records,
  capacityAttestation,
  organizationStateAttestation,
) {
  if (!capacityAttestation || !organizationStateAttestation) {
    throw new Error(
      "management-seed capacity and organization-state attestations are required for the reviewed plan manifest",
    );
  }
  const sorted = [...records].sort((left, right) =>
    left.stack.localeCompare(right.stack),
  );
  const manifest = {
    apiVersion: "security.deus.dev/pulumi-plan-manifest/v1alpha1",
    kind: "PulumiPlanManifest",
    generatedAt: new Date().toISOString(),
    sourceRevision: gitRevision(),
    managementAccountId,
    pulumiOrganization: pulumiOrg,
    pulumiProject,
    bootstrapCandidateDigest: bootstrapCandidate.candidateDigest,
    managementSeedCapacity: capacityAttestation,
    managementSeedOrganizationState: organizationStateAttestation,
    plans: sorted,
  };
  validateJsonAgainstSchema(
    manifest,
    "schemas/pulumi-plan-manifest-v1alpha1.schema.json",
    "Pulumi plan manifest",
  );
  const manifestPath = join(planDirectory, "manifest.json");
  const body = `${JSON.stringify(manifest, null, 2)}\n`;
  writeAtomicPlanFile(manifestPath, body);
  const digest = sha256(body);
  console.log("");
  console.log(`Saved Pulumi plans: ${planDirectory}`);
  console.log(`Plan manifest SHA-256: ${digest}`);
  console.log(
    "Review the diffs and manifest, then pass this exact digest with --confirm-plan-manifest-digest during apply.",
  );
}

function loadReviewedPlanManifest() {
  const manifestPath = join(planDirectory, "manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(
      `reviewed Pulumi plan manifest not found at ${manifestPath}; run --preview first.`,
    );
  }
  assertRegularPlanFile(manifestPath);
  const body = readFileSync(manifestPath, "utf8");
  const digest = sha256(body);
  if (args.confirmPlanManifestDigest !== digest) {
    throw new Error(
      "apply/recovery requires --confirm-plan-manifest-digest matching the reviewed manifest.",
    );
  }
  const manifest = JSON.parse(body);
  validateJsonAgainstSchema(
    manifest,
    "schemas/pulumi-plan-manifest-v1alpha1.schema.json",
    "reviewed Pulumi plan manifest",
  );
  verifyManagementSeedAccountCapacityAttestation(
    manifest.managementSeedCapacity,
    {
      managementAccountId,
      bootstrapCandidateDigest: bootstrapCandidate.candidateDigest,
    },
  );
  verifyManagementSeedOrganizationStateAttestation(
    manifest.managementSeedOrganizationState,
    {
      managementAccountId,
      bootstrapCandidateDigest: bootstrapCandidate.candidateDigest,
    },
  );
  if (
    manifest.apiVersion !== "security.deus.dev/pulumi-plan-manifest/v1alpha1" ||
    manifest.kind !== "PulumiPlanManifest" ||
    manifest.managementAccountId !== managementAccountId ||
    manifest.pulumiOrganization !== pulumiOrg ||
    manifest.pulumiProject !== pulumiProject ||
    manifest.bootstrapCandidateDigest !== bootstrapCandidate.candidateDigest ||
    manifest.managementSeedCapacity.managementAccountId !==
      managementAccountId ||
    manifest.managementSeedCapacity.bootstrapCandidateDigest !==
      bootstrapCandidate.candidateDigest ||
    manifest.managementSeedOrganizationState.managementAccountId !==
      managementAccountId ||
    manifest.managementSeedOrganizationState.bootstrapCandidateDigest !==
      bootstrapCandidate.candidateDigest
  ) {
    throw new Error(
      "reviewed Pulumi plan manifest does not match this bootstrap.",
    );
  }
  const revision = gitRevision();
  if (manifest.sourceRevision !== revision) {
    throw new Error(
      `reviewed Pulumi plan revision '${manifest.sourceRevision}' does not match '${revision}'.`,
    );
  }
  if (
    new Set(manifest.plans.map((entry) => entry.stack)).size !==
    manifest.plans.length
  ) {
    throw new Error("reviewed Pulumi plan manifest contains duplicate stacks.");
  }
  return manifest;
}

function recoverManagementSeedOrganizationState() {
  const manifest = loadReviewedPlanManifest();
  if (
    manifest.managementSeedOrganizationState.expectedState !== "standalone" ||
    manifest.managementSeedOrganizationState.organizationPresent !== false ||
    manifest.managementSeedCapacity.wave !== "organization-only" ||
    manifest.plans.length !== 1 ||
    manifest.plans[0]?.stack !== "management" ||
    manifest.plans[0]?.planFile !== "management.plan.json"
  ) {
    throw new Error(
      "organization recovery requires one reviewed organization-only management plan from an exact standalone state",
    );
  }
  const planPath = join(planDirectory, "management.plan.json");
  const reviewedPlan = verifyReviewedPlan(manifest, "management", planPath);
  closeVerifiedPlan(reviewedPlan);
  const recoveryManagementDocument = parseYaml(
    readFileSync(join(root, "Pulumi.management.yaml"), "utf8"),
  );
  const observedBaselineState = retryExactAttestation(
    () =>
      attestManagementSeedOrganizationState(
        recoveryManagementDocument.config["secure-saas-infra:organization"],
        onboarding,
        awsObservation,
        "organization-baseline",
        { bootstrapCandidateDigest: bootstrapCandidate.candidateDigest },
      ),
    {
      label: "management-seed read-only recovery organization baseline",
    },
  );
  const manifestPath = join(planDirectory, "manifest.json");
  const planManifestDigest = sha256(readFileSync(manifestPath));
  const receipt = createManagementSeedOrganizationRecoveryReceipt({
    bootstrapCandidateDigest: bootstrapCandidate.candidateDigest,
    managementAccountId,
    observedBaselineState,
    plan: manifest.plans[0],
    planManifestDigest,
    reviewedStandaloneState: manifest.managementSeedOrganizationState,
    sourceRevision: gitRevision(),
  });
  validateJsonAgainstSchema(
    receipt,
    "schemas/management-seed-organization-recovery-receipt-v1.schema.json",
    "management-seed organization recovery receipt",
  );
  const output = safeRecoveryOutput(
    args.output ??
      "artifacts/runtime-output/management-seed-organization-recovery.json",
  );
  if (
    [
      manifestPath,
      planPath,
      bootstrapCandidatePath,
      onboardingConfigPath,
    ].includes(output)
  ) {
    throw new Error("organization recovery output must not overwrite an input");
  }
  writeAtomicPlanFile(output, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(
    JSON.stringify(
      {
        recovered: true,
        pulumiInvoked: false,
        cloudMutationPerformed: false,
        output: repositoryRelative(output),
        receiptDigest: receipt.receiptDigest,
        attestationDigest: observedBaselineState.attestationDigest,
      },
      null,
      2,
    ),
  );
}

function safeRecoveryOutput(value) {
  const output = resolve(root, value);
  const allowedRoot = join(root, "artifacts", "runtime-output");
  if (
    output !==
      join(allowedRoot, "management-seed-organization-recovery.json") ||
    !existsSync(allowedRoot) ||
    lstatSync(allowedRoot).isSymbolicLink() ||
    !lstatSync(allowedRoot).isDirectory() ||
    realpathSync(allowedRoot) !== allowedRoot ||
    (existsSync(output) &&
      (lstatSync(output).isSymbolicLink() || !lstatSync(output).isFile()))
  ) {
    throw new Error(
      "organization recovery output must be the regular fixed runtime-output receipt path",
    );
  }
  return output;
}

function verifyReviewedPlan(manifest, stack, expectedPath) {
  const record = manifest.plans.find((entry) => entry.stack === stack);
  if (!record || record.planFile !== `${stack}.plan.json`) {
    throw new Error(
      `reviewed Pulumi plan manifest has no exact plan for '${stack}'.`,
    );
  }
  if (resolve(planDirectory, record.planFile) !== resolve(expectedPath)) {
    throw new Error(`reviewed Pulumi plan path escapes the plan directory.`);
  }
  if (!/^[a-f0-9]{64}$/.test(record.sha256)) {
    throw new Error(`reviewed Pulumi plan hash for '${stack}' is malformed.`);
  }
  assertRegularPlanFile(expectedPath);
  return openVerifiedPlan(expectedPath, record.sha256);
}

function assertRegularPlanFile(file) {
  repositoryRelative(file);
  if (
    !existsSync(file) ||
    lstatSync(file).isSymbolicLink() ||
    !lstatSync(file).isFile() ||
    realpathSync(file) !== file
  ) {
    throw new Error(
      `Pulumi plan artifact must be a regular in-repository file: ${file}`,
    );
  }
}

function writeAtomicPlanFile(target, contents) {
  repositoryRelative(target);
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function hashFile(path) {
  if (!existsSync(path)) throw new Error(`Pulumi plan file not found: ${path}`);
  return sha256(readFileSync(path));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function gitRevision() {
  if (
    !credentialCapability ||
    !/^[a-f0-9]{40}$/.test(credentialCapability.sourceRevision)
  ) {
    throw new Error("credentialed source revision capability is unavailable.");
  }
  return credentialCapability.sourceRevision;
}

function assertManagementRoleArn() {
  const failures = managementSeedAccessConfigurationFailures(onboarding);
  if (failures.length > 0 || managementRoleArn === null) {
    throw new Error(
      `preview/apply/recovery requires valid, distinct target roles and trusted federated principals in onboarding.local.json: ${failures.join("; ") || "selected management role is missing"}.`,
    );
  }
}

function buildPlan(envs, phases) {
  const plan = [];

  if (phases.includes("seed")) {
    plan.push({ stack: "management", account: "self" });
  }

  if (phases.includes("foundation")) {
    plan.push({ stack: "github-governance", account: "self" });
    plan.push({ stack: "identity", account: "self" });
  }

  if (phases.includes("access")) {
    for (const account of accessAccountNames(envs)) {
      plan.push({
        stack: `access-${account}`,
        account,
        kind: "account-access",
      });
    }
  }

  if (phases.includes("foundation")) {
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
      // Ingress remains blocked until the separately owned platform layer
      // publishes a verified internal-NLB handoff. This IaC plan never
      // reconciles Argo CD or any in-cluster object.
      plan.push({ stack: `ingress-${env}`, account: `platform-${env}` });
    }
  }

  return plan;
}

function accessAccountNames(envs) {
  return [
    "security-tooling",
    "log-archive",
    "network",
    "shared-services",
    ...envs.flatMap((environment) => [
      `platform-${environment}`,
      `execution-${environment}`,
    ]),
  ];
}

function filterPlan(plan, { onlyStack, fromStack }) {
  if (onlyStack) {
    const selected = plan.filter((entry) => entry.stack === onlyStack);
    if (selected.length === 0) {
      console.error(`error: --only-stack '${onlyStack}' is not in the plan.`);
      process.exit(2);
    }
    return selected;
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

function assertPreparedMemberStack(fqStackName, entry, accountId) {
  const allowedAccounts = readPulumiConfig(
    fqStackName,
    "aws:allowedAccountIds",
    true,
  );
  if (
    !Array.isArray(allowedAccounts) ||
    allowedAccounts.length !== 1 ||
    allowedAccounts[0] !== accountId
  ) {
    throw new Error(
      `Prepared stack '${entry.stack}' must bind aws:allowedAccountIds to only '${accountId}'.`,
    );
  }
  const expectedRole = `arn:aws:iam::${accountId}:role/DeusOrganizationBootstrap`;
  if (
    readPulumiConfig(fqStackName, "aws:assumeRole.roleArn") !== expectedRole ||
    readPulumiConfig(fqStackName, "aws:assumeRole.sessionName") !==
      `deus-human-bootstrap-${entry.stack}`
  ) {
    throw new Error(
      `Prepared stack '${entry.stack}' does not contain the exact reviewed temporary member-account handoff.`,
    );
  }
  if (entry.kind === "account-access") {
    if (
      readPulumiConfig(fqStackName, "secure-saas-infra:stackKind") !==
        "account-access" ||
      readPulumiConfig(
        fqStackName,
        "secure-saas-infra:awsBootstrapAccessAccountName",
      ) !== entry.account
    ) {
      throw new Error(
        `Prepared access stack '${entry.stack}' is not bound to '${entry.account}'.`,
      );
    }
  }
}

function assertPreparedManagementStack(fqStackName, expectedConfig) {
  const seedWave = expectedConfig["secure-saas-infra:seedWave"];
  assertManagementSeedWaveOperation(seedWave, preview ? "preview" : "apply");
  const keys = readPulumiConfigKeys(fqStackName);
  const allowed = new Set([
    "aws:allowedAccountIds",
    "aws:region",
    "secure-saas-infra:deploymentMode",
    "secure-saas-infra:environment",
    "secure-saas-infra:organization",
    "secure-saas-infra:organizationName",
    "secure-saas-infra:seedWave",
    "secure-saas-infra:stackKind",
  ]);
  const unexpected = keys.filter((key) => !allowed.has(key));
  if (
    unexpected.length > 0 ||
    canonicalJson([...keys].sort()) !==
      canonicalJson(Object.keys(expectedConfig).sort())
  ) {
    throw new Error(
      `Prepared management stack configuration-key inventory differs from the signed management configuration: ${unexpected.join(", ") || "missing or duplicate key"}.`,
    );
  }
  for (const key of keys) {
    const actual = readPulumiConfig(fqStackName, key, true);
    if (canonicalJson(actual) !== canonicalJson(expectedConfig[key])) {
      throw new Error(
        `Prepared management stack configuration '${key}' differs from the signed management configuration.`,
      );
    }
  }
}

function readPulumiConfigKeys(fqStackName) {
  assertPulumiInvocationBoundary();
  const result = spawnSync(
    qualifiedCommand("pulumi"),
    ["config", "--stack", fqStackName, "--json"],
    { cwd: root, encoding: "utf8", env: bootstrapChildEnvironment() },
  );
  assertPulumiCompletionBoundary();
  if (result.status !== 0) {
    throw new Error(
      `Unable to enumerate prepared Pulumi config for '${fqStackName}'.`,
    );
  }
  try {
    const value = JSON.parse(result.stdout);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return Object.keys(value).sort();
  } catch {
    throw new Error(
      `Prepared Pulumi config for '${fqStackName}' is not valid JSON.`,
    );
  }
}

function readPulumiConfig(fqStackName, key, json = false) {
  assertPulumiInvocationBoundary();
  const result = spawnSync(
    qualifiedCommand("pulumi"),
    ["config", "get", "--stack", fqStackName, ...(json ? ["--json"] : []), key],
    { cwd: root, encoding: "utf8", env: bootstrapChildEnvironment() },
  );
  assertPulumiCompletionBoundary();
  if (result.status !== 0) {
    throw new Error(
      `Unable to read prepared Pulumi config '${key}' for '${fqStackName}'.`,
    );
  }
  if (!json) return result.stdout.trim();
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(
      `Prepared Pulumi config '${key}' for '${fqStackName}' is not valid JSON.`,
    );
  }
}

function safeCandidatePath(value) {
  const candidate = resolve(root, value);
  const relative = repositoryRelative(candidate);
  const real = existsSync(candidate) ? realpathSync(candidate) : candidate;
  if (
    !relative ||
    !existsSync(candidate) ||
    lstatSync(candidate).isSymbolicLink() ||
    !lstatSync(candidate).isFile() ||
    real !== candidate
  ) {
    throw new Error(
      "Bootstrap candidate must be a regular file inside the repository.",
    );
  }
  repositoryRelative(real);
  return real;
}

function loadBootstrapCandidate(file) {
  const candidate = JSON.parse(readFileSync(file, "utf8"));
  validateJsonAgainstSchema(
    candidate,
    "schemas/bootstrap-candidate-v1.schema.json",
    "bootstrap candidate",
  );
  const { candidateDigest, signature, ...subject } = candidate;
  if (
    candidate.apiVersion !== "security.deus.dev/bootstrap-candidate/v1" ||
    !/^[a-f0-9]{64}$/.test(candidateDigest ?? "") ||
    candidateDigest !== sha256(canonicalJson(subject)) ||
    candidate.source?.dirty !== false ||
    !Array.isArray(candidate.configuration) ||
    candidate.pulumiBackend?.kind !== pulumiBackend ||
    candidate.pulumiBackend?.url !== pulumiBackendUrl ||
    candidate.pulumiBackend?.organization !== pulumiOrg ||
    !candidate.localGateEvidence ||
    !candidate.releaseEvidence
  ) {
    throw new Error(
      "Bootstrap candidate is malformed or its digest does not match.",
    );
  }
  verifyBootstrapCandidateSignature(candidateDigest, signature);
  const generated = Date.parse(candidate.generatedAt);
  const now = Date.now();
  if (
    !Number.isFinite(generated) ||
    generated > now + 60_000 ||
    now - generated > CANDIDATE_MAX_AGE_MS ||
    candidate.signingKeyId !== signature?.keyId
  ) {
    throw new Error(
      "Bootstrap candidate has a future timestamp or an inconsistent signer binding.",
    );
  }
  return candidate;
}

function verifyBootstrapCandidate() {
  if (!bootstrapCandidate) return;
  const generated = Date.parse(bootstrapCandidate.generatedAt);
  const now = Date.now();
  if (
    !Number.isFinite(generated) ||
    generated > now + 60_000 ||
    now - generated > CANDIDATE_MAX_AGE_MS
  ) {
    throw new Error("Bootstrap candidate has a future timestamp.");
  }
  const currentRevision = gitRevision();
  if (
    currentRevision !== bootstrapCandidate.source.revision ||
    managementSeedTreeDigest(root) !== bootstrapCandidate.source.treeDigest ||
    directoryDigest(resolve(root, bootstrapCandidate.build.path)) !==
      bootstrapCandidate.build.treeDigest
  ) {
    throw new Error(
      "Qualified bootstrap candidate no longer matches the source revision or compiled build.",
    );
  }
  const configured = new Map(
    bootstrapCandidate.configuration.map((entry) => [entry.path, entry.sha256]),
  );
  const onboardingRelative = relativeRepositoryPath(onboardingConfigPath);
  if (!configured.has(onboardingRelative)) {
    throw new Error(
      "Qualified bootstrap candidate does not bind the selected onboarding configuration.",
    );
  }
  const currentConfigurationPaths = [
    onboardingRelative,
    "Pulumi.management.yaml",
  ].sort();
  if (
    JSON.stringify([...configured.keys()].sort()) !==
    JSON.stringify(currentConfigurationPaths)
  ) {
    throw new Error(
      "Qualified bootstrap configuration inventory changed after qualification.",
    );
  }
  for (const [file, digest] of configured) {
    if (hashFile(safeBoundFile(file)) !== digest) {
      throw new Error(
        `Qualified bootstrap configuration '${file}' changed after qualification.`,
      );
    }
  }
  const evidenceDocuments = [];
  for (const evidence of [
    bootstrapCandidate.localGateEvidence,
    bootstrapCandidate.releaseEvidence,
  ]) {
    const file = safeBoundFile(evidence.path);
    const document = JSON.parse(readFileSync(file, "utf8"));
    evidenceDocuments.push(document);
    const observedDigest = document.reportDigest ?? document.evidenceDigest;
    if (
      hashFile(file) !== evidence.sha256 ||
      observedDigest !== evidence.evidenceDigest
    ) {
      throw new Error(
        `Qualified bootstrap evidence '${evidence.path}' changed after qualification.`,
      );
    }
  }
  verifyQualifiedEvidence(...evidenceDocuments);
  assertBootstrapRuntime(root, bootstrapCandidate.runtime, process.env, {
    runVersionProbes: false,
  });
  const runtimeVersions = new Map(
    bootstrapCandidate.runtime.executables.map((entry) => [
      entry.name,
      entry.version,
    ]),
  );
  if (
    bootstrapCandidate.tools.node !== process.version ||
    ["aws", "node", "pulumi"].some(
      (name) => runtimeVersions.get(name) !== bootstrapCandidate.tools[name],
    )
  ) {
    throw new Error(
      "Qualified bootstrap toolchain changed after qualification.",
    );
  }
}

function verifyBootstrapCandidateSignature(candidateDigest, signature) {
  const trustFile = safeBoundFile(
    "security/bootstrap-qualification-trust.json",
  );
  const trust = JSON.parse(readFileSync(trustFile, "utf8"));
  validateJsonAgainstSchema(
    trust,
    "schemas/bootstrap-qualification-trust-v1.schema.json",
    "bootstrap qualification trust root",
  );
  if (trust.configured !== true) {
    throw new Error(
      "Bootstrap qualification trust root is not configured; AWS access remains blocked.",
    );
  }
  const publicDer = Buffer.from(trust.publicKeySpki, "base64url");
  if (
    trust.algorithm !== "Ed25519" ||
    trust.keyId !== sha256(publicDer) ||
    signature?.algorithm !== "Ed25519" ||
    signature?.keyId !== trust.keyId
  ) {
    throw new Error(
      "Bootstrap candidate signer does not match the pinned trust root.",
    );
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: publicDer,
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Error(
      "Bootstrap qualification trust root is not valid Ed25519 SPKI.",
    );
  }
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    !verifySignature(
      null,
      Buffer.from(signaturePayload(candidateDigest), "utf8"),
      publicKey,
      Buffer.from(signature.value, "base64url"),
    )
  ) {
    throw new Error("Bootstrap candidate signature verification failed.");
  }
}

function signaturePayload(candidateDigest) {
  return `security.deus.dev/bootstrap-candidate/v1:${candidateDigest}`;
}

function verifyQualifiedEvidence(localGates, release) {
  validateJsonAgainstSchema(
    localGates,
    "schemas/local-gate-evidence-v1.schema.json",
    "local gate evidence",
  );
  validateJsonAgainstSchema(
    release,
    "schemas/management-seed-release-evidence-v1.schema.json",
    "release evidence",
  );
  const { reportDigest, ...gateSubject } = localGates;
  const { evidenceDigest, ...releaseSubject } = release;
  if (
    reportDigest !== sha256(canonicalJson(gateSubject)) ||
    evidenceDigest !== sha256(canonicalJson(releaseSubject))
  ) {
    throw new Error("Qualified evidence contains an invalid content digest.");
  }
  if (
    localGates.source.revision !== bootstrapCandidate.source.revision ||
    localGates.source.treeDigest !== bootstrapCandidate.source.treeDigest ||
    localGates.source.dirty !== false ||
    release.source.revision !== bootstrapCandidate.source.revision ||
    release.source.dirty !== false
  ) {
    throw new Error("Qualified evidence does not bind the candidate source.");
  }
  if (
    localGates.execution.platform !== "linux" ||
    !["x64", "arm64"].includes(localGates.execution.architecture) ||
    localGates.execution.productionQualification !== true
  ) {
    throw new Error(
      "Qualified local gates were not produced by the sealed Linux production qualifier.",
    );
  }
  const expectedCommands = new Map([
    ["g0-clean-install", "npm ci --ignore-scripts"],
    ["g0-static-contracts", "npm run validate:g0"],
    ["g1-unit", "npm run validate:g1"],
    ["g4-dependencies", "npm run security:audit"],
    [
      "g6-sbom",
      "npm run sbom -- --output artifacts/secure-saas-infra.spdx.json",
    ],
  ]);
  if (
    localGates.gates.length !== expectedCommands.size ||
    localGates.gates.some(
      (gate) => expectedCommands.get(gate.id) !== gate.command,
    ) ||
    new Set(localGates.gates.map((gate) => gate.id)).size !==
      expectedCommands.size
  ) {
    throw new Error("Qualified local gate inventory is not exact.");
  }
  if (
    localGates.adversarialReview.path !==
      "security/adversarial-review-disposition.json" ||
    hashFile(safeBoundFile(localGates.adversarialReview.path)) !==
      localGates.adversarialReview.sha256
  ) {
    throw new Error("Qualified adversarial review binding is invalid.");
  }
  try {
    validateAdversarialReviewDisposition(root, {
      trustImmutableQualifiedSource: true,
    });
  } catch (error) {
    throw new Error(
      `Qualified adversarial review is invalid: ${error.message}`,
    );
  }
  const scope = release.scope;
  if (
    scope.awsMutationPerformed !== false ||
    scope.qualificationScope !== "aws-organizations-management-seed" ||
    scope.cleanInstallResultsBound !== true ||
    scope.staticValidationResultsBound !== true ||
    scope.unitTestResultsBound !== true ||
    scope.dependencyAuditResultsBound !== true ||
    scope.sbomResultsBound !== true ||
    scope.adversarialReviewResultsBound !== true
  ) {
    throw new Error(
      "Qualified release evidence is missing a required local gate.",
    );
  }
  const boundGates = release.validation.localGates;
  if (
    boundGates.path !== bootstrapCandidate.localGateEvidence.path ||
    boundGates.sha256 !== bootstrapCandidate.localGateEvidence.sha256 ||
    boundGates.reportDigest !== reportDigest ||
    boundGates.sourceTreeDigest !== bootstrapCandidate.source.treeDigest ||
    boundGates.adversarialReviewSha256 !== localGates.adversarialReview.sha256
  ) {
    throw new Error(
      "Release evidence does not bind the exact local gate evidence.",
    );
  }
}

function directoryDigest(directory) {
  const base = realpathSync(directory);
  if (base !== directory) {
    throw new Error("Qualified build directory must not traverse a symlink.");
  }
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = resolve(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        throw new Error(`Qualified build contains symlink '${candidate}'.`);
      }
      if (stat.isDirectory()) walk(candidate);
      else if (stat.isFile()) {
        entries.push({
          path: candidate.slice(base.length + 1),
          sha256: hashFile(candidate),
        });
      }
    }
  };
  walk(base);
  if (entries.length === 0) throw new Error("Qualified build is empty.");
  return sha256(canonicalJson(entries));
}

function safeBoundFile(file) {
  const candidate = resolve(root, file);
  const relative = relativeRepositoryPath(candidate);
  const real = existsSync(candidate) ? realpathSync(candidate) : candidate;
  if (
    relative !== file.split("\\").join("/") ||
    !existsSync(candidate) ||
    lstatSync(candidate).isSymbolicLink() ||
    !lstatSync(candidate).isFile() ||
    real !== candidate
  ) {
    throw new Error(`Qualified input '${file}' is unsafe or missing.`);
  }
  repositoryRelative(real);
  return real;
}

function relativeRepositoryPath(file) {
  const absolute = resolve(file);
  return repositoryRelative(absolute);
}

function repositoryRelative(file) {
  const native = pathRelative(root, file);
  const relative = native.split("\\").join("/");
  if (
    !relative ||
    relative === ".." ||
    relative.startsWith("../") ||
    isAbsolute(native)
  ) {
    throw new Error(`Path '${file}' escapes the repository.`);
  }
  return relative;
}

function assertSafePlanDirectory() {
  repositoryRelative(planDirectory);
  if (
    !existsSync(planDirectory) ||
    lstatSync(planDirectory).isSymbolicLink() ||
    !lstatSync(planDirectory).isDirectory() ||
    realpathSync(planDirectory) !== planDirectory
  ) {
    throw new Error(
      "Pulumi plan directory must be a prepared real directory inside the repository.",
    );
  }
  for (const name of readdirSync(planDirectory)) {
    const entry = join(planDirectory, name);
    if (lstatSync(entry).isSymbolicLink() || !lstatSync(entry).isFile()) {
      throw new Error(
        `Pulumi plan directory contains an unsafe artifact '${name}'.`,
      );
    }
  }
}

function validateJsonAgainstSchema(value, schemaPath, label) {
  const schemaFile = resolve(root, schemaPath);
  repositoryRelative(schemaFile);
  if (
    !existsSync(schemaFile) ||
    lstatSync(schemaFile).isSymbolicLink() ||
    !lstatSync(schemaFile).isFile()
  ) {
    throw new Error(`${label} schema is missing or unsafe.`);
  }
  const schema = JSON.parse(readFileSync(schemaFile, "utf8"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(`${label} failed strict schema validation.`);
  }
}

function qualifiedCommand(name) {
  if (!bootstrapCandidate?.runtime) {
    throw new Error(`Qualified runtime is unavailable for '${name}'.`);
  }
  return runtimeExecutable(bootstrapCandidate.runtime, name);
}

function assertCredentialCapability(entrypoint) {
  const capability = globalThis[CREDENTIAL_CAPABILITY];
  if (
    capability?.apiVersion !== "security.deus.dev/credentialed-stage1/v1" ||
    capability.entrypoint !== entrypoint ||
    capability.executionRoot !== root ||
    !/^[a-f0-9]{64}$/.test(capability.candidateDigest ?? "") ||
    !/^[a-f0-9]{40}$/.test(capability.sourceRevision ?? "") ||
    !/^[a-f0-9]{64}$/.test(capability.sourceTreeDigest ?? "") ||
    (recoverOrganizationState
      ? capability.pulumiBrokerToken !== undefined
      : !/^Bearer [A-Za-z0-9_-]{43}$/.test(capability.pulumiBrokerToken ?? ""))
  ) {
    throw new Error(
      "Credentialed preview/apply/recovery requires the installed native launcher and immutable qualified snapshot.",
    );
  }
  return capability;
}

function bootstrapChildEnvironment(extra = {}) {
  assertSafeBootstrapEnvironment(process.env, "credentialed bootstrap");
  const allowed = [
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "TERM",
    "CI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONFIG_FILE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION",
    "PULUMI_HOME",
    "PULUMI_IGNORE_AMBIENT_PLUGINS",
  ];
  const environment = Object.fromEntries(
    allowed
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  );
  environment.PATH = [
    ...new Set(
      ["node", "pulumi", "aws"].map((name) =>
        resolve(qualifiedCommand(name), ".."),
      ),
    ),
  ].join(":");
  return { ...environment, ...brokeredPulumiEnvironment, ...extra };
}

function awsChildEnvironment() {
  const environment = bootstrapChildEnvironment();
  for (const name of Object.keys(environment)) {
    if (name.startsWith("PULUMI_")) delete environment[name];
  }
  return environment;
}

async function readBrokeredPulumiEnvironment(pulumiAuthorization) {
  const credentialsUri = process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI;
  const endpoint = credentialsUri.replace(/\/v1\/credentials$/, "/v1/pulumi");
  const response = await fetch(endpoint, {
    method: "GET",
    headers: { Authorization: pulumiAuthorization },
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) {
    throw new Error(
      "native credential broker did not provide Pulumi credentials",
    );
  }
  const value = await response.json();
  const keys = Object.keys(value).sort();
  if (
    (canonicalJson(keys) !== canonicalJson(["accessToken"]) &&
      canonicalJson(keys) !==
        canonicalJson(["accessToken", "configPassphrase"])) ||
    typeof value.accessToken !== "string" ||
    value.accessToken.length < 16 ||
    value.accessToken.length > 8 * 1024 ||
    /[\u0000\r\n]/u.test(value.accessToken) ||
    (value.configPassphrase !== undefined &&
      (typeof value.configPassphrase !== "string" ||
        /[\u0000\r\n]/u.test(value.configPassphrase)))
  ) {
    throw new Error(
      "native credential broker returned malformed Pulumi credentials",
    );
  }
  return {
    PULUMI_ACCESS_TOKEN: value.accessToken,
    ...(value.configPassphrase
      ? { PULUMI_CONFIG_PASSPHRASE: value.configPassphrase }
      : {}),
  };
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

function stackExists(fqStackName) {
  assertPulumiInvocationBoundary();
  const result = spawnSync(
    qualifiedCommand("pulumi"),
    ["stack", "ls", "--all", "--json"],
    { encoding: "utf8", env: bootstrapChildEnvironment() },
  );
  assertPulumiCompletionBoundary();
  if (result.status !== 0) return false;
  try {
    const stacks = JSON.parse(result.stdout);
    return stacks.some((stack) => stack.name === fqStackName);
  } catch {
    return false;
  }
}

function readManagementAccounts(pulumiOrg, pulumiProject) {
  assertPulumiInvocationBoundary();
  const result = spawnSync(
    qualifiedCommand("pulumi"),
    [
      "stack",
      "output",
      "--stack",
      `${pulumiOrg}/${pulumiProject}/management`,
      "--json",
      "organizationAccountIds",
    ],
    { encoding: "utf8", env: bootstrapChildEnvironment() },
  );
  assertPulumiCompletionBoundary();
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

function assertManagementCaller(expectedAccountId, expectedRoleArn) {
  const result = spawnSync(
    qualifiedCommand("aws"),
    ["sts", "get-caller-identity", "--output", "json"],
    { encoding: "utf8", env: awsChildEnvironment() },
  );
  if (result.status !== 0) {
    throw new Error(
      result.stderr?.trim() || "AWS caller identity check failed.",
    );
  }
  let identity;
  try {
    identity = JSON.parse(result.stdout);
  } catch {
    throw new Error("AWS caller identity returned invalid JSON.");
  }
  if (identity.Account !== expectedAccountId) {
    throw new Error(
      `error: AWS caller account '${identity.Account ?? "unknown"}' does not match confirmed management account '${expectedAccountId}'.`,
    );
  }
  if (/:root$/.test(identity.Arn ?? "")) {
    throw new Error(
      "error: AWS root credentials are forbidden; assume a short-lived MFA/OIDC bootstrap role.",
    );
  }
  const assumedRolePrefix = expectedRoleArn
    .replace(":iam:", ":sts:")
    .replace(":role/", ":assumed-role/");
  if (
    typeof identity.Arn !== "string" ||
    !identity.Arn.startsWith(`${assumedRolePrefix}/`) ||
    identity.Arn.slice(assumedRolePrefix.length + 1).includes("/") ||
    identity.Arn.length === assumedRolePrefix.length + 1
  ) {
    throw new Error(
      `error: AWS caller '${identity.Arn ?? "unknown"}' is not the exact approved assumed role '${expectedRoleArn}'.`,
    );
  }
}

function assertManagementAccessDeployment(stage) {
  const attestation = attestManagementSeedAccessDeployment(
    root,
    onboarding,
    awsJson,
  );
  console.log(
    `  management access attestation (${stage}): ${attestation.attestationDigest}`,
  );
}

function awsJson(commandArgs) {
  const result = spawnSync(
    qualifiedCommand("aws"),
    [...commandArgs, "--output", "json", "--no-cli-pager"],
    { encoding: "utf8", env: awsChildEnvironment() },
  );
  if (result.status !== 0) {
    throw new Error(
      `AWS access attestation command failed: ${result.stderr?.trim() || commandArgs.join(" ")}`,
    );
  }
  try {
    const parsed = JSON.parse(result.stdout);
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new Error("response is not an object");
    }
    return parsed;
  } catch (error) {
    throw new Error(
      `AWS access attestation returned invalid JSON: ${error.message}`,
    );
  }
}

function awsObservation(commandArgs) {
  const result = spawnSync(
    qualifiedCommand("aws"),
    [
      ...commandArgs,
      "--output",
      "json",
      "--cli-error-format",
      "json",
      "--no-cli-pager",
    ],
    { encoding: "utf8", env: awsChildEnvironment() },
  );
  if (result.status === 0) {
    try {
      const value = JSON.parse(result.stdout);
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("response is not an object");
      }
      return { ok: true, value };
    } catch (error) {
      throw new Error(
        `AWS organization-state observation returned invalid JSON: ${error.message}`,
      );
    }
  }
  try {
    const error = JSON.parse(result.stderr);
    if (
      error === null ||
      typeof error !== "object" ||
      Array.isArray(error) ||
      typeof error.Code !== "string"
    ) {
      throw new Error("error response is not structured");
    }
    return { ok: false, errorCode: error.Code };
  } catch (error) {
    throw new Error(
      `AWS organization-state observation failed without a structured error: ${error.message}`,
    );
  }
}

function expectedOrganizationStateForLifecycle(seedWave, operation, stage) {
  if (seedWave === "full") return "organization-baseline";
  if (seedWave !== "organization-only") {
    throw new Error("management-seed organization-state wave is invalid");
  }
  if (operation === "preview" || stage.startsWith("before ")) {
    return "standalone";
  }
  return "organization-baseline";
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
  assertPulumiInvocationBoundary();
  const { inheritedPlanFd, ...spawnOptions } = options;
  const result = spawnSync(qualifiedCommand("pulumi"), pulumiArgs, {
    stdio:
      inheritedPlanFd === undefined
        ? "inherit"
        : ["inherit", "inherit", "inherit", inheritedPlanFd],
    env: bootstrapChildEnvironment({ PULUMI_EXPERIMENTAL: "true" }),
    ...spawnOptions,
  });
  assertPulumiCompletionBoundary();
  if (result.status !== 0) {
    throw new Error(
      `pulumi ${pulumiArgs.join(" ")} failed with code ${result.status}`,
    );
  }
}

function assertPulumiInvocationBoundary() {
  verifyBootstrapCandidate();
  assertPulumiBackendIdentity();
  assertManagementCaller(managementAccountId, managementRoleArn);
}

function assertPulumiCompletionBoundary() {
  assertManagementCaller(managementAccountId, managementRoleArn);
  assertPulumiBackendIdentity();
  verifyBootstrapCandidate();
}

function assertPulumiBackendIdentity() {
  verifyBootstrapCandidate();
  assertManagementCaller(managementAccountId, managementRoleArn);
  const result = spawnSync(
    qualifiedCommand("pulumi"),
    ["whoami", "--json", "--verbose"],
    { cwd: root, encoding: "utf8", env: bootstrapChildEnvironment() },
  );
  assertManagementCaller(managementAccountId, managementRoleArn);
  verifyBootstrapCandidate();
  if (result.status !== 0) {
    throw new Error("Pulumi backend identity is unavailable.");
  }
  let identity;
  try {
    identity = JSON.parse(result.stdout);
  } catch {
    throw new Error("Pulumi backend identity response is invalid.");
  }
  const organizations = Array.isArray(identity.organizations)
    ? identity.organizations
    : [];
  if (
    normalizeBackendUrl(identity.url) !==
      normalizeBackendUrl(pulumiBackendUrl) ||
    ((organizations.length > 0 || pulumiBackend === "pulumi-cloud") &&
      !organizations.includes(pulumiOrg) &&
      identity.user !== pulumiOrg)
  ) {
    throw new Error(
      "Pulumi identity does not match the exact configured backend and organization.",
    );
  }
}

function normalizeBackendUrl(value) {
  return typeof value === "string" ? value.replace(/\/+$/, "") : "";
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

function parseEnvironments(value, enablePreprod, enableProduction) {
  const requested =
    value === "all"
      ? enableProduction
        ? ["dev", "prod"]
        : ["dev"]
      : value.split(",");
  const environments = [
    ...new Set(requested.map((entry) => entry.trim()).filter(Boolean)),
  ];
  const unsupported = environments.filter(
    (environment) => !["dev", "staging", "prod"].includes(environment),
  );
  if (unsupported.length > 0) {
    throw new Error(
      `unsupported environment(s): ${unsupported.join(", ")}. Use dev, staging, prod, or all.`,
    );
  }
  if (environments.includes("staging") && !enablePreprod) {
    throw new Error(
      "staging is declared disabled; enable both staging AWS accounts and pass --enable-preprod explicitly.",
    );
  }
  if (environments.includes("prod") && !enableProduction) {
    throw new Error(
      "production accounts are governed but workload deployment is gated; pass --enable-production explicitly.",
    );
  }
  return environments;
}

function parsePhases(value) {
  const phases = value
    ? [
        ...new Set(
          value
            .split(",")
            .map((phase) => phase.trim())
            .filter(Boolean),
        ),
      ]
    : ["seed", "foundation", "access", "shared", "workload", "edge"];
  const unsupported = phases.filter(
    (phase) =>
      !["seed", "foundation", "access", "shared", "workload", "edge"].includes(
        phase,
      ),
  );
  if (unsupported.length > 0) {
    throw new Error(
      `unsupported phase(s): ${unsupported.join(", ")}. Use seed, foundation, access, shared, workload, or edge.`,
    );
  }
  if (phases.length === 0) {
    throw new Error("at least one bootstrap phase is required.");
  }
  return phases;
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
    const booleanKeys = [
      "help",
      "dryRun",
      "apply",
      "preview",
      "recoverOrganizationState",
      "enablePreprod",
      "enableProduction",
    ];
    const valueKeys = [
      "config",
      "environment",
      "phases",
      "onlyStack",
      "fromStack",
      "root",
      "confirmManagementAccountId",
      "planDirectory",
      "confirmPlanManifestDigest",
      "candidate",
      "output",
    ];
    if (![...booleanKeys, ...valueKeys].includes(key)) {
      throw new Error(`unknown argument: --${rawKey}`);
    }
    if (booleanKeys.includes(key)) {
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
  dev | all (planning set; credentialed execution currently admits seed only)
  prod planning is rejected unless --enable-production is set.
  staging planning is rejected unless its account pair is enabled and --enable-preprod is set.

Phases (default: all phases):
  seed        → management organization/account seed only. This is the only
                wave currently admitted for real preview/apply.
  foundation  → org, identity, log-archive, audit, security tooling, shared
                services, dns, network hub, detection, compliance, macie,
                cost-controls.
  access      → human-approved one-time installation of scoped plan/apply
                capability-lane roles in selected member accounts.
  shared      → per-env backup vaults.
  workload    → per-env platform + execution + network-routing.
  edge        → per-env waf, verified platform-owned NLB handoff, then ingress.

Options:
  --config <path>          Path to onboarding.local.json (default: ./onboarding.local.json).
  --environment <env>      Target environment(s). Required.
  --phases <list>          Comma-separated phases (default: all).
  --only-stack <name>      Run only the named stack.
  --from-stack <name>      Resume from the named stack.
  --preview                Run policy-checked Pulumi previews and save exact
                           update plans plus a SHA-256 manifest. No AWS mutation.
  --apply                  Explicitly authorize Pulumi updates. The default only
                           prints the orchestration plan.
                           Requires the exact reviewed plan manifest digest.
  --recover-organization-state
                           Native-runtime internal mode for read-only recovery
                           after a late-converging organization-only apply.
                           Operators use runtime-service organization-recovery;
                           no Pulumi secret, Pulumi command, or AWS mutation.
  --confirm-management-account-id <12 digits>
                           Required with preview/apply/recovery; must match onboarding.local.json
                           and aws sts get-caller-identity.
  --candidate <path>       Required for preview/apply/recovery. Must be the clean,
                           detached-signature output of npm run bootstrap:finalize.
  --plan-directory <path>  Saved Pulumi plan directory (default: artifacts/pulumi-plans).
  --confirm-plan-manifest-digest <sha256>
                           Required with --apply/recover-organization-state;
                           must match the reviewed manifest and selected plan.
  --output <path>          Recovery only; fixed to artifacts/runtime-output/
                           management-seed-organization-recovery.json.
  --enable-preprod         Admit explicit staging plans after both accounts are enabled.
  --enable-production      Admit production workload plans after release gates pass.
  --dry-run                Force plan-only behavior even when --apply is present.
  --root <path>            Repository root (default: cwd).
  --help                   Show this help.

Environment variables:
  GITHUB_TOKEN             Required for github-governance and github-oidc stacks.
  PULUMI_ACCESS_TOKEN      For non-interactive Pulumi backend access.
  AWS credentials must use managementPreviewRoleArn for --preview and the
  distinct managementApplyRoleArn for --apply. Both are short-lived,
  MFA/OIDC-authenticated, human-only roles using the checked-in seed policies.
  Never use root credentials, IAM-user credentials, OrganizationAccountAccessRole,
  or the transient DeusOrganizationBootstrap member-account role.

Example:
  node scripts/bootstrap.mjs --environment dev --phases seed --preview --candidate artifacts/bootstrap-candidate.json --confirm-management-account-id 111122223333
  node scripts/bootstrap.mjs --environment all --dry-run
  node scripts/bootstrap.mjs --environment staging --enable-preprod --dry-run
  node scripts/bootstrap.mjs --environment dev --from-stack platform-dev
`);
}
