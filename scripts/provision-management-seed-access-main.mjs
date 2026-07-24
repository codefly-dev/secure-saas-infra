#!/usr/bin/env node
// Credentialed implementation loaded only by the builtins-only guard.

import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { verifyBootstrapCandidateRuntime } from "./bootstrap-candidate-runtime.mjs";
import {
  assertExportedAwsSession,
  assertSafeBootstrapEnvironment,
  assertSafeCredentialTransportEnvironment,
} from "./bootstrap-runtime-integrity.mjs";
import {
  createManagementSeedAccessBundle,
  renderManagementSeedAccessTemplate,
} from "./management-seed-access.mjs";
import {
  attestActiveProvisioner,
  attestManagementSeedAccessFoundation,
  attestManagementSeedAccessInstallationProgress,
  attestManagementSeedAccessDeployment,
  attestProvisionerRetirementProgress,
  attestRetirementAuthority,
} from "./management-seed-access-live.mjs";
import {
  EXECUTE_CONFIRMATION,
  RETIRE_CONFIRMATION,
  assertExactAccessChangeSet,
  assertFoundationObservationAwsCommand,
  assertPreparedAccessReceipt,
  createExecutedAccessReceipt,
  createFoundationObservationReceipt,
  createPreparedAccessReceipt,
  createProvisionerRetirementReceipt,
  executeAccessChangeSet,
  observeCompletedAccessStack,
  prepareAccessChangeSet,
  performNextProvisionerRetirementOperation,
  reverifyAccessChangeSet,
} from "./management-seed-access-provisioning.mjs";
import { canonicalJson, safeFile, sha256 } from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const credentialCapability =
  globalThis[Symbol.for("security.deus.dev/credentialed-stage1/v1")];

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printUsage();
    process.exit(0);
  }
  if (
    credentialCapability?.apiVersion !==
      "security.deus.dev/credentialed-stage1/v1" ||
    credentialCapability.entrypoint !== "access-provisioner" ||
    credentialCapability.executionRoot !== root
  ) {
    throw new Error(
      "credentialed provisioning must start through /usr/local/bin/deus-aws-bootstrap runtime-service access-provisioner",
    );
  }
  assertSafeBootstrapEnvironment(process.env, "access provisioner");
  assertSafeCredentialTransportEnvironment(process.env, "access provisioner");
  assertExportedAwsSession(process.env);

  const configPath = safeFile(root, args.config ?? "onboarding.local.json");
  const bundlePath = safeFile(
    root,
    args.bundle ?? "artifacts/management-seed-access-bundle.json",
  );
  const templatePath = safeFile(
    root,
    args.template ?? "artifacts/management-seed-access.template.json",
  );
  const candidatePath = safeFile(root, args.candidate);
  const onboarding = parseObject(configPath, "onboarding configuration");
  const actualBundle = parseObject(bundlePath, "management-seed access bundle");
  const templateSource = readFileSync(templatePath);
  const actualTemplate = parseObjectSource(
    templateSource,
    "management-seed access template",
  );
  const bundle = createManagementSeedAccessBundle(root, onboarding);
  validate(
    actualBundle,
    "schemas/management-seed-access-bundle-v1.schema.json",
    "management-seed access bundle",
  );
  assertCanonicalEqual(actualBundle, bundle, "access bundle");
  assertCanonicalEqual(
    actualTemplate,
    bundle.cloudFormationTemplate,
    "access template",
  );
  if (
    templateSource.toString("utf8") !==
      renderManagementSeedAccessTemplate(bundle.cloudFormationTemplate) ||
    sha256(templateSource) !== bundle.cloudFormationTemplateFileSha256
  ) {
    throw new Error("access template bytes do not match the governed bundle");
  }
  if (args.confirmBundleDigest !== bundle.bundleDigest) {
    throw new Error(
      "--confirm-bundle-digest must equal the verified access bundle digest",
    );
  }
  const runtime = verifyBootstrapCandidateRuntime(
    root,
    path.relative(root, candidatePath),
    path.relative(root, configPath),
  );
  if (
    credentialCapability.candidateDigest !== runtime.candidate.candidateDigest
  ) {
    throw new Error(
      "credentialed provisioning requires the builtins-only signed-runtime stage 1",
    );
  }
  const aws = createAwsAdapter(runtime.awsExecutable, {
    observationOnly: args.observeFoundation,
  });
  const identity = aws.json(["sts", "get-caller-identity"]);
  const caller = args.retire
    ? assertExactSourceCaller(
        identity,
        bundle,
        bundle.provisioning.retirement.principalArn,
        "retirement authority",
      )
    : assertExactSourceCaller(
        identity,
        bundle,
        bundle.provisioning.principalArn,
        "JIT provisioner",
      );
  attestRetirementAuthority(bundle, aws.json);
  let foundationAttestation;
  let installationProgress;
  if (args.retire) {
    attestProvisionerRetirementProgress(bundle, aws.json);
  } else if (args.observeFoundation || args.prepare) {
    foundationAttestation = attestManagementSeedAccessFoundation(
      root,
      onboarding,
      aws.json,
    );
    attestActiveProvisioner(bundle, aws.json);
  } else {
    attestActiveProvisioner(bundle, aws.json);
    installationProgress = attestManagementSeedAccessInstallationProgress(
      root,
      onboarding,
      aws.json,
    );
  }

  if (args.observeFoundation) {
    const output = safeOutput(
      args.output ??
        "artifacts/runtime-output/management-seed-access-foundation.observed.json",
    );
    assertDistinctOutput(output, [
      configPath,
      bundlePath,
      templatePath,
      candidatePath,
    ]);
    const receipt = createFoundationObservationReceipt({
      bundle,
      candidateDigest: runtime.candidate.candidateDigest,
      callerArn: caller.Arn,
      attestation: foundationAttestation,
    });
    validate(
      receipt,
      "schemas/management-seed-access-foundation-observation-receipt-v1.schema.json",
      "foundation observation receipt",
    );
    writeAtomic(output, `${JSON.stringify(receipt, null, 2)}\n`);
    process.stdout.write(
      `${JSON.stringify({ foundationObserved: true, cloudControlPlaneMutationPerformed: false, iamMutationPerformed: false, output: path.relative(root, output), receiptDigest: receipt.receiptDigest, foundationAttestationDigest: receipt.foundationAttestationDigest }, null, 2)}\n`,
    );
  } else if (args.prepare) {
    const output = safeOutput(
      args.output ??
        "artifacts/runtime-output/management-seed-access-change-set.prepared.json",
    );
    assertDistinctOutput(output, [
      configPath,
      bundlePath,
      templatePath,
      candidatePath,
    ]);
    process.stderr.write(
      `PREPARE ONLY: creating a CloudFormation change set in ${bundle.managementAccountId}/${bundle.provisioning.region}; this does not create IAM resources.\n`,
    );
    const description = prepareAccessChangeSet(
      bundle,
      templateSource.toString("utf8"),
      aws,
    );
    const receipt = createPreparedAccessReceipt({
      bundle,
      candidateDigest: runtime.candidate.candidateDigest,
      callerArn: caller.Arn,
      description,
    });
    validate(
      receipt,
      "schemas/management-seed-access-change-set-receipt-v1.schema.json",
      "prepared access receipt",
    );
    writeAtomic(output, `${JSON.stringify(receipt, null, 2)}\n`);
    process.stdout.write(
      `${JSON.stringify({ prepared: true, iamMutationPerformed: false, output: path.relative(root, output), receiptDigest: receipt.receiptDigest, changeSetId: receipt.changeSet.id }, null, 2)}\n`,
    );
  } else if (args.execute) {
    if (args.confirmExecute !== EXECUTE_CONFIRMATION) {
      throw new Error(`--confirm-execute must equal ${EXECUTE_CONFIRMATION}`);
    }
    const receiptPath = safeFile(
      root,
      args.receipt ??
        "artifacts/runtime-output/management-seed-access-change-set.prepared.json",
    );
    const prepared = parseObject(receiptPath, "prepared access receipt");
    validate(
      prepared,
      "schemas/management-seed-access-change-set-receipt-v1.schema.json",
      "prepared access receipt",
    );
    assertPreparedAccessReceipt(prepared);
    if (
      prepared.bundleDigest !== bundle.bundleDigest ||
      prepared.candidateDigest !== runtime.candidate.candidateDigest ||
      prepared.callerArn !== caller.Arn
    ) {
      throw new Error(
        "prepared receipt does not bind this bundle, candidate, and provisioner caller",
      );
    }
    const output = safeOutput(
      args.output ??
        "artifacts/runtime-output/management-seed-access-change-set.executed.json",
    );
    assertDistinctOutput(output, [
      configPath,
      bundlePath,
      templatePath,
      candidatePath,
      receiptPath,
    ]);
    const recoveredAfterPriorExecution =
      installationProgress.state === "deployed";
    const expectedExecutionStatus = recoveredAfterPriorExecution
      ? "EXECUTE_COMPLETE"
      : "AVAILABLE";
    const description = reverifyAccessChangeSet(
      bundle,
      prepared.changeSet.id,
      aws,
      { executionStatus: expectedExecutionStatus },
    );
    const changes = assertExactAccessChangeSet(bundle, description, {
      executionStatus: expectedExecutionStatus,
    });
    if (
      description.ChangeSetId !== prepared.changeSet.id ||
      sha256(canonicalJson(changes)) !== prepared.changeSet.changesDigest
    ) {
      throw new Error("live change set changed after preparation");
    }
    let stack;
    let iamMutationPerformed;
    if (recoveredAfterPriorExecution) {
      process.stderr.write(
        `RECOVERY READ ONLY: the exact access stack and policies already exist; reconstructing the executed receipt without another mutation.\n`,
      );
      stack = observeCompletedAccessStack(bundle, aws);
      iamMutationPerformed = false;
    } else {
      process.stderr.write(
        `IAM MUTATION: installing exactly two retained, pre-bounded IAM role policies in ${bundle.managementAccountId}/${bundle.provisioning.region}.\n`,
      );
      stack = executeAccessChangeSet(bundle, prepared.changeSet.id, aws);
      iamMutationPerformed = true;
    }
    const attestation = attestManagementSeedAccessDeployment(
      root,
      onboarding,
      aws.json,
      { requireProvisionerRetired: false },
    );
    const executed = createExecutedAccessReceipt({
      prepared,
      candidateDigest: runtime.candidate.candidateDigest,
      callerArn: caller.Arn,
      stack,
      attestation,
      recoveredAfterPriorExecution,
    });
    validate(
      executed,
      "schemas/management-seed-access-change-set-receipt-v1.schema.json",
      "executed access receipt",
    );
    writeAtomic(output, `${JSON.stringify(executed, null, 2)}\n`);
    process.stdout.write(
      `${JSON.stringify({ executed: true, iamMutationPerformed, recoveredAfterPriorExecution, output: path.relative(root, output), receiptDigest: executed.receiptDigest, attestationDigest: attestation.attestationDigest, provisionerRetirementRequired: true }, null, 2)}\n`,
    );
  } else {
    if (args.confirmRetire !== RETIRE_CONFIRMATION) {
      throw new Error(`--confirm-retire must equal ${RETIRE_CONFIRMATION}`);
    }
    const receiptPath = safeFile(
      root,
      args.receipt ??
        "artifacts/runtime-output/management-seed-access-change-set.executed.json",
    );
    const executedAccessReceipt = parseObject(
      receiptPath,
      "executed access receipt",
    );
    validate(
      executedAccessReceipt,
      "schemas/management-seed-access-change-set-receipt-v1.schema.json",
      "executed access receipt",
    );
    if (
      executedAccessReceipt.stage !== "executed" ||
      executedAccessReceipt.bundleDigest !== bundle.bundleDigest ||
      executedAccessReceipt.candidateDigest !==
        runtime.candidate.candidateDigest
    ) {
      throw new Error(
        "executed access receipt does not bind this bundle and candidate",
      );
    }
    const output = safeOutput(
      args.output ??
        "artifacts/runtime-output/management-seed-provisioner-retirement.json",
    );
    assertDistinctOutput(output, [
      configPath,
      bundlePath,
      templatePath,
      candidatePath,
      receiptPath,
    ]);
    process.stderr.write(
      `IAM MUTATION: independently retiring only ${bundle.provisioning.principalArn}.\n`,
    );
    let progress = attestProvisionerRetirementProgress(bundle, aws.json);
    const startingState = progress.state;
    const performedOperations = [];
    while (progress.state !== "retired") {
      const transition = performNextProvisionerRetirementOperation(
        bundle,
        progress,
        aws,
      );
      performedOperations.push(transition.operation);
      progress = await retryRetirementProgress(
        bundle,
        aws.json,
        transition.expectedState,
      );
    }
    const attestation = await retryRetirementAttestation(
      root,
      onboarding,
      aws.json,
    );
    const receipt = createProvisionerRetirementReceipt({
      bundle,
      candidateDigest: runtime.candidate.candidateDigest,
      callerArn: caller.Arn,
      executedAccessReceipt,
      attestation,
      startingState,
      performedOperations,
    });
    validate(
      receipt,
      "schemas/management-seed-provisioner-retirement-receipt-v1.schema.json",
      "provisioner retirement receipt",
    );
    writeAtomic(output, `${JSON.stringify(receipt, null, 2)}\n`);
    process.stdout.write(
      `${JSON.stringify({ retired: true, iamMutationPerformed: receipt.accessMutationPerformed, startingState: receipt.startingState, output: path.relative(root, output), receiptDigest: receipt.receiptDigest, attestationDigest: receipt.attestationDigest, upstreamIdpAssignmentRetired: false }, null, 2)}\n`,
    );
  }
} catch (error) {
  process.stderr.write(`provision-management-seed-access: ${error.message}\n`);
  process.exitCode = 1;
}

function assertExactSourceCaller(identity, bundle, roleArn, label) {
  const roleName = path.posix.basename(roleArn);
  const prefix = `arn:${bundle.awsPartition}:sts::${bundle.managementAccountId}:assumed-role/${roleName}/`;
  if (
    identity?.Account !== bundle.managementAccountId ||
    typeof identity.Arn !== "string" ||
    !identity.Arn.startsWith(prefix) ||
    identity.Arn.slice(prefix.length).length === 0 ||
    identity.Arn.slice(prefix.length).includes("/")
  ) {
    throw new Error(
      `AWS caller is not the exact configured ${label} assumed role`,
    );
  }
  return identity;
}

async function retryRetirementAttestation(root, onboarding, awsJson) {
  let lastError;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      return attestManagementSeedAccessDeployment(root, onboarding, awsJson);
    } catch (error) {
      lastError = error;
      if (attempt < 11) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
      }
    }
  }
  throw new Error(
    `retired provisioner did not reach its exact postcondition: ${lastError?.message ?? "unknown attestation failure"}`,
  );
}

async function retryRetirementProgress(bundle, awsJson, expectedState) {
  let lastError;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    try {
      const progress = attestProvisionerRetirementProgress(bundle, awsJson);
      if (progress.state !== expectedState) {
        throw new Error(
          `observed '${progress.state}' while waiting for '${expectedState}'`,
        );
      }
      return progress;
    } catch (error) {
      lastError = error;
      if (attempt < 11) {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
      }
    }
  }
  throw new Error(
    `provisioner retirement did not converge to '${expectedState}': ${lastError?.message ?? "unknown attestation failure"}`,
  );
}

function createAwsAdapter(executable, { observationOnly = false } = {}) {
  const run = (args) => {
    if (observationOnly) assertFoundationObservationAwsCommand(args);
    const result = spawnSync(executable, args, {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
      env: awsEnvironment(),
    });
    if (result.status !== 0) {
      throw new Error(
        `AWS CLI command failed: ${result.stderr?.trim() || args.join(" ")}`,
      );
    }
    return result;
  };
  const json = (args) => {
    const result = run([...args, "--output", "json", "--no-cli-pager"]);
    return parseObjectSource(Buffer.from(result.stdout), "AWS CLI response");
  };
  return { run, json };
}

function awsEnvironment() {
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
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONFIG_FILE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_SHARED_CREDENTIALS_FILE",
  ];
  return Object.fromEntries(
    allowed
      .filter((name) => process.env[name] !== undefined)
      .map((name) => [name, process.env[name]]),
  );
}

function validate(value, schemaValue, label) {
  const schema = parseObject(safeFile(root, schemaValue), `${label} schema`);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(`${label} failed strict schema validation`);
  }
}

function parseObject(file, label) {
  return parseObjectSource(readFileSync(file), label);
}

function parseObjectSource(source, label) {
  try {
    const value = JSON.parse(source.toString("utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("must be an object");
    }
    return value;
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function assertCanonicalEqual(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(`${label} does not exactly match governed source`);
  }
}

function safeOutput(value) {
  const output = path.resolve(root, value);
  const artifactRoot = path.join(root, "artifacts");
  if (!output.startsWith(`${artifactRoot}${path.sep}`)) {
    throw new Error("output must remain under the artifacts directory");
  }
  let current = root;
  for (const segment of path
    .relative(root, path.dirname(output))
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) mkdirSync(current, { mode: 0o700 });
    if (
      lstatSync(current).isSymbolicLink() ||
      !lstatSync(current).isDirectory() ||
      realpathSync(current) !== current
    ) {
      throw new Error("output directory must not traverse symbolic links");
    }
  }
  if (
    existsSync(output) &&
    (lstatSync(output).isSymbolicLink() || !lstatSync(output).isFile())
  ) {
    throw new Error("output must be a regular non-symlink file");
  }
  return output;
}

function assertDistinctOutput(output, inputs) {
  if (inputs.includes(output)) {
    throw new Error("output must not overwrite an input artifact");
  }
}

function writeAtomic(output, body) {
  const temporary = `${output}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, body, { mode: 0o600, flag: "wx" });
    renameSync(temporary, output);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function parseArgs(values) {
  const args = {};
  const valueNames = new Set([
    "config",
    "bundle",
    "template",
    "candidate",
    "receipt",
    "output",
    "confirm-bundle-digest",
    "confirm-execute",
    "confirm-retire",
  ]);
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (
      token === "--help" ||
      token === "--observe-foundation" ||
      token === "--prepare" ||
      token === "--execute" ||
      token === "--retire"
    ) {
      const name = token.slice(2);
      if (Object.hasOwn(args, name)) throw new Error(`duplicate ${token}`);
      args[name] = true;
      continue;
    }
    if (!token.startsWith("--") || !valueNames.has(token.slice(2))) {
      throw new Error(`unknown argument '${token}'`);
    }
    const name = token.slice(2);
    if (Object.hasOwn(args, name)) throw new Error(`duplicate ${token}`);
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`missing value for ${token}`);
    }
    args[name] = value;
    index += 1;
  }
  if (args.help) return { help: true };
  if (
    [
      args["observe-foundation"],
      args.prepare,
      args.execute,
      args.retire,
    ].filter(Boolean).length !== 1
  ) {
    throw new Error(
      "choose exactly one of --observe-foundation, --prepare, --execute, or --retire",
    );
  }
  if (!args.candidate || !args["confirm-bundle-digest"]) {
    throw new Error("--candidate and --confirm-bundle-digest are required");
  }
  return {
    ...args,
    observeFoundation: args["observe-foundation"],
    confirmBundleDigest: args["confirm-bundle-digest"],
    confirmExecute: args["confirm-execute"],
    confirmRetire: args["confirm-retire"],
  };
}

function printUsage() {
  process.stdout.write(`Usage:
  credential-envelope ... | sudo --non-interactive \\
    /usr/local/bin/deus-aws-bootstrap runtime-service access-provisioner --observe-foundation \\
    --candidate artifacts/bootstrap-candidate.json \\
    --confirm-bundle-digest <sha256>

  credential-envelope ... | sudo --non-interactive \\
    /usr/local/bin/deus-aws-bootstrap runtime-service access-provisioner --prepare \\
    --candidate artifacts/bootstrap-candidate.json \\
    --confirm-bundle-digest <sha256>

  credential-envelope ... | sudo --non-interactive \\
    /usr/local/bin/deus-aws-bootstrap runtime-service access-provisioner --execute \\
    --candidate artifacts/bootstrap-candidate.json \\
    --confirm-bundle-digest <sha256> \\
    --confirm-execute ${EXECUTE_CONFIRMATION}

  credential-envelope ... | sudo --non-interactive \\
    /usr/local/bin/deus-aws-bootstrap runtime-service access-provisioner --retire \\
    --candidate artifacts/bootstrap-candidate.json \\
    --receipt artifacts/runtime-output/management-seed-access-change-set.executed.json \\
    --confirm-bundle-digest <sha256> \\
    --confirm-retire ${RETIRE_CONFIRMATION}

Observe-foundation performs only exact IAM/SAML read-back and writes a
mutation-free receipt. Prepare creates and verifies a CloudFormation change set
but no IAM resources.
Execute re-verifies the same change set/template and then performs the exact
two-policy IAM mutation, or reconstructs the receipt read-only when that exact
execution already completed. Retirement requires the separate exact retirement
authority and performs deny-all boundary -> sole policy deletion -> retired tag,
resuming only from an exact monotonic prefix. Every mode requires temporary
credentials, a signed clean-source candidate, and no proxy/custom CA.
See docs/management-seed-runbook.md for the complete anonymous-pipe commands.
`);
}
