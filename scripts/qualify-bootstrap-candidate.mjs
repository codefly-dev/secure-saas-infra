#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  assertBootstrapRuntime,
  assertSafeBootstrapEnvironment,
  bootstrapRuntimeProvenanceBinding,
  collectBootstrapRuntime,
} from "./bootstrap-runtime-integrity.mjs";
import { assertHostToolchainPins } from "./bootstrap-host-toolchain.mjs";
import {
  assertBootstrapSealInventory,
  writeBootstrapSealInventory,
} from "./bootstrap-seal-inventory.mjs";
import { managementSeedSourceState } from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const args = parseArgs(process.argv.slice(2));
assertCredentialFreeEnvironment();
assertFixedExecutionRoot();
for (const value of [
  args.output ?? "artifacts/bootstrap-candidate.unsigned.json",
  args["payload-output"] ?? "artifacts/bootstrap-candidate.payload",
  args["review-bundle-output"] ??
    "artifacts/bootstrap-signing-review-bundle.json",
  args["gate-output"] ?? "artifacts/local-gate-evidence.json",
  args["release-output"] ?? "artifacts/security-contract-evidence.json",
  "artifacts/secure-saas-infra.spdx.json",
]) {
  ensureSafeDirectory(path.dirname(path.resolve(root, value)));
}
ensureSafeDirectory(path.resolve(root, "artifacts/pulumi-plans"));
const output = safeOutput(
  args.output ?? "artifacts/bootstrap-candidate.unsigned.json",
);
const payloadOutput = safeOutput(
  args["payload-output"] ?? "artifacts/bootstrap-candidate.payload",
);
const reviewBundleOutput = safeOutput(
  args["review-bundle-output"] ??
    "artifacts/bootstrap-signing-review-bundle.json",
);
const gateOutput = safeOutput(
  args["gate-output"] ?? "artifacts/local-gate-evidence.json",
);
const releaseOutput = safeOutput(
  args["release-output"] ?? "artifacts/security-contract-evidence.json",
);
const sbomOutput = safeOutput("artifacts/secure-saas-infra.spdx.json");

let Ajv2020;
let addFormats;
assertSafeBootstrapEnvironment(process.env, "bootstrap qualification");
const initialTools = currentToolVersions();
assertPinnedTools(initialTools);
const onboardingPath = safeInput(
  args.config ?? "onboarding.local.json",
  "onboarding configuration",
);
if (relative(onboardingPath) !== "onboarding.local.json") {
  fail(
    "BOOTSTRAP_CANDIDATE_CONFIGURATION_PATH_DENIED",
    "Production qualification requires the fixed onboarding.local.json path.",
  );
}

function assertFixedExecutionRoot() {
  const expected = "/usr/local/lib/deus-bootstrap/execution";
  if (
    root !== expected ||
    process.env.PULUMI_HOME !== `${expected}/artifacts/bootstrap-pulumi-home`
  ) {
    fail(
      "BOOTSTRAP_CANDIDATE_EXECUTION_ROOT_DENIED",
      "Qualification must run in the fixed execution root with its exact Pulumi home.",
    );
  }
}

function currentToolVersions() {
  return {
    node: process.version,
    npm: commandVersion("npm", ["--version"]),
    pulumi: commandVersion("pulumi", ["version"]),
    aws: commandVersion("aws", ["--version"]),
    git: commandVersion("git", ["--version"]),
  };
}
const source = sourceState();
if (source.dirty) {
  fail(
    "BOOTSTRAP_CANDIDATE_DIRTY_SOURCE",
    "Qualification requires a clean committed worktree after onboarding.",
  );
}
runRequired(process.execPath, [
  "scripts/run-local-gates.mjs",
  "--output",
  relative(gateOutput),
]);
const [ajvModule, formatsModule, contractModule] = await Promise.all([
  import("ajv/dist/2020.js"),
  import("ajv-formats"),
  import("./management-seed-contract.mjs"),
]);
Ajv2020 = ajvModule.default;
addFormats = formatsModule.default;
const qualificationTrust = loadQualificationTrust();
verifyOfflineBootstrapReadiness(onboardingPath);
const onboarding = parseJson(onboardingPath);
contractModule.assertManagementSeedConfiguration(root, onboarding);
const qualifiedSource = sourceState();
if (
  qualifiedSource.dirty ||
  qualifiedSource.revision !== source.revision ||
  qualifiedSource.treeDigest !== source.treeDigest
) {
  fail(
    "BOOTSTRAP_CANDIDATE_SOURCE_CHANGED",
    "Source changed while local qualification gates were running.",
  );
}
const gateReport = parseJson(gateOutput);
validate(
  gateReport,
  "schemas/local-gate-evidence-v1.schema.json",
  "local gate report",
);
const { reportDigest: gateDigest, ...gateSubject } = gateReport;
if (
  gateReport.source.revision !== qualifiedSource.revision ||
  gateReport.source.treeDigest !== qualifiedSource.treeDigest ||
  gateReport.source.dirty !== false ||
  gateDigest !== sha256(canonicalJson(gateSubject))
) {
  fail(
    "BOOTSTRAP_CANDIDATE_GATE_SOURCE_DENIED",
    "Local gate evidence does not bind the exact qualified source.",
  );
}

runRequired(process.execPath, [
  "scripts/generate-release-evidence.mjs",
  "--validation-report",
  "artifacts/contract-schema-validation.json",
  "--sbom",
  relative(sbomOutput),
  "--gate-report",
  relative(gateOutput),
  "--require-clean",
  "--output",
  relative(releaseOutput),
]);
const release = parseJson(releaseOutput);
validate(
  release,
  "schemas/management-seed-release-evidence-v1.schema.json",
  "release evidence",
);
const { evidenceDigest: releaseDigest, ...releaseSubject } = release;
if (
  releaseDigest !== sha256(canonicalJson(releaseSubject)) ||
  release.scope?.cleanInstallResultsBound !== true ||
  release.scope?.staticValidationResultsBound !== true ||
  release.scope?.unitTestResultsBound !== true ||
  release.scope?.dependencyAuditResultsBound !== true ||
  release.scope?.sbomResultsBound !== true ||
  release.scope?.adversarialReviewResultsBound !== true ||
  release.scope?.awsMutationPerformed !== false
) {
  fail(
    "BOOTSTRAP_CANDIDATE_RELEASE_EVIDENCE_DENIED",
    "Release evidence did not bind all local gates or incorrectly claimed AWS mutation.",
  );
}

const configuration = [
  onboardingPath,
  safeInput("Pulumi.management.yaml", "management stack configuration"),
]
  .map((file) => ({ path: relative(file), sha256: hashFile(file) }))
  .sort((left, right) => left.path.localeCompare(right.path));
const generatedAt = new Date();
const tools = currentToolVersions();
assertPinnedTools(tools);
const runtime = collectBootstrapRuntime(root);
const runtimeProvenance = bootstrapRuntimeProvenanceBinding(runtime);
const sealInventory = writeBootstrapSealInventory(root);
const nativeLauncherPath = safeInput(
  "artifacts/deus-aws-bootstrap",
  "reproducible native credential launcher",
);
const candidateSubject = {
  apiVersion: "security.deus.dev/bootstrap-candidate/v1",
  generatedAt: generatedAt.toISOString(),
  signingKeyId: qualificationTrust.keyId,
  source: qualifiedSource,
  configuration,
  pulumiBackend: {
    kind: onboarding.pulumiBackend,
    url: onboarding.pulumiBackendUrl,
    organization: onboarding.pulumiOrg,
  },
  build: {
    path: "dist-management-seed",
    treeDigest: directoryDigest("dist-management-seed"),
  },
  localGateEvidence: {
    path: relative(gateOutput),
    sha256: hashFile(gateOutput),
    evidenceDigest: gateReport.reportDigest,
  },
  nativeLauncher: {
    path: relative(nativeLauncherPath),
    sha256: hashFile(nativeLauncherPath),
  },
  releaseEvidence: {
    path: relative(releaseOutput),
    sha256: hashFile(releaseOutput),
    evidenceDigest: release.evidenceDigest,
  },
  tools,
  runtime,
  runtimeProvenance,
  sealInventory,
};
const candidateDigest = sha256(canonicalJson(candidateSubject));
const qualificationRequest = {
  ...candidateSubject,
  candidateDigest,
};
validate(
  qualificationRequest,
  "schemas/bootstrap-qualification-request-v1.schema.json",
  "bootstrap qualification request",
);
const finalSource = sourceState();
if (
  finalSource.dirty ||
  finalSource.revision !== qualifiedSource.revision ||
  finalSource.treeDigest !== qualifiedSource.treeDigest ||
  directoryDigest("dist-management-seed") !==
    qualificationRequest.build.treeDigest ||
  configuration.some(
    (entry) =>
      hashFile(safeInput(entry.path, "qualified configuration")) !==
      entry.sha256,
  ) ||
  hashFile(gateOutput) !== qualificationRequest.localGateEvidence.sha256 ||
  hashFile(nativeLauncherPath) !== qualificationRequest.nativeLauncher.sha256 ||
  hashFile(releaseOutput) !== qualificationRequest.releaseEvidence.sha256 ||
  hashFile(runtimeProvenance.path) !== runtimeProvenance.sha256
) {
  fail(
    "BOOTSTRAP_CANDIDATE_FINAL_STATE_DENIED",
    "Source, build, configuration, or evidence changed before candidate publication.",
  );
}
assertBootstrapSealInventory(root, qualificationRequest.sealInventory);
assertBootstrapRuntime(root, runtime);
writeAtomic(output, `${JSON.stringify(qualificationRequest, null, 2)}\n`);
writeAtomic(payloadOutput, signaturePayload(candidateDigest));
writeSigningReviewBundle(qualificationRequest);
process.stdout.write(
  `Credential-free qualification request ${relative(output)} (${candidateDigest}) is ready. Transfer only the confidential ${relative(reviewBundleOutput)} to the independent signer; return only the detached signature.\n`,
);

function writeSigningReviewBundle(request) {
  const inputs = [
    ["qualification-request", output, relative(output)],
    ["qualification-payload", payloadOutput, relative(payloadOutput)],
    ["onboarding-configuration", onboardingPath, relative(onboardingPath)],
    [
      "pulumi-configuration",
      safeInput("Pulumi.management.yaml", "management stack configuration"),
      "Pulumi.management.yaml",
    ],
    ["runtime-provenance", runtimeProvenance.path, runtimeProvenance.path],
    [
      "seal-inventory",
      safeInput(sealInventory.path, "exact execution seal inventory"),
      sealInventory.path,
    ],
    ["local-gate-evidence", gateOutput, relative(gateOutput)],
    ["release-evidence", releaseOutput, relative(releaseOutput)],
    ["sbom", sbomOutput, relative(sbomOutput)],
    [
      "contract-validation",
      safeInput(
        "artifacts/contract-schema-validation.json",
        "contract validation evidence",
      ),
      "artifacts/contract-schema-validation.json",
    ],
    [
      "access-bundle",
      safeInput(
        "artifacts/management-seed-access-bundle.json",
        "management access bundle",
      ),
      "artifacts/management-seed-access-bundle.json",
    ],
    [
      "access-template",
      safeInput(
        "artifacts/management-seed-access.template.json",
        "management access template",
      ),
      "artifacts/management-seed-access.template.json",
    ],
    ["native-launcher", nativeLauncherPath, relative(nativeLauncherPath)],
  ];
  const files = inputs
    .map(([role, file, sourcePath]) => {
      const content = readFileSync(file);
      return {
        role,
        sourcePath,
        sha256: sha256(content),
        encoding: "base64",
        content: content.toString("base64"),
      };
    })
    .sort((left, right) => left.role.localeCompare(right.role));
  const subject = {
    apiVersion: "security.deus.dev/bootstrap-signing-review-bundle/v1",
    candidateDigest: request.candidateDigest,
    files,
  };
  const bundle = { ...subject, bundleDigest: sha256(canonicalJson(subject)) };
  validate(
    bundle,
    "schemas/bootstrap-signing-review-bundle-v1.schema.json",
    "bootstrap signing review bundle",
  );
  writeAtomic(reviewBundleOutput, `${JSON.stringify(bundle, null, 2)}\n`);
}

function sourceState() {
  const { entries: _entries, ...source } = managementSeedSourceState(root);
  return source;
}

function directoryDigest(directory) {
  const base = safeDirectory(directory);
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        fail(
          "BOOTSTRAP_CANDIDATE_SYMLINK_DENIED",
          `${candidate} is a symlink.`,
        );
      }
      if (stat.isDirectory()) walk(candidate);
      else if (stat.isFile()) {
        entries.push({
          path: path.relative(base, candidate),
          sha256: hashFile(candidate),
        });
      }
    }
  };
  walk(base);
  if (entries.length === 0) {
    fail("BOOTSTRAP_CANDIDATE_BUILD_MISSING", `${directory} is empty.`);
  }
  return sha256(canonicalJson(entries));
}

function assertCredentialFreeEnvironment() {
  const forbidden = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "PULUMI_ACCESS_TOKEN",
    "PULUMI_CONFIG_PASSPHRASE",
    "PULUMI_CONFIG_PASSPHRASE_FILE",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "SSH_AUTH_SOCK",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "ARM_CLIENT_ID",
    "ARM_CLIENT_SECRET",
    "ARM_TENANT_ID",
    "ARM_SUBSCRIPTION_ID",
  ].filter((name) => process.env[name]);
  if (forbidden.length > 0) {
    fail(
      "BOOTSTRAP_CANDIDATE_CREDENTIALS_DENIED",
      `Credential-free qualification rejects environment variables: ${forbidden.join(", ")}.`,
    );
  }
}

function loadQualificationTrust() {
  const trustPath = safeInput(
    "security/bootstrap-qualification-trust.json",
    "bootstrap qualification trust root",
  );
  const trust = parseJson(trustPath);
  validate(
    trust,
    "schemas/bootstrap-qualification-trust-v1.schema.json",
    "bootstrap qualification trust root",
  );
  if (trust.configured !== true) {
    fail(
      "BOOTSTRAP_CANDIDATE_TRUST_NOT_CONFIGURED",
      "Provision the Ed25519 key on an independent signer and commit only its public trust root before qualification.",
    );
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
    fail(
      "BOOTSTRAP_CANDIDATE_TRUST_DENIED",
      "The pinned qualification public key is not valid Ed25519 SPKI.",
    );
  }
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    trust.keyId !== sha256(publicDer)
  ) {
    fail(
      "BOOTSTRAP_CANDIDATE_TRUST_DENIED",
      "The pinned qualification key ID does not match its Ed25519 public key.",
    );
  }
  return { ...trust, publicKey };
}

function signaturePayload(candidateDigest) {
  return `security.deus.dev/bootstrap-candidate/v1:${candidateDigest}`;
}

function assertPinnedTools(tools) {
  const pins = Object.fromEntries(
    readFileSync(safeInput(".tool-versions", "toolchain pins"), "utf8")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.split(/\s+/, 2)),
  );
  const expected = {
    node: `v${pins.nodejs ?? ""}`,
    npm: pins.npm,
    pulumi: pins.pulumi,
    ...hostToolPins(),
  };
  for (const [tool, version] of Object.entries(expected)) {
    const observed = normalizedToolVersion(tool, tools[tool]);
    const wanted = version?.replace(/^v/, "");
    if (!wanted || observed !== wanted) {
      fail(
        "BOOTSTRAP_CANDIDATE_TOOL_VERSION_DENIED",
        `${tool} must match .tool-versions exactly (${wanted ?? "missing"}); observed ${observed}.`,
      );
    }
  }
}

function hostToolPins() {
  const value = parseJson(
    safeInput("security/bootstrap-host-toolchain.json", "host toolchain pins"),
  );
  try {
    assertHostToolchainPins(value);
  } catch {
    fail(
      "BOOTSTRAP_CANDIDATE_TOOL_VERSION_DENIED",
      "security/bootstrap-host-toolchain.json is malformed.",
    );
  }
  return { aws: value.awsCli, git: value.git };
}

function normalizedToolVersion(tool, value) {
  if (tool === "aws") return value.match(/^aws-cli\/([^\s]+)/)?.[1] ?? value;
  if (tool === "git") return value.match(/^git version ([^\s]+)/)?.[1] ?? value;
  return tool === "pulumi" ? value.replace(/^v/, "") : value.replace(/^v/, "");
}

function commandVersion(command, commandArgs) {
  const result = spawnSync(command, commandArgs, {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  if (result.status !== 0) {
    fail(
      "BOOTSTRAP_CANDIDATE_TOOL_MISSING",
      `${command} is required before qualification.`,
    );
  }
  return `${result.stdout ?? ""} ${result.stderr ?? ""}`
    .trim()
    .split(/\r?\n/)[0];
}

function verifyOfflineBootstrapReadiness(config) {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    { cwd: root, encoding: "utf8", env: process.env },
  );
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    fail(
      "BOOTSTRAP_CANDIDATE_DOCTOR_DENIED",
      "Offline bootstrap doctor did not return valid JSON.",
    );
  }
  if (
    result.status !== 0 ||
    report.offline !== true ||
    report.cloudMutation !== false ||
    report.summary?.failures !== 0
  ) {
    fail(
      "BOOTSTRAP_CANDIDATE_DOCTOR_DENIED",
      "Offline bootstrap readiness checks must pass before qualification.",
    );
  }
}

function runRequired(command, commandArgs) {
  const result = spawnSync(command, commandArgs, {
    cwd: root,
    stdio: "inherit",
    env: process.env,
  });
  if (result.status !== 0) {
    fail(
      "BOOTSTRAP_CANDIDATE_EVIDENCE_FAILED",
      `${command} ${commandArgs.join(" ")} failed.`,
    );
  }
}

function validate(value, schemaName, label) {
  const schema = parseJson(safeInput(schemaName, "candidate schema"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  if (schemaName === "schemas/bootstrap-qualification-request-v1.schema.json") {
    ajv.addSchema(
      parseJson(
        safeInput(
          "schemas/bootstrap-candidate-v1.schema.json",
          "candidate schema",
        ),
      ),
    );
  }
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    fail(
      "BOOTSTRAP_CANDIDATE_SCHEMA_DENIED",
      `${label} is invalid: ${JSON.stringify(validator.errors)}.`,
    );
  }
}

function parseArgs(values) {
  const allowed = new Set([
    "output",
    "gate-output",
    "release-output",
    "payload-output",
    "review-bundle-output",
    "config",
  ]);
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token?.startsWith("--") || !allowed.has(token.slice(2))) {
      fail(
        "BOOTSTRAP_CANDIDATE_ARGUMENT_DENIED",
        `Unknown argument '${token}'.`,
      );
    }
    const key = token.slice(2);
    if (Object.hasOwn(parsed, key)) {
      fail(
        "BOOTSTRAP_CANDIDATE_ARGUMENT_DENIED",
        `Duplicate argument '${token}'.`,
      );
    }
    const value = values[++index];
    if (!value || value.startsWith("--")) {
      fail("BOOTSTRAP_CANDIDATE_ARGUMENT_DENIED", `${token} requires a value.`);
    }
    parsed[key] = value;
  }
  return parsed;
}

function safeInput(value, label) {
  const candidate = path.resolve(root, value);
  assertInside(candidate);
  if (!existsSync(candidate)) {
    fail("BOOTSTRAP_CANDIDATE_INPUT_MISSING", `${label} is missing: ${value}.`);
  }
  const stat = lstatSync(candidate);
  const real = realpathSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink() || real !== candidate) {
    fail(
      "BOOTSTRAP_CANDIDATE_INPUT_UNSAFE",
      `${label} must be a regular file.`,
    );
  }
  assertInside(real);
  return real;
}

function safeDirectory(value) {
  const candidate = path.resolve(root, value);
  assertInside(candidate);
  const stat = statSync(candidate);
  const real = realpathSync(candidate);
  if (
    !stat.isDirectory() ||
    lstatSync(candidate).isSymbolicLink() ||
    real !== candidate
  ) {
    fail(
      "BOOTSTRAP_CANDIDATE_INPUT_UNSAFE",
      `${value} must be a real directory.`,
    );
  }
  assertInside(real);
  return real;
}

function safeOutput(value) {
  const candidate = path.resolve(root, value);
  assertInside(candidate);
  const parent = path.dirname(candidate);
  if (!existsSync(parent)) {
    fail(
      "BOOTSTRAP_CANDIDATE_OUTPUT_UNSAFE",
      `Output parent must already exist: ${parent}.`,
    );
  }
  if (!lstatSync(parent).isDirectory() || lstatSync(parent).isSymbolicLink()) {
    fail(
      "BOOTSTRAP_CANDIDATE_OUTPUT_UNSAFE",
      "Output parent must be a real directory.",
    );
  }
  if (realpathSync(parent) !== parent) {
    fail(
      "BOOTSTRAP_CANDIDATE_OUTPUT_UNSAFE",
      "Output parent must not contain an ancestor symlink.",
    );
  }
  if (existsSync(candidate)) {
    const stat = lstatSync(candidate);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      fail(
        "BOOTSTRAP_CANDIDATE_OUTPUT_UNSAFE",
        "Output must be a regular file.",
      );
    }
  }
  return candidate;
}

function ensureSafeDirectory(directory) {
  assertInside(directory);
  const relativePath = path.relative(root, directory);
  let current = root;
  for (const segment of relativePath.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) {
      mkdirSync(current, { mode: 0o700 });
    }
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(
        "BOOTSTRAP_CANDIDATE_OUTPUT_UNSAFE",
        "Output directory must not contain symlinks or non-directories.",
      );
    }
  }
}

function writeAtomic(target, contents) {
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function parseJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail("BOOTSTRAP_CANDIDATE_JSON_DENIED", `${file}: ${error.message}`);
  }
}

function relative(file) {
  return path.relative(root, file).split(path.sep).join("/");
}

function assertInside(candidate) {
  const relativePath = path.relative(root, candidate);
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    fail(
      "BOOTSTRAP_CANDIDATE_PATH_DENIED",
      `${candidate} escapes the repository.`,
    );
  }
}

function hashFile(file) {
  return sha256(readFileSync(file));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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

function fail(code, message) {
  process.stderr.write(`[${code}] ${message}\n`);
  process.exit(1);
}
