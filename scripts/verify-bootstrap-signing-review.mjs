#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  fstatSync,
  lstatSync,
  readFileSync,
  readSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

let Ajv2020;
let addFormats;
let parseYaml;
let createManagementSeedAccessBundle;
let renderManagementSeedAccessTemplate;
let assertManagementSeedConfigurationDocument;
let managementSeedSourceState;
let assertBootstrapRuntime;
let assertEmbeddedBootstrapSealInventory;
let bootstrapRuntimeProvenanceBinding;
let collectBootstrapRuntime;
let verifyEmbeddedContractValidation;
let verifyEmbeddedLocalGateEvidence;
let verifyEmbeddedSbom;

const expectedRoles = [
  "access-bundle",
  "access-template",
  "contract-validation",
  "local-gate-evidence",
  "native-launcher",
  "onboarding-configuration",
  "pulumi-configuration",
  "qualification-payload",
  "qualification-request",
  "release-evidence",
  "runtime-provenance",
  "seal-inventory",
  "sbom",
].sort();

try {
  assertCredentialFree();
  const bundleFD = parseArgs(process.argv.slice(2));
  const root = realpathSync(process.cwd());
  assertFixedSignerRuntime(root);
  assertAuthenticatedSigningStage0();
  await loadReviewedImplementation();
  const bundle = parseJson(readBoundedFD(bundleFD), "signing review bundle");
  validate(
    root,
    bundle,
    "schemas/bootstrap-signing-review-bundle-v1.schema.json",
  );
  const { bundleDigest, ...bundleSubject } = bundle;
  if (bundleDigest !== sha256(canonicalJson(bundleSubject))) {
    throw new Error("signing review bundle digest does not match");
  }
  const roles = bundle.files.map((entry) => entry.role).sort();
  if (canonicalJson(roles) !== canonicalJson(expectedRoles)) {
    throw new Error("signing review bundle file-role inventory is not exact");
  }
  const files = new Map();
  for (const entry of bundle.files) {
    if (files.has(entry.role)) throw new Error(`duplicate role ${entry.role}`);
    const bytes = Buffer.from(entry.content, "base64");
    if (
      bytes.toString("base64") !== entry.content ||
      sha256(bytes) !== entry.sha256
    ) {
      throw new Error(`embedded ${entry.role} bytes do not match their digest`);
    }
    files.set(entry.role, { ...entry, bytes });
  }

  const request = parseJson(
    files.get("qualification-request").bytes,
    "qualification request",
  );
  validate(
    root,
    request,
    "schemas/bootstrap-qualification-request-v1.schema.json",
    ["schemas/bootstrap-candidate-v1.schema.json"],
  );
  const { candidateDigest, ...candidateSubject } = request;
  if (
    candidateDigest !== bundle.candidateDigest ||
    candidateDigest !== sha256(canonicalJson(candidateSubject))
  ) {
    throw new Error("qualification request digest does not match bundle");
  }
  const { entries: _entries, ...source } = managementSeedSourceState(root);
  if (
    source.dirty ||
    source.revision !== request.source.revision ||
    source.treeDigest !== request.source.treeDigest
  ) {
    throw new Error(
      "signer checkout does not reproduce the requested source revision and tree digest",
    );
  }
  if (
    buildDirectoryDigest(path.join(root, request.build.path)) !==
    request.build.treeDigest
  ) {
    throw new Error(
      "signer build does not reproduce the requested program digest",
    );
  }
  const expectedPayload = Buffer.from(
    `security.deus.dev/bootstrap-candidate/v1:${candidateDigest}`,
    "utf8",
  );
  if (!files.get("qualification-payload").bytes.equals(expectedPayload)) {
    throw new Error("qualification payload does not match candidate digest");
  }

  const onboardingEntry = files.get("onboarding-configuration");
  const pulumiEntry = files.get("pulumi-configuration");
  const onboarding = parseJson(
    onboardingEntry.bytes,
    "onboarding configuration",
  );
  const pulumi = parseYaml(pulumiEntry.bytes.toString("utf8"));
  const requestedConfiguration = new Map(
    request.configuration.map((entry) => [entry.path, entry.sha256]),
  );
  if (
    requestedConfiguration.size !== 2 ||
    requestedConfiguration.get(onboardingEntry.sourcePath) !==
      onboardingEntry.sha256 ||
    requestedConfiguration.get("Pulumi.management.yaml") !==
      pulumiEntry.sha256 ||
    pulumiEntry.sourcePath !== "Pulumi.management.yaml"
  ) {
    throw new Error(
      "embedded configuration does not match qualification request",
    );
  }
  if (
    request.pulumiBackend.kind !== onboarding.pulumiBackend ||
    request.pulumiBackend.url !== onboarding.pulumiBackendUrl ||
    request.pulumiBackend.organization !== onboarding.pulumiOrg
  ) {
    throw new Error(
      "embedded onboarding backend does not match qualification request",
    );
  }
  assertManagementSeedConfigurationDocument(pulumi, onboarding);

  bindFile(request.localGateEvidence, files.get("local-gate-evidence"));
  bindFile(request.releaseEvidence, files.get("release-evidence"));
  bindFile(request.nativeLauncher, files.get("native-launcher"));
  bindFile(request.runtimeProvenance, files.get("runtime-provenance"));
  bindFile(request.sealInventory, files.get("seal-inventory"));
  verifyRuntimeProvenance(
    parseJson(files.get("runtime-provenance").bytes, "runtime provenance"),
    request,
  );

  const reproducedLauncher = path.join(root, request.nativeLauncher.path);
  if (
    !existsSync(reproducedLauncher) ||
    hashFile(reproducedLauncher) !== request.nativeLauncher.sha256
  ) {
    throw new Error(
      "signer must reproducibly build the native launcher before approval",
    );
  }
  const reproducedRuntime = collectBootstrapRuntime(root, process.env);
  assertBootstrapRuntime(root, reproducedRuntime, process.env);
  if (canonicalJson(reproducedRuntime) !== canonicalJson(request.runtime)) {
    throw new Error(
      "signer runtime does not reproduce the requested executable, directory, and plugin closure",
    );
  }
  const sealedGeneratedFiles = new Map(
    [
      ["Pulumi.management.yaml", "pulumi-configuration"],
      ["artifacts/contract-schema-validation.json", "contract-validation"],
      ["artifacts/deus-aws-bootstrap", "native-launcher"],
      ["artifacts/local-gate-evidence.json", "local-gate-evidence"],
      ["artifacts/management-seed-access-bundle.json", "access-bundle"],
      ["artifacts/management-seed-access.template.json", "access-template"],
      ["artifacts/secure-saas-infra.spdx.json", "sbom"],
      ["artifacts/security-contract-evidence.json", "release-evidence"],
      ["onboarding.local.json", "onboarding-configuration"],
    ].map(([sourcePath, role]) => {
      const entry = files.get(role);
      if (entry.sourcePath !== sourcePath) {
        throw new Error(`embedded ${role} source path is not exact`);
      }
      return [sourcePath, entry.bytes];
    }),
  );
  assertEmbeddedBootstrapSealInventory(
    root,
    request.sealInventory,
    files.get("seal-inventory").bytes,
    sealedGeneratedFiles,
  );
  const reproducedExecutables = new Map(
    reproducedRuntime.executables.map((entry) => [entry.name, entry.version]),
  );
  const reproducedTools = {
    node: process.version,
    npm: commandVersion("npm", ["--version"]),
    pulumi: reproducedExecutables.get("pulumi"),
    aws: reproducedExecutables.get("aws"),
    git: commandVersion("git", ["--version"]),
  };
  if (canonicalJson(reproducedTools) !== canonicalJson(request.tools)) {
    throw new Error("signer qualification tools do not reproduce the request");
  }
  if (
    canonicalJson(bootstrapRuntimeProvenanceBinding(reproducedRuntime)) !==
    canonicalJson(request.runtimeProvenance)
  ) {
    throw new Error(
      "signer root-owned runtime provenance does not reproduce the qualification host",
    );
  }

  const localGates = parseJson(
    files.get("local-gate-evidence").bytes,
    "local gate evidence",
  );
  validate(root, localGates, "schemas/local-gate-evidence-v1.schema.json");
  const { reportDigest, ...localGateSubject } = localGates;
  if (
    reportDigest !== sha256(canonicalJson(localGateSubject)) ||
    localGates.source.revision !== request.source.revision ||
    localGates.source.treeDigest !== request.source.treeDigest
  ) {
    throw new Error("local gate evidence does not bind the reviewed source");
  }
  verifyEmbeddedLocalGateEvidence(root, localGates, source);

  const release = parseJson(
    files.get("release-evidence").bytes,
    "release evidence",
  );
  validate(
    root,
    release,
    "schemas/management-seed-release-evidence-v1.schema.json",
  );
  bindFile(
    release.validation.contractSchemas,
    files.get("contract-validation"),
  );
  bindFile(release.validation.sbom, files.get("sbom"));
  bindFile(release.validation.localGates, files.get("local-gate-evidence"));
  const { evidenceDigest, ...releaseSubject } = release;
  if (evidenceDigest !== sha256(canonicalJson(releaseSubject))) {
    throw new Error("release evidence digest does not match");
  }
  const contracts = parseJson(
    files.get("contract-validation").bytes,
    "contract validation evidence",
  );
  verifyEmbeddedContractValidation(root, contracts);
  const sbom = parseJson(files.get("sbom").bytes, "SBOM");
  verifyEmbeddedSbom(root, sbom);

  const expectedAccess = createManagementSeedAccessBundle(root, onboarding);
  const actualAccess = parseJson(
    files.get("access-bundle").bytes,
    "management access bundle",
  );
  if (canonicalJson(actualAccess) !== canonicalJson(expectedAccess)) {
    throw new Error(
      "management access bundle does not match reviewed configuration",
    );
  }
  if (
    files.get("access-template").bytes.toString("utf8") !==
    renderManagementSeedAccessTemplate(expectedAccess.cloudFormationTemplate)
  ) {
    throw new Error(
      "management access template does not match reviewed configuration",
    );
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        apiVersion: "security.deus.dev/bootstrap-signing-review-result/v1",
        verified: true,
        candidateDigest,
        sourceRevision: request.source.revision,
        managementAccountId: onboarding.managementAccountId,
        pulumiBackend: request.pulumiBackend,
        fileDigests: Object.fromEntries(
          [...files].map(([role, entry]) => [role, entry.sha256]),
        ),
      },
      null,
      2,
    )}\n`,
  );
} catch (error) {
  process.stderr.write(`BOOTSTRAP_SIGNING_REVIEW_DENIED: ${error.message}\n`);
  process.exitCode = 1;
}

function bindFile(binding, entry) {
  if (
    !binding ||
    !entry ||
    binding.sha256 !== entry.sha256 ||
    binding.path !== entry.sourcePath
  ) {
    throw new Error(
      `candidate/evidence binding does not match ${entry?.role ?? "file"}`,
    );
  }
}

function verifyRuntimeProvenance(provenance, request) {
  const executable = new Map(
    request.runtime.executables.map((entry) => [entry.name, entry]),
  );
  const directory = new Map(
    request.runtime.directories.map((entry) => [entry.name, entry]),
  );
  if (
    provenance.apiVersion !==
      "security.deus.dev/bootstrap-runtime-provenance/v1" ||
    provenance.platform !== "linux" ||
    !["go", "node", "pulumi"].every(
      (name) =>
        provenance.artifacts?.[name]?.verification ===
        "authenticated-host-kit-pinned-sha256",
    ) ||
    provenance.artifacts?.awsCli?.verification !== "aws-cli-team-pgp" ||
    provenance.artifacts?.awsCli?.signingKeyFingerprint !==
      "FB5DB77FD5C118B80511ADA8A6310ACC4672475C" ||
    provenance.installed?.nodeSha256 !== executable.get("node")?.sha256 ||
    provenance.installed?.pulumiTreeDigest !==
      directory.get("pulumi-install")?.treeDigest ||
    provenance.installed?.awsCliTreeDigest !==
      directory.get("aws-cli-install")?.treeDigest
  ) {
    throw new Error("runtime provenance does not bind the requested runtime");
  }
  verifySystemRuntimeClosure(provenance.systemRuntime);
}

function verifySystemRuntimeClosure(value) {
  const architecture = process.arch === "x64" ? "amd64" : process.arch;
  if (
    value?.apiVersion !== "security.deus.dev/system-runtime-closure/v1" ||
    value.architecture !== architecture ||
    !Array.isArray(value.loaders) ||
    value.loaders.length === 0 ||
    value.loaders.length > 8 ||
    !Array.isArray(value.libraries) ||
    value.libraries.length > 512
  ) {
    throw new Error("signer system runtime closure is malformed");
  }
  const seen = new Set();
  for (const entries of [value.loaders, value.libraries]) {
    const paths = entries.map((entry) => entry.path);
    if (canonicalJson(paths) !== canonicalJson([...paths].sort())) {
      throw new Error("signer system runtime closure is not sorted");
    }
    for (const entry of entries) {
      if (
        typeof entry.path !== "string" ||
        (!entry.path.startsWith("/usr/lib/") &&
          !entry.path.startsWith("/lib/")) ||
        seen.has(entry.path) ||
        !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "") ||
        realpathSync(entry.path) !== entry.path ||
        hashFile(entry.path) !== entry.sha256
      ) {
        throw new Error("signer system runtime file changed");
      }
      seen.add(entry.path);
    }
  }
}

function buildDirectoryDigest(value) {
  const base = realpathSync(value);
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        throw new Error("reproduced build contains a symlink");
      }
      if (stat.isDirectory()) walk(candidate);
      else if (stat.isFile()) {
        entries.push({
          path: path.relative(base, candidate),
          sha256: hashFile(candidate),
        });
      } else {
        throw new Error("reproduced build contains an unsafe entry");
      }
    }
  };
  walk(base);
  if (entries.length === 0) throw new Error("reproduced build is empty");
  return sha256(canonicalJson(entries));
}

function validate(root, value, schemaName, dependencies = []) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const dependency of dependencies) {
    ajv.addSchema(
      parseJson(readFileSync(path.join(root, dependency)), dependency),
    );
  }
  const schema = parseJson(
    readFileSync(path.join(root, schemaName)),
    schemaName,
  );
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(
      `${schemaName} rejected the document: ${JSON.stringify(validator.errors)}`,
    );
  }
}

function readSafeFile(value) {
  const candidate = path.resolve(value);
  if (!existsSync(candidate)) throw new Error("review bundle is missing");
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    throw new Error("review bundle must be a direct regular file");
  }
  return readFileSync(candidate);
}

function parseJson(value, label) {
  try {
    const parsed = JSON.parse(value.toString("utf8"));
    if (
      parsed === null ||
      typeof parsed !== "object" ||
      Array.isArray(parsed)
    ) {
      throw new Error("must be an object");
    }
    return parsed;
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function parseArgs(values) {
  if (values.length !== 2 || values[0] !== "--bundle-fd" || values[1] !== "3") {
    throw new Error("signing review requires the sealed stage-zero bundle");
  }
  return 3;
}

function readBoundedFD(fd) {
  const stat = fstatSync(fd);
  if (stat.size <= 0 || stat.size > 100 * 1024 * 1024) {
    throw new Error("sealed signing review bundle is empty or excessive");
  }
  const contents = Buffer.alloc(stat.size);
  let offset = 0;
  while (offset < contents.length) {
    const count = readSync(
      fd,
      contents,
      offset,
      contents.length - offset,
      offset,
    );
    if (count <= 0) {
      throw new Error("sealed signing review bundle is truncated");
    }
    offset += count;
  }
  return contents;
}

function assertCredentialFree() {
  const forbidden = Object.keys(process.env)
    .filter((name) => process.env[name])
    .filter(
      (name) =>
        (/^PULUMI_/.test(name) && name !== "PULUMI_HOME") ||
        /^(?:AWS_|GITHUB_TOKEN$|GH_TOKEN$|NPM_TOKEN$|NODE_AUTH_TOKEN$|SSH_AUTH_SOCK$|NODE_OPTIONS$|NODE_PATH$|BUN_OPTIONS$|DENO_DIR$|LD_|DYLD_|(?:HTTP|HTTPS|ALL|NO)_PROXY$|(?:AWS|REQUESTS|CURL)_CA_BUNDLE$|SSL_CERT_(?:FILE|DIR)$|NODE_EXTRA_CA_CERTS$)/.test(
          name,
        ),
    );
  if (forbidden.length > 0) {
    throw new Error(
      `signing review refuses credentials: ${forbidden.sort().join(", ")}`,
    );
  }
}

function assertFixedSignerRuntime(root) {
  const installRoot = "/usr/local/lib/deus-bootstrap";
  const expectedRoot = `${installRoot}/execution`;
  if (
    root !== expectedRoot ||
    process.execPath !== `${installRoot}/bin/node` ||
    process.env.PULUMI_HOME !==
      `${expectedRoot}/artifacts/bootstrap-pulumi-home` ||
    process.env.PATH !==
      `${installRoot}/bin:${installRoot}/qualification-bin:${installRoot}/toolchains/go/bin:/usr/bin:/bin`
  ) {
    throw new Error(
      "signing review requires the fixed authenticated Linux runtime and execution root",
    );
  }
}

function assertAuthenticatedSigningStage0() {
  const installRoot = "/usr/local/lib/deus-bootstrap";
  const stageZeroPID = process.ppid;
  const launcherPID = parentPID(stageZeroPID);
  const manifestPath =
    "/usr/local/lib/deus-bootstrap/management-seed-source-manifest.json";
  const manifest = parseJson(
    readFileSync(manifestPath),
    "authenticated host source manifest",
  );
  const { manifestDigest, ...subject } = manifest;
  if (
    manifest.apiVersion !==
      "security.deus.dev/bootstrap-host-source-manifest/v1" ||
    !/^[a-f0-9]{64}$/.test(manifestDigest ?? "") ||
    manifestDigest !== sha256(canonicalJson(subject)) ||
    process.env.DEUS_SIGNING_STAGE0 !== manifestDigest ||
    realpathSync(`/proc/${stageZeroPID}/exe`) !== `${installRoot}/bin/node` ||
    realpathSync(`/proc/${launcherPID}/exe`) !==
      "/usr/local/bin/deus-aws-bootstrap"
  ) {
    throw new Error(
      "signing review did not enter through authenticated stage zero",
    );
  }
}

function parentPID(pid) {
  const status = readFileSync(`/proc/${pid}/status`, "utf8");
  const value = status.match(/^PPid:\s+([0-9]+)$/m)?.[1];
  if (!value || value === "0") {
    throw new Error("signing stage-zero process lineage is unavailable");
  }
  return Number(value);
}

async function loadReviewedImplementation() {
  const [
    ajvModule,
    formatsModule,
    yamlModule,
    accessModule,
    contractModule,
    scopeModule,
    runtimeModule,
    sealModule,
    evidenceModule,
  ] = await Promise.all([
    import("ajv/dist/2020.js"),
    import("ajv-formats"),
    import("yaml"),
    import("./management-seed-access.mjs"),
    import("./management-seed-contract.mjs"),
    import("./management-seed-scope.mjs"),
    import("./bootstrap-runtime-integrity.mjs"),
    import("./bootstrap-seal-inventory.mjs"),
    import("./verify-management-seed-release-evidence.mjs"),
  ]);
  Ajv2020 = ajvModule.default;
  addFormats = formatsModule.default;
  parseYaml = yamlModule.parse;
  createManagementSeedAccessBundle =
    accessModule.createManagementSeedAccessBundle;
  renderManagementSeedAccessTemplate =
    accessModule.renderManagementSeedAccessTemplate;
  assertManagementSeedConfigurationDocument =
    contractModule.assertManagementSeedConfigurationDocument;
  managementSeedSourceState = scopeModule.managementSeedSourceState;
  assertBootstrapRuntime = runtimeModule.assertBootstrapRuntime;
  bootstrapRuntimeProvenanceBinding =
    runtimeModule.bootstrapRuntimeProvenanceBinding;
  collectBootstrapRuntime = runtimeModule.collectBootstrapRuntime;
  assertEmbeddedBootstrapSealInventory =
    sealModule.assertEmbeddedBootstrapSealInventory;
  verifyEmbeddedContractValidation =
    evidenceModule.verifyEmbeddedContractValidation;
  verifyEmbeddedLocalGateEvidence =
    evidenceModule.verifyEmbeddedLocalGateEvidence;
  verifyEmbeddedSbom = evidenceModule.verifyEmbeddedSbom;
}

function commandVersion(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: process.env,
  });
  const output = `${result.stdout ?? ""} ${result.stderr ?? ""}`
    .trim()
    .split(/\r?\n/)[0];
  if (result.status !== 0 || !output) {
    throw new Error(`signer could not verify ${command}`);
  }
  return output;
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

function hashFile(value) {
  return sha256(readFileSync(value));
}
