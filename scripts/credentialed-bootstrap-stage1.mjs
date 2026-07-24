#!/usr/bin/env node

// Credential-bearing entrypoint stage 1. Keep this module builtins-only: no
// package or other repository module may execute until the signed candidate
// has bound every source, dependency, executable, plugin, and build byte.
import { spawnSync } from "node:child_process";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const SHA256 = /^[a-f0-9]{64}$/;
const CANDIDATE_MAX_AGE_MS = 24 * 60 * 60 * 1_000;
const INSTALL_ROOT = "/usr/local/lib/deus-bootstrap";
const EXECUTION_ROOT = `${INSTALL_ROOT}/execution`;
const INSTALLED_STAGE1 = `${INSTALL_ROOT}/credentialed-bootstrap-stage1.mjs`;
const INSTALLED_TRUST = `${INSTALL_ROOT}/bootstrap-qualification-trust.json`;
const RUNTIME_PROVENANCE = `${INSTALL_ROOT}/runtime-provenance.json`;
const FIXED_PULUMI_HOME = `${EXECUTION_ROOT}/artifacts/bootstrap-pulumi-home`;
const FIXED_PATH = `${INSTALL_ROOT}/bin`;
const CAPABILITY = Symbol.for("security.deus.dev/credentialed-stage1/v1");
const ENTRYPOINTS = new Set([
  "bootstrap",
  "access-provisioner",
  "organization-recovery",
]);
const FORBIDDEN_ENVIRONMENT = [
  /^NODE_OPTIONS$/i,
  /^NODE_PATH$/i,
  /^BUN_OPTIONS$/i,
  /^DENO_DIR$/i,
  /^PULUMI_NODEJS_/i,
  /^PULUMI_DEBUG_COMMANDS$/i,
  /^PULUMI_AUTOMATION_API_SKIP_VERSION_CHECK$/i,
  /^AWS_ENDPOINT_URL(?:_|$)/i,
  /^AWS_EC2_METADATA_SERVICE_ENDPOINT$/i,
  /^AWS_PROFILE$/i,
  /^AWS_DEFAULT_PROFILE$/i,
  /^AWS_SDK_LOAD_CONFIG$/i,
  /^AWS_WEB_IDENTITY_TOKEN_FILE$/i,
  /^AWS_ROLE_ARN$/i,
  /^AWS_CONTAINER_CREDENTIALS_RELATIVE_URI$/i,
  /^LOCALSTACK_/i,
  /^(?:HTTP|HTTPS|ALL|NO)_PROXY$/i,
  /^(?:AWS|REQUESTS|CURL)_CA_BUNDLE$/i,
  /^SSL_CERT_(?:FILE|DIR)$/i,
  /^NODE_EXTRA_CA_CERTS$/i,
  /^LD_(?:AUDIT|LIBRARY_PATH|PRELOAD)$/i,
  /^DYLD_/i,
];

try {
  const [entrypoint, ...entryArgs] = process.argv.slice(2);
  if (!ENTRYPOINTS.has(entrypoint)) {
    throw new Error(
      "stage 1 requires bootstrap, access-provisioner, or organization-recovery",
    );
  }
  assertCredentialEnvironment();
  if (
    process.env.DEUS_NATIVE_CREDENTIAL_LAUNCHER !== "v1" ||
    process.env.DEUS_EXECUTION_CONFINEMENT !== "systemd-noexec-landlock-v1" ||
    process.env.DEUS_QUALIFIED_EXECUTION_ROOT !== EXECUTION_ROOT ||
    process.env.PULUMI_HOME !== FIXED_PULUMI_HOME ||
    process.env.PULUMI_IGNORE_AMBIENT_PLUGINS !== "true" ||
    process.env.PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION !== "true" ||
    process.env.AWS_CONFIG_FILE !== "/dev/null" ||
    process.env.AWS_SHARED_CREDENTIALS_FILE !== "/dev/null" ||
    process.env.AWS_EC2_METADATA_DISABLED !== "true" ||
    process.env.PATH !== FIXED_PATH
  ) {
    throw new Error("stage 1 requires the fixed native credential launcher");
  }
  assertExecutionConfinement();
  if (option(entryArgs, "--root") !== undefined) {
    throw new Error("credentialed execution root cannot be overridden");
  }
  const runningStage1 = realpathSync(fileURLToPath(import.meta.url));
  if (runningStage1 !== INSTALLED_STAGE1) {
    throw new Error("stage 1 is not the installed trust-domain verifier");
  }
  assertRootOwnedChain(INSTALL_ROOT, "bootstrap trust domain");
  assertRootOwnedChain(runningStage1, "credentialed verifier");
  assertRootOwnedChain(INSTALLED_TRUST, "qualification trust root");
  const root = realpathSync(EXECUTION_ROOT);
  if (root !== EXECUTION_ROOT) {
    throw new Error("qualified execution root is not exact");
  }
  assertRootOwnedChain(root, "qualified execution root");
  const candidateValue = option(entryArgs, "--candidate");
  if (!candidateValue) {
    throw new Error("credentialed stage 1 requires --candidate");
  }
  const configurationValue =
    option(entryArgs, "--config") ?? "onboarding.local.json";
  const candidatePath = safeFile(root, candidateValue, "bootstrap candidate");
  const configurationPath = safeFile(
    root,
    configurationValue,
    "onboarding configuration",
  );
  const candidate = parseObject(candidatePath, "bootstrap candidate");

  assertCandidateEnvelope(candidate);
  const { candidateDigest, signature, ...subject } = candidate;
  if (candidateDigest !== sha256(canonicalJson(subject))) {
    throw new Error("bootstrap candidate digest does not match");
  }
  verifyCandidateSignature(candidateDigest, signature, candidate);
  assertCandidateFreshness(candidate);

  // The launcher starts only an OS-owned Node. Bind that already-running
  // runtime before reading or executing any other candidate-controlled path.
  assertRunningNode(candidate.runtime);
  const snapshotStage1 = safeFile(
    root,
    "scripts/credentialed-bootstrap-stage1.mjs",
    "qualified stage 1 mirror",
  );
  if (
    sha256(readFileSync(snapshotStage1)) !== sha256(readFileSync(runningStage1))
  ) {
    throw new Error("installed verifier does not match the qualified source");
  }
  assertSourceTree(root, candidate.source.treeDigest);
  assertConfiguration(root, configurationPath, candidate.configuration);
  assertBuildBinding(root, candidate.build.path, candidate.build.treeDigest);
  for (const evidence of [
    candidate.localGateEvidence,
    candidate.releaseEvidence,
  ]) {
    if (
      !isRecord(evidence) ||
      !SHA256.test(evidence.sha256 ?? "") ||
      sha256(readFileSync(safeFile(root, evidence.path, "evidence"))) !==
        evidence.sha256
    ) {
      throw new Error(`qualified evidence '${evidence?.path}' changed`);
    }
  }
  assertRuntimeBytes(root, candidate.runtime);
  assertRuntimeProvenance(candidate.runtimeProvenance, candidate.runtime);
  if (
    candidate.nativeLauncher?.path !== "artifacts/deus-aws-bootstrap" ||
    sha256(
      readFileSync(
        safeFile(root, candidate.nativeLauncher.path, "native launcher"),
      ),
    ) !== candidate.nativeLauncher.sha256 ||
    sha256(readFileSync("/usr/local/bin/deus-aws-bootstrap")) !==
      candidate.nativeLauncher.sha256
  ) {
    throw new Error("installed native launcher is not candidate-bound");
  }

  process.env.PATH = verifiedPath(candidate.runtime);
  Object.defineProperty(globalThis, CAPABILITY, {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      apiVersion: "security.deus.dev/credentialed-stage1/v1",
      candidateDigest,
      entrypoint:
        entrypoint === "organization-recovery" ? "bootstrap" : entrypoint,
      executionRoot: root,
      sourceRevision: candidate.source.revision,
      sourceTreeDigest: candidate.source.treeDigest,
      ...(entrypoint === "bootstrap"
        ? { pulumiBrokerToken: readPulumiBrokerCapability() }
        : {}),
    }),
  });
  const importedEntrypoint = path.join(
    root,
    "scripts",
    entrypoint === "bootstrap" || entrypoint === "organization-recovery"
      ? "bootstrap.mjs"
      : "provision-management-seed-access.mjs",
  );
  process.argv = [
    process.execPath,
    importedEntrypoint,
    ...(entrypoint === "organization-recovery"
      ? ["--recover-organization-state"]
      : []),
    ...entryArgs,
  ];
  // Keep both execution-root imports literal so the qualification scope can
  // prove their exact source closure before this verifier is installed.
  if (entrypoint === "bootstrap" || entrypoint === "organization-recovery") {
    await import("file:///usr/local/lib/deus-bootstrap/execution/scripts/bootstrap.mjs");
  } else {
    await import("file:///usr/local/lib/deus-bootstrap/execution/scripts/provision-management-seed-access.mjs");
  }
} catch (error) {
  process.stderr.write(`credentialed-bootstrap-stage1: ${error.message}\n`);
  process.exitCode = 1;
}

function assertExecutionConfinement() {
  // The marker records launcher intent; this kernel-enforced denial proves the
  // already-running verifier actually inherited the execute allowlist. Never
  // forward the credential-bearing environment to the deliberately denied
  // diagnostic child.
  const denial = spawnSync("/bin/sh", ["-c", "exit 0"], {
    env: {},
    stdio: "ignore",
  });
  if (denial.error?.code !== "EACCES" || denial.status !== null) {
    throw new Error("stage 1 is not protected by executable confinement");
  }
}

function assertCredentialEnvironment() {
  const forbidden = Object.keys(process.env)
    .filter((name) => process.env[name])
    .filter((name) =>
      FORBIDDEN_ENVIRONMENT.some((pattern) => pattern.test(name)),
    )
    .sort();
  if (forbidden.length > 0) {
    throw new Error(
      `forbidden environment indirection: ${forbidden.join(", ")}`,
    );
  }
  for (const name of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PULUMI_ACCESS_TOKEN",
    "PULUMI_CONFIG_PASSPHRASE",
    "PULUMI_CONFIG_PASSPHRASE_FILE",
  ]) {
    if (process.env[name]) {
      throw new Error(`raw credential material is forbidden in ${name}`);
    }
  }
  if (
    !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/v1\/credentials$/.test(
      process.env.AWS_CONTAINER_CREDENTIALS_FULL_URI ?? "",
    ) ||
    !/^Bearer [A-Za-z0-9_-]{43}$/.test(
      process.env.AWS_CONTAINER_AUTHORIZATION_TOKEN ?? "",
    )
  ) {
    throw new Error("stage 1 requires the native loopback credential broker");
  }
}

function readPulumiBrokerCapability() {
  if (process.env.DEUS_PULUMI_BROKER_FD !== "3") {
    throw new Error("bootstrap requires the native Pulumi capability pipe");
  }
  const token = readFileSync(3, "utf8");
  if (!/^Bearer [A-Za-z0-9_-]{43}\n$/.test(token)) {
    throw new Error("native Pulumi broker capability is malformed");
  }
  return token.slice(0, -1);
}

function assertCandidateEnvelope(candidate) {
  assertExactKeys(
    candidate,
    [
      "apiVersion",
      "build",
      "candidateDigest",
      "configuration",
      "generatedAt",
      "localGateEvidence",
      "nativeLauncher",
      "pulumiBackend",
      "releaseEvidence",
      "runtime",
      "runtimeProvenance",
      "sealInventory",
      "signature",
      "signingKeyId",
      "source",
      "tools",
    ],
    "bootstrap candidate",
  );
  if (
    candidate.apiVersion !== "security.deus.dev/bootstrap-candidate/v1" ||
    !SHA256.test(candidate.candidateDigest ?? "") ||
    !SHA256.test(candidate.signingKeyId ?? "") ||
    !isRecord(candidate.source) ||
    candidate.source.dirty !== false ||
    !/^[a-f0-9]{40}$/.test(candidate.source.revision ?? "") ||
    !SHA256.test(candidate.source.treeDigest ?? "") ||
    !Array.isArray(candidate.configuration) ||
    !isRecord(candidate.build) ||
    candidate.build.path !== "dist-management-seed" ||
    !SHA256.test(candidate.build.treeDigest ?? "") ||
    !isRecord(candidate.runtime)
  ) {
    throw new Error("bootstrap candidate envelope is invalid");
  }
}

function verifyCandidateSignature(digest, signature, candidate) {
  assertExactKeys(
    signature,
    ["algorithm", "keyId", "value"],
    "candidate signature",
  );
  const trust = parseObject(INSTALLED_TRUST, "qualification trust root");
  assertExactKeys(
    trust,
    ["algorithm", "apiVersion", "configured", "keyId", "publicKeySpki"],
    "qualification trust root",
  );
  const publicDer = Buffer.from(trust.publicKeySpki ?? "", "base64url");
  if (
    trust.apiVersion !== "security.deus.dev/bootstrap-qualification-trust/v1" ||
    trust.configured !== true ||
    trust.algorithm !== "Ed25519" ||
    trust.keyId !== sha256(publicDer) ||
    candidate.signingKeyId !== trust.keyId ||
    signature?.algorithm !== "Ed25519" ||
    signature?.keyId !== trust.keyId ||
    !/^[A-Za-z0-9_-]{86}$/.test(signature?.value ?? "")
  ) {
    throw new Error("candidate signer does not match the trust root");
  }
  const publicKey = createPublicKey({
    key: publicDer,
    format: "der",
    type: "spki",
  });
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    !verifySignature(
      null,
      Buffer.from(`security.deus.dev/bootstrap-candidate/v1:${digest}`, "utf8"),
      publicKey,
      Buffer.from(signature.value, "base64url"),
    )
  ) {
    throw new Error("candidate signature verification failed");
  }
}

function assertCandidateFreshness(candidate) {
  const generated = Date.parse(candidate.generatedAt);
  if (
    !Number.isFinite(generated) ||
    generated > Date.now() + 60_000 ||
    Date.now() - generated > CANDIDATE_MAX_AGE_MS ||
    candidate.signingKeyId !== candidate.signature.keyId
  ) {
    throw new Error("candidate timestamp or signer binding is invalid");
  }
}

function assertRunningNode(runtime) {
  const node = executable(runtime, "node");
  const running = realpathSync(process.execPath);
  if (
    node.realPath !== running ||
    sha256(readFileSync(running)) !== node.sha256 ||
    node.version !== process.version
  ) {
    throw new Error("running Node is not the exact candidate-bound runtime");
  }
}

function assertSourceTree(root, expectedDigest) {
  const scope = parseObject(
    safeFile(
      root,
      "security/management-seed-qualification-scope.json",
      "management-seed scope",
    ),
    "management-seed scope",
  );
  const files = scope.sourceFiles;
  if (
    scope.apiVersion !==
      "security.deus.dev/management-seed-qualification-scope/v1" ||
    !Array.isArray(files) ||
    files.some((entry) => typeof entry !== "string") ||
    new Set(files).size !== files.length ||
    canonicalJson(files) !== canonicalJson([...files].sort())
  ) {
    throw new Error("management-seed source scope is invalid");
  }
  const entries = files.map((entry) => ({
    path: entry,
    sha256: sha256(readFileSync(safeFile(root, entry, "governed source"))),
  }));
  if (sha256(canonicalJson(entries)) !== expectedDigest) {
    throw new Error("governed source tree changed after qualification");
  }
}

function assertConfiguration(root, selectedPath, expected) {
  if (!Array.isArray(expected) || expected.length !== 2) {
    throw new Error("candidate configuration inventory is not exact");
  }
  const selected = relative(root, selectedPath);
  const wanted = [selected, "Pulumi.management.yaml"].sort();
  const actual = expected.map((entry) => entry?.path).sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) {
    throw new Error("candidate does not bind the selected configuration");
  }
  for (const entry of expected) {
    if (
      !isRecord(entry) ||
      !SHA256.test(entry.sha256 ?? "") ||
      sha256(readFileSync(safeFile(root, entry.path, "configuration"))) !==
        entry.sha256
    ) {
      throw new Error(`qualified configuration '${entry?.path}' changed`);
    }
  }
}

function assertRuntimeBytes(root, runtime) {
  const names = [
    "aws",
    "node",
    "pulumi",
    "pulumi-analyzer-policy",
    "pulumi-language-nodejs",
    "pulumi-resource-pulumi-nodejs",
  ];
  if (
    !Array.isArray(runtime.executables) ||
    canonicalJson(runtime.executables.map((entry) => entry?.name).sort()) !==
      canonicalJson(names)
  ) {
    throw new Error("candidate executable inventory is not exact");
  }
  for (const entry of runtime.executables) {
    assertExactKeys(
      entry,
      ["name", "path", "realPath", "sha256", "version"],
      `runtime executable ${entry?.name}`,
    );
    const locator = path.resolve(root, entry.path);
    if (!existsSync(locator)) throw new Error(`${entry.name} is missing`);
    const real = realpathSync(locator);
    assertRootOwnedChain(real, `${entry.name} executable`);
    if (
      real !== entry.realPath ||
      !lstatSync(real).isFile() ||
      lstatSync(real).isSymbolicLink() ||
      sha256(readFileSync(real)) !== entry.sha256
    ) {
      throw new Error(`${entry.name} executable integrity changed`);
    }
  }
  const directoryNames = [
    "aws-cli-install",
    "dependencies",
    "policy-build",
    "pulumi-install",
  ];
  if (
    !Array.isArray(runtime.directories) ||
    canonicalJson(runtime.directories.map((entry) => entry?.name).sort()) !==
      canonicalJson(directoryNames)
  ) {
    throw new Error("candidate directory inventory is not exact");
  }
  for (const entry of runtime.directories) {
    assertDirectoryBinding(
      root,
      entry.path,
      entry.treeDigest,
      entry.name === "aws-cli-install",
      entry.name,
      entry.realPath,
    );
  }
  if (
    !Array.isArray(runtime.pulumiPlugins) ||
    runtime.pulumiPlugins.length !== 1 ||
    runtime.pulumiPlugins[0]?.kind !== "resource" ||
    runtime.pulumiPlugins[0]?.name !== "aws" ||
    runtime.pulumiPlugins[0]?.version !== "7.27.0"
  ) {
    throw new Error("candidate Pulumi plugin inventory is not exact");
  }
  const plugin = runtime.pulumiPlugins[0];
  if (
    path.resolve(root, plugin.path) !==
    path.join(FIXED_PULUMI_HOME, "plugins", "resource-aws-v7.27.0")
  ) {
    throw new Error("candidate AWS plugin is outside the fixed Pulumi home");
  }
  assertDirectoryBinding(
    root,
    plugin.path,
    plugin.treeDigest,
    false,
    "AWS Pulumi plugin",
    plugin.realPath,
  );
}

function assertRuntimeProvenance(binding, runtime) {
  assertExactKeys(binding, ["path", "sha256"], "runtime provenance binding");
  if (
    !isRecord(binding) ||
    binding.path !== RUNTIME_PROVENANCE ||
    !SHA256.test(binding.sha256 ?? "")
  ) {
    throw new Error("candidate runtime provenance binding is invalid");
  }
  assertRootOwnedChain(RUNTIME_PROVENANCE, "runtime provenance");
  const contents = readFileSync(RUNTIME_PROVENANCE);
  if (sha256(contents) !== binding.sha256) {
    throw new Error("root-owned runtime provenance changed");
  }
  const provenance = parseObject(RUNTIME_PROVENANCE, "runtime provenance");
  const executable = new Map(
    runtime.executables.map((entry) => [entry.name, entry]),
  );
  const directory = new Map(
    runtime.directories.map((entry) => [entry.name, entry]),
  );
  if (
    provenance.apiVersion !==
      "security.deus.dev/bootstrap-runtime-provenance/v1" ||
    provenance.platform !== "linux" ||
    provenance.installed?.nodeSha256 !== executable.get("node")?.sha256 ||
    provenance.installed?.pulumiTreeDigest !==
      directory.get("pulumi-install")?.treeDigest ||
    provenance.installed?.awsCliTreeDigest !==
      directory.get("aws-cli-install")?.treeDigest ||
    provenance.artifacts?.awsCli?.signingKeyFingerprint !==
      "FB5DB77FD5C118B80511ADA8A6310ACC4672475C"
  ) {
    throw new Error("runtime provenance does not bind the candidate runtime");
  }
  assertSystemRuntimeClosure(provenance.systemRuntime);
}

function assertSystemRuntimeClosure(value) {
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
    throw new Error("system runtime closure is malformed");
  }
  const seen = new Set();
  for (const entries of [value.loaders, value.libraries]) {
    const paths = entries.map((entry) => entry.path);
    if (canonicalJson(paths) !== canonicalJson([...paths].sort())) {
      throw new Error("system runtime closure is not sorted");
    }
    for (const entry of entries) {
      if (
        typeof entry.path !== "string" ||
        (!entry.path.startsWith("/usr/lib/") &&
          !entry.path.startsWith("/lib/")) ||
        seen.has(entry.path) ||
        !SHA256.test(entry.sha256 ?? "") ||
        realpathSync(entry.path) !== entry.path ||
        sha256(readFileSync(entry.path)) !== entry.sha256
      ) {
        throw new Error("system runtime file changed after qualification");
      }
      assertRootOwnedChain(entry.path, "system runtime file");
      seen.add(entry.path);
    }
  }
}

function assertBuildBinding(root, locatorValue, expectedDigest) {
  const base = path.resolve(root, locatorValue);
  if (
    !within(root, base) ||
    !existsSync(base) ||
    lstatSync(base).isSymbolicLink() ||
    !lstatSync(base).isDirectory() ||
    realpathSync(base) !== base
  ) {
    throw new Error("compiled infrastructure build is missing or unsafe");
  }
  assertRootOwnedTree(base, "compiled infrastructure build");
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        throw new Error("compiled infrastructure build contains a symlink");
      }
      if (stat.isDirectory()) walk(candidate);
      else if (stat.isFile()) {
        entries.push({
          path: relative(base, candidate),
          sha256: sha256(readFileSync(candidate)),
        });
      } else {
        throw new Error(
          "compiled infrastructure build contains an unsafe entry",
        );
      }
    }
  };
  walk(base);
  if (
    entries.length === 0 ||
    sha256(canonicalJson(entries)) !== expectedDigest
  ) {
    throw new Error("compiled infrastructure build integrity changed");
  }
}

function assertDirectoryBinding(
  root,
  locatorValue,
  expectedDigest,
  allowExternalSymlinks,
  label,
  expectedRealPath,
) {
  const locator = path.resolve(root, locatorValue);
  if (
    !existsSync(locator) ||
    lstatSync(locator).isSymbolicLink() ||
    !lstatSync(locator).isDirectory()
  ) {
    throw new Error(`${label} is missing or unsafe`);
  }
  const real = realpathSync(locator);
  assertRootOwnedTree(real, label);
  if (
    (expectedRealPath !== undefined && real !== expectedRealPath) ||
    directoryDigest(real, allowExternalSymlinks) !== expectedDigest
  ) {
    throw new Error(`${label} integrity changed`);
  }
}

function directoryDigest(value, allowExternalSymlinks = false) {
  const base = realpathSync(path.resolve(value));
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      const entryPath = relative(base, candidate);
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(candidate);
        const resolved = realpathSync(candidate);
        const resolvedStat = lstatSync(resolved);
        if (!within(base, resolved) && !allowExternalSymlinks) {
          throw new Error(
            `runtime symlink '${candidate}' escapes its directory`,
          );
        }
        if (resolvedStat.isDirectory() && within(base, resolved)) {
          entries.push({ path: entryPath, type: "symlink", target });
        } else if (resolvedStat.isDirectory() && allowExternalSymlinks) {
          entries.push({
            path: entryPath,
            type: "symlink",
            target,
            resolvedTreeDigest: directoryDigest(resolved, true),
          });
        } else if (resolvedStat.isFile()) {
          entries.push({
            path: entryPath,
            type: "symlink",
            target,
            resolvedSha256: sha256(readFileSync(resolved)),
          });
        } else {
          throw new Error(`runtime symlink '${candidate}' is unsafe`);
        }
      } else if (stat.isDirectory()) {
        walk(candidate);
      } else if (stat.isFile()) {
        entries.push({
          path: entryPath,
          type: "file",
          sha256: sha256(readFileSync(candidate)),
        });
      } else {
        throw new Error(`runtime entry '${candidate}' is unsafe`);
      }
    }
  };
  walk(base);
  if (entries.length === 0) throw new Error("runtime directory is empty");
  return sha256(canonicalJson(entries));
}

function executable(runtime, name) {
  const entry = runtime?.executables?.find((item) => item?.name === name);
  if (!entry) throw new Error(`candidate does not bind executable '${name}'`);
  return entry;
}

function verifiedPath(runtime) {
  return [
    ...new Set(
      runtime.executables.map((entry) => path.dirname(entry.realPath)),
    ),
  ].join(":");
}

function safeFile(root, value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    path.isAbsolute(value) ||
    value.split(/[\\/]/).includes("..")
  ) {
    throw new Error(`${label} path is unsafe`);
  }
  const candidate = path.resolve(root, value);
  if (!within(root, candidate) || !existsSync(candidate)) {
    throw new Error(`${label} is outside the repository or missing`);
  }
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    throw new Error(`${label} must be a direct regular file`);
  }
  assertRootOwnedChain(candidate, label);
  return candidate;
}

function assertRootOwnedTree(value, label) {
  assertRootOwnedChain(value, label);
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        assertRootOwnedChain(realpathSync(candidate), label);
        continue;
      }
      assertRootOwnedMetadata(candidate, stat, label);
      if (stat.isDirectory()) walk(candidate);
      else if (!stat.isFile()) {
        throw new Error(`${label} contains an unsafe filesystem entry`);
      }
    }
  };
  walk(value);
}

function assertRootOwnedChain(value, label) {
  const absolute = path.resolve(value);
  const parsed = path.parse(absolute);
  let current = parsed.root;
  for (const segment of absolute.slice(parsed.root.length).split(path.sep)) {
    if (!segment) continue;
    current = path.join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) {
      throw new Error(`${label} crosses a symlink at '${current}'`);
    }
    assertRootOwnedMetadata(current, stat, label);
  }
}

function assertRootOwnedMetadata(value, stat, label) {
  if (stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
    throw new Error(
      `${label} is not root-owned and non-writable at '${value}'`,
    );
  }
}

function option(args, name) {
  const indexes = args
    .map((entry, index) => (entry === name ? index : -1))
    .filter((index) => index >= 0);
  if (indexes.length > 1) throw new Error(`${name} may appear only once`);
  if (indexes.length === 0) return undefined;
  const value = args[indexes[0] + 1];
  if (!value || value.startsWith("--"))
    throw new Error(`${name} needs a value`);
  return value;
}

function parseObject(file, label) {
  let value;
  try {
    value = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function assertExactKeys(value, expected, label) {
  if (
    !isRecord(value) ||
    canonicalJson(Object.keys(value).sort()) !==
      canonicalJson([...expected].sort())
  ) {
    throw new Error(`${label} fields are not exact`);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function relative(root, value) {
  const result = path.relative(root, value);
  if (
    !result ||
    result.startsWith(`..${path.sep}`) ||
    path.isAbsolute(result)
  ) {
    throw new Error("path is not a repository child");
  }
  return result.split(path.sep).join("/");
}

function within(root, value) {
  const result = path.relative(root, value);
  return (
    result !== ".." &&
    !result.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(result)
  );
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
