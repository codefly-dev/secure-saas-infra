#!/usr/bin/env node

// Root-installed, builtins-only independent-signer stage zero. This is part of
// the authenticated host kit and must authenticate the release checkout before
// npm, package scripts, node_modules, or checkout JavaScript can execute.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  fstatSync,
  lstatSync,
  readFileSync,
  readdirSync,
  readSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

const INSTALL_ROOT = "/usr/local/lib/deus-bootstrap";
const NATIVE_LAUNCHER = "/usr/local/bin/deus-aws-bootstrap";
const EXECUTION_ROOT = `${INSTALL_ROOT}/execution`;
const MANIFEST_PATH = `${INSTALL_ROOT}/management-seed-source-manifest.json`;
const RELEASE_PATH = `${INSTALL_ROOT}/RELEASE`;
const CHECKOUT_VERIFIER = `${EXECUTION_ROOT}/scripts/verify-bootstrap-signing-review.mjs`;
const NPM_CLI = `${INSTALL_ROOT}/qualification/node_modules/npm/bin/npm-cli.js`;
const SHA256 = /^[a-f0-9]{64}$/;

try {
  assertFixedRuntime();
  const mode = parseMode(process.argv.slice(2));
  const release = parseRelease(readProtectedFile(RELEASE_PATH, 4_096));
  const manifest = parseJson(
    readProtectedFile(MANIFEST_PATH, 20 * 1024 * 1024),
    "host source manifest",
  );
  assertManifestEnvelope(manifest, release);
  if (mode === "prepare") {
    sanitizeGitMetadata();
    assertCanonicalGitGraph();
    git(["clean", "-ffdx"]);
    assertPristineCheckout(manifest, []);
    assertCheckout(manifest);
    runTrustedNpm(["ci", "--ignore-scripts"]);
    installExactProvider();
    for (const args of [
      ["run", "validate:local"],
      ["run", "security:audit"],
      ["run", "sbom"],
    ]) {
      runTrustedNpm(args);
    }
    // Candidate gates may write only during the disposable online phase.
    // Purge every ignored output, re-authenticate the direct source tree, and
    // reconstruct only the closure consumed by the confidential review. The
    // root parent independently inventories and freezes this tree before it
    // reads the bundle.
    sanitizeGitMetadata();
    assertCanonicalGitGraph();
    git(["clean", "-ffdx"]);
    assertPristineCheckout(manifest, []);
    assertCheckout(manifest);
    runTrustedNpm(["ci", "--ignore-scripts"]);
    installExactProvider();
    for (const script of [
      "build",
      "policy:build",
      "support:build",
      "launcher:build",
    ]) {
      runTrustedNpm(["run", script]);
    }
    // Build scripts are authenticated candidate source but still execute with
    // write access. Recreate both executable dependency closures one final
    // time with script-free trusted installers before root inventory/freeze.
    runTrustedNpm(["ci", "--ignore-scripts"]);
    installExactProvider();
    assertCheckout(manifest);
    process.stdout.write("Authenticated signer preparation completed.\n");
    process.exit(0);
  }
  assertCanonicalGitGraph();
  assertCheckout(manifest);
  const bundleBytes = readSealedBundle();
  const signingInputs = extractSigningInputs(bundleBytes);
  const request = signingInputs.request;
  if (request.source?.revision !== manifest.sourceRevision) {
    throw new Error(
      "signing request revision differs from authenticated host kit",
    );
  }
  const result = spawnSync(
    process.execPath,
    [CHECKOUT_VERIFIER, "--bundle-fd", "3"],
    {
      cwd: EXECUTION_ROOT,
      encoding: "utf8",
      maxBuffer: 100 * 1024 * 1024,
      env: {
        ...process.env,
        DEUS_SIGNING_STAGE0: manifest.manifestDigest,
      },
      stdio: ["inherit", "pipe", "pipe", 3],
    },
  );
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status !== 0 || result.error) {
    throw new Error("authenticated checkout signing verifier failed");
  }
  assertCheckout(manifest);
  assertCanonicalGitGraph();
} catch (error) {
  process.stderr.write(`BOOTSTRAP_SIGNING_STAGE0_DENIED: ${error.message}\n`);
  process.exitCode = 1;
}

function assertFixedRuntime() {
  if (
    process.platform !== "linux" ||
    process.geteuid?.() === 0 ||
    process.ppid <= 1 ||
    realpathSync(`/proc/${process.ppid}/exe`) !== NATIVE_LAUNCHER ||
    realpathSync(process.cwd()) !== EXECUTION_ROOT ||
    process.execPath !== `${INSTALL_ROOT}/bin/node` ||
    process.env.PATH !==
      `${INSTALL_ROOT}/bin:${INSTALL_ROOT}/qualification-bin:${INSTALL_ROOT}/toolchains/go/bin:/usr/bin:/bin` ||
    process.env.PULUMI_HOME !==
      `${EXECUTION_ROOT}/artifacts/bootstrap-pulumi-home` ||
    process.env.DEUS_NATIVE_SIGNING_LAUNCHER !== "v1"
  ) {
    throw new Error(
      "signing stage zero requires the fixed native signer runtime",
    );
  }
}

function extractSigningInputs(bundleBytes) {
  const bundle = parseJson(bundleBytes, "bootstrap signing review bundle");
  if (!Array.isArray(bundle.files)) {
    throw new Error("signing bundle file inventory is invalid");
  }
  const files = new Map();
  for (const entry of bundle.files) {
    if (
      typeof entry?.role !== "string" ||
      files.has(entry.role) ||
      typeof entry.content !== "string" ||
      !SHA256.test(entry.sha256 ?? "")
    ) {
      throw new Error("signing bundle file entry is invalid");
    }
    const bytes = Buffer.from(entry.content, "base64");
    if (
      bytes.toString("base64") !== entry.content ||
      sha256(bytes) !== entry.sha256
    ) {
      throw new Error(`embedded ${entry.role} bytes are invalid`);
    }
    files.set(entry.role, { ...entry, bytes });
  }
  const requestEntry = files.get("qualification-request");
  const onboarding = files.get("onboarding-configuration");
  const pulumi = files.get("pulumi-configuration");
  if (!requestEntry || !onboarding || !pulumi) {
    throw new Error("signing bundle lacks stage-zero inputs");
  }
  const request = parseJson(requestEntry.bytes, "qualification request");
  if (!/^[a-f0-9]{40}$/.test(request.source?.revision ?? "")) {
    throw new Error("qualification request source revision is invalid");
  }
  const requested = new Map(
    Array.isArray(request.configuration)
      ? request.configuration.map((entry) => [entry.path, entry.sha256])
      : [],
  );
  if (
    onboarding.sourcePath !== "onboarding.local.json" ||
    pulumi.sourcePath !== "Pulumi.management.yaml" ||
    requested.size !== 2 ||
    requested.get(onboarding.sourcePath) !== onboarding.sha256 ||
    requested.get(pulumi.sourcePath) !== pulumi.sha256
  ) {
    throw new Error("stage-zero configuration inventory is not exact");
  }
  return {
    request,
    onboarding: onboarding.bytes,
    pulumi: pulumi.bytes,
    configurationPaths: [onboarding.sourcePath, pulumi.sourcePath],
  };
}

function assertManifestEnvelope(manifest, release) {
  const { manifestDigest, ...subject } = manifest ?? {};
  if (
    manifest?.apiVersion !==
      "security.deus.dev/bootstrap-host-source-manifest/v1" ||
    manifest.releaseTag !== release.releaseTag ||
    manifest.sourceRevision !== release.sourceRevision ||
    !SHA256.test(manifestDigest ?? "") ||
    manifestDigest !== sha256(canonicalJson(subject)) ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0 ||
    manifest.files.length > 10_000 ||
    Object.keys(manifest).sort().join(",") !==
      "apiVersion,files,manifestDigest,releaseTag,sourceRevision"
  ) {
    throw new Error("authenticated host source manifest is malformed");
  }
}

function assertCheckout(manifest) {
  const revision = git(["rev-parse", "HEAD"]).trim();
  const expected = manifest.files.map((entry) => entry.path);
  if (
    revision !== manifest.sourceRevision ||
    new Set(expected).size !== expected.length ||
    canonicalJson(expected) !== canonicalJson([...expected].sort())
  ) {
    throw new Error("signer checkout is not the exact clean host-kit revision");
  }
  for (const entry of manifest.files) {
    assertRelativePath(entry.path);
    if (
      Object.keys(entry).sort().join(",") !== "executable,path,sha256" ||
      typeof entry.executable !== "boolean" ||
      !SHA256.test(entry.sha256 ?? "")
    ) {
      throw new Error("host source manifest file entry is malformed");
    }
    const absolute = path.join(EXECUTION_ROOT, entry.path);
    const stat = lstatSync(absolute);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      ((stat.mode & 0o111) !== 0) !== entry.executable ||
      sha256(readFileSync(absolute)) !== entry.sha256
    ) {
      throw new Error(`signer checkout differs at '${entry.path}'`);
    }
  }
}

function sanitizeGitMetadata() {
  const gitDirectory = path.join(EXECUTION_ROOT, ".git");
  const infoDirectory = path.join(gitDirectory, "info");
  for (const directory of [gitDirectory, infoDirectory]) {
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error("signer Git metadata directory is unsafe");
    }
  }
  for (const relative of [
    "config",
    "config.worktree",
    "info/attributes",
    "info/exclude",
  ]) {
    const value = path.join(gitDirectory, relative);
    try {
      rmSync(value, { force: true, recursive: false });
    } catch (error) {
      throw new Error(`cannot sanitize signer Git metadata: ${error.message}`);
    }
  }
  writeFileSync(
    path.join(gitDirectory, "config"),
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n\thooksPath = /dev/null\n\tfsmonitor = false\n",
    { flag: "wx", mode: 0o600 },
  );
  writeFileSync(path.join(infoDirectory, "exclude"), "", {
    flag: "wx",
    mode: 0o600,
  });
}

function assertCanonicalGitGraph() {
  const forbiddenMetadata = [
    path.join(EXECUTION_ROOT, ".git", "info", "grafts"),
    path.join(EXECUTION_ROOT, ".git", "shallow"),
  ];
  for (const value of forbiddenMetadata) {
    try {
      lstatSync(value);
      throw new Error("signer Git history contains graft or shallow metadata");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  if (git(["for-each-ref", "--format=%(refname)", "refs/replace"]).trim()) {
    throw new Error("signer Git history contains replacement refs");
  }
}

function assertPristineCheckout(manifest, allowedExtras) {
  const expected = new Set([
    ...manifest.files.map((entry) => entry.path),
    ...allowedExtras,
  ]);
  const observed = [];
  const walk = (directory, relativeRoot = "") => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (relativeRoot === "" && entry.name === ".git") continue;
      const relative = relativeRoot
        ? `${relativeRoot}/${entry.name}`
        : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(absolute, relative);
      } else if (entry.isFile() && !entry.isSymbolicLink()) {
        observed.push(relative);
      } else {
        throw new Error(`pristine signer tree rejects '${relative}'`);
      }
    }
  };
  walk(EXECUTION_ROOT);
  observed.sort();
  if (
    observed.length !== expected.size ||
    observed.some((entry) => !expected.has(entry))
  ) {
    throw new Error("signer checkout contains an unexpected ignored input");
  }
}

function runTrustedNpm(args) {
  assertProtectedPath(NPM_CLI);
  const result = spawnSync(process.execPath, [NPM_CLI, ...args], {
    cwd: EXECUTION_ROOT,
    encoding: "utf8",
    maxBuffer: 100 * 1024 * 1024,
    env: process.env,
  });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status !== 0 || result.error) {
    throw new Error(`trusted npm ${args.join(" ")} failed`);
  }
}

function installExactProvider() {
  const checksum = {
    x64: "6622158479a5f03877933fb26df8bc6c793dd2bbf841527eca699e8e8e62fdbf",
    arm64: "43f14692bdd1dcee11e413e90742120a41e353767e795f56cab9fc74951771ed",
  }[process.arch];
  if (!checksum) throw new Error("unsupported signer provider architecture");
  rmSync(process.env.PULUMI_HOME, { recursive: true, force: true });
  const result = spawnSync(
    `${INSTALL_ROOT}/toolchains/pulumi/pulumi`,
    [
      "plugin",
      "install",
      "resource",
      "aws",
      "7.27.0",
      "--exact",
      "--reinstall",
      "--checksum",
      checksum,
    ],
    {
      cwd: EXECUTION_ROOT,
      encoding: "utf8",
      maxBuffer: 100 * 1024 * 1024,
      env: {
        HOME: process.env.HOME,
        LANG: "C",
        PATH: "/usr/bin:/bin",
        PULUMI_HOME: process.env.PULUMI_HOME,
      },
    },
  );
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status !== 0 || result.error) {
    throw new Error("trusted exact provider installation failed");
  }
}

function parseMode(values) {
  if (
    values.length === 0 &&
    process.env.DEUS_SIGNING_REVIEW_PHASE === "review"
  ) {
    return "review";
  }
  if (
    values.length === 1 &&
    values[0] === "--prepare" &&
    process.env.DEUS_SIGNING_REVIEW_PHASE === "prepare"
  ) {
    return "prepare";
  }
  throw new Error("signing stage zero requires a fixed service phase");
}

function git(command) {
  const result = spawnSync(
    "/usr/bin/git",
    [
      "-c",
      "core.fileMode=true",
      "-c",
      "core.fsmonitor=false",
      "-c",
      "core.hooksPath=/dev/null",
      "-c",
      "credential.helper=",
      ...command,
    ],
    {
      cwd: EXECUTION_ROOT,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
      env: {
        HOME: process.env.HOME,
        LANG: "C",
        PATH: "/usr/bin:/bin",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_REPLACE_OBJECTS: "1",
        GIT_OPTIONAL_LOCKS: "0",
      },
    },
  );
  if (result.status !== 0 || result.error) {
    throw new Error(
      `trusted Git inspection failed: ${result.stderr || result.error?.message}`,
    );
  }
  return result.stdout;
}

function readSealedBundle() {
  if (process.env.DEUS_SIGNING_BUNDLE_FD !== "3") {
    throw new Error("signing stage zero requires the native sealed bundle");
  }
  const stat = fstatSync(3);
  if (stat.size <= 0 || stat.size > 100 * 1024 * 1024) {
    throw new Error("sealed signing bundle is empty or excessive");
  }
  const contents = Buffer.alloc(stat.size);
  let offset = 0;
  while (offset < contents.length) {
    const count = readSync(
      3,
      contents,
      offset,
      contents.length - offset,
      offset,
    );
    if (count <= 0) throw new Error("sealed signing bundle is truncated");
    offset += count;
  }
  return contents;
}

function readProtectedFile(value, maximum) {
  assertProtectedPath(value);
  const stat = lstatSync(value);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) {
    throw new Error(`protected signer input '${value}' is invalid`);
  }
  return readFileSync(value);
}

function assertProtectedPath(value) {
  assertProtectedAncestors(value);
  const stat = lstatSync(value);
  if (stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
    throw new Error(`signer trust path '${value}' is not root-protected`);
  }
}

function assertProtectedAncestors(value) {
  let current = path.parse(value).root;
  for (const part of value.slice(current.length).split(path.sep)) {
    if (!part) continue;
    current = path.join(current, part);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (stat.mode & 0o022) !== 0) {
      throw new Error(
        `signer input ancestor '${current}' is writable or linked`,
      );
    }
  }
}

function parseRelease(bytes) {
  const match = Buffer.from(bytes)
    .toString("utf8")
    .match(
      /^releaseTag=(v[0-9]+\.[0-9]+\.[0-9]+(?:[+-][A-Za-z0-9.-]+)?)\nsourceRevision=([a-f0-9]{40})\narchitecture=(amd64|arm64)\n$/,
    );
  if (!match)
    throw new Error("installed host-kit release identity is malformed");
  return {
    releaseTag: match[1],
    sourceRevision: match[2],
    architecture: match[3],
  };
}

function assertNoArguments(values) {
  if (values.length !== 0) {
    throw new Error("signing stage zero accepts no checkout-controlled path");
  }
}

function parseJson(bytes, label) {
  try {
    const value = JSON.parse(Buffer.from(bytes).toString("utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return value;
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
}

function assertRelativePath(value) {
  if (
    typeof value !== "string" ||
    !value ||
    value !== value.normalize("NFC") ||
    path.isAbsolute(value) ||
    path.normalize(value) !== value ||
    value === ".." ||
    value.startsWith(`..${path.sep}`) ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("host source manifest contains an unsafe path");
  }
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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
