#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { assertSafeBootstrapEnvironment } from "./bootstrap-runtime-integrity.mjs";
import { managementSeedSourceState } from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const outputValue = parseOutput(process.argv.slice(2));
assertCredentialFreeEnvironment();
assertSafeBootstrapEnvironment(process.env, "local qualification gates");
const isolatedHome = mkdtempSync(path.join(tmpdir(), "deus-seed-gates-home-"));
process.on("exit", () =>
  rmSync(isolatedHome, { recursive: true, force: true }),
);
ensureSafeDirectory(path.dirname(path.resolve(root, outputValue)));
const output = safeOutput(outputValue);
const source = sourceState();
const execution = observeExecution();
if (source.dirty)
  fail("Local gate evidence requires a clean committed source tree.");
const gates = [runGate("g0-clean-install", "npm", ["ci", "--ignore-scripts"])];
const { validateAdversarialReviewDisposition } =
  await import("./review-disposition.mjs");
let validatedReview;
try {
  validatedReview = validateAdversarialReviewDisposition(root);
} catch (error) {
  fail(error.message);
}
const reviewPath = validatedReview.reviewPath;
gates.push(
  ...[
    ["g0-static-contracts", "npm", ["run", "validate:g0"]],
    ["g1-unit", "npm", ["run", "validate:g1"]],
    ["g4-dependencies", "npm", ["run", "security:audit"]],
    [
      "g6-sbom",
      "npm",
      [
        "run",
        "sbom",
        "--",
        "--output",
        "artifacts/secure-saas-infra.spdx.json",
      ],
    ],
  ].map(([id, command, args]) => runGate(id, command, args)),
);
assertSource();
if (canonicalJson(observeExecution()) !== canonicalJson(execution)) {
  fail("Qualification execution platform or toolchain changed during gates.");
}
const subject = {
  apiVersion: "evidence.security.deus.dev/local-gates/v1",
  generatedAt: new Date().toISOString(),
  source,
  execution,
  adversarialReview: {
    path: "security/adversarial-review-disposition.json",
    sha256: hashFile(reviewPath),
    approvedForLocalQualification: true,
  },
  gates,
  pass: true,
};
const report = {
  ...subject,
  reportDigest: sha256(canonicalJson(subject)),
};
writeAtomic(output, `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(
  `Local gate evidence written to ${path.relative(root, output)}.\n`,
);

function runGate(id, command, args) {
  assertSource();
  process.stdout.write(`\n=== ${id}: ${command} ${args.join(" ")} ===\n`);
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 100 * 1024 * 1024,
    env: gateEnvironment(),
  });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status !== 0)
    fail(`${id} failed with exit code ${result.status}.`);
  assertSource();
  return {
    id,
    command: `${command} ${args.join(" ")}`,
    status: "pass",
    outputDigest: sha256(`${result.stdout ?? ""}\n${result.stderr ?? ""}`),
  };
}

function gateEnvironment() {
  const allowed = [
    "PATH",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "TERM",
    "CI",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
  ];
  const environment = {
    ...Object.fromEntries(
      allowed
        .filter((name) => process.env[name] !== undefined)
        .map((name) => [name, process.env[name]]),
    ),
    HOME: isolatedHome,
    NPM_CONFIG_USERCONFIG: "/dev/null",
  };
  if (root === "/usr/local/lib/deus-bootstrap/execution") {
    environment.DEUS_PRODUCTION_QUALIFICATION = "1";
    environment.DEUS_TRUSTED_GO =
      "/usr/local/lib/deus-bootstrap/toolchains/go/bin/go";
    environment.PATH =
      "/usr/local/lib/deus-bootstrap/bin:/usr/local/lib/deus-bootstrap/qualification-bin:/usr/local/lib/deus-bootstrap/toolchains/go/bin:/usr/bin:/bin";
  }
  return environment;
}

function observeExecution() {
  return {
    platform: process.platform,
    architecture: process.arch,
    productionQualification:
      root === "/usr/local/lib/deus-bootstrap/execution" &&
      process.env.DEUS_PRODUCTION_QUALIFICATION === "1",
    toolchain: {
      node: process.version,
      npm: toolVersion("npm", ["--version"], "npm"),
      go: toolVersion("go", ["version"], "Go").split(/\s+/)[2] ?? "",
      pulumi: toolVersion("pulumi", ["version"], "Pulumi"),
    },
  };
}

function toolVersion(command, args, label) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: gateEnvironment(),
  });
  if (result.status !== 0 || !result.stdout?.trim()) {
    fail(`${label} version probe failed.`);
  }
  return result.stdout.trim();
}

function assertSource() {
  const current = sourceState();
  if (
    current.dirty ||
    current.revision !== source.revision ||
    current.treeDigest !== source.treeDigest
  ) {
    fail("Source changed while local gates were running.");
  }
}

function sourceState() {
  const { entries: _entries, ...source } = managementSeedSourceState(root);
  return source;
}

function parseOutput(values) {
  if (values.length === 0) return "artifacts/local-gate-evidence.json";
  if (values.length !== 2 || values[0] !== "--output" || !values[1]) {
    fail("Usage: node scripts/run-local-gates.mjs [--output <path>]");
  }
  return values[1];
}

function safeFile(value) {
  const candidate = path.resolve(root, value);
  assertInside(candidate);
  const stat = lstatSync(candidate);
  const real = realpathSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink() || real !== candidate) {
    fail(`${value} is not a safe file.`);
  }
  assertInside(real);
  return real;
}

function safeOutput(value) {
  const candidate = path.resolve(root, value);
  assertInside(candidate);
  const parent = path.dirname(candidate);
  if (!existsSync(parent) || lstatSync(parent).isSymbolicLink()) {
    fail("Output parent must be an existing real directory.");
  }
  if (realpathSync(parent) !== parent) {
    fail("Output parent must not traverse an ancestor symlink.");
  }
  if (existsSync(candidate)) {
    const stat = lstatSync(candidate);
    if (!stat.isFile() || stat.isSymbolicLink())
      fail("Output must be a safe file.");
  }
  return candidate;
}

function ensureSafeDirectory(directory) {
  assertInside(directory);
  const relative = path.relative(root, directory);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) {
      mkdirSync(current, { mode: 0o700 });
    }
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail("Output directory must not contain symlinks or non-directories.");
    }
  }
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
    fail(`Credential-free local gates reject: ${forbidden.join(", ")}.`);
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

function assertInside(candidate) {
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`${candidate} escapes the repository.`);
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

function fail(message) {
  process.stderr.write(`run-local-gates: ${message}\n`);
  process.exit(1);
}
