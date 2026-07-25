#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repositoryRoot = realpathSync(
  resolve(fileURLToPath(new URL("..", import.meta.url))),
);
const decisionPath = join(
  repositoryRoot,
  "security",
  "pulumi-cloud-backend.json",
);
let activeTemporaryPath = null;

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (error) {
  fail(error.message);
}

if (args.help) {
  printUsage();
  process.exit(0);
}

if (!args.outputDir) {
  fail("--output-dir is required");
}
if (!isAbsolute(args.outputDir)) {
  fail("--output-dir must be an absolute path");
}
if (!existsSync(args.outputDir)) {
  fail("--output-dir must already exist");
}

const outputDirectory = realpathSync(args.outputDir);
const relativeToRepository = relative(repositoryRoot, outputDirectory);
if (
  relativeToRepository === "" ||
  (!relativeToRepository.startsWith("..") && !isAbsolute(relativeToRepository))
) {
  fail("Pulumi recovery exports must be stored outside the repository");
}

const decision = readDecision();
const stackName = decision.allowedStacks[0];
const qualifiedStack = `${decision.organization}/${decision.project}/${stackName}`;
const expectedStackUrl = `${decision.consoleUrl}/${decision.organization}/${decision.project}/${stackName}`;

verifyIdentity(decision);
verifyStackInventory(expectedStackUrl);

process.umask(0o077);
const timestamp = new Date()
  .toISOString()
  .replaceAll("-", "")
  .replaceAll(":", "")
  .replace(/\.\d{3}Z$/, "Z");
const stem = `pulumi-${decision.organization}-${decision.project}-${stackName}-${timestamp}`;
const exportName = `${stem}.json`;
const checksumName = `${exportName}.sha256`;
const exportPath = join(outputDirectory, exportName);
const checksumPath = join(outputDirectory, checksumName);

if (existsSync(exportPath) || existsSync(checksumPath)) {
  fail(`refusing to overwrite an existing recovery export for ${timestamp}`);
}

const temporaryPath = join(
  outputDirectory,
  `.${exportName}.${randomBytes(8).toString("hex")}.tmp`,
);
let temporaryCreated = false;

try {
  const descriptor = openSync(temporaryPath, "wx", 0o600);
  closeSync(descriptor);
  temporaryCreated = true;
  activeTemporaryPath = temporaryPath;

  runPulumi([
    "stack",
    "export",
    "--stack",
    qualifiedStack,
    "--file",
    temporaryPath,
    "--non-interactive",
  ]);

  const exported = readFileSync(temporaryPath);
  let deployment;
  try {
    deployment = JSON.parse(exported.toString("utf8"));
  } catch {
    fail("Pulumi returned an invalid JSON deployment export");
  }
  if (
    deployment?.version !== 1 ||
    deployment.deployment === null ||
    typeof deployment.deployment !== "object" ||
    Array.isArray(deployment.deployment)
  ) {
    fail("Pulumi returned an unsupported deployment export");
  }

  chmodSync(temporaryPath, 0o600);
  renameSync(temporaryPath, exportPath);
  temporaryCreated = false;
  activeTemporaryPath = null;

  const digest = createHash("sha256").update(exported).digest("hex");
  writeFileSync(checksumPath, `${digest}  ${basename(exportPath)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });

  console.log(`Pulumi Cloud recovery export: ${exportPath}`);
  console.log(`SHA-256 checksum: ${checksumPath}`);
  console.log(`Stack: ${qualifiedStack}`);
} finally {
  if (temporaryCreated && existsSync(temporaryPath)) {
    unlinkSync(temporaryPath);
  }
}

function readDecision() {
  let value;
  try {
    value = JSON.parse(readFileSync(decisionPath, "utf8"));
  } catch {
    fail("Pulumi Cloud backend decision is not valid JSON");
  }
  const expectedKeys = [
    "allowedStacks",
    "apiVersion",
    "backendUrl",
    "consoleUrl",
    "initializationScope",
    "kind",
    "organization",
    "project",
    "recovery",
    "secretsProvider",
  ];
  if (
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify(expectedKeys) ||
    value.apiVersion !== "security.deus.dev/pulumi-cloud-backend/v1" ||
    value.kind !== "PulumiCloudBackend" ||
    value.backendUrl !== "https://api.pulumi.com" ||
    value.consoleUrl !== "https://app.pulumi.com" ||
    value.secretsProvider !== "pulumi-cloud" ||
    value.initializationScope !== "empty-backend-state-only" ||
    !/^[A-Za-z0-9_.-]+$/.test(value.organization ?? "") ||
    !/^[A-Za-z0-9_.-]+$/.test(value.project ?? "") ||
    JSON.stringify(value.allowedStacks) !== JSON.stringify(["management"]) ||
    value.recovery?.normalExportMode !== "service-encrypted" ||
    value.recovery?.plaintextSecretsPermitted !== false ||
    value.recovery?.repositoryLocalBackupPermitted !== false
  ) {
    fail("Pulumi Cloud backend decision violates the recovery contract");
  }
  return value;
}

function verifyIdentity(decision) {
  const identity = parseJsonCommand(["whoami", "--json", "--verbose"]);
  if (
    identity.user !== decision.organization &&
    !identity.organizations?.includes(decision.organization)
  ) {
    fail(`Pulumi identity is not a member of ${decision.organization}`);
  }
  if (
    typeof identity.url !== "string" ||
    !identity.url.startsWith(`${decision.consoleUrl}/${decision.organization}`)
  ) {
    fail("Pulumi CLI is logged into an unexpected backend");
  }
}

function verifyStackInventory(expectedStackUrl) {
  const stacks = parseJsonCommand(["stack", "ls", "--json"]);
  if (
    !Array.isArray(stacks) ||
    !stacks.some((stack) => stack.url === expectedStackUrl)
  ) {
    fail(`expected Pulumi stack is absent: ${expectedStackUrl}`);
  }
}

function parseJsonCommand(commandArgs) {
  const result = runPulumi(commandArgs);
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(`pulumi ${commandArgs[0]} returned invalid JSON`);
  }
}

function runPulumi(commandArgs) {
  const result = spawnSync("pulumi", commandArgs, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: process.env,
  });
  if (result.error?.code === "ENOENT") {
    fail("pulumi is not installed or is absent from PATH");
  }
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ""}`.trim();
    fail(`pulumi ${commandArgs[0]} failed${detail ? `: ${detail}` : ""}`);
  }
  return result;
}

function parseArgs(values) {
  const parsed = { help: false, outputDir: null };
  for (let index = 0; index < values.length; index += 1) {
    const argument = values[index];
    if (argument === "--help" || argument === "-h") {
      parsed.help = true;
      continue;
    }
    if (argument === "--output-dir") {
      const value = values[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("--output-dir requires a value");
      }
      parsed.outputDir = value;
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${argument}`);
  }
  return parsed;
}

function fail(message) {
  if (activeTemporaryPath && existsSync(activeTemporaryPath)) {
    unlinkSync(activeTemporaryPath);
    activeTemporaryPath = null;
  }
  console.error(`error: ${message}`);
  process.exit(1);
}

function printUsage() {
  console.log(`Usage:
  node scripts/backup-pulumi-cloud-state.mjs --output-dir /secure/external/path

Exports the configured management stack in service-encrypted form to an
existing directory outside this repository and writes a SHA-256 sidecar.`);
}
