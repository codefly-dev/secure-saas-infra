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
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import Ajv2020 from "ajv/dist/2020.js";
import {
  assertExactBuildOutputs,
  canonicalJson,
  loadManagementSeedScope,
  safeFile,
  writeAtomicArtifact,
} from "./management-seed-scope.mjs";

const root = process.cwd();
const scope = loadManagementSeedScope(root);
const buildDirectory = path.resolve(root, "dist-management-seed-test");
const compiledDirectory = path.join(buildDirectory, "tests");
if (!existsSync(buildDirectory) || !existsSync(compiledDirectory))
  fail("compiled seed test directory is missing");
assertExactBuildOutputs(
  root,
  "dist-management-seed-test",
  scope.tests.compiledOutputs,
);

const expectedTests = scope.tests.included.map((name) =>
  path.join(buildDirectory, name.replace(/\.ts$/, ".js")),
);
const reporter = path.resolve(
  root,
  "scripts/management-seed-test-reporter.mjs",
);
const guard = path.resolve(
  root,
  "scripts/management-seed-test-runtime-guard.cjs",
);
const guardedEnvironment = {
  ...process.env,
  MANAGEMENT_SEED_TEST_ROOT: root,
  MANAGEMENT_SEED_TEST_ALLOWED_FILES: JSON.stringify(
    scope.tests.compiledOutputs,
  ),
  MANAGEMENT_SEED_TEST_ALLOWED_SOURCE_FILES: JSON.stringify(
    scope.sourceFiles.filter((entry) =>
      /^scripts\/.*\.(?:cjs|mjs)$/.test(entry),
    ),
  ),
};

const evidenceInputs = [
  "package-lock.json",
  "package.json",
  "schemas/management-seed-test-evidence-v1.schema.json",
  "scripts/management-seed-test-reporter.mjs",
  "scripts/management-seed-test-runtime-guard.cjs",
  "scripts/run-iac-unit-tests.mjs",
  "security/management-seed-qualification-scope.json",
  "tsconfig.management-seed-test.json",
  ...scope.tests.compilationSourceFiles,
]
  .filter((entry, index, values) => values.indexOf(entry) === index)
  .sort()
  .map((entry) => ({
    path: entry,
    sha256: hashFile(safeFile(root, entry)),
  }));
const npmVersion = exactNpmVersion();
const metadata = {
  apiVersion: "evidence.security.deus.dev/management-seed-test-metadata/v1",
  root,
  expectedTestFiles: scope.tests.included,
  compiledToSource: Object.fromEntries(
    scope.tests.included.map((entry) => [
      path
        .join("dist-management-seed-test", entry.replace(/\.ts$/, ".js"))
        .split(path.sep)
        .join("/"),
      entry,
    ]),
  ),
  toolchain: {
    node: process.version,
    npm: npmVersion,
    runner: "node:test",
  },
  inputs: evidenceInputs,
  inputAggregateSha256: sha256(canonicalJson(evidenceInputs)),
};

const commonJsProbeDirectory = mkdtempSync(
  path.join(tmpdir(), "management-seed-external-module-"),
);
const commonJsProbe = path.join(commonJsProbeDirectory, "external.cjs");
writeFileSync(commonJsProbe, "module.exports = 'outside';\n", { mode: 0o600 });
const externalCommonJsProbe = spawnSync(
  process.execPath,
  ["--require", guard, "-e", `require(${JSON.stringify(commonJsProbe)})`],
  { cwd: root, encoding: "utf8", env: guardedEnvironment },
);
rmSync(commonJsProbeDirectory, { recursive: true, force: true });
if (
  externalCommonJsProbe.status !== 86 ||
  !externalCommonJsProbe.stderr.includes("MANAGEMENT_SEED_TEST_RUNTIME_DENIED")
) {
  fail("runtime closure guard did not reject an external CommonJS module");
}

const quarantinedEsmProbe = spawnSync(
  process.execPath,
  [
    "--require",
    guard,
    "--input-type=module",
    "-e",
    'await import("./src/cidr.ts")',
  ],
  { cwd: root, encoding: "utf8", env: guardedEnvironment },
);
if (
  quarantinedEsmProbe.status !== 86 ||
  !quarantinedEsmProbe.stderr.includes("MANAGEMENT_SEED_TEST_RUNTIME_DENIED")
) {
  fail("runtime closure guard did not reject a quarantined ESM module");
}

const reportDirectory = mkdtempSync(
  path.join(tmpdir(), "management-seed-test-evidence-"),
);
const rawJsonReport = path.join(reportDirectory, "results.json");
const result = spawnSync(
  process.execPath,
  [
    "--require",
    guard,
    "--test-reporter=spec",
    `--test-reporter=${reporter}`,
    "--test-reporter-destination=stdout",
    `--test-reporter-destination=${rawJsonReport}`,
    "--test",
    ...expectedTests,
  ],
  {
    cwd: root,
    stdio: "inherit",
    env: {
      ...guardedEnvironment,
      MANAGEMENT_SEED_TEST_EVIDENCE_METADATA: JSON.stringify(metadata),
    },
  },
);
let evidenceFailure = result.error?.message ?? null;
try {
  if (evidenceFailure === null) {
    const report = JSON.parse(readFileSync(rawJsonReport, "utf8"));
    assertTestEvidence(report, metadata, result.status);
    assertTestEvidenceSchema(report);
    ensureArtifactDirectory();
    writeAtomicArtifact(
      root,
      "artifacts/management-seed-test-results.json",
      `${JSON.stringify(report, null, 2)}\n`,
    );
    writeAtomicArtifact(
      root,
      "artifacts/management-seed-test-results.junit.xml",
      renderJunit(report),
    );
  }
} catch (error) {
  evidenceFailure = `test evidence generation failed: ${error.message}`;
} finally {
  rmSync(reportDirectory, { recursive: true, force: true });
}
if (evidenceFailure !== null) fail(evidenceFailure);
process.exit(result.status ?? 1);

function fail(message) {
  process.stderr.write(`run-iac-unit-tests: ${message}\n`);
  process.exit(1);
}

function exactNpmVersion() {
  const result = spawnSync("npm", ["--version"], {
    cwd: root,
    encoding: "utf8",
    env: process.env,
  });
  const version = result.stdout?.trim();
  if (result.status !== 0 || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version ?? "")) {
    fail("could not determine the exact npm version");
  }
  return version;
}

function assertTestEvidence(report, expected, testStatus) {
  const reportedFiles = [
    ...new Set(report?.testCases?.map((entry) => entry.file) ?? []),
  ].sort();
  const expectedFiles = [...expected.expectedTestFiles].sort();
  const sortedCases = [...(report?.testCases ?? [])].sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.name.localeCompare(right.name) ||
      left.status.localeCompare(right.status),
  );
  if (
    report?.apiVersion !==
      "evidence.security.deus.dev/management-seed-tests/v1" ||
    canonicalJson(report.toolchain) !== canonicalJson(expected.toolchain) ||
    canonicalJson(report.inputs) !== canonicalJson(expected.inputs) ||
    report.inputAggregateSha256 !== expected.inputAggregateSha256 ||
    !Array.isArray(report.testCases) ||
    report.testCases.length === 0 ||
    canonicalJson(report.testCases) !== canonicalJson(sortedCases) ||
    canonicalJson(reportedFiles) !== canonicalJson(expectedFiles) ||
    report.results?.tests !== report.testCases.length ||
    report.results.failed !==
      report.testCases.filter((entry) => entry.status === "failed").length ||
    report.results.passed !==
      report.testCases.filter((entry) => entry.status === "passed").length ||
    report.results.skipped !==
      report.testCases.filter((entry) => entry.status === "skipped").length ||
    report.results.todo !==
      report.testCases.filter((entry) => entry.status === "todo").length ||
    report.testCases.some(
      (entry) =>
        !expected.expectedTestFiles.includes(entry.file) ||
        typeof entry.name !== "string" ||
        !["passed", "failed", "skipped", "todo"].includes(entry.status) ||
        (entry.status === "failed") !==
          /^[A-Z][A-Z0-9_]{0,127}$/.test(entry.failureCode ?? ""),
    ) ||
    (testStatus === 0 && report.results.failed !== 0) ||
    (testStatus !== 0 && report.results.failed === 0)
  ) {
    throw new Error("management-seed test report is malformed or unbound");
  }
}

function assertTestEvidenceSchema(report) {
  const schema = JSON.parse(
    readFileSync(
      safeFile(root, "schemas/management-seed-test-evidence-v1.schema.json"),
      "utf8",
    ),
  );
  const validate = new Ajv2020({ strict: true, allErrors: true }).compile(
    schema,
  );
  if (!validate(report)) {
    throw new Error(
      `management-seed test report failed schema validation: ${JSON.stringify(validate.errors)}`,
    );
  }
}

function ensureArtifactDirectory() {
  const directory = path.join(root, "artifacts");
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
  const stat = lstatSync(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    realpathSync(directory) !== directory
  ) {
    throw new Error("artifacts must be a direct real directory");
  }
}

function renderJunit(report) {
  const failures = report.results.failed;
  const skipped = report.results.skipped + report.results.todo;
  const cases = report.testCases
    .map((entry) => {
      const body =
        entry.status === "failed"
          ? `<failure message="${xml(entry.failureCode)}"/>`
          : entry.status === "skipped" || entry.status === "todo"
            ? `<skipped message="${xml(entry.status)}"/>`
            : "";
      return `    <testcase classname="${xml(entry.file)}" name="${xml(entry.name)}">${body}</testcase>`;
    })
    .join("\n");
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites tests="${report.results.tests}" failures="${failures}" skipped="${skipped}">`,
    `  <testsuite name="management-seed" tests="${report.results.tests}" failures="${failures}" skipped="${skipped}">`,
    "    <properties>",
    `      <property name="node.version" value="${xml(report.toolchain.node)}"/>`,
    `      <property name="npm.version" value="${xml(report.toolchain.npm)}"/>`,
    `      <property name="input.aggregate.sha256" value="${xml(report.inputAggregateSha256)}"/>`,
    "    </properties>",
    cases,
    "  </testsuite>",
    "</testsuites>",
    "",
  ].join("\n");
}

function xml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function hashFile(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
