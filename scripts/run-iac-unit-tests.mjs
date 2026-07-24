#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import {
  assertExactBuildOutputs,
  loadManagementSeedScope,
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

const result = spawnSync(
  process.execPath,
  ["--require", guard, "--test", ...expectedTests],
  { cwd: root, stdio: "inherit", env: guardedEnvironment },
);
if (result.error) fail(result.error.message);
process.exit(result.status ?? 1);

function fail(message) {
  process.stderr.write(`run-iac-unit-tests: ${message}\n`);
  process.exit(1);
}
