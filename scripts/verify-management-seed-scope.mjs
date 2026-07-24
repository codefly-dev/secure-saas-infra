#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  assertExactBuildOutputs,
  loadManagementSeedScope,
} from "./management-seed-scope.mjs";
import { assertManagementSeedSourceImportClosure } from "./management-seed-source-closure.mjs";

try {
  const root = process.cwd();
  const scope = loadManagementSeedScope(root);
  assertManagementSeedSourceImportClosure(root, scope);
  assertTsconfig("tsconfig.management-seed.json", [
    scope.build.programEntrypoint,
  ]);
  assertTsconfig("tsconfig.management-seed-policy.json", [
    scope.build.policyEntrypoint,
  ]);
  assertTsconfig("tsconfig.management-seed-support.json", [
    scope.build.supportEntrypoint,
  ]);
  assertTsconfig("tsconfig.management-seed-test.json", scope.tests.included);
  assertTestCompilationClosure(root, scope.tests.compilationSourceFiles);
  assertGoPackageClosure(root, scope.sourceFiles);
  if (process.argv.includes("--build")) {
    assertExactBuildOutputs(
      root,
      scope.build.programDirectory,
      scope.build.programOutputs,
    );
    assertExactBuildOutputs(
      root,
      scope.build.policyDirectory,
      scope.build.policyOutputs,
    );
    assertExactBuildOutputs(
      root,
      scope.build.supportDirectory,
      scope.build.supportOutputs,
    );
  }
  process.stdout.write("Management-seed qualification scope verified.\n");
} catch (error) {
  process.stderr.write(`MANAGEMENT_SEED_SCOPE_DENIED: ${error.message}\n`);
  process.exit(1);
}

function assertGoPackageClosure(root, sourceFiles) {
  const packageDirectory = "cmd/deus-aws-bootstrap";
  const actual = readdirSync(path.resolve(root, packageDirectory))
    .filter((entry) => entry.endsWith(".go"))
    .map((entry) => `${packageDirectory}/${entry}`)
    .sort();
  const expected = sourceFiles
    .filter(
      (entry) =>
        entry.startsWith(`${packageDirectory}/`) && entry.endsWith(".go"),
    )
    .sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const unexpected = actual.filter((entry) => !expected.includes(entry));
    const missing = expected.filter((entry) => !actual.includes(entry));
    throw new Error(
      `native launcher Go closure mismatch (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"})`,
    );
  }
}

function assertTsconfig(file, expected) {
  const config = JSON.parse(readFileSync(path.resolve(file), "utf8"));
  const actual = [...(config.include ?? [])].sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${file} include list does not match the positive scope.`);
  }
}

function assertTestCompilationClosure(root, expected) {
  const compiler = path.resolve(root, "node_modules/typescript/bin/tsc");
  const result = spawnSync(
    process.execPath,
    [compiler, "-p", "tsconfig.management-seed-test.json", "--listFilesOnly"],
    { cwd: root, encoding: "utf8", maxBuffer: 20 * 1024 * 1024 },
  );
  if (result.status !== 0) {
    throw new Error(
      result.stderr || "TypeScript could not enumerate the seed test closure.",
    );
  }
  const actual = result.stdout
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => path.resolve(entry))
    .filter((entry) => {
      const relative = path.relative(root, entry);
      return (
        relative !== "" &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative) &&
        !relative.startsWith(`node_modules${path.sep}`)
      );
    })
    .map((entry) => path.relative(root, entry).split(path.sep).join("/"))
    .sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    const unexpected = actual.filter((entry) => !wanted.includes(entry));
    const missing = wanted.filter((entry) => !actual.includes(entry));
    throw new Error(
      `management-seed test compilation closure mismatch (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"})`,
    );
  }
}
