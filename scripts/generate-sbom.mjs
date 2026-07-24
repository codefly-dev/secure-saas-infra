#!/usr/bin/env node
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { normalizeManagementSeedSbom } from "./management-seed-sbom.mjs";

const root = realpathSync(process.cwd());
const output = safeOutput(parseOutput(process.argv.slice(2)));
const result = spawnSync(
  "npm",
  [
    "sbom",
    "--package-lock-only",
    "--sbom-format",
    "spdx",
    "--sbom-type",
    "application",
  ],
  { encoding: "utf8", maxBuffer: 50 * 1024 * 1024 },
);
if (result.status !== 0 || !result.stdout) {
  console.error(result.stderr || result.error?.message || "npm sbom failed");
  process.exit(result.status ?? 1);
}

const generated = JSON.parse(result.stdout);
const lock = JSON.parse(readFileSync(resolve(root, "package-lock.json")));
const sbom = normalizeManagementSeedSbom(lock, generated);

writeAtomic(output, `${JSON.stringify(sbom, null, 2)}\n`);
console.log(
  `Wrote SPDX SBOM with ${sbom.packages.length} packages to ${output}`,
);

function parseOutput(values) {
  if (values.length === 0) return "artifacts/secure-saas-infra.spdx.json";
  if (
    values.length !== 2 ||
    values[0] !== "--output" ||
    !values[1] ||
    values[1].startsWith("--")
  ) {
    throw new Error(
      "Usage: node scripts/generate-sbom.mjs [--output <artifacts path>]",
    );
  }
  return values[1];
}

function safeOutput(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    isAbsolute(value) ||
    value.split(/[\\/]/).includes("..")
  ) {
    throw new Error("SBOM output must be a repository-relative artifacts path");
  }
  const output = resolve(root, value);
  const artifactRoot = resolve(root, "artifacts");
  const withinArtifacts = relative(artifactRoot, output);
  if (
    !withinArtifacts ||
    withinArtifacts === ".." ||
    withinArtifacts.startsWith(
      `..${process.platform === "win32" ? "\\" : "/"}`,
    ) ||
    isAbsolute(withinArtifacts)
  ) {
    throw new Error("SBOM output must remain below the artifacts directory");
  }
  const parent = dirname(output);
  if (
    !existsSync(parent) ||
    lstatSync(parent).isSymbolicLink() ||
    !lstatSync(parent).isDirectory() ||
    realpathSync(parent) !== parent
  ) {
    throw new Error("SBOM output parent must be an existing real directory");
  }
  if (
    existsSync(output) &&
    (lstatSync(output).isSymbolicLink() || !lstatSync(output).isFile())
  ) {
    throw new Error("SBOM output must be a regular non-symlink file");
  }
  return output;
}

function writeAtomic(output, contents) {
  const temporary = `${output}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, contents, { mode: 0o600, flag: "wx" });
    if (realpathSync(dirname(output)) !== dirname(output)) {
      throw new Error("SBOM output parent changed during generation");
    }
    renameSync(temporary, output);
  } finally {
    rmSync(temporary, { force: true });
  }
}
