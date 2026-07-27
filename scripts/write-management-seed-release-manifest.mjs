#!/usr/bin/env node

import { readFileSync } from "node:fs";
import process from "node:process";
import {
  assertExactBuildOutputs,
  canonicalJson,
  loadManagementSeedScope,
  safeFile,
  safeArtifactOutput,
  sha256,
  writeAtomicArtifact,
} from "./management-seed-scope.mjs";
import { verifyManagementSeedReleaseEvidence } from "./verify-management-seed-release-evidence.mjs";

const root = process.cwd();
const scope = loadManagementSeedScope(root);
const args = parseArgs(process.argv.slice(2));
const verified = verifyManagementSeedReleaseEvidence(root, {
  requireClean: true,
  requireQualified: !args.sourceRelease,
});
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

const generated = [
  "artifacts/contract-schema-validation.json",
  "artifacts/management-seed-test-results.json",
  "artifacts/management-seed-test-results.junit.xml",
  "artifacts/secure-saas-infra.spdx.json",
  "artifacts/security-contract-evidence.json",
  ...(args.sourceRelease ? [] : ["artifacts/local-gate-evidence.json"]),
  ...scope.build.programOutputs.map(
    (entry) => `${scope.build.programDirectory}/${entry}`,
  ),
  ...scope.build.policyOutputs.map(
    (entry) => `${scope.build.policyDirectory}/${entry}`,
  ),
  ...scope.build.supportOutputs.map(
    (entry) => `${scope.build.supportDirectory}/${entry}`,
  ),
].sort();
const files = [...scope.sourceFiles, ...generated].sort().map((entry) => ({
  path: entry,
  sha256: sha256(readFileSync(safeFile(root, entry))),
}));
const subject = {
  apiVersion: "security.deus.dev/management-seed-release-manifest/v1",
  scope: "aws-organizations-management-seed",
  qualification: args.sourceRelease
    ? "source-release-unqualified"
    : "sealed-linux-production",
  evidenceDigest: verified.release.evidenceDigest,
  files,
};
const manifest = { ...subject, manifestDigest: sha256(canonicalJson(subject)) };
const manifestPath = "artifacts/management-seed-release-manifest.json";
const fileListPath = "artifacts/management-seed-release-files.txt";
safeArtifactOutput(root, manifestPath);
safeArtifactOutput(root, fileListPath);
writeAtomicArtifact(
  root,
  manifestPath,
  `${JSON.stringify(manifest, null, 2)}\n`,
);
writeAtomicArtifact(
  root,
  fileListPath,
  `${[...files.map((entry) => entry.path), manifestPath].sort().join("\n")}\n`,
);
process.stdout.write(
  `Management-seed release manifest binds ${files.length} files.\n`,
);

function parseArgs(values) {
  if (values.length === 0) return { sourceRelease: false };
  if (values.length === 1 && values[0] === "--source-release") {
    return { sourceRelease: true };
  }
  throw new Error(
    "Usage: node scripts/write-management-seed-release-manifest.mjs [--source-release]",
  );
}
