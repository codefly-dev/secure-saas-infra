#!/usr/bin/env node

import path from "node:path";
import process from "node:process";

export default async function* managementSeedTestReporter(source) {
  const metadata = parseMetadata(
    process.env.MANAGEMENT_SEED_TEST_EVIDENCE_METADATA,
  );
  const testCases = [];

  for await (const event of source) {
    if (event.type !== "test:pass" && event.type !== "test:fail") continue;
    if (event.data?.type === "suite") continue;
    const compiledFile = relativeFile(metadata.root, event.data?.file);
    const file = metadata.compiledToSource[compiledFile] ?? compiledFile;
    if (!metadata.expectedTestFiles.includes(file)) continue;
    const status =
      event.type === "test:fail"
        ? "failed"
        : event.data?.todo
          ? "todo"
          : event.data?.skip
            ? "skipped"
            : "passed";
    testCases.push({
      file,
      name: String(event.data?.name ?? "unnamed test"),
      status,
      failureCode:
        status === "failed"
          ? stableFailureCode(event.data?.details?.error)
          : null,
    });
  }

  testCases.sort(
    (left, right) =>
      left.file.localeCompare(right.file) ||
      left.name.localeCompare(right.name) ||
      left.status.localeCompare(right.status),
  );
  const results = {
    tests: testCases.length,
    passed: testCases.filter((entry) => entry.status === "passed").length,
    failed: testCases.filter((entry) => entry.status === "failed").length,
    skipped: testCases.filter((entry) => entry.status === "skipped").length,
    todo: testCases.filter((entry) => entry.status === "todo").length,
  };
  yield `${JSON.stringify(
    {
      apiVersion: "evidence.security.deus.dev/management-seed-tests/v1",
      toolchain: metadata.toolchain,
      inputs: metadata.inputs,
      inputAggregateSha256: metadata.inputAggregateSha256,
      results,
      testCases,
    },
    null,
    2,
  )}\n`;
}

function parseMetadata(value) {
  let metadata;
  try {
    metadata = JSON.parse(value ?? "");
  } catch {
    throw new Error("MANAGEMENT_SEED_TEST_EVIDENCE_METADATA is invalid");
  }
  if (
    metadata?.apiVersion !==
      "evidence.security.deus.dev/management-seed-test-metadata/v1" ||
    typeof metadata.root !== "string" ||
    !Array.isArray(metadata.expectedTestFiles) ||
    typeof metadata.compiledToSource !== "object" ||
    metadata.compiledToSource === null ||
    !Array.isArray(metadata.inputs) ||
    !/^[a-f0-9]{64}$/.test(metadata.inputAggregateSha256 ?? "") ||
    typeof metadata.toolchain?.node !== "string" ||
    typeof metadata.toolchain?.npm !== "string" ||
    metadata.toolchain?.runner !== "node:test"
  ) {
    throw new Error("management-seed test evidence metadata is malformed");
  }
  return metadata;
}

function relativeFile(root, file) {
  if (typeof file !== "string") return "unknown";
  return path.relative(root, file).split(path.sep).join("/");
}

function stableFailureCode(error) {
  for (const value of [error?.code, error?.failureType, error?.cause?.code]) {
    if (typeof value === "string" && /^[A-Z][A-Z0-9_]{0,127}$/.test(value)) {
      return value;
    }
  }
  return "TEST_FAILURE";
}
