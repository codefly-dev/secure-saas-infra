import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  createWardenMindBlueprint,
  parseCloudContextCatalog,
  parseManagedPostgresIntent,
} from "../src/core";

const script = "scripts/render-cloud-contexts.mjs";
const fixturePath = "contracts/cloud-context-v1alpha1.json";
const baseArgs = [
  script,
  "--environment",
  "development",
  "--platform-account-id",
  "111111111111",
  "--execution-account-id",
  "222222222222",
  "--region",
  "us-east-1",
  "--pulumi-organization",
  "deus",
];

test("cloud context renderer is deterministic and matches its checked fixture", () => {
  const first = run(baseArgs);
  const second = run(baseArgs);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  assert.equal(first.stdout, readFileSync(fixturePath, "utf8"));
});

test("cloud context renderer requires distinct explicit account boundaries", () => {
  const sameAccount = run(
    baseArgs.map((value) =>
      value === "222222222222" ? "111111111111" : value,
    ),
  );
  assert.notEqual(sameAccount.status, 0);
  assert.match(sameAccount.stderr, /require separate accounts/i);

  const legacy = run([script, "--account-id", "111111111111"]);
  assert.notEqual(legacy.status, 0);
  assert.match(legacy.stderr, /CLOUD_CONTEXT_SINGLE_ACCOUNT_DENIED/);
});

test("cloud context renderer rejects duplicate and unknown arguments", () => {
  const duplicate = run([...baseArgs, "--region", "us-west-2"]);
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /CLOUD_CONTEXT_ARGUMENT_DUPLICATE/);
  const unknown = run([...baseArgs, "--credentials", "forbidden"]);
  assert.notEqual(unknown.status, 0);
  assert.match(unknown.stderr, /CLOUD_CONTEXT_ARGUMENT_UNKNOWN/);
});

test("cloud context renderer never follows an output symlink", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "cloud-context-output-"));
  const target = path.join(root, "target.json");
  const output = path.join(root, "catalog.json");
  try {
    writeFileSync(target, "do-not-overwrite\n");
    symlinkSync(target, output);
    const result = run([...baseArgs, "--output", output]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /CLOUD_CONTEXT_OUTPUT_UNSAFE/);
    assert.equal(readFileSync(target, "utf8"), "do-not-overwrite\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("cloud context parser fails closed on version, fields, credentials, and context substitution", () => {
  const baseline = JSON.parse(readFileSync(fixturePath, "utf8"));
  const blueprint = createWardenMindBlueprint();
  const postgres = parseManagedPostgresIntent(
    JSON.parse(
      readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
    ),
    "development",
    blueprint,
  );
  const parse = (value: unknown) =>
    parseCloudContextCatalog(value, blueprint, postgres);

  assert.doesNotThrow(() => parse(baseline));
  assert.throws(
    () =>
      parse({
        ...baseline,
        apiVersion: "security.deus.dev/cloud-context/v1alpha2",
      }),
    /apiVersion/,
  );
  assert.throws(
    () => parse({ ...baseline, futureField: true }),
    /unknown field/i,
  );

  const credential = structuredClone(baseline);
  credential.contexts[0].provider.boundaryRef =
    "provider-boundary://aws/password/222222222222";
  assert.throws(() => parse(credential), /credential-free exact reference/i);

  const substituted = structuredClone(baseline);
  substituted.placements[0].contextId = "aws-execution-development";
  assert.throws(
    () => parse(substituted),
    /unknown runtime capability|untrusted runtime|context mismatch/i,
  );
});

function run(args: string[]) {
  return spawnSync(process.execPath, args, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}
