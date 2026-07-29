import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const publisher = "scripts/publish-platform-iac-handoff.mjs";
const verifier = "scripts/verify-platform-iac-handoff.mjs";
const fixture = "contracts/platform-iac-handoff-v1.json";
const fixtureKey = "keys/qualification-platform-handoff-ecdsa-p256.pub";

test("IaC stack outputs materialize as a signed credential-free handoff", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-handoff-"));
  try {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const privateKeyFile = path.join(directory, "signing-key.pem");
    const publicKeyFile = path.join(directory, "signing-key.pub");
    const output = path.join(directory, "handoff.json");
    writeFileSync(
      privateKeyFile,
      privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600 },
    );
    writeFileSync(
      publicKeyFile,
      publicKey.export({ type: "spki", format: "pem" }),
      { mode: 0o600 },
    );
    const published = run(publisher, [
      "--stack-outputs",
      "fixtures/platform-iac-stack-outputs-v1.json",
      "--private-key",
      privateKeyFile,
      "--output",
      output,
    ]);
    assert.equal(published.status, 0, published.stderr);
    const handoff = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(
      handoff.spec.cluster.certificateAuthorityReference,
      `sha256:${createHash("sha256")
        .update(Buffer.from("qualification-platform-cluster-ca"))
        .digest("hex")}`,
    );
    assert.equal(handoff.spec.cluster.certificateAuthority, undefined);
    assert.equal(JSON.stringify(handoff).includes("PRIVATE KEY"), false);
    assert.match(
      handoff.signature.publicKeyReference,
      /^key-id:\/\/sha256\/[a-f0-9]{64}$/,
    );
    const verified = run(verifier, [
      "--handoff",
      output,
      "--public-key",
      publicKeyFile,
    ]);
    assert.equal(verified.status, 0, verified.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("source qualification schema-checks and signature-verifies the fixture", () => {
  const verified = run(verifier, [
    "--handoff",
    fixture,
    "--public-key",
    fixtureKey,
  ]);
  assert.equal(verified.status, 0, verified.stderr);

  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-hostile-"));
  try {
    const hostile = JSON.parse(readFileSync(fixture, "utf8"));
    hostile.spec.bootstrapIdentity.accessEntryReference =
      "eks-access://user:password@platform-prod/bootstrap?token=secret";
    const hostileFile = path.join(directory, "credential-reference.json");
    writeFileSync(hostileFile, `${JSON.stringify(hostile)}\n`);
    const rejected = run(verifier, [
      "--handoff",
      hostileFile,
      "--public-key",
      fixtureKey,
    ]);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /schema validation/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("publisher rejects a credential-bearing stack output before signing", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-output-"));
  try {
    const stackOutputs = JSON.parse(
      readFileSync("fixtures/platform-iac-stack-outputs-v1.json", "utf8"),
    );
    stackOutputs.platformIacHandoff.bootstrapIdentity.accessEntryReference =
      "eks-access://user:password@platform-prod/bootstrap?token=secret";
    const stackOutputsFile = path.join(directory, "stack-outputs.json");
    writeFileSync(stackOutputsFile, `${JSON.stringify(stackOutputs)}\n`);
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const privateKeyFile = path.join(directory, "signing-key.pem");
    writeFileSync(
      privateKeyFile,
      privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600 },
    );
    const rejected = run(publisher, [
      "--stack-outputs",
      stackOutputsFile,
      "--private-key",
      privateKeyFile,
      "--output",
      path.join(directory, "handoff.json"),
    ]);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /schema validation/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function run(script: string, args: string[]) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}
