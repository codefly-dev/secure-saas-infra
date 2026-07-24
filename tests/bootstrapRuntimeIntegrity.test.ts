import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

test("bootstrap runtime rejects dependency mutation, same-version executable replacement, and preload overrides", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import {
      assertBootstrapRuntime,
      assertSafeBootstrapEnvironment,
      assertSafeCredentialTransportEnvironment,
      collectBootstrapRuntime,
    } from "./scripts/bootstrap-runtime-integrity.mjs";

    const root = mkdtempSync(path.join(tmpdir(), "bootstrap-runtime-"));
    const bin = path.join(root, "bin");
    const pulumiHome = path.join(root, "pulumi-home");
    mkdirSync(bin);
    mkdirSync(path.join(root, "node_modules"));
    mkdirSync(path.join(root, "dist-management-seed-policy"));
    mkdirSync(path.join(pulumiHome, "plugins", "resource-aws-v7.27.0"), { recursive: true });
    writeFileSync(path.join(root, "node_modules", "dependency.js"), "trusted");
    writeFileSync(path.join(root, "dist-management-seed-policy", "main.js"), "trusted");
    writeFileSync(path.join(pulumiHome, "plugins", "resource-aws-v7.27.0", "pulumi-resource-aws"), "trusted");
    const command = (name, output) => {
      const file = path.join(bin, name);
      writeFileSync(file, "#!/bin/sh\necho '" + output + "'\n");
      chmodSync(file, 0o700);
    };
    command("npm", "11.16.0");
    command("pulumi", "v3.253.0");
    command("aws", "aws-cli/2.test");
    command("git", "git version 2.test");
    command("pulumi-analyzer-policy", "bundled");
    command("pulumi-language-nodejs", "bundled");
    command("pulumi-resource-pulumi-nodejs", "bundled");
    const environment = { ...process.env, PATH: bin, PULUMI_HOME: pulumiHome };
    delete environment.NODE_OPTIONS;
    delete environment.NODE_PATH;
    const sealed = collectBootstrapRuntime(root, environment);

    writeFileSync(path.join(root, "node_modules", "dependency.js"), "mutated");
    assert.throws(() => assertBootstrapRuntime(root, sealed, environment), /integrity changed/);
    writeFileSync(path.join(root, "node_modules", "dependency.js"), "trusted");

    command("pulumi", "v3.253.0");
    const executedMarker = path.join(root, "rejected-tool-executed");
    writeFileSync(path.join(bin, "pulumi"), "#!/bin/sh\n# different bytes, same version\n/usr/bin/touch '" + executedMarker + "'\necho 'v3.253.0'\n");
    chmodSync(path.join(bin, "pulumi"), 0o700);
    assert.throws(() => assertBootstrapRuntime(root, sealed, environment), /integrity changed/);
    assert.equal(existsSync(executedMarker), false);

    const analyzerMarker = path.join(root, "rejected-analyzer-executed");
    writeFileSync(path.join(bin, "pulumi"), "#!/bin/sh\necho 'v3.253.0'\n");
    chmodSync(path.join(bin, "pulumi"), 0o700);
    writeFileSync(path.join(bin, "pulumi-analyzer-policy"), "#!/bin/sh\n/usr/bin/touch '" + analyzerMarker + "'\n");
    chmodSync(path.join(bin, "pulumi-analyzer-policy"), 0o700);
    assert.throws(() => assertBootstrapRuntime(root, sealed, environment), /integrity changed/);
    assert.equal(existsSync(analyzerMarker), false);
    assert.throws(
      () => assertSafeBootstrapEnvironment({ NODE_OPTIONS: "--require attacker" }),
      /NODE_OPTIONS/,
    );
    assert.throws(
      () => assertSafeCredentialTransportEnvironment({ HTTPS_PROXY: "https://attacker.invalid" }),
      /HTTPS_PROXY/,
    );
    rmSync(root, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("credentialed JavaScript accepts only the native loopback broker capability", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { assertExportedAwsSession } from "./scripts/bootstrap-runtime-integrity.mjs";

    const brokerEnvironment = {
      AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://127.0.0.1:49152/v1/credentials",
      AWS_CONTAINER_AUTHORIZATION_TOKEN: "Bearer " + "A".repeat(43),
    };
    assert.doesNotThrow(() => assertExportedAwsSession(brokerEnvironment));
    assert.throws(
      () => assertExportedAwsSession({
        ...brokerEnvironment,
        AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
      }),
      /raw credential material/,
    );
    assert.throws(
      () => assertExportedAwsSession({
        ...brokerEnvironment,
        AWS_CONTAINER_CREDENTIALS_FULL_URI: "http://0.0.0.0:49152/v1/credentials",
      }),
      /native loopback credential broker/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("bootstrap seal inventory rejects unreviewed generated files", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import {
      assertBootstrapSealInventory,
      assertEmbeddedBootstrapSealInventory,
      writeBootstrapSealInventory,
    } from "./scripts/bootstrap-seal-inventory.mjs";

    const root = mkdtempSync(path.join(tmpdir(), "bootstrap-seal-"));
    const roots = [
      "artifacts/bootstrap-pulumi-home/plugins/resource-aws-v7.27.0",
      "dist-management-seed",
      "dist-management-seed-policy",
      "node_modules",
    ];
    const files = [
      "Pulumi.management.yaml",
      "artifacts/contract-schema-validation.json",
      "artifacts/deus-aws-bootstrap",
      "artifacts/local-gate-evidence.json",
      "artifacts/management-seed-access-bundle.json",
      "artifacts/management-seed-access.template.json",
      "artifacts/secure-saas-infra.spdx.json",
      "artifacts/security-contract-evidence.json",
      "onboarding.local.json",
    ];
    for (const value of roots) {
      mkdirSync(path.join(root, value), { recursive: true });
      writeFileSync(path.join(root, value, "reviewed"), value);
    }
    for (const name of ["README.md", "a-b", "a_b", "pulumi-resource-aws"]) {
      writeFileSync(path.join(root, "node_modules", name), name);
    }
    for (const value of files) {
      mkdirSync(path.dirname(path.join(root, value)), { recursive: true });
      writeFileSync(path.join(root, value), value);
    }
    chmodSync(path.join(root, "artifacts/deus-aws-bootstrap"), 0o700);
    for (const value of ["artifacts/pulumi-plans", "artifacts/runtime-output"])
      mkdirSync(path.join(root, value), { recursive: true });

    const binding = writeBootstrapSealInventory(root);
    const inventory = JSON.parse(
      readFileSync(path.join(root, binding.path), "utf8"),
    );
    const inventoryPaths = inventory.entries.map((entry) => entry.path);
    assert.deepEqual(
      inventoryPaths,
      [...inventoryPaths].sort((left, right) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
      ),
    );
    assert.ok(
      inventoryPaths.indexOf("node_modules/README.md") <
        inventoryPaths.indexOf("node_modules/pulumi-resource-aws"),
    );
    assert.ok(
      inventoryPaths.indexOf("node_modules/a-b") <
        inventoryPaths.indexOf("node_modules/a_b"),
    );
    assert.doesNotThrow(() => assertBootstrapSealInventory(root, binding));
    const inventoryBytes = readFileSync(path.join(root, binding.path));
    const embedded = new Map(
      files.map((value) => [value, readFileSync(path.join(root, value))]),
    );
    assert.doesNotThrow(() =>
      assertEmbeddedBootstrapSealInventory(
        root,
        binding,
        inventoryBytes,
        embedded,
      ),
    );
    assert.throws(
      () =>
        assertEmbeddedBootstrapSealInventory(
          root,
          binding,
          Buffer.from("{}"),
          embedded,
        ),
      /bytes changed/,
    );
    const incomplete = new Map(embedded);
    incomplete.delete("onboarding.local.json");
    assert.throws(
      () =>
        assertEmbeddedBootstrapSealInventory(
          root,
          binding,
          inventoryBytes,
          incomplete,
        ),
      /not exact/,
    );
    embedded.set("Pulumi.management.yaml", Buffer.from("substituted"));
    assert.throws(
      () =>
        assertEmbeddedBootstrapSealInventory(
          root,
          binding,
          inventoryBytes,
          embedded,
        ),
      /does not match/,
    );
    embedded.set(
      "Pulumi.management.yaml",
      readFileSync(path.join(root, "Pulumi.management.yaml")),
    );
    writeFileSync(path.join(root, "node_modules", "attacker.js"), "unreviewed");
    assert.throws(
      () => assertBootstrapSealInventory(root, binding),
      /no longer matches/,
    );
    assert.throws(
      () =>
        assertEmbeddedBootstrapSealInventory(
          root,
          binding,
          inventoryBytes,
          embedded,
        ),
      /does not match/,
    );
    rmSync(root, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});
