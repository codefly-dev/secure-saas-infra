import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
} from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";

const directory = path.resolve(
  "artifacts",
  `bootstrap-qualification-test-${process.pid}`,
);

test("bootstrap qualification is credential-free and delegates to the canonical gate runner", () => {
  const source = readFileSync(
    "scripts/qualify-bootstrap-candidate.mjs",
    "utf8",
  );
  assert.match(source, /assertCredentialFreeEnvironment\(\)/);
  assert.match(source, /scripts\/run-local-gates\.mjs/);
  assert.match(source, /assertPinnedTools/);
  assert.match(source, /verifyOfflineBootstrapReadiness/);
  assert.match(source, /Ed25519/);
  assert.match(source, /bootstrap-candidate\.payload/);
  assert.match(source, /bootstrap-signing-review-bundle\.json/);
  assert.match(source, /collectBootstrapRuntime/);
  assert.doesNotMatch(source, /--signing-key|createPrivateKey|signBytes/);
  assert.doesNotMatch(source, /const gates = \[/);
  assert.doesNotMatch(source, /aws\s+sts|pulumi\s+(?:preview|up)/);
  const cleanGate = source.indexOf('"scripts/run-local-gates.mjs"');
  assert.ok(cleanGate > 0);
  for (const postInstallDependency of [
    'import("ajv/dist/2020.js")',
    'import("ajv-formats")',
    'import("./management-seed-contract.mjs")',
    "verifyOfflineBootstrapReadiness(onboardingPath)",
  ]) {
    assert.ok(
      source.indexOf(postInstallDependency) > cleanGate,
      `${postInstallDependency} must execute only after the clean-install gate`,
    );
  }

  const gateRunner = readFileSync("scripts/run-local-gates.mjs", "utf8");
  const cleanInstall = gateRunner.indexOf(
    'runGate("g0-clean-install", "npm", ["ci", "--ignore-scripts"])',
  );
  const reviewImport = gateRunner.indexOf(
    'await import("./review-disposition.mjs")',
  );
  assert.ok(cleanInstall > 0 && reviewImport > cleanInstall);
  assert.doesNotMatch(
    gateRunner,
    /^import .*review-disposition/m,
    "review dependencies must not load before npm ci",
  );

  const result = spawnSync(
    process.execPath,
    ["scripts/qualify-bootstrap-candidate.mjs"],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: "must-not-be-read-or-emitted",
      },
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /BOOTSTRAP_CANDIDATE_CREDENTIALS_DENIED/);
  assert.doesNotMatch(result.stderr, /must-not-be-read-or-emitted/);
});

test("provider preparation rejects ambient credentials before any download", () => {
  for (const hostile of [
    { AWS_ACCESS_KEY_ID: "ASIAEXAMPLE" },
    { HTTPS_PROXY: "https://attacker.invalid" },
    { NODE_OPTIONS: "--require=/tmp/attacker.cjs" },
  ]) {
    const [name, value] = Object.entries(hostile)[0];
    const result = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `process.env[${JSON.stringify(name)}]=${JSON.stringify(value)}; await import("./scripts/prepare-bootstrap-plugins.mjs")`,
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { LANG: "C", PATH: process.env.PATH ?? "" },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /bootstrap plugin installer rejects inherited environment variable/,
    );
  }
});

test("independent signer receives exact ignored configuration and evidence bytes", () => {
  const qualifier = readFileSync(
    "scripts/qualify-bootstrap-candidate.mjs",
    "utf8",
  );
  const verifier = readFileSync(
    "scripts/verify-bootstrap-signing-review.mjs",
    "utf8",
  );
  const signerStage0 = readFileSync(
    "scripts/bootstrap-signing-stage0.mjs",
    "utf8",
  );
  const schema = JSON.parse(
    readFileSync(
      "schemas/bootstrap-signing-review-bundle-v1.schema.json",
      "utf8",
    ),
  );
  const expectedRoles = [
    "access-bundle",
    "access-template",
    "contract-validation",
    "local-gate-evidence",
    "native-launcher",
    "onboarding-configuration",
    "pulumi-configuration",
    "qualification-payload",
    "qualification-request",
    "release-evidence",
    "runtime-provenance",
    "seal-inventory",
    "sbom",
  ].sort();
  assert.equal(schema.properties.files.minItems, expectedRoles.length);
  assert.equal(schema.properties.files.maxItems, expectedRoles.length);
  assert.deepEqual(
    [...schema.properties.files.items.properties.role.enum].sort(),
    expectedRoles,
  );
  for (const role of expectedRoles) {
    assert.match(qualifier, new RegExp(`"${role}"`));
    assert.match(verifier, new RegExp(`"${role}"`));
  }
  assert.match(verifier, /assertManagementSeedConfigurationDocument/);
  assert.match(verifier, /createManagementSeedAccessBundle/);
  assert.match(verifier, /assertEmbeddedBootstrapSealInventory/);
  assert.match(
    verifier,
    /qualification payload does not match candidate digest/,
  );
  assert.doesNotMatch(
    verifier.slice(0, verifier.indexOf("try {")),
    /from "(?:ajv|yaml|\.\/)/,
  );
  assert.ok(
    verifier.indexOf("assertCredentialFree()") <
      verifier.indexOf("await loadReviewedImplementation()"),
  );
  for (const gate of ["validate:local", "security:audit", "sbom"]) {
    assert.match(signerStage0, new RegExp(`"${gate}"`));
  }
  assert.ok(
    signerStage0.indexOf("assertCheckout(manifest)") <
      signerStage0.indexOf('runTrustedNpm(["ci", "--ignore-scripts"])'),
  );
  const finalPurge = signerStage0.lastIndexOf('git(["clean", "-ffdx"])');
  const finalInstall = signerStage0.lastIndexOf(
    'runTrustedNpm(["ci", "--ignore-scripts"])',
  );
  const finalBuild = signerStage0.indexOf('"launcher:build"', finalPurge);
  assert.ok(
    finalPurge > 0 &&
      finalBuild > finalPurge &&
      finalInstall > finalBuild &&
      signerStage0.indexOf("[CHECKOUT_VERIFIER,") > finalInstall,
  );
  assert.match(signerStage0, /git\(\["clean", "-ffdx"\]\)/);
  assert.match(signerStage0, /DEUS_SIGNING_BUNDLE_FD/);
  assert.match(signerStage0, /--bundle-fd/);
  assert.match(signerStage0, /\/proc\/\$\{process\.ppid\}\/exe/);
  assert.match(verifier, /signing stage-zero process lineage/);
  assert.doesNotMatch(signerStage0, /bootstrap:plugins/);
  assert.match(signerStage0, /process\.geteuid\?\.\(\) === 0/);
  assert.match(signerStage0, /sourceRevision/);
  assert.match(signerStage0, /core\.hooksPath/);
  assert.match(verifier, /DEUS_SIGNING_STAGE0/);
  const nativeLauncher = readFileSync("cmd/deus-aws-bootstrap/main.go", "utf8");
  const signerService = readFileSync(
    "cmd/deus-aws-bootstrap/signing_service_linux.go",
    "utf8",
  );
  const signerTree = readFileSync(
    "cmd/deus-aws-bootstrap/signer_tree_linux.go",
    "utf8",
  );
  assert.match(nativeLauncher, /runSigningReview/);
  assert.match(nativeLauncher, /DEUS_NATIVE_SIGNING_LAUNCHER=v1/);
  assert.match(
    nativeLauncher,
    /independent signing review as OS root is forbidden/,
  );
  assert.match(signerService, /acquireSigningTransaction/);
  assert.match(signerService, /requireNoProcessesForUID/);
  assert.match(signerService, /consumeRootSignerBundle/);
  assert.match(signerService, /replaceSignerReviewTreeWithSnapshot/);
  assert.match(signerService, /WorkingDirectory=/);
  assert.match(signerTree, /unexpected ignored path/);
  assert.match(signerTree, /fresh signer snapshot differs/);
  assert.match(signerTree, /deus-signer-runtime/);
  const rejected = spawnSync(
    process.execPath,
    ["scripts/verify-bootstrap-signing-review.mjs", "--bundle", "package.json"],
    { cwd: process.cwd(), encoding: "utf8", env: credentialFreeEnvironment() },
  );
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /BOOTSTRAP_SIGNING_REVIEW_DENIED/);
});

test("host-kit source manifest binds the exact clean tagged checkout before signer code", () => {
  const root = mkdtempSync(path.join(tmpdir(), "bootstrap-host-manifest-"));
  const writer = path.resolve(
    "scripts/write-bootstrap-host-source-manifest.mjs",
  );
  const git = (...args: string[]) =>
    spawnSync("/usr/bin/git", args, {
      cwd: root,
      encoding: "utf8",
      env: { HOME: root, LANG: "C", PATH: "/usr/bin:/bin" },
    });
  try {
    assert.equal(git("init", "-q").status, 0);
    writeFileSync(path.join(root, "package.json"), '{"name":"trusted"}\n');
    mkdirSync(path.join(root, "scripts"));
    writeFileSync(
      path.join(root, "scripts", "verify-bootstrap-signing-review.mjs"),
      'throw new Error("must not execute while manifesting");\n',
    );
    assert.equal(git("add", ".").status, 0);
    assert.equal(
      git(
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
      ).status,
      0,
    );
    assert.equal(git("tag", "v1.2.3").status, 0);
    const revision = git("rev-parse", "HEAD").stdout.trim();
    const accepted = spawnSync(
      process.execPath,
      [
        writer,
        "--tag",
        "v1.2.3",
        "--revision",
        revision,
        "--output",
        "manifest.json",
      ],
      { cwd: root, encoding: "utf8" },
    );
    assert.equal(accepted.status, 0, accepted.stderr);
    const manifest = JSON.parse(
      readFileSync(path.join(root, "manifest.json"), "utf8"),
    );
    assert.deepEqual(
      manifest.files.map((entry: { path: string }) => entry.path),
      ["package.json", "scripts/verify-bootstrap-signing-review.mjs"],
    );
    rmSync(path.join(root, "manifest.json"));
    writeFileSync(path.join(root, "package.json"), '{"name":"attacker"}\n');
    const rejected = spawnSync(
      process.execPath,
      [
        writer,
        "--tag",
        "v1.2.3",
        "--revision",
        revision,
        "--output",
        "manifest.json",
      ],
      { cwd: root, encoding: "utf8" },
    );
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /exact clean tagged checkout/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("bootstrap qualification never accepts a private signing key", () => {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/qualify-bootstrap-candidate.mjs",
      "--signing-key",
      "/definitely/missing/private-key.pem",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: credentialFreeEnvironment(),
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /BOOTSTRAP_CANDIDATE_ARGUMENT_DENIED/);

  const finalizer = readFileSync(
    "scripts/finalize-bootstrap-candidate.mjs",
    "utf8",
  );
  assert.doesNotMatch(finalizer, /createPrivateKey|--signing-key/);
  assert.match(finalizer, /rmSync\(signingReviewBundlePath\)/);
  const unsigned = spawnSync(
    process.execPath,
    ["scripts/finalize-bootstrap-candidate.mjs", "--request", "package.json"],
    { cwd: process.cwd(), encoding: "utf8", env: credentialFreeEnvironment() },
  );
  assert.notEqual(unsigned.status, 0);
  assert.match(unsigned.stderr, /--signature is required/);
});

test("credentialed runtime binding excludes qualification-only Git and npm", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { assertCredentialedRuntimeToolBindings } from "./scripts/bootstrap-candidate-runtime.mjs";
    const candidate = {
      tools: {
        node: "v24.18.0",
        npm: "11.16.0",
        git: "git version 2.55.0",
        pulumi: "v3.253.0",
        aws: "aws-cli/2.36.2",
      },
      runtime: {
        executables: [
          { name: "node", version: "v24.18.0" },
          { name: "pulumi", version: "v3.253.0" },
          { name: "aws", version: "aws-cli/2.36.2" },
          { name: "pulumi-language-nodejs", version: "bundled" },
          { name: "pulumi-resource-pulumi-nodejs", version: "bundled" },
        ],
      },
    };
    assert.doesNotThrow(() => assertCredentialedRuntimeToolBindings(candidate));
    candidate.runtime.executables[1].version = "substituted";
    assert.throws(() => assertCredentialedRuntimeToolBindings(candidate), /pulumi.*inconsistent/);
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("direct Node cannot submit a forged candidate before AWS access", () => {
  const root = mkdtempSync(path.join(tmpdir(), "bootstrap-signature-"));
  mkdirSync(path.join(root, "schemas"));
  mkdirSync(path.join(root, "security"));
  const { publicKey } = generateKeyPairSync("ed25519");
  const { privateKey: attackerKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const keyId = createHash("sha256").update(publicDer).digest("hex");
  const trust = {
    apiVersion: "security.deus.dev/bootstrap-qualification-trust/v1",
    configured: true,
    algorithm: "Ed25519",
    keyId,
    publicKeySpki: publicDer.toString("base64url"),
  };
  const generatedAt = new Date();
  const subject = {
    apiVersion: "security.deus.dev/bootstrap-candidate/v1",
    generatedAt: generatedAt.toISOString(),
    signingKeyId: keyId,
    source: {
      revision: "1".repeat(40),
      dirty: false,
      treeDigest: "2".repeat(64),
    },
    configuration: [{ path: "onboarding.local.json", sha256: "3".repeat(64) }],
    pulumiBackend: {
      kind: "pulumi-cloud",
      url: "https://api.pulumi.com",
      organization: "deus",
    },
    build: { path: "dist-management-seed", treeDigest: "4".repeat(64) },
    localGateEvidence: {
      path: "artifacts/local-gate-evidence.json",
      sha256: "5".repeat(64),
      evidenceDigest: "6".repeat(64),
    },
    nativeLauncher: {
      path: "artifacts/deus-aws-bootstrap",
      sha256: "9".repeat(64),
    },
    releaseEvidence: {
      path: "artifacts/security-contract-evidence.json",
      sha256: "7".repeat(64),
      evidenceDigest: "8".repeat(64),
    },
    tools: {
      node: process.version,
      npm: "11.16.0",
      pulumi: "v3.253.0",
      aws: "aws-cli/2.36.2",
      git: "git version 2.55.0",
    },
    runtime: candidateRuntime(),
    runtimeProvenance: {
      path: "/usr/local/lib/deus-bootstrap/runtime-provenance.json",
      sha256: "d".repeat(64),
    },
    sealInventory: {
      path: "artifacts/bootstrap-seal-inventory.json",
      sha256: "e".repeat(64),
      entryCount: 1,
      totalFileBytes: 1,
      maximumFileSize: 1,
    },
  };
  const candidateDigest = createHash("sha256")
    .update(canonicalJson(subject))
    .digest("hex");
  const candidate = {
    ...subject,
    candidateDigest,
    signature: {
      algorithm: "Ed25519",
      keyId,
      value: signBytes(
        null,
        Buffer.from(
          `security.deus.dev/bootstrap-candidate/v1:${candidateDigest}`,
        ),
        attackerKey,
      ).toString("base64url"),
    },
  };
  writeFileSync(
    path.join(root, "schemas", "bootstrap-candidate-v1.schema.json"),
    readFileSync("schemas/bootstrap-candidate-v1.schema.json"),
  );
  writeFileSync(
    path.join(root, "schemas", "bootstrap-qualification-trust-v1.schema.json"),
    readFileSync("schemas/bootstrap-qualification-trust-v1.schema.json"),
  );
  writeFileSync(
    path.join(root, "security", "bootstrap-qualification-trust.json"),
    JSON.stringify(trust),
  );
  writeFileSync(
    path.join(root, "onboarding.local.json"),
    JSON.stringify({
      pulumiOrg: "deus",
      pulumiProject: "secure-saas-infra",
      pulumiBackend: "pulumi-cloud",
      pulumiBackendUrl: "https://api.pulumi.com",
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    }),
  );
  writeFileSync(path.join(root, "candidate.json"), JSON.stringify(candidate));
  try {
    const result = spawnSync(
      process.execPath,
      [
        path.resolve("scripts/bootstrap.mjs"),
        "--root",
        root,
        "--preview",
        "--phases",
        "seed",
        "--config",
        "onboarding.local.json",
        "--candidate",
        "candidate.json",
        "--confirm-management-account-id",
        "999988887777",
      ],
      { cwd: root, encoding: "utf8", env: credentialedTestEnvironment() },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /deus-aws-bootstrap/i);
    assert.doesNotMatch(result.stderr, /AWS caller identity check failed/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("direct Node rejects an ancestor-symlink candidate before opening it", () => {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const real = path.join(directory, "real");
  const linked = path.join(directory, "linked");
  mkdirSync(real, { recursive: true });
  symlinkSync(real, linked, "dir");
  writeFileSync(path.join(real, "candidate.json"), "{}\n");
  writeFileSync(
    path.join(directory, "onboarding.json"),
    JSON.stringify({ pulumiOrg: "deus" }),
  );
  try {
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap.mjs",
        "--preview",
        "--phases",
        "seed",
        "--config",
        path.relative(process.cwd(), path.join(directory, "onboarding.json")),
        "--candidate",
        path.relative(process.cwd(), path.join(linked, "candidate.json")),
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: credentialedTestEnvironment(),
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /deus-aws-bootstrap/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("bootstrap qualification rejects output-contract substitutions", () => {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/qualify-bootstrap-candidate.mjs",
      "--cluster-report",
      "artifacts/substituted.json",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /BOOTSTRAP_CANDIDATE_ARGUMENT_DENIED/);
});

function credentialFreeEnvironment() {
  const env = { ...process.env };
  for (const name of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "PULUMI_ACCESS_TOKEN",
    "PULUMI_CONFIG_PASSPHRASE",
    "PULUMI_CONFIG_PASSPHRASE_FILE",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "SSH_AUTH_SOCK",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "ARM_CLIENT_ID",
    "ARM_CLIENT_SECRET",
    "ARM_TENANT_ID",
    "ARM_SUBSCRIPTION_ID",
  ]) {
    delete env[name];
  }
  return env;
}

function credentialedTestEnvironment() {
  return {
    ...credentialFreeEnvironment(),
    DEUS_CREDENTIAL_LAUNCHER: "v1",
    AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
    AWS_SECRET_ACCESS_KEY: "temporary-secret",
    AWS_SESSION_TOKEN: "temporary-token",
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function candidateRuntime() {
  const executable = (name: string, index: number) => ({
    name,
    path: `/tools/${name}`,
    realPath: `/tools/${name}`,
    sha256: String(index).repeat(64),
    version: "test",
  });
  return {
    executables: [
      executable("aws", 1),
      executable("node", 3),
      executable("pulumi", 5),
      executable("pulumi-analyzer-policy", 2),
      executable("pulumi-language-nodejs", 6),
      executable("pulumi-resource-pulumi-nodejs", 7),
    ],
    directories: [
      {
        name: "aws-cli-install",
        path: "/tools/aws-cli",
        realPath: "/tools/aws-cli",
        treeDigest: "b".repeat(64),
      },
      {
        name: "dependencies",
        path: "node_modules",
        realPath: "/repo/node_modules",
        treeDigest: "8".repeat(64),
      },
      {
        name: "policy-build",
        path: "dist-management-seed-policy",
        realPath: "/repo/dist-management-seed-policy",
        treeDigest: "9".repeat(64),
      },
      {
        name: "pulumi-install",
        path: "/tools/pulumi",
        realPath: "/tools/pulumi",
        treeDigest: "c".repeat(64),
      },
    ],
    pulumiPlugins: [
      {
        kind: "resource",
        name: "aws",
        version: "7.27.0",
        path: "/plugins/resource-aws-v7.27.0",
        realPath: "/plugins/resource-aws-v7.27.0",
        treeDigest: "a".repeat(64),
      },
    ],
  };
}

test("credentialed bootstrap rejects a malformed candidate before AWS access", () => {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const config = path.join(directory, "onboarding.json");
  const candidate = path.join(directory, "candidate.json");
  writeFileSync(
    config,
    `${JSON.stringify({
      pulumiOrg: "deus",
      pulumiProject: "secure-saas-infra",
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    })}\n`,
    { mode: 0o600 },
  );
  writeFileSync(
    candidate,
    `${JSON.stringify({
      apiVersion: "security.deus.dev/bootstrap-candidate/v1",
      generatedAt: new Date().toISOString(),
      runtimeProvenance: {
        path: "/usr/local/lib/deus-bootstrap/runtime-provenance.json",
        sha256: "d".repeat(64),
      },
      unexpectedAuthority: "arn:aws:iam::999988887777:root",
    })}\n`,
    { mode: 0o600 },
  );
  try {
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap.mjs",
        "--preview",
        "--phases",
        "seed",
        "--config",
        path.relative(process.cwd(), config),
        "--candidate",
        path.relative(process.cwd(), candidate),
        "--confirm-management-account-id",
        "999988887777",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: credentialedTestEnvironment(),
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /deus-aws-bootstrap/i);
    assert.doesNotMatch(result.stderr, /AWS caller identity check failed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
