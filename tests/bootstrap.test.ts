import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

test("bootstrap exposes the seed preview/apply safety controls", () => {
  const help = execFileSync(
    process.execPath,
    ["scripts/bootstrap.mjs", "--help"],
    {
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        LANG: process.env.LANG,
        PATH: process.env.PATH,
      },
    },
  );
  for (const expected of [
    /--phases <list>/,
    /--apply/,
    /--preview/,
    /--recover-organization-state/,
    /--candidate/,
    /--confirm-management-account-id/,
    /--confirm-plan-manifest-digest/,
    /OrganizationAccountAccessRole/,
    /Never use\s+root credentials/,
  ]) {
    assert.match(help, expected);
  }
  const guard = readFileSync("scripts/bootstrap.mjs", "utf8");
  const body = `${guard}\n${readFileSync("scripts/bootstrap-main.mjs", "utf8")}`;
  for (const expected of [
    /currently admits only '--phases seed'/,
    /managementPreviewRoleArn/,
    /managementApplyRoleArn/,
    /--save-plan/,
    /--plan/,
    /PulumiPlanManifest/,
    /openVerifiedPlan/,
    /inheritedPlanFd/,
    /assertPulumiInvocationBoundary/,
    /assertPulumiCompletionBoundary/,
    /attestManagementSeedAccessDeployment/,
    /before Pulumi backend verification/,
    /before Pulumi \$\{preview \? "preview" : "apply"\}/,
    /after Pulumi \$\{preview \? "preview" : "apply"\}/,
    /assertManagementSeedWaveOperation\(seedWave, preview \? "preview" : "apply"\)/,
    /configuration-key inventory differs from the signed management configuration/,
    /configuration '\$\{key\}' differs from the signed management configuration/,
    /managementSeedCapacity: capacityAttestation/,
    /verifyManagementSeedAccountCapacityAttestation/,
    /management-seed capacity\/state changed during the Pulumi lifecycle/,
  ]) {
    assert.match(body, expected);
  }
  assert.ok(
    body.indexOf("preparedSeedDocument") <
      body.indexOf("assertManagementCaller(managementAccountId"),
    "full-apply wave denial must run before any AWS caller observation",
  );
  const accessControls = `${body}\n${readFileSync(
    "scripts/management-seed-access.mjs",
    "utf8",
  )}`;
  for (const expected of [
    /managementPreviewTrustedPrincipalArn/,
    /managementApplyTrustedPrincipalArn/,
    /managementBootstrapSamlProviderArn/,
    /managementBootstrapSamlMetadataSha256/,
    /managementProvisionerPrincipalArn/,
  ]) {
    assert.match(accessControls, expected);
  }
  assert.doesNotMatch(body, /stack: `argocd-/);
  assert.doesNotMatch(body, /npm run build|npm run onboard --write/);
});

test("reviewed plan uses an unlinked snapshot immune to path and inode mutation", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { createHash } from "node:crypto";
    import { mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import { closeVerifiedPlan, openVerifiedPlan } from "./scripts/immutable-plan.mjs";
    const directory = mkdtempSync(path.join(tmpdir(), "immutable-plan-"));
    const plan = path.join(directory, "management.plan.json");
    const replacement = path.join(directory, "replacement");
    const reviewed = Buffer.from("reviewed-plan");
    writeFileSync(plan, reviewed);
    const digest = createHash("sha256").update(reviewed).digest("hex");
    const binding = openVerifiedPlan(plan, digest);
    writeFileSync(plan, "in-place-attacker-plan");
    writeFileSync(replacement, "attacker-plan");
    renameSync(replacement, plan);
    assert.equal(readFileSync(binding.fd, "utf8"), "reviewed-plan");
    closeVerifiedPlan(binding);
    rmSync(directory, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("repository bootstrap wrapper refuses every credentialed invocation", () => {
  for (const environment of [
    { NODE_OPTIONS: "--require attacker.js" },
    { AWS_PROFILE: "mutable-profile" },
    { HTTPS_PROXY: "https://attacker.invalid" },
    { https_proxy: "https://attacker.invalid" },
    { AWS_CA_BUNDLE: "/tmp/attacker-ca.pem" },
    { SSL_CERT_FILE: "/tmp/attacker-ca.pem" },
  ]) {
    const result = spawnSync("./scripts/credentialed-bootstrap", ["--help"], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
        AWS_SECRET_ACCESS_KEY: "temporary-secret",
        AWS_SESSION_TOKEN: "temporary-token",
        ...environment,
      },
    });
    assert.equal(result.status, 78);
    assert.match(
      result.stderr,
      /repository scripts are not a credential boundary/,
    );
    assert.match(result.stderr, /\/usr\/local\/bin\/deus-aws-bootstrap/);
  }
});

test("repository access wrapper refuses every credentialed invocation", () => {
  for (const environment of [
    { HTTPS_PROXY: "https://attacker.invalid" },
    { AWS_CA_BUNDLE: "/tmp/attacker-ca.pem" },
  ]) {
    const result = spawnSync(
      "./scripts/management-seed-access-provisioner",
      ["--help"],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
          AWS_SECRET_ACCESS_KEY: "temporary-secret",
          AWS_SESSION_TOKEN: "temporary-token",
          ...environment,
        },
      },
    );
    assert.equal(result.status, 78);
    assert.match(
      result.stderr,
      /repository scripts are not a credential boundary/,
    );
  }
});

test("operator guidance never recommends bypassing the fixed runtime service", () => {
  const guidance = [
    "scripts/credentialed-bootstrap",
    "scripts/management-seed-access-provisioner",
    "scripts/provision-management-seed-access-main.mjs",
    "package.json",
  ]
    .map((file) => readFileSync(file, "utf8"))
    .join("\n");
  assert.doesNotMatch(
    guidance,
    /deus-aws-bootstrap (?:bootstrap|access-provisioner)/,
  );
  assert.match(guidance, /runtime-service/);
});

test("credentialed launchers never execute caller-PATH shims", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "bootstrap-path-shim-"));
  try {
    for (const name of ["node", "git", "dirname", "mktemp", "rm"]) {
      const shim = path.join(directory, name);
      writeFileSync(
        shim,
        `#!/bin/sh\nprintf '%s' "$AWS_ACCESS_KEY_ID" > "${path.join(directory, `${name}.executed`)}"\nexit 99\n`,
      );
      chmodSync(shim, 0o700);
    }
    for (const launcher of [
      "./scripts/credentialed-bootstrap",
      "./scripts/management-seed-access-provisioner",
    ]) {
      const result = spawnSync(launcher, ["--candidate", "missing.json"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          PATH: directory,
          AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
          AWS_SECRET_ACCESS_KEY: "temporary-secret",
          AWS_SESSION_TOKEN: "temporary-token",
        },
      });
      assert.notEqual(result.status, 99);
      assert.match(
        result.stderr,
        /repository scripts are not a credential boundary/,
      );
    }
    for (const name of ["node", "git", "dirname", "mktemp", "rm"]) {
      assert.equal(
        readFileIfPresent(path.join(directory, `${name}.executed`)),
        undefined,
        `${name} shim executed with credentials`,
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("installed stage 1 verifies all runtime bytes before package imports", () => {
  const source = readFileSync(
    "scripts/credentialed-bootstrap-stage1.mjs",
    "utf8",
  );
  assert.doesNotMatch(source, /from\s+["'](?:ajv|\.\/)/);
  const runtimeCheck = source.indexOf(
    "assertRuntimeBytes(root, candidate.runtime)",
  );
  const packageImport = source.indexOf("await import(");
  assert.ok(runtimeCheck > 0 && packageImport > runtimeCheck);
  const argumentRewrite = source.indexOf("process.argv = [");
  assert.ok(argumentRewrite > runtimeCheck && packageImport > argumentRewrite);
  for (const launcher of [
    "scripts/credentialed-bootstrap",
    "scripts/management-seed-access-provisioner",
  ]) {
    const body = readFileSync(launcher, "utf8");
    assert.doesNotMatch(body, /^\s*(?:node|git|dirname|mktemp|rm)(?:\s|$)/m);
    assert.match(body, /repository scripts are not a credential boundary/);
  }
  const native = readFileSync("cmd/deus-aws-bootstrap/main.go", "utf8");
  assert.match(native, /credentialed-bootstrap-stage1\.mjs/);
  assert.match(native, /executionRoot/);
  assert.match(native, /buildChildEnvironment/);
  assert.match(native, /confineCredentialExecution/);
  assert.match(native, /runtime\.LockOSThread\(\)/);
  const linuxHardening = readFileSync(
    "cmd/deus-aws-bootstrap/hardening_linux.go",
    "utf8",
  );
  assert.match(linuxHardening, /landlockRestrictSelf/);
  assert.match(linuxHardening, /landlockAccessFSExecute/);
  assert.match(linuxHardening, /pulumi-resource-aws/);
  assert.doesNotMatch(linuxHardening, /plugins\/resource-aws-v7\.27\.0"/);
  assert.match(source, /DEUS_EXECUTION_CONFINEMENT/);
  assert.match(source, /assertExecutionConfinement\(\)/);
  assert.match(source, /spawnSync\("\/bin\/sh"/);
  assert.match(source, /denial\.error\?\.code !== "EACCES"/);
  assert.match(source, /env: \{\}/);
  assert.match(native, /installRoot \+ "\/bin"/);
  assert.doesNotMatch(native, /installRoot \+ "\/bin:\/usr\/bin:\/bin"/);
  assert.doesNotMatch(
    readFileSync("scripts/credentialed-bootstrap-stage1.mjs", "utf8"),
    /FIXED_PATH.*\/usr\/bin/,
  );
  for (const guard of [
    "scripts/bootstrap.mjs",
    "scripts/provision-management-seed-access.mjs",
  ]) {
    const guardedSource = readFileSync(guard, "utf8");
    assert.doesNotMatch(guardedSource, /^import\s/m);
    assert.ok(
      guardedSource.indexOf("credentialed-stage1/v1") <
        guardedSource.indexOf("await import("),
    );
  }
});

test("direct Node treats every AWS or Pulumi channel as credential-bearing", () => {
  const result = spawnSync(
    process.execPath,
    ["scripts/bootstrap.mjs", "--help"],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        AWS_WEB_IDENTITY_TOKEN_FILE: "/tmp/untrusted-token",
        AWS_ROLE_ARN: "arn:aws:iam::999988887777:role/Untrusted",
      },
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /immutable qualified snapshot/);
});

test("root runtime installer authenticates archives before installation", () => {
  const installer = readFileSync("scripts/install-bootstrap-runtime", "utf8");
  const writer = readFileSync(
    "scripts/write-bootstrap-runtime-provenance.mjs",
    "utf8",
  );
  assert.match(installer, /VALIDSIG/);
  assert.match(installer, /FB5DB77FD5C118B80511ADA8A6310ACC4672475C/);
  assert.match(installer, /checksum mismatch/);
  assert.ok(
    installer.indexOf("VALIDSIG") <
      installer.indexOf('"$temporary/aws/aws/install"'),
  );
  assert.doesNotMatch(writer, /from\s+["'](?:ajv|\.\/)/);
  assert.match(writer, /bootstrap-runtime-provenance\/v1/);
});

test("AWS provider installation is fresh, exact, and archive-checksum bound", () => {
  const toolchain = JSON.parse(
    readFileSync("security/bootstrap-host-toolchain.json", "utf8"),
  );
  const wrapper = readFileSync("scripts/prepare-bootstrap-plugins", "utf8");
  const installer = readFileSync(
    "scripts/prepare-bootstrap-plugins.mjs",
    "utf8",
  );
  assert.match(wrapper, /env -i/);
  assert.match(wrapper, /NODE_OPTIONS/);
  assert.match(wrapper, /--pulumi/);
  for (const hostile of [
    { NODE_OPTIONS: "--require=/tmp/attacker.cjs" },
    { AWS_ACCESS_KEY_ID: "must-not-be-emitted" },
  ]) {
    const result = spawnSync(
      path.resolve("scripts/prepare-bootstrap-plugins"),
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          HOME: process.cwd(),
          LANG: "C",
          PATH: process.env.PATH,
          ...hostile,
        },
      },
    );
    assert.equal(result.status, 64);
    assert.match(
      result.stderr,
      /credentials, preload, proxy, or executable indirection are forbidden/,
    );
    assert.doesNotMatch(result.stderr, /must-not-be-emitted/);
  }
  assert.equal(toolchain.pulumiAwsProvider.version, "7.27.0");
  assert.deepEqual(toolchain.pulumiAwsProvider.linuxArchives, {
    amd64: {
      file: "pulumi-resource-aws-v7.27.0-linux-amd64.tar.gz",
      sha256:
        "6622158479a5f03877933fb26df8bc6c793dd2bbf841527eca699e8e8e62fdbf",
    },
    arm64: {
      file: "pulumi-resource-aws-v7.27.0-linux-arm64.tar.gz",
      sha256:
        "43f14692bdd1dcee11e413e90742120a41e353767e795f56cab9fc74951771ed",
    },
  });
  assert.match(
    installer,
    /rmSync\(pulumiHome, \{ recursive: true, force: true \}\)/,
  );
  assert.match(installer, /"--exact"/);
  assert.match(installer, /"--reinstall"/);
  assert.match(installer, /"--checksum"/);
  assert.ok(
    installer.indexOf("rmSync(pulumiHome") < installer.indexOf("spawnSync("),
  );
  assert.doesNotMatch(installer, /npm\s+run|shell:\s*true/);

  const validatorProbe = String.raw`
    import { readFileSync } from "node:fs";
    import { assertHostToolchainPins } from "./scripts/bootstrap-host-toolchain.mjs";
    const value = JSON.parse(readFileSync("security/bootstrap-host-toolchain.json", "utf8"));
    if (process.env.MUTATE_PROVIDER === "1") {
      value.pulumiAwsProvider.linuxArchives.amd64.sha256 = "0".repeat(64);
    }
    assertHostToolchainPins(value);
  `;
  const accepted = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", validatorProbe],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { HOME: process.env.HOME, PATH: process.env.PATH },
    },
  );
  assert.equal(accepted.status, 0, accepted.stderr);
  const rejected = spawnSync(
    process.execPath,
    ["--input-type=module", "--eval", validatorProbe],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        MUTATE_PROVIDER: "1",
      },
    },
  );
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /host toolchain is malformed/);
});

test("caller assertion failures unwind instead of terminating cleanup", () => {
  const source = readFileSync("scripts/bootstrap-main.mjs", "utf8");
  const start = source.indexOf("function assertManagementCaller(");
  const end = source.indexOf("function assertManagementAccessDeployment(");
  const callerAssertion = source.slice(start, end);
  assert.ok(start > 0 && end > start);
  assert.match(callerAssertion, /throw new Error/);
  assert.doesNotMatch(callerAssertion, /process\.exit/);
  assert.match(source, /runAttestedPulumiLifecycle/);
});

test("management document remains in scope through prepared-config and lifecycle checks", () => {
  const source = readFileSync("scripts/bootstrap-main.mjs", "utf8");
  assert.match(source, /let managementDocument = null;/);
  assert.match(
    source,
    /managementDocument = parseYaml[\s\S]+assertPreparedManagementStack\(fqStackName, managementDocument\.config\)[\s\S]+expectedOrganizationStateForLifecycle/,
  );
  assert.doesNotMatch(source, /const managementDocument = parseYaml/);
});

test("failed Pulumi invocation behaviorally runs post-attestation and closes the reviewed plan", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { createHash } from "node:crypto";
    import { fstatSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import { closeVerifiedPlan, openVerifiedPlan } from "./scripts/immutable-plan.mjs";
    import { runAttestedPulumiLifecycle } from "./scripts/pulumi-lifecycle.mjs";
    const directory = mkdtempSync(path.join(tmpdir(), "pulumi-lifecycle-"));
    const plan = path.join(directory, "plan.json");
    const bytes = Buffer.from("reviewed-plan");
    writeFileSync(plan, bytes);
    const reviewedPlan = openVerifiedPlan(plan, createHash("sha256").update(bytes).digest("hex"));
    const fd = reviewedPlan.fd;
    const attestations = [];
    assert.throws(() => runAttestedPulumiLifecycle({
      beforeLabel: "before",
      afterLabel: "after",
      attest: (label) => attestations.push(label),
      invoke: () => { throw new Error("pulumi failed"); },
      reviewedPlan,
      closePlan: closeVerifiedPlan,
    }), /pulumi failed/);
    assert.deepEqual(attestations, ["before", "after"]);
    assert.throws(() => fstatSync(fd), /bad file descriptor|EBADF/i);
    rmSync(directory, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("exact post-apply attestation retries boundedly and fails closed", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { retryExactAttestation } from "./scripts/pulumi-lifecycle.mjs";
    let attempts = 0;
    const sleeps = [];
    const result = retryExactAttestation(
      () => {
        attempts += 1;
        if (attempts < 3) throw new Error("transitional Organizations state");
        return { pass: true, digest: "exact" };
      },
      { attempts: 3, delayMs: 7, sleep: (delay) => sleeps.push(delay) },
    );
    assert.deepEqual(result, { pass: true, digest: "exact" });
    assert.equal(attempts, 3);
    assert.deepEqual(sleeps, [7, 7]);
    assert.throws(
      () => retryExactAttestation(
        () => { throw new Error("foreign or stale state"); },
        { attempts: 2, delayMs: 0, sleep: () => {} },
      ),
      /did not converge after 2 attempts: foreign or stale state/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("organization recovery receipt is reviewed-plan-bound and mutation-free", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { createManagementSeedOrganizationRecoveryReceipt, verifyManagementSeedOrganizationRecoveryReceipt } from "./scripts/management-seed-organization-recovery.mjs";
    import { canonicalJson, sha256 } from "./scripts/management-seed-scope.mjs";
    const managementAccountId = "999988887777";
    const bootstrapCandidateDigest = "a".repeat(64);
    const configurationDigest = "b".repeat(64);
    const digest = (subject) => ({ ...subject, attestationDigest: sha256(canonicalJson(subject)) });
    const reviewedStandaloneState = digest({
      apiVersion: "security.deus.dev/management-seed-organization-state/v1",
      expectedState: "standalone",
      managementAccountId,
      bootstrapCandidateDigest,
      configurationDigest,
      observationRegion: "us-east-1",
      organizationPresent: false,
      pass: true,
    });
    const observedBaselineState = digest({
      apiVersion: "security.deus.dev/management-seed-organization-state/v1",
      expectedState: "organization-baseline",
      managementAccountId,
      bootstrapCandidateDigest,
      configurationDigest,
      observationRegion: "us-east-1",
      organizationPresent: true,
      organizationId: "o-abcdefghij",
      organizationArn: "arn:aws:organizations::999988887777:organization/o-abcdefghij",
      featureSet: "ALL",
      rootId: "r-abcd",
      rootArn: "arn:aws:organizations::999988887777:root/o-abcdefghij/r-abcd",
      rootPolicyTypes: ["S3_POLICY", "SERVICE_CONTROL_POLICY"],
      rootTags: [],
      managementAccount: { id: managementAccountId, name: "Management", email: "management@example.com", state: "ACTIVE", tags: [] },
      organizationalUnits: [],
      trustedServicePrincipals: [],
      delegatedAdministrators: [],
      resourcePolicyPresent: false,
      customerPolicies: [],
      fullAwsAccessTargetId: "r-abcd",
      openInvitations: 0,
      pendingAccountCreations: 0,
      pass: true,
    });
    const bindings = {
      bootstrapCandidateDigest,
      managementAccountId,
      planManifestDigest: "c".repeat(64),
      sourceRevision: "d".repeat(40),
    };
    const receipt = createManagementSeedOrganizationRecoveryReceipt({
      ...bindings,
      generatedAt: "2026-07-21T00:00:00.000Z",
      observedBaselineState,
      plan: { stack: "management", planFile: "management.plan.json", sha256: "e".repeat(64) },
      reviewedStandaloneState,
    });
    assert.equal(receipt.pulumiInvoked, false);
    assert.equal(receipt.cloudMutationPerformed, false);
    assert.equal(verifyManagementSeedOrganizationRecoveryReceipt(receipt, bindings), receipt);
    const substituted = structuredClone(receipt);
    substituted.plan.sha256 = "f".repeat(64);
    assert.throws(
      () => verifyManagementSeedOrganizationRecoveryReceipt(substituted, bindings),
      /receipt binding is invalid/,
    );
    const wrongTransition = structuredClone(observedBaselineState);
    wrongTransition.configurationDigest = "f".repeat(64);
    const { attestationDigest: ignored, ...wrongSubject } = wrongTransition;
    wrongTransition.attestationDigest = sha256(canonicalJson(wrongSubject));
    assert.throws(
      () => createManagementSeedOrganizationRecoveryReceipt({
        ...bindings,
        observedBaselineState: wrongTransition,
        plan: receipt.plan,
        reviewedStandaloneState,
      }),
      /transition is not exact/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("released operator guidance exposes no raw Pulumi bypass", () => {
  const body = readFileSync("docs/management-seed-runbook.md", "utf8");
  assert.doesNotMatch(body, /^\s*pulumi\s+(?:preview|up)(?:\s|$)/gm);
  assert.match(body, /scripts\/credential-free-qualification/);
  assert.match(body, /\/usr\/local\/bin\/deus-aws-bootstrap/);
  assert.match(body, /separate host\/identity/);
  assert.doesNotMatch(
    readFileSync("docs/bootstrap.md", "utf8"),
    /^\s*pulumi destroy(?:\s|$)/gm,
  );
  assert.match(body, /ManagementSeedRetirement/);
  assert.match(body, /--observe-foundation/);
  assert.match(body, /--retire/);
});

test("direct credentialed Node invocation is rejected before config or AWS access", () => {
  for (const mode of ["--preview", "--apply", "--recover-organization-state"]) {
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap.mjs",
        "--environment",
        "dev",
        "--phases",
        "access",
        mode,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          DEUS_CREDENTIAL_LAUNCHER: "v1",
          AWS_ACCESS_KEY_ID: "ASIA1234567890123456",
          AWS_SECRET_ACCESS_KEY: "temporary-secret",
          AWS_SESSION_TOKEN: "temporary-token",
        },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /deus-aws-bootstrap/);
    assert.doesNotMatch(result.stderr, /onboarding config not found/i);
    assert.doesNotMatch(result.stderr, /AWS caller identity check/i);
  }
});

function readFileIfPresent(file: string): string | undefined {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}
