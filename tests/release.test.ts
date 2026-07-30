import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { parse as parseYaml } from "yaml";

test("management-seed source closure rejects ungoverned and dynamic local imports", () => {
  const fixture = mkdtempSync(path.join(tmpdir(), "seed-source-closure-"));
  mkdirSync(path.join(fixture, "src"));
  writeFileSync(
    path.join(fixture, "src", "entry.mjs"),
    'import "./unreviewed.mjs";\n',
  );
  writeFileSync(path.join(fixture, "src", "unreviewed.mjs"), "export {};\n");
  const probe = (sourceFiles: string[]) =>
    spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
          import { assertManagementSeedSourceImportClosure } from "./scripts/management-seed-source-closure.mjs";
          assertManagementSeedSourceImportClosure(${JSON.stringify(fixture)}, {
            sourceFiles: ${JSON.stringify(sourceFiles)},
            build: {
              programDirectory: "dist-program", programOutputs: [],
              policyDirectory: "dist-policy", policyOutputs: [],
              supportDirectory: "dist-support", supportOutputs: []
            }
          });
        `,
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
  try {
    const ungoverned = probe(["src/entry.mjs"]);
    assert.notEqual(ungoverned.status, 0);
    assert.match(ungoverned.stderr, /exactly one governed source/);

    const governed = probe(["src/entry.mjs", "src/unreviewed.mjs"]);
    assert.equal(governed.status, 0, governed.stderr);

    writeFileSync(
      path.join(fixture, "src", "entry.mjs"),
      'const target = "./unreviewed.mjs"; await import(target);\n',
    );
    const dynamic = probe(["src/entry.mjs", "src/unreviewed.mjs"]);
    assert.notEqual(dynamic.status, 0);
    assert.match(dynamic.stderr, /non-literal dynamic module load/);

    writeFileSync(
      path.join(fixture, "src", "entry.mjs"),
      'await import("file:///tmp/unreviewed.mjs");\n',
    );
    const externalFile = probe(["src/entry.mjs", "src/unreviewed.mjs"]);
    assert.notEqual(externalFile.status, 0);
    assert.match(externalFile.stderr, /unsupported file import/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("static gate syntax-checks every governed JavaScript and shell program", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import { validateManagementSeedSyntax } from "./scripts/validate-management-seed-syntax.mjs";
    const root = mkdtempSync(path.join(tmpdir(), "seed-syntax-"));
    mkdirSync(path.join(root, "scripts"));
    const module = path.join(root, "scripts", "program.mjs");
    const shell = path.join(root, "scripts", "program");
    writeFileSync(module, "export const valid = true;\n");
    writeFileSync(shell, "#!/bin/sh\nset -eu\nexit 0\n");
    chmodSync(shell, 0o700);
    const inventory = ["scripts/program.mjs", "scripts/program"];
    assert.doesNotThrow(() => validateManagementSeedSyntax(root, inventory));
    writeFileSync(module, "export const = broken;\n");
    assert.throws(
      () => validateManagementSeedSyntax(root, inventory),
      /syntax validation failed/,
    );
    writeFileSync(module, "export const valid = true;\n");
    writeFileSync(shell, "#!/bin/sh\nif then\n");
    assert.throws(
      () => validateManagementSeedSyntax(root, inventory),
      /syntax validation failed/,
    );
    rmSync(root, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  assert.match(
    packageJson.scripts["validate:g0"],
    /validate-management-seed-syntax\.mjs/,
  );
});

test("release workflow uses the exact SLSA Level 3 tag exception", () => {
  const body = readFileSync(".github/workflows/release.yml", "utf8");
  const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as {
    scripts: Record<string, string>;
  };
  const gateRunner = readFileSync("scripts/run-local-gates.mjs", "utf8");
  const safeGit = readFileSync("scripts/safe-git.mjs", "utf8");
  const signerStage0 = readFileSync(
    "scripts/bootstrap-signing-stage0.mjs",
    "utf8",
  );
  const releaseEvidenceVerifier = readFileSync(
    "scripts/verify-management-seed-release-evidence.mjs",
    "utf8",
  );

  assert.match(
    body,
    /uses: slsa-framework\/slsa-github-generator\/.+@v2\.1\.0/,
  );
  assert.match(body, /id-token: write/);
  assert.match(body, /provenance-name:/);
  assert.match(body, /environment: production/);
  assert.match(body, /tags:\s*\n\s*-\s*"v\*\.\*\.\*"/);
  assert.doesNotMatch(body, /npm run verify:all/);
  assert.match(body, /npm run validate:source/);
  assert.match(body, /verify-review-promotion\.mjs --release/);
  assert.match(body, /release:manifest -- --source-release/);
  assert.doesNotMatch(body, /artifacts\/local-gate-evidence\.json/);
  assert.match(body, /go-version: "1\.26\.5"/);
  assert.match(body, /\.\/scripts\/package-bootstrap-host-kit/);
  assert.match(
    body,
    /sha256sum[\s\S]+deus-bootstrap-host-kit-\$\{RELEASE_TAG\}-amd64\.tar\.gz/,
  );
  assert.match(
    body,
    /gh release create[\s\S]+deus-bootstrap-host-kit-\$\{RELEASE_TAG\}-arm64\.tar\.gz/,
  );
  const runBlocks = [...body.matchAll(/\n\s+run: \|\n((?:\s{10,}.*\n?)*)/g)]
    .map((match) => match[1])
    .join("\n");
  assert.doesNotMatch(runBlocks, /\$\{\{\s*github\.(?:ref_name|sha)\s*\}\}/);
  assert.match(body, /RELEASE_TAG: \$\{\{ github\.ref_name \}\}/);
  assert.match(body, /ref: \$\{\{ github\.ref \}\}/);
  assert.match(body, /fetch-tags: true/);
  assert.match(body, /refs\/tags\/\$\{RELEASE_TAG\}\^\{commit\}/);
  assert.match(body, /merge-base --is-ancestor/);
  assert.match(body, /pulumi-resource-aws[\s\S]+--version/);
  assert.match(body, /verify-host-kit-archive/);
  assert.doesNotMatch(body, /pattern: deus-bootstrap-host-kit/);
  assert.doesNotMatch(body, /merge-multiple: true/);
  for (const architecture of ["amd64", "arm64"]) {
    assert.match(
      body,
      new RegExp(
        `name: deus-bootstrap-host-kit-\\$\\{\\{ github\\.ref_name \\}\\}-${architecture}`,
      ),
    );
  }
  assert.match(
    body,
    /EXPECTED_HOST_KIT_SUBJECTS: \$\{\{ needs\.host-kit-subjects\.outputs\.digest \}\}/,
  );
  assert.match(
    body,
    /actual_subjects=\$\(cd artifacts\/host-kit-download && sha256sum/,
  );
  assert.match(
    body,
    /test "\$actual_subjects" = "\$EXPECTED_HOST_KIT_SUBJECTS"/,
  );
  assert.match(body, /tar -xOzf[\s\S]+deus-aws-bootstrap > "\$verifier"/);
  assert.match(
    body,
    /"\$verifier" verify-host-kit-archive[\s\S]+--architecture amd64[\s\S]+"\$verifier" verify-host-kit-archive[\s\S]+--architecture arm64/,
  );
  assert.match(body, /tar --sort=name --mtime='@0'/);
  assert.match(body, /gzip -n/);
  for (const workflowPath of [
    ".github/workflows/release.yml",
    ".github/workflows/infra-ci.yml",
    ".github/workflows/review-promotion.yml",
  ]) {
    const workflow = parseYaml(readFileSync(workflowPath, "utf8")) as {
      jobs: Record<string, { steps?: Array<{ run?: string }> }>;
    };
    for (const [jobName, job] of Object.entries(workflow.jobs)) {
      for (const [index, step] of (job.steps ?? []).entries()) {
        assert.doesNotMatch(
          step.run ?? "",
          /\$\{\{/,
          `${workflowPath} ${jobName} run step ${index} interpolates an Actions expression into shell`,
        );
      }
    }
  }
  assert.match(packageJson.scripts["verify:all"], /gates:local/);
  assert.match(packageJson.scripts["verify:all"], /evidence:release/);
  assert.doesNotMatch(packageJson.scripts["verify:all"], /cluster|gitops/i);
  assert.match(gateRunner, /g4-dependencies/);
  assert.match(gateRunner, /security:audit/);
  assert.match(gateRunner, /productionQualification/);
  assert.match(gateRunner, /process\.platform/);
  assert.match(gateRunner, /process\.arch/);
  assert.match(gateRunner, /toolchain/);
  assert.match(
    releaseEvidenceVerifier,
    /execution\.platform !== "linux"[\s\S]+execution\.productionQualification !== true/,
  );
  assert.doesNotMatch(gateRunner, /disposable-cluster|gitops|k3s/i);
  assert.match(gateRunner, /g6-sbom/);
  assert.doesNotMatch(body, /disposable-cluster|gitops|k3s/i);
  assert.match(body, /artifacts\/secure-saas-infra\.spdx\.json/);
  assert.match(body, /artifacts\/management-seed-test-results\.json/);
  assert.match(body, /artifacts\/management-seed-test-results\.junit\.xml/);
  assert.match(body, /sha256sum[\s\S]+secure-saas-infra\.spdx\.json/);
  assert.match(
    body,
    /sha256sum[\s\S]+management-seed-test-results\.json[\s\S]+management-seed-test-results\.junit\.xml/,
  );
  assert.match(body, /sha256sum[\s\S]+security-contract-evidence\.json/);
  assert.match(body, /sha256sum[\s\S]+management-seed-release-manifest\.json/);
  assert.match(body, /gh release create[\s\S]+secure-saas-infra\.spdx\.json/);
  assert.match(
    body,
    /gh release create[\s\S]+management-seed-test-results\.json[\s\S]+management-seed-test-results\.junit\.xml/,
  );
  assert.match(safeGit, /GIT_NO_REPLACE_OBJECTS: "1"/);
  assert.match(signerStage0, /assertCanonicalGitGraph\(\)/);
  assert.match(signerStage0, /refs\/replace/);
  assert.match(signerStage0, /\.git", "info", "grafts"/);
  assert.match(
    releaseEvidenceVerifier,
    /verifyEmbeddedLocalGateEvidence\(root, report, source\) \{[\s\S]*verifyLocalGates\([\s\S]*false\)/,
  );
  assert.match(body, /RELEASE_REVISION: \$\{\{ github\.sha \}\}/);
  assert.match(body, /peel_live_tag\(\)/);
  assert.match(body, /git\/ref\/tags\/\$\{RELEASE_TAG\}/);
  assert.match(body, /git\/tags\/\$\{object_sha\}/);
  assert.match(body, /test "\$\(peel_live_tag\)" = "\$RELEASE_REVISION"/);
  assert.match(body, /gh release create "\$RELEASE_TAG" --verify-tag/);
  assert.match(body, /gh release view "\$RELEASE_TAG" --json isImmutable/);
  assert.match(body, /releases\/tags\/\$\{RELEASE_TAG\}/);

  const workflowPaths = [
    ".github/workflows/release.yml",
    ".github/workflows/infra-ci.yml",
    ".github/workflows/review-promotion.yml",
  ];
  let slsaGeneratorReferences = 0;
  for (const workflowPath of workflowPaths) {
    for (const line of readFileSync(workflowPath, "utf8").split("\n")) {
      const match = /^\s*uses:\s*([^\s#]+)/.exec(line);
      if (!match) continue;
      if (
        match[1] ===
        "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0"
      ) {
        slsaGeneratorReferences += 1;
        assert.equal(workflowPath, ".github/workflows/release.yml");
        continue;
      }
      assert.match(
        match[1],
        /@[a-f0-9]{40}$/,
        `${workflowPath} must pin ${match[1]} to a full commit SHA`,
      );
    }
  }
  assert.equal(slsaGeneratorReferences, 2);
});

test("privileged bootstrap inputs are packaged only as an authenticated release kit", () => {
  const packager = readFileSync("scripts/package-bootstrap-host-kit", "utf8");
  const installer = readFileSync("scripts/install-bootstrap-runtime", "utf8");
  const workflow = readFileSync(".github/workflows/release.yml", "utf8");
  assert.match(packager, /configured !== true/);
  assert.match(packager, /artifacts\/deus-aws-bootstrap/);
  assert.match(packager, /security\/bootstrap-qualification-trust\.json/);
  assert.match(packager, /scripts\/install-bootstrap-runtime/);
  assert.match(packager, /scripts\/bootstrap-signing-stage0\.mjs/);
  assert.match(packager, /management-seed-source-manifest\.json/);
  assert.match(packager, /--architecture/);
  assert.match(workflow, /ubuntu-24\.04-arm/);
  assert.match(workflow, /go test -count=1/);
  assert.match(workflow, /-amd64\.tar\.gz/);
  assert.match(workflow, /-arm64\.tar\.gz/);
  assert.match(
    workflow,
    /digest=\$\(cd artifacts\/host-kit-download && sha256sum/,
  );
  assert.doesNotMatch(
    workflow,
    /sha256sum \\\n\s+"artifacts\/host-kit-download\/deus-bootstrap-host-kit-\$\{RELEASE_TAG\}/,
  );
  assert.match(packager, /scripts\/write-bootstrap-runtime-provenance\.mjs/);
  assert.match(packager, /sha256sum/);
  assert.match(packager, /--sort=name/);
  assert.match(packager, /--mtime='@0'/);
  assert.match(packager, /actual_revision/);
  assert.match(packager, /actual_tag/);
  assert.match(installer, /assert_root_protected/);
  assert.match(installer, /bootstrap-signing-stage0\.mjs/);
  assert.match(installer, /management-seed-source-manifest\.json/);
  assert.match(
    installer,
    /repository\/scripts\/write-bootstrap-runtime-provenance\.mjs|repository.*write-bootstrap-runtime-provenance/,
  );

  const isolated = workflow.slice(
    workflow.indexOf("\n  host-kit:"),
    workflow.indexOf("\n  provenance:"),
  );
  assert.match(isolated, /needs: build/);
  assert.match(isolated, /build-native-bootstrap-launcher/);
  assert.match(isolated, /package-bootstrap-host-kit/);
  assert.doesNotMatch(isolated, /npm|pulumi/i);
  assert.match(workflow, /host-kit-provenance:/);

  const runbook = readFileSync("docs/management-seed-runbook.md", "utf8");
  assert.match(runbook, /slsa-verifier verify-artifact/);
  assert.match(
    runbook,
    /--source-uri github\.com\/codefly-dev\/secure-saas-infra/,
  );
  assert.match(runbook, /RELEASE_REVISION/);
  assert.match(runbook, /REVIEWED_SOURCE_REVISION/);
  assert.doesNotMatch(runbook, /APPROVED_REVISION/);
  assert.match(runbook, /git diff --name-only/);
  assert.match(runbook, /security\/adversarial-review-disposition\.json/);
  assert.match(runbook, /--revision "\$RELEASE_REVISION"/);
  assert.doesNotMatch(runbook, /--revision "\$REVIEWED_SOURCE_REVISION"/);
  assert.match(runbook, /verify-host-kit-archive/);
  assert.match(runbook, /test ! -e .*stage0\/\$\{RELEASE_TAG\}/);
  assert.ok(
    runbook.indexOf("verify-host-kit-archive") <
      runbook.indexOf("sudo /bin/tar -xzf"),
    "native archive preflight must precede privileged extraction",
  );
  assert.doesNotMatch(runbook, /sudo \.\/scripts\/install-bootstrap-runtime/);

  const launcherBuilder = readFileSync(
    "scripts/build-native-bootstrap-launcher",
    "utf8",
  );
  assert.match(
    launcherBuilder,
    /\[ -L "\$artifact_directory" \].*artifacts must be a direct directory/s,
  );
  assert.match(
    launcherBuilder,
    /\[ -L "\$output" \].*output must be a direct regular file/s,
  );
  assert.match(
    launcherBuilder,
    /\/bin\/rm -f "\$output"\n\/bin\/mv "\$temporary" "\$output"\ncleanup\ntrap - EXIT/,
  );
});

test("source CI and evidence-only promotion enforce the two-stage review topology", () => {
  const workflow = readFileSync(".github/workflows/infra-ci.yml", "utf8");
  const promotion = readFileSync(
    ".github/workflows/review-promotion.yml",
    "utf8",
  );
  const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as {
    scripts: Record<string, string>;
  };
  const gateRunner = readFileSync("scripts/run-local-gates.mjs", "utf8");
  const secretScanner = readFileSync("scripts/scan-source-secrets", "utf8");

  assert.match(workflow, /run: npm run validate:source/);
  assert.doesNotMatch(workflow, /run: npm run verify:all/);
  assert.match(
    workflow,
    /name: source qualification \(\$\{\{ matrix\.architecture \}\}\)/,
  );
  assert.match(workflow, /runner: ubuntu-24\.04-arm/);
  assert.match(
    workflow,
    /name: secure-saas-infra-sbom-\$\{\{ matrix\.architecture \}\}/,
  );
  assert.match(
    workflow,
    /provider=artifacts\/bootstrap-pulumi-home\/plugins\/resource-aws-v7\.27\.0\/pulumi-resource-aws/,
  );
  assert.match(
    workflow,
    /env -i HOME="\$RUNNER_TEMP\/provider-smoke-home" LANG=C "\$provider" --version/,
  );
  assert.match(promotion, /run: npm run validate:source/);
  assert.doesNotMatch(promotion, /run: npm run verify:all/);
  assert.doesNotMatch(promotion, /artifacts\/local-gate-evidence\.json/);
  assert.match(promotion, /security\/adversarial-review-disposition\.json/);
  assert.match(promotion, /fetch-depth: 2/);
  assert.match(promotion, /pull_request\.head\.sha \|\| github\.sha/);
  assert.match(promotion, /DEUS_REVIEW_BASE_REVISION/);
  assert.match(promotion, /verify-review-promotion\.mjs/);
  assert.match(promotion, /run: npm ci --ignore-scripts/);
  assert.ok(
    promotion.indexOf("run: npm ci --ignore-scripts") <
      promotion.indexOf("run: node scripts/verify-review-promotion.mjs"),
    "promotion dependencies must be installed before the verifier runs",
  );
  assert.match(workflow, /artifacts\/secure-saas-infra\.spdx\.json/);
  assert.match(workflow, /artifacts\/management-seed-test-results\.json/);
  assert.match(workflow, /artifacts\/management-seed-test-results\.junit\.xml/);
  const testRunner = readFileSync("scripts/run-iac-unit-tests.mjs", "utf8");
  const testReporter = readFileSync(
    "scripts/management-seed-test-reporter.mjs",
    "utf8",
  );
  const releaseManifest = readFileSync(
    "scripts/write-management-seed-release-manifest.mjs",
    "utf8",
  );
  assert.match(
    testRunner,
    /evidence\.security\.deus\.dev\/management-seed-test-metadata\/v1/,
  );
  assert.match(testRunner, /\.\.\.scope\.sourceFiles/);
  assert.match(testRunner, /assertTestEvidenceSchema\(report\)/);
  assert.match(testReporter, /stableFailureCode/);
  assert.match(releaseManifest, /management-seed-test-results\.json/);
  assert.match(releaseManifest, /management-seed-test-results\.junit\.xml/);
  assert.match(
    packageJson.scripts["validate:source"],
    /npm ci --ignore-scripts/,
  );
  assert.match(packageJson.scripts["validate:source"], /security:secrets/);
  assert.match(packageJson.scripts["validate:source"], /security:go-vuln/);
  assert.match(packageJson.scripts["validate:source"], /validate:local/);
  assert.match(packageJson.scripts["validate:source"], /security:audit/);
  assert.equal(
    packageJson.scripts["security:secrets"],
    "./scripts/scan-source-secrets",
  );
  assert.equal(
    packageJson.scripts["security:go-vuln"],
    "go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...",
  );
  assert.match(secretScanner, /version=8\.30\.1/);
  assert.match(secretScanner, /git ls-files -co --exclude-standard -z/);
  assert.match(secretScanner, /"\$temporary\/gitleaks" dir/);
  assert.match(secretScanner, /"\$temporary\/gitleaks" git/);
  assert.match(secretScanner, /--log-opts=--all/);
  assert.match(secretScanner, /--redact=100/);
  assert.match(secretScanner, /expected_sha256=/);
  assert.match(packageJson.scripts["verify:all"], /gates:local/);
  assert.match(packageJson.scripts["verify:all"], /evidence:release/);
  assert.doesNotMatch(packageJson.scripts["verify:all"], /cluster|gitops/i);
  for (const gate of [
    "g0-clean-install",
    "g0-static-contracts",
    "g1-unit",
    "g4-dependencies",
    "g6-sbom",
  ]) {
    assert.match(gateRunner, new RegExp(gate));
  }
  assert.match(
    gateRunner,
    /g0-clean-install", "npm", \["ci", "--ignore-scripts"\]/,
  );
  assert.match(workflow, /pulumi-version: "3\.253\.0"/);
  assert.match(workflow, /runner: ubuntu-24\.04-arm/);
  assert.match(workflow, /go vet \.\/cmd\/deus-aws-bootstrap/);
  assert.match(workflow, /go test \.\/cmd\/deus-aws-bootstrap/);
  assert.doesNotMatch(workflow, /docker|disposable-cluster|gitops|k3s/i);
  assert.match(promotion, /security-contract-evidence\.json/);
  assert.doesNotMatch(workflow, /disposable-cluster-validation\.json/);

  const codeowners = readFileSync(".github/CODEOWNERS", "utf8");
  assert.match(codeowners, /@codefly-dev\/platform-security/);
  assert.doesNotMatch(codeowners, /your-github-org|placeholder/i);
});

test("management-seed release and dependency inventories exclude the platform layer", () => {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  const scope = JSON.parse(
    readFileSync("security/management-seed-qualification-scope.json", "utf8"),
  );
  const workflow = readFileSync(".github/workflows/release.yml", "utf8");
  const project = readFileSync("Pulumi.yaml", "utf8");
  const audit = readFileSync("scripts/audit-dependencies.mjs", "utf8");
  const manifestWriter = readFileSync(
    "scripts/write-management-seed-release-manifest.mjs",
    "utf8",
  );
  const releaseVerifier = readFileSync(
    "scripts/verify-management-seed-release-evidence.mjs",
    "utf8",
  );

  assert.deepEqual(Object.keys(packageJson.dependencies).sort(), [
    "@pulumi/aws",
    "@pulumi/pulumi",
  ]);
  assert.equal(packageJson.devDependencies["@pulumi/kubernetes"], undefined);
  assert.ok(
    Object.keys(packageJson.scripts).every(
      (name) => !name.startsWith("platform:"),
    ),
  );
  for (const path of [
    "gitops",
    ".github/workflows/platform-ci.yml",
    "scripts/validate-gitops.mjs",
    "scripts/validate-argocd-cluster-roles.mjs",
    "scripts/validate-disposable-cluster.mjs",
    "src/argocd.ts",
    "src/argocdValues.ts",
    "src/stacks/argocdStack.ts",
  ]) {
    assert.equal(existsSync(path), false, `${path} remains in cloud IaC`);
  }
  assert.ok(
    scope.contracts.quarantinedChecked.some(
      (entry: { contract: string; schema: string }) =>
        entry.contract === "platform-iac-handoff-v1.json" &&
        entry.schema === "platform-iac-handoff-v1.schema.json",
    ),
  );
  assert.match(project, /main: dist-management-seed\/managementSeed\.js/);
  assert.match(audit, /dist-management-seed-support\/dependencySecurity\.js/);
  assert.doesNotMatch(audit, /\.\.\/dist\/dependencySecurity\.js/);
  assert.match(
    manifestWriter,
    /verifyManagementSeedReleaseEvidence\(root, \{[\s\S]+requireClean: true/,
  );
  assert.match(manifestWriter, /requireQualified: !args\.sourceRelease/);
  assert.match(manifestWriter, /source-release-unqualified/);
  assert.match(manifestWriter, /sealed-linux-production/);
  assert.match(
    releaseVerifier,
    /verifyLocalGates\([\s\S]+repositoryRoot,[\s\S]+gates,[\s\S]+source,/,
  );
  assert.match(releaseVerifier, /release\.validation\.localGates/);
  assert.match(
    releaseVerifier,
    /canonicalJson\(release\.buildInputs\)[\s\S]+canonicalJson\(source\.entries\)/,
  );
  assert.match(workflow, /npm run release:manifest/);
  assert.match(workflow, /-T artifacts\/management-seed-release-files\.txt/);
  assert.doesNotMatch(
    workflow,
    /\b(?:dist|contracts|docs|schemas|scripts|security|artifacts)\s*$/m,
  );
  for (const entry of scope.sourceFiles) {
    assert.doesNotMatch(
      entry,
      /(?:gitops|argocd|disposable-cluster|infrastructure-controller|managed-postgres|cloud-context)/i,
    );
  }
  assert.ok(
    scope.tests.included.every((entry: string) =>
      scope.sourceFiles.includes(entry),
    ),
  );
  assert.ok(
    scope.tests.quarantined.every(
      (entry: string) => !scope.sourceFiles.includes(entry),
    ),
  );
  assert.deepEqual(scope.tests.compilationSourceFiles, [
    "policy/managementSeed.ts",
    "src/dependencySecurity.ts",
    "src/managementSeedConfig.ts",
    "src/organization.ts",
    ...scope.tests.included.slice(0, 7),
    "tests/helpers/managementSeedPulumiMocks.ts",
    ...scope.tests.included.slice(7),
  ]);
  assert.ok(
    scope.tests.compiledOutputs.every(
      (entry: string) =>
        !/(?:codefly|kubernetes|argocd|gitops|managedPostgres|paas)/i.test(
          entry,
        ),
    ),
  );
});

test("Pulumi Cloud recovery is exact, encrypted, and repository-external", () => {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  const decision = JSON.parse(
    readFileSync("security/pulumi-cloud-backend.json", "utf8"),
  );
  const backup = readFileSync("scripts/backup-pulumi-cloud-state.mjs", "utf8");
  const runbook = readFileSync("docs/pulumi-cloud-recovery.md", "utf8");

  assert.equal(decision.backendUrl, "https://api.pulumi.com");
  assert.equal(decision.organization, "toussaint-antoine-gmail-com");
  assert.equal(decision.project, "secure-saas-infra");
  assert.deepEqual(decision.allowedStacks, ["management"]);
  assert.equal(decision.secretsProvider, "pulumi-cloud");
  assert.equal(decision.recovery.maximumRecoveryPointAge, "PT1H");
  assert.equal(decision.recovery.plaintextSecretsPermitted, false);
  assert.equal(decision.recovery.repositoryLocalBackupPermitted, false);
  assert.equal(
    packageJson.scripts["pulumi:backup"],
    "node scripts/backup-pulumi-cloud-state.mjs",
  );
  assert.match(backup, /process\.umask\(0o077\)/);
  assert.match(backup, /Pulumi recovery exports must be stored outside/);
  assert.match(backup, /flag:\s*"wx",\s*mode:\s*0o600/s);
  assert.match(backup, /createHash\("sha256"\)/);
  assert.doesNotMatch(backup, /show-secrets/);
  assert.match(runbook, /service-encrypted deployment/);
  assert.match(runbook, /Google-backed account/);
  assert.match(runbook, /registered Pulumi passkey/);
  assert.match(runbook, /Google 2-Step Verification/);
  assert.doesNotMatch(runbook, /Pulumi MFA recovery key/);
  assert.match(
    runbook,
    /Individual Edition does not provide Pulumi Cloud's self-service/,
  );
  assert.match(runbook, /Do not use `--force`/);
  assert.match(runbook, /Import mutates Pulumi state/);
  assert.doesNotMatch(
    runbook,
    /Use Pulumi Cloud's deleted-stack recovery from the console/,
  );
});
