import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import path from "node:path";
import { tmpdir } from "node:os";

const directory = path.resolve(
  "artifacts",
  `release-evidence-test-${process.pid}`,
);
const sbom = path.join(directory, "test.spdx.json");
const validation = path.join(directory, "contract-schema-validation.json");

test("IaC release evidence is deterministic and explicitly scoped", () => {
  prepareSbom();
  prepareValidation();
  const first = path.join(directory, "first.json");
  const second = path.join(directory, "second.json");
  try {
    const one = runGenerator(first);
    assert.equal(one.status, 0, one.stderr);
    const two = runGenerator(second);
    assert.equal(two.status, 0, two.stderr);
    assert.equal(readFileSync(first, "utf8"), readFileSync(second, "utf8"));

    const report = JSON.parse(readFileSync(first, "utf8"));
    assert.equal(report.generatedAt, "1970-01-01T00:00:00.000Z");
    assert.deepEqual(report.scope, {
      repository: "secure-saas-infra",
      qualificationScope: "aws-organizations-management-seed",
      awsMutationPerformed: false,
      cleanInstallResultsBound: false,
      staticValidationResultsBound: false,
      unitTestResultsBound: false,
      dependencyAuditResultsBound: false,
      sbomResultsBound: false,
      adversarialReviewResultsBound: false,
    });
    assert.match(report.evidenceDigest, /^[a-f0-9]{64}$/);
    assert.ok(
      report.buildInputs.some(
        (entry: any) => entry.path === "src/managementSeed.ts",
      ),
    );
    assert.ok(
      report.buildInputs.some((entry: any) => entry.path === ".tool-versions"),
    );
    assert.ok(
      report.buildInputs.some(
        (entry: any) =>
          entry.path === "security/adversarial-review-disposition.json",
      ),
    );
    assert.ok(
      report.buildInputs.some(
        (entry: any) =>
          entry.path === "schemas/bootstrap-candidate-v1.schema.json",
      ),
    );
    assert.ok(
      !report.buildInputs.some(
        (entry: any) =>
          entry.path.includes("argocd") ||
          entry.path.includes("gitops") ||
          entry.path.includes("infrastructureController") ||
          entry.path.includes("managedPostgres"),
      ),
    );
    const sourceRelease = runVerifier(first, false);
    assert.equal(sourceRelease.status, 0, sourceRelease.stderr);
    const promotedWithoutSealedGates = runVerifier(first, true);
    assert.notEqual(promotedWithoutSealedGates.status, 0);
    assert.match(
      promotedWithoutSealedGates.stderr,
      /release scope is not fully qualified/i,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("IaC release evidence rejects a substituted validation report", () => {
  prepareSbom();
  prepareValidation();
  const substituted = path.join(directory, "substituted-validation.json");
  try {
    const report = JSON.parse(readFileSync(validation, "utf8"));
    report.publishedSchemas[0].sha256 = "0".repeat(64);
    writeFileSync(substituted, `${JSON.stringify(report, null, 2)}\n`, {
      mode: 0o600,
    });
    const rejected = path.join(directory, "rejected.json");
    const result = runGenerator(rejected, substituted);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /digest does not match/i);
    assert.equal(existsSync(rejected), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("release evidence rejects version, digest, path, Unicode, duplicate, and sequence mutations", () => {
  prepareSbom();
  prepareValidation();
  const originalPath = path.join(directory, "mutation-source.json");
  try {
    const generated = runGenerator(originalPath);
    assert.equal(generated.status, 0, generated.stderr);
    const original = JSON.parse(readFileSync(originalPath, "utf8"));
    const schemaCases: Array<[string, (value: any) => void, RegExp]> = [
      [
        "future API version",
        (value) => {
          value.apiVersion =
            "evidence.security.deus.dev/management-seed-release/v2";
        },
        /schema validation.*constant/i,
      ],
      [
        "Unicode-confusable qualification scope",
        (value) => {
          value.scope.qualificationScope = "aws-organizations-management-sеed";
        },
        /schema validation.*constant/i,
      ],
      [
        "uppercase source digest",
        (value) => {
          value.source.revision = value.source.revision.toUpperCase();
        },
        /schema validation.*pattern/i,
      ],
      [
        "substituted build-input digest",
        (value) => {
          value.buildInputs[0].sha256 = "A".repeat(64);
        },
        /schema validation.*pattern/i,
      ],
      [
        "duplicate build input",
        (value) => {
          value.buildInputs.push(structuredClone(value.buildInputs[0]));
        },
        /schema validation.*(?:duplicate|unique)/i,
      ],
      [
        "path traversal",
        (value) => {
          value.validation.contractSchemas.path = "../validation.json";
        },
        /schema validation.*pattern/i,
      ],
      [
        "URI query",
        (value) => {
          value.validation.contractSchemas.path =
            "artifacts/validation.json?authority=attacker";
        },
        /schema validation.*pattern/i,
      ],
      [
        "URI fragment",
        (value) => {
          value.validation.sbom.path = "artifacts/sbom.json#attacker";
        },
        /schema validation.*pattern/i,
      ],
    ];
    for (const [name, mutate, expected] of schemaCases) {
      const hostile = structuredClone(original);
      mutate(hostile);
      hostile.evidenceDigest = releaseEvidenceDigest(hostile);
      const hostilePath = path.join(
        directory,
        `${name.replaceAll(" ", "-")}.json`,
      );
      writeFileSync(hostilePath, `${JSON.stringify(hostile, null, 2)}\n`, {
        mode: 0o600,
      });
      const result = runVerifier(hostilePath, false);
      assert.notEqual(result.status, 0, name);
      assert.match(result.stderr, expected, name);
    }

    const reordered = structuredClone(original);
    [reordered.buildInputs[0], reordered.buildInputs[1]] = [
      reordered.buildInputs[1],
      reordered.buildInputs[0],
    ];
    reordered.evidenceDigest = releaseEvidenceDigest(reordered);
    const reorderedPath = path.join(directory, "reordered-build-inputs.json");
    writeFileSync(reorderedPath, `${JSON.stringify(reordered, null, 2)}\n`, {
      mode: 0o600,
    });
    const reorderedResult = runVerifier(reorderedPath, false);
    assert.notEqual(reorderedResult.status, 0);
    assert.match(reorderedResult.stderr, /does not bind the exact source/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("IaC release evidence rejects SPDX path, multiplicity, and relationship substitution", () => {
  prepareSbom();
  prepareValidation();
  const substituted = path.join(directory, "substituted.spdx.json");
  try {
    const original = JSON.parse(readFileSync(sbom, "utf8"));
    const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
    assert.equal(original.packages.length, Object.keys(lock.packages).length);
    assert.equal(original.creationInfo.created, "1970-01-01T00:00:00.000Z");
    assert.equal(
      original.packages.find((entry: any) => entry.name === "@logdna/tail-file")
        .licenseDeclared,
      "NOASSERTION",
    );
    for (const mutate of [
      (report: any) => report.packages.pop(),
      (report: any) =>
        report.packages.push(structuredClone(report.packages[1])),
      (report: any) => {
        report.packages[1].packageFileName = "node_modules/substituted";
      },
      (report: any) => {
        report.relationships[0].relatedSpdxElement = report.packages[1].SPDXID;
      },
      (report: any) => {
        report.packages[1].licenseDeclared = "GPL-3.0-only";
      },
      (report: any) => {
        report.packages[1].downloadLocation =
          "https://attacker.invalid/package.tgz";
      },
      (report: any) => {
        report.packages[1].externalRefs = [
          {
            referenceCategory: "OTHER",
            referenceType: "attacker",
            referenceLocator: "forged",
          },
        ];
      },
      (report: any) => {
        report.comment = "forged document metadata";
      },
      (report: any) => {
        report.packages.find(
          (entry: any) => entry.name === "@logdna/tail-file",
        ).licenseDeclared = "SEE LICENSE IN LICENSE";
      },
    ]) {
      const report = structuredClone(original);
      mutate(report);
      writeFileSync(substituted, `${JSON.stringify(report, null, 2)}\n`, {
        mode: 0o600,
      });
      const result = runGenerator(
        path.join(directory, "rejected-sbom.json"),
        undefined,
        substituted,
      );
      assert.notEqual(result.status, 0);
      assert.match(
        result.stderr,
        /(?:official SPDX|invalid license expression|SPDX package path, multiplicity, document, or relationship graph)/i,
      );
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("evidence writers reject output symlinks without touching their targets", () => {
  prepareSbom();
  prepareValidation();
  const external = mkdtempSync(path.join(tmpdir(), "iac-evidence-sentinel-"));
  const sentinel = path.join(external, "sentinel.json");
  const outputLink = path.join(directory, "output-link.json");
  const ancestorLink = path.join(directory, "linked-parent");
  writeFileSync(sentinel, "do-not-touch\n", { mode: 0o600 });
  symlinkSync(sentinel, outputLink);
  symlinkSync(external, ancestorLink, "dir");
  try {
    const release = runGenerator(outputLink);
    assert.notEqual(release.status, 0);
    assert.match(release.stderr, /non-symlink/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");

    const ancestor = runGenerator(path.join(ancestorLink, "new.json"));
    assert.notEqual(ancestor.status, 0);
    assert.match(ancestor.stderr, /existing real directory/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");

    const outside = runGenerator(
      path.resolve("dist-management-seed-test", "release-evidence-audit.json"),
    );
    assert.notEqual(outside.status, 0);
    assert.match(outside.stderr, /Unsafe management-seed artifact output/);

    const packageBefore = readFileSync("package.json", "utf8");
    const traversal = runGeneratorWithOutputValue("artifacts/../package.json");
    assert.notEqual(traversal.status, 0);
    assert.match(traversal.stderr, /Unsafe management-seed artifact output/);
    assert.equal(readFileSync("package.json", "utf8"), packageBefore);
  } finally {
    rmSync(directory, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test("SBOM writer rejects unsafe paths and malformed output flags", () => {
  const base = path.resolve("artifacts", `sbom-writer-test-${process.pid}`);
  const external = mkdtempSync(path.join(tmpdir(), "iac-sbom-sentinel-"));
  const sentinel = path.join(external, "sentinel.json");
  const outputLink = path.join(base, "output.spdx.json");
  const ancestorLink = path.join(base, "linked-parent");
  mkdirSync(base, { recursive: true, mode: 0o700 });
  writeFileSync(sentinel, "do-not-touch\n", { mode: 0o600 });
  symlinkSync(sentinel, outputLink);
  symlinkSync(external, ancestorLink, "dir");
  try {
    const outputSymlink = runSbomWriter([
      "--output",
      path.relative(process.cwd(), outputLink),
    ]);
    assert.notEqual(outputSymlink.status, 0);
    assert.match(outputSymlink.stderr, /regular non-symlink file/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");

    const ancestorSymlink = runSbomWriter([
      "--output",
      path.relative(process.cwd(), path.join(ancestorLink, "new.json")),
    ]);
    assert.notEqual(ancestorSymlink.status, 0);
    assert.match(ancestorSymlink.stderr, /existing real directory/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");

    for (const args of [
      ["--output"],
      ["--output", "artifacts/one.json", "--output", "artifacts/two.json"],
      ["--unknown", "artifacts/one.json"],
    ]) {
      const malformed = runSbomWriter(args);
      assert.notEqual(malformed.status, 0);
      assert.match(malformed.stderr, /Usage: node scripts\/generate-sbom/);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test("release-manifest writer rejects output and ancestor symlinks", () => {
  const base = path.resolve(
    "artifacts",
    `release-manifest-writer-test-${process.pid}`,
  );
  const external = mkdtempSync(path.join(tmpdir(), "iac-manifest-sentinel-"));
  const sentinel = path.join(external, "sentinel.json");
  const outputLink = path.join(base, "manifest.json");
  const ancestorLink = path.join(base, "linked-parent");
  mkdirSync(base, { recursive: true, mode: 0o700 });
  writeFileSync(sentinel, "do-not-touch\n", { mode: 0o600 });
  symlinkSync(sentinel, outputLink);
  symlinkSync(external, ancestorLink, "dir");
  const run = (output: string) => {
    const probe = `
      import { writeAtomicArtifact } from "./scripts/management-seed-scope.mjs";
      writeAtomicArtifact(process.cwd(), ${JSON.stringify(
        path.relative(process.cwd(), output),
      )}, "replacement\\n");
    `;
    return spawnSync(process.execPath, ["--input-type=module", "-e", probe], {
      cwd: process.cwd(),
      encoding: "utf8",
    });
  };
  try {
    const outputSymlink = run(outputLink);
    assert.notEqual(outputSymlink.status, 0);
    assert.match(outputSymlink.stderr, /regular non-symlink file/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");

    const ancestorSymlink = run(path.join(ancestorLink, "manifest.json"));
    assert.notEqual(ancestorSymlink.status, 0);
    assert.match(ancestorSymlink.stderr, /existing real directory/);
    assert.equal(readFileSync(sentinel, "utf8"), "do-not-touch\n");
  } finally {
    rmSync(base, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test("release verifier rejects digest-valid gate claims without local-gate evidence", () => {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const forgedPath = path.join(directory, "forged-release.json");
  const subject = {
    apiVersion: "evidence.security.deus.dev/management-seed-release/v1",
    generatedAt: "1970-01-01T00:00:00.000Z",
    scope: {
      repository: "secure-saas-infra",
      qualificationScope: "aws-organizations-management-seed",
      awsMutationPerformed: false,
      cleanInstallResultsBound: true,
      staticValidationResultsBound: true,
      unitTestResultsBound: true,
      dependencyAuditResultsBound: true,
      sbomResultsBound: true,
      adversarialReviewResultsBound: true,
    },
    source: { revision: "0".repeat(40), dirty: false },
    buildInputs: [{ path: "package.json", sha256: "1".repeat(64) }],
    validation: {
      contractSchemas: {
        path: "artifacts/contract-schema-validation.json",
        sha256: "2".repeat(64),
        apiVersion: "evidence.security.deus.dev/contract-schema-validation/v1",
        publishedSchemaAggregateSha256: "3".repeat(64),
        validatedContractAggregateSha256: "4".repeat(64),
      },
      sbom: {
        path: "artifacts/secure-saas-infra.spdx.json",
        sha256: "5".repeat(64),
        spdxVersion: "SPDX-2.3",
        packageCount: 216,
      },
    },
  };
  writeFileSync(
    forgedPath,
    `${JSON.stringify({
      ...subject,
      evidenceDigest: createHash("sha256")
        .update(canonicalJson(subject))
        .digest("hex"),
    })}\n`,
    { mode: 0o600 },
  );
  const probe = `
    import { verifyManagementSeedReleaseEvidence } from "./scripts/verify-management-seed-release-evidence.mjs";
    verifyManagementSeedReleaseEvidence(process.cwd(), {
      requireClean: false,
      releaseEvidencePath: ${JSON.stringify(path.relative(process.cwd(), forgedPath))}
    });
  `;
  try {
    const result = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", probe],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /schema validation.*(?:constant|else|localGates)/i,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function prepareSbom(): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const result = spawnSync(
    process.execPath,
    [
      "scripts/generate-sbom.mjs",
      "--output",
      path.relative(process.cwd(), sbom),
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
}

function runSbomWriter(args: string[]) {
  return spawnSync(process.execPath, ["scripts/generate-sbom.mjs", ...args], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

function prepareValidation(): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const result = spawnSync(
    process.execPath,
    [
      "scripts/validate-contract-schemas.mjs",
      "--output",
      path.relative(process.cwd(), validation),
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, SOURCE_DATE_EPOCH: "0" },
    },
  );
  assert.equal(result.status, 0, result.stderr);
}

function runGenerator(
  output: string,
  validationReport?: string,
  sbomReport?: string,
) {
  const args = [
    "scripts/generate-release-evidence.mjs",
    "--validation-report",
    validationReport ?? path.relative(process.cwd(), validation),
    "--sbom",
    path.relative(process.cwd(), sbomReport ?? sbom),
    "--output",
    path.relative(process.cwd(), output),
  ];
  return spawnSync(process.execPath, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, SOURCE_DATE_EPOCH: "0" },
  });
}

function runGeneratorWithOutputValue(output: string) {
  return spawnSync(
    process.execPath,
    [
      "scripts/generate-release-evidence.mjs",
      "--validation-report",
      path.relative(process.cwd(), validation),
      "--sbom",
      path.relative(process.cwd(), sbom),
      "--output",
      output,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, SOURCE_DATE_EPOCH: "0" },
    },
  );
}

function runVerifier(releaseEvidence: string, requireQualified: boolean) {
  const probe = `
    import { verifyManagementSeedReleaseEvidence } from "./scripts/verify-management-seed-release-evidence.mjs";
    verifyManagementSeedReleaseEvidence(process.cwd(), {
      requireClean: false,
      requireQualified: ${requireQualified},
      releaseEvidencePath: ${JSON.stringify(path.relative(process.cwd(), releaseEvidence))},
      contractValidationPath: ${JSON.stringify(path.relative(process.cwd(), validation))},
      sbomPath: ${JSON.stringify(path.relative(process.cwd(), sbom))}
    });
  `;
  return spawnSync(process.execPath, ["--input-type=module", "-e", probe], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
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

function releaseEvidenceDigest(value: any): string {
  const { evidenceDigest: _ignored, ...subject } = value;
  return createHash("sha256").update(canonicalJson(subject)).digest("hex");
}
