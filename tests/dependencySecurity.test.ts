import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join, relative } from "node:path";
import { evaluateDependencyAudit } from "../src/dependencySecurity";

const exception = {
  schemaVersion: 1,
  exceptions: [
    {
      advisoryId: "GHSA-moderate",
      severity: "moderate",
      owner: "platform-security",
      reason: "Upstream fix pending",
      expiresAt: "2999-01-01T00:00:00.000Z",
      compensatingControls: ["Short-lived runner"],
    },
  ],
};

function report(severity: string, id: string) {
  return {
    vulnerabilities: {
      example: {
        severity,
        via: [
          {
            source: 123,
            severity,
            title: `${severity} synthetic advisory`,
            url: `https://github.com/advisories/${id}`,
          },
        ],
      },
    },
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: severity === "moderate" ? 1 : 0,
        high: severity === "high" ? 1 : 0,
        critical: severity === "critical" ? 1 : 0,
        total: 1,
      },
    },
  };
}

test("dependency gate accepts only reviewed, unexpired moderate advisories", () => {
  const evaluation = evaluateDependencyAudit(
    report("moderate", "GHSA-moderate"),
    exception,
    new Date("2026-07-12T00:00:00.000Z"),
  );
  assert.deepEqual(evaluation.failures, []);
  assert.equal(evaluation.accepted.length, 1);
});

test("dependency gate rejects every high advisory even if an exception is attempted", () => {
  assert.throws(
    () =>
      evaluateDependencyAudit(report("high", "GHSA-high"), {
        schemaVersion: 1,
        exceptions: [
          {
            ...exception.exceptions[0],
            advisoryId: "GHSA-high",
            severity: "high",
          },
        ],
      }),
    /cannot accept severity 'high'/,
  );
  const evaluation = evaluateDependencyAudit(report("high", "GHSA-high"), {
    schemaVersion: 1,
    exceptions: [],
  });
  assert.match(evaluation.failures[0], /HIGH dependency advisory/);

  const downgraded = report("high", "GHSA-moderate");
  downgraded.vulnerabilities.example.via[0].severity = "moderate";
  const downgradeEvaluation = evaluateDependencyAudit(downgraded, exception);
  assert.ok(
    downgradeEvaluation.failures.some((failure) =>
      /HIGH dependency advisory npm-package-example/.test(failure),
    ),
  );
});

test("dependency exception expiry is machine enforced", () => {
  const evaluation = evaluateDependencyAudit(
    report("moderate", "GHSA-moderate"),
    exception,
    new Date("3000-01-01T00:00:00.000Z"),
  );
  assert.ok(evaluation.failures.some((failure) => /expired/.test(failure)));
});

test("dependency gate fails closed on audit errors and malformed exceptions", () => {
  assert.throws(
    () =>
      evaluateDependencyAudit(
        { error: { message: "registry offline" } },
        exception,
      ),
    /returned an error/,
  );
  assert.throws(
    () =>
      evaluateDependencyAudit(report("moderate", "GHSA-moderate"), {
        schemaVersion: 1,
        exceptions: [
          { ...exception.exceptions[0], expiresAt: "not-a-timestamp" },
        ],
      }),
    /invalid expiresAt/,
  );
  assert.throws(
    () =>
      evaluateDependencyAudit(report("moderate", "GHSA-moderate"), {
        schemaVersion: 1,
        exceptions: [exception.exceptions[0], exception.exceptions[0]],
      }),
    /must be unique/,
  );
});

test("dependency gate preserves string-only findings and rejects severity/count drift", () => {
  const stringOnly = report("moderate", "ignored");
  stringOnly.vulnerabilities.example.via = ["transitive-parent"] as any;
  const evaluation = evaluateDependencyAudit(stringOnly, {
    schemaVersion: 1,
    exceptions: [],
  });
  assert.equal(evaluation.advisories.length, 1);
  assert.equal(evaluation.advisories[0].advisoryId, "npm-package-example");
  assert.match(evaluation.failures[0], /Moderate dependency advisory/);

  const mixed = report("high", "GHSA-moderate");
  mixed.vulnerabilities.example.via = [
    "transitive-high-parent",
    { ...mixed.vulnerabilities.example.via[0], severity: "moderate" },
  ] as any;
  const mixedEvaluation = evaluateDependencyAudit(mixed, {
    schemaVersion: 1,
    exceptions: [exception.exceptions[0]],
  });
  assert.ok(
    mixedEvaluation.failures.some((failure) =>
      /HIGH dependency advisory npm-package-example/.test(failure),
    ),
  );

  assert.throws(
    () => evaluateDependencyAudit(report("mystery", "GHSA-unknown"), exception),
    /unsupported severity 'mystery'/,
  );
  const inconsistent = report("high", "GHSA-high");
  inconsistent.metadata.vulnerabilities.high = 0;
  assert.throws(
    () =>
      evaluateDependencyAudit(inconsistent, {
        schemaVersion: 1,
        exceptions: [],
      }),
    /reports 0 but 1 package vulnerabilities were parsed/,
  );
});

test("SBOM generator emits a populated SPDX document from the complete lockfile", () => {
  const directory = mkdtempSync(join("artifacts", "secure-saas-sbom-"));
  const output = join(directory, "sbom.spdx.json");
  try {
    execFileSync(process.execPath, [
      "scripts/generate-sbom.mjs",
      "--output",
      relative(process.cwd(), output),
    ]);
    const sbom = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(sbom.spdxVersion, "SPDX-2.3");
    assert.ok(
      sbom.packages.length > 100,
      "SBOM should include the complete dependency tree",
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
