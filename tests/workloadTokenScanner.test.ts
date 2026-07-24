import test from "node:test";
import assert from "node:assert/strict";
import { stringify } from "yaml";
import {
  assertRenderedWorkloadTokens,
  scanRenderedWorkloadTokens,
  type WorkloadTokenException,
} from "../src/core";

const scannedAt = "2026-07-16T12:00:00Z";

const workloadKinds = [
  ["v1", "Pod"],
  ["v1", "ReplicationController"],
  ["apps/v1", "Deployment"],
  ["apps/v1", "StatefulSet"],
  ["apps/v1", "DaemonSet"],
  ["apps/v1", "ReplicaSet"],
  ["batch/v1", "Job"],
  ["batch/v1", "CronJob"],
  ["argoproj.io/v1alpha1", "Rollout"],
] as const;

test("scanner parses the full YAML stream and accepts every hardened workload kind", () => {
  const resources = [
    serviceAccount(false),
    ...workloadKinds.map(([apiVersion, kind], index) =>
      workload(apiVersion, kind, `workload-${index}`, false),
    ),
  ];
  const report = assertRenderedWorkloadTokens({
    sources: [{ path: "rendered/all.yaml", yaml: yamlStream(resources) }],
    scannedAt,
  });
  assert.equal(report.pass, true);
  assert.equal(report.workloadCount, workloadKinds.length);
  assert.equal(report.serviceAccountCount, 1);
  assert.equal(report.resourceCount, resources.length);
  assert.match(report.sourceDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(report.exceptionsUsed, []);
});

test("scanner denies omitted, true, null, and string false automount values", () => {
  for (const [id, automount] of [
    ["omitted", undefined],
    ["true", true],
    ["null", null],
    ["string", "false"],
  ] as const) {
    const report = scanRenderedWorkloadTokens({
      sources: [
        {
          path: `rendered/${id}.yaml`,
          yaml: stringify(workload("apps/v1", "Deployment", id, automount)),
        },
      ],
      scannedAt,
    });
    assert.equal(report.pass, false, id);
    assert.ok(
      report.findings.some(
        (finding) => finding.code === "TOKEN_SCAN_WORKLOAD_AUTOMOUNT_NOT_FALSE",
      ),
      id,
    );
  }
});

test("scanner denies unsafe ServiceAccounts and projected tokens inside secondary List workloads", () => {
  const deployment = workload("apps/v1", "Deployment", "secondary", false);
  const podSpec = (deployment.spec as any).template.spec;
  podSpec.volumes = [
    {
      name: "api-token",
      projected: {
        sources: [
          { configMap: { name: "public" } },
          { serviceAccountToken: { audience: "kubernetes" } },
        ],
      },
    },
  ];
  const report = scanRenderedWorkloadTokens({
    sources: [
      {
        path: "rendered/list.yaml",
        yaml: stringify({
          apiVersion: "v1",
          kind: "List",
          items: [serviceAccount(undefined), deployment],
        }),
      },
    ],
    scannedAt,
  });
  assert.equal(report.workloadCount, 1);
  assert.equal(report.serviceAccountCount, 1);
  assert.deepEqual(
    new Set(report.findings.map((finding) => finding.code)),
    new Set([
      "TOKEN_SCAN_PROJECTED_TOKEN_FORBIDDEN",
      "TOKEN_SCAN_SERVICE_ACCOUNT_AUTOMOUNT_NOT_FALSE",
    ]),
  );
});

test("scanner fails closed for unknown PodSpec-shaped CRDs and missing known PodSpecs", () => {
  const unknown = {
    apiVersion: "platform.deus.dev/v1alpha1",
    kind: "MagicDeployment",
    metadata: { name: "unknown", namespace: "tenant-warden" },
    spec: { template: { spec: { containers: [{ name: "app" }] } } },
  };
  const missing = {
    apiVersion: "apps/v1",
    kind: "Deployment",
    metadata: { name: "missing", namespace: "tenant-warden" },
    spec: {},
  };
  const report = scanRenderedWorkloadTokens({
    sources: [
      { path: "rendered/unknown.yaml", yaml: yamlStream([unknown, missing]) },
    ],
    scannedAt,
  });
  assert.deepEqual(
    new Set(report.findings.map((finding) => finding.code)),
    new Set([
      "TOKEN_SCAN_WORKLOAD_KIND_UNKNOWN",
      "TOKEN_SCAN_POD_SPEC_MISSING",
    ]),
  );
});

test("scanner rejects duplicate YAML keys, aliases, and duplicate resource identities", () => {
  const duplicateKey = scanRenderedWorkloadTokens({
    sources: [
      {
        path: "rendered/duplicate-key.yaml",
        yaml: `apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app\n  name: other\n`,
      },
    ],
    scannedAt,
  });
  assert.ok(
    duplicateKey.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_YAML_INVALID",
    ),
  );

  const alias = scanRenderedWorkloadTokens({
    sources: [
      {
        path: "rendered/alias.yaml",
        yaml: `apiVersion: v1\nkind: ServiceAccount\nmetadata: &meta\n  name: app\n  namespace: tenant-warden\ncopy: *meta\nautomountServiceAccountToken: false\n`,
      },
    ],
    scannedAt,
  });
  assert.ok(
    alias.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_YAML_INVALID",
    ),
  );

  const repeated = serviceAccount(false);
  const duplicateIdentity = scanRenderedWorkloadTokens({
    sources: [
      {
        path: "rendered/duplicate-resource.yaml",
        yaml: yamlStream([repeated, repeated]),
      },
    ],
    scannedAt,
  });
  assert.ok(
    duplicateIdentity.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_RESOURCE_DUPLICATE",
    ),
  );
});

test("exceptions are exact, approved, expiring, consumed, and cannot be stale", () => {
  const unsafe = workload("apps/v1", "Deployment", "legacy", true);
  const exception: WorkloadTokenException = {
    id: "legacy.token.review",
    apiVersion: "apps/v1",
    kind: "Deployment",
    namespace: "tenant-warden",
    name: "legacy",
    issue: "workload-automount",
    reason: "SEC-1234 temporary Kubernetes API access",
    approvedBy: "security.platform",
    expiresAt: "2026-07-17T12:00:00Z",
  };
  const accepted = scanRenderedWorkloadTokens({
    sources: [{ path: "rendered/legacy.yaml", yaml: stringify(unsafe) }],
    scannedAt,
    exceptions: [exception],
  });
  assert.equal(accepted.pass, true);
  assert.deepEqual(accepted.exceptionsUsed, [exception.id]);

  const expired = scanRenderedWorkloadTokens({
    sources: [{ path: "rendered/legacy.yaml", yaml: stringify(unsafe) }],
    scannedAt,
    exceptions: [{ ...exception, expiresAt: scannedAt }],
  });
  assert.ok(
    expired.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_EXCEPTION_INVALID",
    ),
  );
  assert.ok(
    expired.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_WORKLOAD_AUTOMOUNT_NOT_FALSE",
    ),
  );

  const unused = scanRenderedWorkloadTokens({
    sources: [
      {
        path: "rendered/hardened.yaml",
        yaml: stringify(workload("apps/v1", "Deployment", "legacy", false)),
      },
    ],
    scannedAt,
    exceptions: [exception],
  });
  assert.ok(
    unused.findings.some(
      (finding) => finding.code === "TOKEN_SCAN_EXCEPTION_UNUSED",
    ),
  );
});

test("scan evidence is deterministic and binds every rendered source byte", () => {
  const source = stringify(workload("apps/v1", "Deployment", "digest", false));
  const first = scanRenderedWorkloadTokens({
    sources: [{ path: "rendered/digest.yaml", yaml: source }],
    scannedAt,
  });
  const second = scanRenderedWorkloadTokens({
    sources: [{ path: "rendered/digest.yaml", yaml: source }],
    scannedAt,
  });
  const changed = scanRenderedWorkloadTokens({
    sources: [{ path: "rendered/digest.yaml", yaml: `${source}\n` }],
    scannedAt,
  });
  assert.deepEqual(first, second);
  assert.notEqual(first.sourceDigest, changed.sourceDigest);
  assert.throws(
    () =>
      assertRenderedWorkloadTokens({
        sources: [
          {
            path: "rendered/unsafe.yaml",
            yaml: stringify(workload("apps/v1", "Deployment", "unsafe", true)),
          },
        ],
        scannedAt,
      }),
    /WORKLOAD_TOKEN_SCAN_FAILED.*TOKEN_SCAN_WORKLOAD_AUTOMOUNT_NOT_FALSE/,
  );
});

function serviceAccount(automount: unknown) {
  return {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: { name: "app", namespace: "tenant-warden" },
    ...(automount === undefined
      ? {}
      : { automountServiceAccountToken: automount }),
  };
}

function workload(
  apiVersion: string,
  kind: string,
  name: string,
  automount: unknown,
) {
  const podSpec = {
    serviceAccountName: "app",
    containers: [{ name: "app", image: "example.invalid/app@sha256:deadbeef" }],
    ...(automount === undefined
      ? {}
      : { automountServiceAccountToken: automount }),
  };
  const spec =
    kind === "Pod"
      ? podSpec
      : kind === "CronJob"
        ? { jobTemplate: { spec: { template: { spec: podSpec } } } }
        : { template: { spec: podSpec } };
  return {
    apiVersion,
    kind,
    metadata: { name, namespace: "tenant-warden" },
    spec,
  };
}

function yamlStream(resources: readonly unknown[]) {
  return resources.map((resource) => stringify(resource)).join("---\n");
}
