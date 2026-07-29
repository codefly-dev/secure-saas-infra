import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";

const script = "scripts/validate-ownership-boundary.mjs";
const stagedFiles = [
  "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
  "gitops/bootstrap/argocd/base/projects.appproject.yaml",
  "scripts/verify-review-promotion.mjs",
  "scripts/credential-free-qualification",
  ".github/workflows/review-promotion.yml",
  "package.json",
  "security/management-seed-qualification-scope.json",
];

function stage(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "ownership-boundary-"));
  for (const relative of stagedFiles) {
    const destination = path.join(root, relative);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(relative, destination);
  }
  return root;
}

function run(root: string) {
  return spawnSync(process.execPath, [script, "--root", root], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

function editJson(root: string, relative: string, mutate: (value: any) => void) {
  const file = path.join(root, relative);
  const value = JSON.parse(readFileSync(file, "utf8"));
  mutate(value);
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

test("ownership boundary holds for the real repository", () => {
  const result = run(process.cwd());
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /disjoint paths and responsibilities/);
});

test("a handoff that allows application mutation is rejected", () => {
  const root = stage();
  try {
    editJson(
      root,
      "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
      (handoff) => {
        handoff.applicationMutationAllowed = true;
      },
    );
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /OWNERSHIP_BOUNDARY_DENIED/);
    assert.match(result.stderr, /forbid application mutation/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a handoff that embeds an Argo Application payload is rejected", () => {
  const root = stage();
  try {
    editJson(
      root,
      "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
      (handoff) => {
        handoff.readiness.smuggled = { kind: "Application" };
      },
    );
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not embed an Argo Application/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a plugin-owned first-party Argo source binding is rejected", () => {
  const root = stage();
  try {
    const file = path.join(
      root,
      "gitops/bootstrap/argocd/base/projects.appproject.yaml",
    );
    const poisoned = readFileSync(file, "utf8").replace(
      "  sourceRepos:\n    - https://github.com/codefly-dev/secure-saas-infra.git",
      "  sourceRepos:\n    - https://github.com/codefly-dev/tenant-plugin.git",
    );
    writeFileSync(file, poisoned);
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /plugin-owned repository source binding/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a cloud-IaC script that publishes application commits is rejected", () => {
  const root = stage();
  try {
    editJson(root, "package.json", (manifest) => {
      manifest.scripts["publish:apps"] = "git push origin gitops";
    });
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not publish application commits/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a platform path inside the cloud-IaC inventory is rejected", () => {
  const root = stage();
  try {
    editJson(
      root,
      "security/management-seed-qualification-scope.json",
      (scope) => {
        scope.sourceFiles.push("gitops/base/kyverno/workload-native-admission.yaml");
      },
    );
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not own the platform tree/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("qualification that leaks a provider credential is rejected", () => {
  const root = stage();
  try {
    const file = path.join(root, "scripts/credential-free-qualification");
    const poisoned = readFileSync(file, "utf8").replace(
      "${PULUMI_ACCESS_TOKEN-}",
      "",
    );
    writeFileSync(file, poisoned);
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must reject 'PULUMI_ACCESS_TOKEN'/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
