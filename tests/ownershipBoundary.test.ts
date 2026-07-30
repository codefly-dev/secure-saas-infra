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
const stagedPaths = [
  "contracts",
  "scripts",
  ".github",
  "security",
  "package.json",
];

function stage(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "ownership-boundary-"));
  for (const relative of stagedPaths) {
    cpSync(relative, path.join(root, relative), { recursive: true });
  }
  return root;
}

function run(root: string) {
  return spawnSync(process.execPath, [script, "--root", root], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
}

function editJson(
  root: string,
  relative: string,
  mutate: (value: any) => void,
) {
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
    editJson(root, "contracts/platform-iac-handoff-v1.json", (handoff) => {
      handoff.spec.gitops.repository =
        "https://github.com/codefly-dev/tenant-plugin.git";
    });
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /plugin-owned repository source binding/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a local platform tree is rejected after extraction", () => {
  const root = stage();
  try {
    const gitops = path.join(root, "gitops");
    mkdirSync(gitops);
    writeFileSync(
      path.join(gitops, "legacy-platform.application.yaml"),
      "kind: Application\n",
    );
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not contain the extracted platform tree/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a cloud-IaC command that publishes application commits is rejected", () => {
  const root = stage();
  try {
    editJson(root, "package.json", (manifest) => {
      manifest.scripts["publish:apps"] = "git push origin gitops";
    });
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /command 'publish:apps' must not publish/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a governed cloud-IaC script that publishes application commits is rejected", () => {
  const root = stage();
  try {
    // A publish hidden inside an invoked governed script rather than a
    // package.json command body.
    const file = path.join(root, "scripts/credential-free-qualification");
    writeFileSync(
      file,
      `${readFileSync(file, "utf8")}\ngit push origin main\n`,
    );
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /script 'scripts\/credential-free-qualification' must not publish/,
    );
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
        scope.sourceFiles.push(
          "gitops/base/kyverno/workload-native-admission.yaml",
        );
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
