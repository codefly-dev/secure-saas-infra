import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("release workflow uses the SLSA Level 3 generator with a tagged ref", () => {
  const body = readFileSync(".github/workflows/release.yml", "utf8");

  assert.match(body, /uses: slsa-framework\/slsa-github-generator\/.+@v\d+\.\d+\.\d+/);
  assert.match(body, /id-token: write/);
  assert.match(body, /provenance-name:/);
  assert.match(body, /environment: production/);
  assert.match(body, /tags:\s*\n\s*-\s*"v\*\.\*\.\*"/);
});

test("vault and falco Argo CD applications are wired into the bootstrap", () => {
  const kustomization = readFileSync(
    "gitops/bootstrap/argocd/base/kustomization.yaml",
    "utf8",
  );
  assert.match(kustomization, /vault.application.yaml/);
  assert.match(kustomization, /falco.application.yaml/);

  const vault = readFileSync(
    "gitops/bootstrap/argocd/base/apps/vault.application.yaml",
    "utf8",
  );
  assert.match(vault, /chart: vault/);
  assert.match(vault, /seal "awskms"/);
  assert.match(vault, /raft/);

  const falco = readFileSync(
    "gitops/bootstrap/argocd/base/apps/falco.application.yaml",
    "utf8",
  );
  assert.match(falco, /chart: falco/);
  assert.match(falco, /modern_ebpf/);
});
