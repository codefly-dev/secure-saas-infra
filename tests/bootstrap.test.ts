import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

test("bootstrap script exposes a usage banner and dry-run mode", () => {
  const help = execFileSync(
    process.execPath,
    ["scripts/bootstrap.mjs", "--help"],
    { encoding: "utf8" },
  );
  assert.match(help, /--environment <env\|all>/);
  assert.match(help, /--phases <list>/);
  assert.match(help, /Phases.*foundation.*shared.*workload.*edge/s);
  assert.match(help, /OrganizationAccountAccessRole/);
});

test("bootstrap script enumerates the modular per-env stack plan", () => {
  const body = readFileSync("scripts/bootstrap.mjs", "utf8");

  for (const expected of [
    /buildPlan/,
    /github-governance/,
    /management/,
    /identity/,
    /log-archive/,
    /security-tooling/,
    /shared-services/,
    /dns/,
    /network-routing/,
    /backup-\$\{env\}/,
    /platform-\$\{env\}/,
    /execution-\$\{env\}/,
    /waf-\$\{env\}/,
    /ingress-\$\{env\}/,
    /argocd-platform-\$\{env\}/,
    /argocd-execution-\$\{env\}/,
  ]) {
    assert.match(body, expected);
  }
});

test("per-environment example files are present for the modular stacks", () => {
  for (const stack of ["waf", "ingress", "backup"]) {
    for (const env of ["dev", "staging", "prod"]) {
      const body = readFileSync(
        `Pulumi.${stack}-${env}.yaml.example`,
        "utf8",
      );
      assert.match(body, new RegExp(`stackKind: ${stack}`));
      assert.match(body, new RegExp(`environment: ${stack}-${env}`));
    }
  }
  for (const env of ["dev", "staging", "prod"]) {
    for (const spoke of ["platform", "execution"]) {
      const body = readFileSync(
        `Pulumi.argocd-${spoke}-${env}.yaml.example`,
        "utf8",
      );
      assert.match(body, /stackKind: argocd/);
      assert.match(
        body,
        new RegExp(`clusterStackRef: .+/${spoke}-${env}`),
      );
    }
  }
  const dns = readFileSync("Pulumi.dns.yaml.example", "utf8");
  assert.match(dns, /environmentSubdomains:/);
  assert.match(dns, /- dev/);
  assert.match(dns, /- staging/);
  assert.match(dns, /- prod/);
});
