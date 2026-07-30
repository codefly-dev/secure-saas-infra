import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

test("onboarding helper generates filled stack files without touching examples", () => {
  const outDir = mkdtempSync(join(tmpdir(), "secure-saas-onboard-"));
  const configPath = join(outDir, "onboarding.local.json");
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        githubOrg: "deus-ai",
        pulumiOrg: "deus-pulumi",
        repo: "infra",
        accountEmailDomain: "aws.example.org",
        managementAccountId: "111122223333",
        codeownersTeam: "platform-security",
      },
      null,
      2,
    ),
  );

  const output = execFileSync(
    process.execPath,
    [
      "scripts/onboard.mjs",
      "--write",
      "--out-dir",
      outDir,
      "--config",
      configPath,
    ],
    { encoding: "utf8" },
  );

  assert.match(output, /wrote/);
  assert.ok(existsSync(join(outDir, "Pulumi.management.yaml")));

  const management = readFileSync(
    join(outDir, "Pulumi.management.yaml"),
    "utf8",
  );
  assert.match(management, /aws\+security-tooling@aws\.example\.org/);
  assert.doesNotMatch(management, /aws\+security-tooling@example\.com/);

  const platform = readFileSync(
    join(outDir, "Pulumi.platform-dev.yaml"),
    "utf8",
  );
  assert.match(platform, /deus-pulumi\/secure-saas-infra\/network/);

  const governance = readFileSync(
    join(outDir, "Pulumi.github-governance.yaml"),
    "utf8",
  );
  assert.match(governance, /github:owner: deus-ai/);
  assert.match(governance, /repository: infra/);
  assert.doesNotMatch(governance, /your-github-org/);
  assert.doesNotMatch(governance, /security@example\.com/);

  const oidc = readFileSync(join(outDir, "Pulumi.github-oidc.yaml"), "utf8");
  assert.match(oidc, /owner: deus-ai/);
  assert.match(oidc, /repo: infra/);
  assert.match(oidc, /arn:aws:iam::111122223333:policy/);

  const codeowners = readFileSync(
    join(outDir, ".github", "CODEOWNERS"),
    "utf8",
  );
  assert.match(codeowners, /@deus-ai\/platform-security/);

  const summary = readFileSync(join(outDir, "ONBOARDING.generated.md"), "utf8");
  assert.match(summary, /GitHub organization: deus-ai/);
  assert.match(summary, /qualify:bootstrap/);
  assert.doesNotMatch(summary, /^\s*pulumi\s+(?:preview|up)(?:\s|$)/gm);

  const verifyOutput = execFileSync(
    process.execPath,
    ["scripts/verify-onboarding.mjs", "--root", outDir, "--config", configPath],
    { encoding: "utf8" },
  );
  assert.match(verifyOutput, /Onboarding verification passed/);
});
