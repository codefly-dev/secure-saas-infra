import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("dev, staging, and production ESC environment templates exist", () => {
  for (const environment of ["dev", "staging", "production"]) {
    const body = readFileSync(
      `environments/${environment}.yaml.example`,
      "utf8",
    );
    assert.match(body, /values:/);
    assert.match(body, /pulumiConfig:/);
    assert.match(
      body,
      new RegExp(`secure-saas-infra:environment: ${environment}`),
    );
    assert.match(body, /endpointPublicAccess: false/);
    assert.match(body, /networkPolicyMode: strict/);
  }
});

test("platform and execution stacks import the intended ESC environments", () => {
  const stackEnvironmentPairs = [
    ["Pulumi.platform-dev.yaml.example", "secure-saas-infra/dev"],
    ["Pulumi.execution-dev.yaml.example", "secure-saas-infra/dev"],
    ["Pulumi.platform-staging.yaml.example", "secure-saas-infra/staging"],
    ["Pulumi.execution-staging.yaml.example", "secure-saas-infra/staging"],
    ["Pulumi.platform-prod.yaml.example", "secure-saas-infra/production"],
    ["Pulumi.execution-prod.yaml.example", "secure-saas-infra/production"],
  ];

  for (const [stackFile, environmentName] of stackEnvironmentPairs) {
    const body = readFileSync(stackFile, "utf8");
    assert.match(body, /environment:/);
    assert.match(body, new RegExp(`- ${environmentName}`));
    assert.match(body, /secure-saas-infra:stackKind: (platform|execution)/);
    assert.match(body, /secure-saas-infra:spoke:/);
    assert.match(body, /networkStackRef:/);
  }
});

test("modular account stack examples declare explicit stack kinds", () => {
  const stackKinds = new Map([
    ["Pulumi.management.yaml.example", "management"],
    ["Pulumi.network.yaml.example", "network-hub"],
    ["Pulumi.network-routing.yaml.example", "network-routing"],
    ["Pulumi.organization-audit.yaml.example", "organization-audit"],
    ["Pulumi.identity.yaml.example", "identity"],
    ["Pulumi.github-governance.yaml.example", "github-governance"],
    ["Pulumi.github-oidc.yaml.example", "github-oidc"],
    ["Pulumi.dev.yaml.example", "single-account"],
    ["Pulumi.security-tooling.yaml.example", "security-tooling"],
    ["Pulumi.log-archive.yaml.example", "log-archive"],
    ["Pulumi.shared-services.yaml.example", "shared-services"],
  ]);

  for (const [stackFile, stackKind] of stackKinds) {
    const body = readFileSync(stackFile, "utf8");
    assert.match(body, new RegExp(`secure-saas-infra:stackKind: ${stackKind}`));
  }
});
