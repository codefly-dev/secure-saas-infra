import test from "node:test";
import assert from "node:assert/strict";
import { flushPulumiMocks, installPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("github oidc stack creates roles scoped to repository refs and environments", async () => {
  const { resources } = await installPulumiMocks();
  const { createGithubOidc } = await import("../src/githubOidc.js");

  createGithubOidc({
    enabled: true,
    repositories: [
      {
        owner: "deus-ai",
        repo: "infra",
        allowedRefs: ["refs/heads/main"],
        allowedEnvironments: ["production"],
        managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
        inlinePolicy: {
          Version: "2012-10-17",
          Statement: [{ Effect: "Allow", Action: "sts:GetCallerIdentity", Resource: "*" }],
        },
      },
    ],
  });

  await flushPulumiMocks();

  const providers = resourcesOfType(resources, "aws:iam/openIdConnectProvider:OpenIdConnectProvider");
  assert.equal(providers.length, 1);
  assert.equal(providers[0].inputs.url, "https://token.actions.githubusercontent.com");
  assert.deepEqual(providers[0].inputs.clientIdLists, ["sts.amazonaws.com"]);

  const roles = resourcesOfType(resources, "aws:iam/role:Role");
  assert.equal(roles.length, 1);
  assert.equal(roles[0].inputs.maxSessionDuration, 3600);

  const assumeRolePolicy = JSON.parse(roles[0].inputs.assumeRolePolicy);
  const condition = assumeRolePolicy.Statement[0].Condition;
  assert.equal(condition.StringEquals["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com");
  assert.deepEqual(condition.StringLike["token.actions.githubusercontent.com:sub"], [
    "repo:deus-ai/infra:ref:refs/heads/main",
    "repo:deus-ai/infra:environment:production",
  ]);

  const managedPolicyAttachments = resourcesOfType(resources, "aws:iam/rolePolicyAttachment:RolePolicyAttachment");
  assert.equal(managedPolicyAttachments.length, 1);
  assert.equal(managedPolicyAttachments[0].inputs.policyArn, "arn:aws:iam::aws:policy/ReadOnlyAccess");

  const inlinePolicies = resourcesOfType(resources, "aws:iam/rolePolicy:RolePolicy");
  assert.equal(inlinePolicies.length, 1);
  assert.equal(JSON.parse(inlinePolicies[0].inputs.policy).Statement[0].Action, "sts:GetCallerIdentity");
});
