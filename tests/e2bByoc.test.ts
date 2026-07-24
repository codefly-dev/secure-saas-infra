import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("E2B BYOC access role requires vendor role principal and external id", async () => {
  const { resources } = await installPulumiMocks();
  const { createE2bByocAccess } = await import("../src/e2bByoc");

  createE2bByocAccess({
    createVendorRole: true,
    vendorPrincipalArns: [
      "arn:aws:iam::123456789012:role/e2b-byoc-control-plane",
    ],
    externalId: "example-external-id-123456",
    managedPolicyArns: [
      "arn:aws:iam::111111111111:policy/e2b-byoc-least-privilege",
    ],
    inlinePolicy: {
      Version: "2012-10-17",
      Statement: [
        { Effect: "Allow", Action: "sts:GetCallerIdentity", Resource: "*" },
      ],
    },
    maxSessionDurationSeconds: 3600,
  });

  await flushPulumiMocks();

  const roles = resourcesOfType(resources, "aws:iam/role:Role");
  assert.equal(roles.length, 1);
  assert.equal(roles[0].inputs.maxSessionDuration, 3600);

  const assumeRolePolicy = JSON.parse(roles[0].inputs.assumeRolePolicy);
  assert.deepEqual(assumeRolePolicy.Statement[0].Principal.AWS, [
    "arn:aws:iam::123456789012:role/e2b-byoc-control-plane",
  ]);
  assert.equal(
    assumeRolePolicy.Statement[0].Condition.StringEquals["sts:ExternalId"],
    "example-external-id-123456",
  );

  const managedPolicyAttachments = resourcesOfType(
    resources,
    "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
  );
  assert.equal(managedPolicyAttachments.length, 1);
  assert.equal(
    managedPolicyAttachments[0].inputs.policyArn,
    "arn:aws:iam::111111111111:policy/e2b-byoc-least-privilege",
  );

  const inlinePolicies = resourcesOfType(
    resources,
    "aws:iam/rolePolicy:RolePolicy",
  );
  assert.equal(inlinePolicies.length, 1);
  assert.equal(
    JSON.parse(inlinePolicies[0].inputs.policy).Statement[0].Action,
    "sts:GetCallerIdentity",
  );
});
