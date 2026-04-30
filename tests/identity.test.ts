import test from "node:test";
import assert from "node:assert/strict";
import { flushPulumiMocks, installPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("identity center stack creates group-based permission sets and account assignments", async () => {
  const { resources } = await installPulumiMocks();
  const { createIdentityCenter } = await import("../src/identity");

  createIdentityCenter({
    organizationStackRef: "org/secure-saas-infra/management",
    groups: [
      { name: "security-admins", displayName: "AWS Security Admins", create: true },
      { name: "developers", displayName: "AWS Developers", create: true },
    ],
    permissionSets: [
      {
        name: "SecurityAuditReadOnly",
        description: "Read-only security visibility across accounts.",
        sessionDuration: "PT4H",
        managedPolicyArns: ["arn:aws:iam::aws:policy/SecurityAudit"],
      },
      {
        name: "DeveloperReadOnly",
        description: "Read-only developer access.",
        sessionDuration: "PT4H",
        managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
        inlinePolicy: {
          Version: "2012-10-17",
          Statement: [{ Effect: "Deny", Action: "iam:*", Resource: "*" }],
        },
      },
    ],
    assignments: [
      {
        groupName: "security-admins",
        permissionSetName: "SecurityAuditReadOnly",
        accountNames: ["security-tooling", "log-archive"],
      },
      {
        groupName: "developers",
        permissionSetName: "DeveloperReadOnly",
        accountIds: ["111111111199"],
      },
    ],
  });

  await flushPulumiMocks();

  const groups = resourcesOfType(resources, "aws:identitystore/group:Group");
  assert.equal(groups.length, 2);
  assert.ok(groups.every((group) => group.inputs.identityStoreId === "d-1234567890"));

  const permissionSets = resourcesOfType(resources, "aws:ssoadmin/permissionSet:PermissionSet");
  assert.equal(permissionSets.length, 2);
  assert.ok(permissionSets.every((permissionSet) => permissionSet.inputs.instanceArn.includes("ssoins-")));
  assert.ok(permissionSets.every((permissionSet) => permissionSet.inputs.sessionDuration === "PT4H"));

  const managedPolicyAttachments = resourcesOfType(resources, "aws:ssoadmin/managedPolicyAttachment:ManagedPolicyAttachment");
  assert.equal(managedPolicyAttachments.length, 2);
  assert.ok(
    managedPolicyAttachments.some(
      (attachment) => attachment.inputs.managedPolicyArn === "arn:aws:iam::aws:policy/SecurityAudit",
    ),
  );

  const inlinePolicies = resourcesOfType(resources, "aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy");
  assert.equal(inlinePolicies.length, 1);
  assert.equal(JSON.parse(inlinePolicies[0].inputs.inlinePolicy).Statement[0].Action, "iam:*");

  const assignments = resourcesOfType(resources, "aws:ssoadmin/accountAssignment:AccountAssignment");
  assert.equal(assignments.length, 3);
  assert.ok(assignments.every((assignment) => assignment.inputs.principalType === "GROUP"));
  assert.ok(assignments.every((assignment) => assignment.inputs.targetType === "AWS_ACCOUNT"));
  assert.deepEqual(
    assignments.map((assignment) => assignment.inputs.targetId).sort(),
    ["111111111112", "111111111113", "111111111199"],
  );
});
