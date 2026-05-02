import test from "node:test";
import assert from "node:assert/strict";
import { installPulumiMocks, flushPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("organization foundation creates OUs, accounts, RAM sharing, and SCP guardrails", async () => {
  const { resources } = await installPulumiMocks();
  const { createOrganizationFoundation } = await import("../src/organization");

  createOrganizationFoundation({
    createOrganization: true,
    defaultAccountRoleName: "OrganizationAccountAccessRole",
    enableRamSharing: true,
    enableSecurityDelegatedAdmin: true,
    securityDelegatedAdminAccountName: "security-tooling",
    serviceAccessPrincipals: ["cloudtrail.amazonaws.com", "config.amazonaws.com", "securityhub.amazonaws.com"],
    enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"],
    organizationalUnits: [{ name: "Security" }, { name: "Workloads" }, { name: "Execution" }],
    accounts: [
      { name: "security-tooling", email: "security@example.com", ou: "Security", kind: "security" },
      { name: "platform-prod", email: "platform-prod@example.com", ou: "Workloads", kind: "workload" },
      { name: "execution-prod", email: "execution-prod@example.com", ou: "Execution", kind: "execution" },
    ],
    guardrailScpsEnabled: true,
    guardrailTargetOuNames: ["Security", "Workloads", "Execution"],
  });

  await flushPulumiMocks();

  const organization = resourcesOfType(resources, "aws:organizations/organization:Organization")[0];
  assert.equal(organization.inputs.featureSet, "ALL");
  assert.deepEqual(organization.inputs.enabledPolicyTypes, ["SERVICE_CONTROL_POLICY"]);

  assert.equal(resourcesOfType(resources, "aws:organizations/organizationalUnit:OrganizationalUnit").length, 3);

  const accounts = resourcesOfType(resources, "aws:organizations/account:Account");
  assert.equal(accounts.length, 3);
  assert.ok(accounts.every((account) => account.inputs.iamUserAccessToBilling === "DENY"));
  assert.ok(accounts.every((account) => account.inputs.closeOnDeletion === false));
  assert.ok(accounts.every((account) => account.inputs.roleName === "OrganizationAccountAccessRole"));

  assert.equal(resourcesOfType(resources, "aws:ram/sharingWithOrganization:SharingWithOrganization").length, 1);

  const serviceAccess = resourcesOfType(
    resources,
    "aws:organizations/awsServiceAccess:AwsServiceAccess",
  );
  const enabledPrincipals = serviceAccess.map(
    (entry) => entry.inputs.servicePrincipal,
  );
  for (const expected of [
    "backup.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "sso.amazonaws.com",
    "ram.amazonaws.com",
  ]) {
    assert.ok(
      enabledPrincipals.includes(expected),
      `expected service-access enabled for ${expected}`,
    );
  }

  const policies = resourcesOfType(resources, "aws:organizations/policy:Policy");
  assert.equal(policies.length, 7);

  const policyActions = policies.flatMap((policy) =>
    JSON.parse(policy.inputs.content).Statement.flatMap((statement: { Action: string | string[] }) =>
      Array.isArray(statement.Action) ? statement.Action : [statement.Action],
    ),
  );
  for (const action of [
    "organizations:LeaveOrganization",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "kms:DisableKeyRotation",
    "ec2:DisableEbsEncryptionByDefault",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
  ]) {
    assert.ok(
      policyActions.includes(action),
      `expected SCP action ${action}`,
    );
  }

  const attachments = resourcesOfType(resources, "aws:organizations/policyAttachment:PolicyAttachment");
  assert.equal(
    attachments.length,
    21,
    "seven guardrail SCPs should be attached to three target OUs",
  );

  assert.equal(resourcesOfType(resources, "aws:guardduty/organizationAdminAccount:OrganizationAdminAccount").length, 1);
  assert.equal(resourcesOfType(resources, "aws:securityhub/organizationAdminAccount:OrganizationAdminAccount").length, 1);
  assert.equal(resourcesOfType(resources, "aws:inspector2/delegatedAdminAccount:DelegatedAdminAccount").length, 1);
  assert.equal(resourcesOfType(resources, "aws:organizations/delegatedAdministrator:DelegatedAdministrator").length, 2);
});
