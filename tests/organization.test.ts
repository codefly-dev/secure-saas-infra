import test from "node:test";
import assert from "node:assert/strict";
import {
  flushManagementSeedPulumiMocks,
  installManagementSeedPulumiMocks,
  seedResourcesOfType,
} from "./helpers/managementSeedPulumiMocks";
import type { OrganizationConfig } from "../src/managementSeedConfig";

test("organization-only wave renders exactly one Organization resource", async () => {
  const { resources } = await installManagementSeedPulumiMocks();
  const { createOrganizationFoundation } = await import("../src/organization");

  // The first wave returns before any downstream topology is inspected. The
  // full candidate remains responsible for validating and rendering that
  // topology after the Organization exists and live account capacity is known.
  createOrganizationFoundation(
    {
      createOrganization: true,
      enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
    } as OrganizationConfig,
    "organization-only",
  );

  await flushManagementSeedPulumiMocks();

  assert.deepEqual(
    resources.map((resource) => resource.type),
    ["aws:organizations/organization:Organization"],
  );
  const organization = resources[0];
  assert.equal(organization.inputs.featureSet, "ALL");
  assert.deepEqual(organization.inputs.enabledPolicyTypes, [
    "SERVICE_CONTROL_POLICY",
    "S3_POLICY",
  ]);
});

test("organization foundation renders the exact bounded greenfield seed", async () => {
  const { resources } = await installManagementSeedPulumiMocks();
  const { createOrganizationFoundation } = await import("../src/organization");

  createOrganizationFoundation({
    createOrganization: true,
    defaultAccountRoleName: "DeusOrganizationBootstrap",
    enableRamSharing: true,
    enableSecurityDelegatedAdmin: false,
    serviceAccessPrincipals: [
      "cloudtrail.amazonaws.com",
      "config.amazonaws.com",
      "config-multiaccountsetup.amazonaws.com",
      "guardduty.amazonaws.com",
      "securityhub.amazonaws.com",
      "inspector2.amazonaws.com",
    ],
    enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
    organizationalUnits: [
      { name: "Security" },
      { name: "Infrastructure" },
      { name: "Workloads" },
      { name: "NonProd", parent: "Workloads" },
      { name: "PreProd", parent: "Workloads" },
      { name: "Prod", parent: "Workloads" },
      { name: "Suspended" },
    ],
    accounts: [
      {
        name: "security-tooling",
        email: "security-tooling@aws.deus.internal",
        ou: "Security",
        kind: "security",
      },
      {
        name: "log-archive",
        email: "log-archive@aws.deus.internal",
        ou: "Security",
        kind: "log-archive",
      },
      {
        name: "network",
        email: "network@aws.deus.internal",
        ou: "Infrastructure",
        kind: "network",
      },
      {
        name: "shared-services",
        email: "shared-services@aws.deus.internal",
        ou: "Infrastructure",
        kind: "shared-services",
      },
      {
        name: "platform-dev",
        email: "platform-dev@aws.deus.internal",
        ou: "NonProd",
        kind: "workload",
      },
      {
        name: "execution-dev",
        email: "execution-dev@aws.deus.internal",
        ou: "NonProd",
        kind: "execution",
      },
      {
        name: "platform-staging",
        email: "platform-staging@aws.deus.internal",
        ou: "PreProd",
        kind: "workload",
        create: false,
      },
      {
        name: "execution-staging",
        email: "execution-staging@aws.deus.internal",
        ou: "PreProd",
        kind: "execution",
        create: false,
      },
      {
        name: "platform-prod",
        email: "platform-prod@aws.deus.internal",
        ou: "Prod",
        kind: "workload",
      },
      {
        name: "execution-prod",
        email: "execution-prod@aws.deus.internal",
        ou: "Prod",
        kind: "execution",
      },
    ],
    guardrailScpsEnabled: true,
    guardrailTargetOuNames: ["Security", "Infrastructure", "Workloads"],
  });

  await flushManagementSeedPulumiMocks();

  const organization = seedResourcesOfType(
    resources,
    "aws:organizations/organization:Organization",
  )[0];
  assert.equal(organization.inputs.featureSet, "ALL");
  assert.deepEqual(organization.inputs.enabledPolicyTypes, [
    "SERVICE_CONTROL_POLICY",
    "S3_POLICY",
  ]);
  assert.equal(
    Object.hasOwn(organization.inputs, "awsServiceAccessPrincipals"),
    false,
  );

  assert.equal(
    seedResourcesOfType(
      resources,
      "aws:organizations/organizationalUnit:OrganizationalUnit",
    ).length,
    7,
  );

  const accounts = seedResourcesOfType(
    resources,
    "aws:organizations/account:Account",
  );
  assert.equal(accounts.length, 8);
  assert.ok(
    accounts.every(
      (account) => !String(account.inputs.name).includes("staging"),
    ),
  );
  assert.ok(
    accounts.every(
      (account) => account.inputs.iamUserAccessToBilling === "DENY",
    ),
  );
  assert.ok(
    accounts.every((account) => account.inputs.closeOnDeletion === false),
  );
  assert.ok(
    accounts.every(
      (account) => account.inputs.roleName === "DeusOrganizationBootstrap",
    ),
  );

  assert.equal(
    seedResourcesOfType(
      resources,
      "aws:ram/sharingWithOrganization:SharingWithOrganization",
    ).length,
    1,
  );

  const serviceAccess = seedResourcesOfType(
    resources,
    "aws:organizations/awsServiceAccess:AwsServiceAccess",
  );
  assert.deepEqual(
    serviceAccess.map((entry) => entry.inputs.servicePrincipal),
    [
      "cloudtrail.amazonaws.com",
      "config.amazonaws.com",
      "config-multiaccountsetup.amazonaws.com",
      "guardduty.amazonaws.com",
      "securityhub.amazonaws.com",
      "inspector2.amazonaws.com",
    ],
  );
  assert.ok(
    !serviceAccess.some(
      (entry) => entry.inputs.servicePrincipal === "ram.amazonaws.com",
    ),
  );

  const policies = seedResourcesOfType(
    resources,
    "aws:organizations/policy:Policy",
  );
  assert.equal(policies.length, 3);
  const s3Policy = policies.find(
    (policy) => policy.inputs.type === "S3_POLICY",
  );
  assert.ok(s3Policy);
  assert.deepEqual(JSON.parse(s3Policy.inputs.content), {
    s3_attributes: {
      public_access_block_configuration: { "@@assign": "all" },
    },
  });

  const baselineScp = policies.find((policy) =>
    String(policy.inputs.name).includes("baseline-deny-guardrails"),
  );
  assert.ok(baselineScp);
  const scpActions = JSON.parse(baselineScp.inputs.content).Statement.flatMap(
    (statement: { Action: string | string[] }) =>
      Array.isArray(statement.Action) ? statement.Action : [statement.Action],
  );
  for (const action of [
    "organizations:LeaveOrganization",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "kms:DisableKeyRotation",
    "ec2:DisableEbsEncryptionByDefault",
    "cloudtrail:DeleteTrail",
    "cloudtrail:UpdateTrail",
    "guardduty:DisassociateFromAdministratorAccount",
  ]) {
    assert.ok(scpActions.includes(action), `expected SCP action ${action}`);
  }

  const attachments = seedResourcesOfType(
    resources,
    "aws:organizations/policyAttachment:PolicyAttachment",
  );
  assert.deepEqual(attachments.map((attachment) => attachment.name).sort(), [
    "deus-unit-policy-baseline-deny-guardrails-infrastructure-attachment",
    "deus-unit-policy-baseline-deny-guardrails-security-attachment",
    "deus-unit-policy-baseline-deny-guardrails-workloads-attachment",
    "deus-unit-policy-enforce-s3-public-access-block-root-attachment",
    "deus-unit-policy-suspended-deny-all-suspended-attachment",
  ]);

  const suspendedScp = policies.find((policy) =>
    String(policy.inputs.name).includes("suspended-deny-all"),
  );
  assert.ok(suspendedScp);
  assert.deepEqual(JSON.parse(suspendedScp.inputs.content).Statement, [
    {
      Sid: "DenyAllSuspendedAccountActions",
      Effect: "Deny",
      Action: "*",
      Resource: "*",
    },
  ]);

  assert.equal(
    resources.filter((resource) =>
      /delegatedAdmin|organizationAdmin/.test(resource.type),
    ).length,
    0,
    "delegated administrators belong to a separately scoped post-seed lane",
  );
});

test("organization policy attachment planning reserves AWS-managed quota", async () => {
  await installManagementSeedPulumiMocks();
  const { assertOrganizationPolicyAttachmentQuotas } =
    await import("../src/organization");

  assert.doesNotThrow(() =>
    assertOrganizationPolicyAttachmentQuotas([
      ...Array.from({ length: 4 }, () => ({
        target: "Workloads",
        policyType: "SERVICE_CONTROL_POLICY" as const,
      })),
      ...Array.from({ length: 10 }, () => ({
        target: "Workloads",
        policyType: "S3_POLICY" as const,
      })),
    ]),
  );
  assert.throws(
    () =>
      assertOrganizationPolicyAttachmentQuotas(
        Array.from({ length: 5 }, () => ({
          target: "Workloads",
          policyType: "SERVICE_CONTROL_POLICY" as const,
        })),
      ),
    /exceed the conservative Organizations quota/,
  );
  assert.throws(
    () =>
      assertOrganizationPolicyAttachmentQuotas(
        Array.from({ length: 11 }, () => ({
          target: "Security",
          policyType: "S3_POLICY" as const,
        })),
      ),
    /exceed the conservative Organizations quota/,
  );
});

test("account vending has exactly three concurrency lanes", async () => {
  await installManagementSeedPulumiMocks();
  const { boundedAccountCreationPredecessor } =
    await import("../src/organization");
  const created = ["a", "b", "c", "d", "e", "f"];
  assert.equal(
    boundedAccountCreationPredecessor(created.slice(0, 0)),
    undefined,
  );
  assert.equal(
    boundedAccountCreationPredecessor(created.slice(0, 1)),
    undefined,
  );
  assert.equal(
    boundedAccountCreationPredecessor(created.slice(0, 2)),
    undefined,
  );
  assert.equal(boundedAccountCreationPredecessor(created.slice(0, 3)), "a");
  assert.equal(boundedAccountCreationPredecessor(created.slice(0, 4)), "b");
  assert.equal(boundedAccountCreationPredecessor(created.slice(0, 5)), "c");
});
