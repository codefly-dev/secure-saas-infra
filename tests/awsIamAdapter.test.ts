import test from "node:test";
import assert from "node:assert/strict";
import { AwsIamProviderExtensions, compileAwsIam } from "../src/adapters/aws";
import { createReferenceBlueprint } from "../src/core";

function extensions(): AwsIamProviderExtensions {
  return {
    accountId: "123456789012",
    organizationId: "o-example123456",
    identities: {
      "tenant-a-workload": {
        roleArn: "arn:aws:iam::123456789012:role/tenant-a-workload",
        podIdentity: { namespace: "mind", serviceAccount: "tenant-a" },
      },
      "tenant-b-workload": {
        roleArn: "arn:aws:iam::123456789012:role/tenant-b-workload",
        podIdentity: { namespace: "mind", serviceAccount: "tenant-b" },
      },
    },
    resources: {
      "tenant-a-data": {
        kind: "data",
        bucketArn: "arn:aws:s3:::tenant-a-data",
        prefixByTenant: { "tenant-a": "tenants/tenant-a/" },
        keyArnByTenant: {
          "tenant-a": "arn:aws:kms:us-east-1:123456789012:key/tenant-a-key",
        },
      },
      "tenant-b-data": {
        kind: "data",
        bucketArn: "arn:aws:s3:::tenant-b-data",
        prefixByTenant: { "tenant-b": "tenants/tenant-b/" },
        keyArnByTenant: {
          "tenant-b": "arn:aws:kms:us-east-1:123456789012:key/tenant-b-key",
        },
      },
    },
  };
}

test("AWS IAM compiler emits deterministic tenant-scoped identity, S3, KMS, and workload trust plans", () => {
  const blueprint = createReferenceBlueprint("dedicated-data");
  const first = compileAwsIam(blueprint, extensions());
  const second = compileAwsIam(blueprint, {
    ...extensions(),
    identities: Object.fromEntries(
      Object.entries(extensions().identities).reverse(),
    ),
    resources: Object.fromEntries(
      Object.entries(extensions().resources).reverse(),
    ),
  });
  assert.deepEqual(first, second);
  assert.equal(first.identityPolicies.length, 2);
  assert.equal(first.trustPolicies.length, 2);
  assert.equal(first.s3ResourcePolicies.length, 2);
  assert.equal(first.kmsKeyPolicies.length, 2);
  assert.equal(first.workloadIdentityAssociations.length, 2);

  const tenantA = first.identityPolicies.find(
    (policy) => policy.identityId === "tenant-a-workload",
  )!;
  assert.match(tenantA.canonicalJson, /tenants\/tenant-a\//);
  assert.match(tenantA.canonicalJson, /deus-tenant-id/);
  assert.match(tenantA.canonicalJson, /deus-brokered/);
  assert.doesNotMatch(tenantA.canonicalJson, /tenant-b/);
  assert.ok(
    tenantA.document.Statement.every((statement) => {
      const resources = Array.isArray(statement.Resource)
        ? statement.Resource
        : [statement.Resource];
      return resources.every((resource) => resource !== "*");
    }),
  );
  assert.deepEqual(first.workloadIdentityAssociations[0], {
    mode: "eks-pod-identity",
    identityId: "tenant-a-workload",
    roleArn: "arn:aws:iam::123456789012:role/tenant-a-workload",
    namespace: "mind",
    serviceAccount: "tenant-a",
    sessionTagsEnabled: true,
  });
  const workloadTrust = first.trustPolicies.find(
    (policy) => policy.identityId === "tenant-a-workload",
  )!;
  assert.match(workloadTrust.canonicalJson, /pods\.eks\.amazonaws\.com/);
  assert.match(workloadTrust.canonicalJson, /aws:SourceOrgId/);
  assert.match(workloadTrust.canonicalJson, /kubernetes-service-account/);
  assert.doesNotMatch(workloadTrust.canonicalJson, /AssumeRoleWithWebIdentity/);
});

test("AWS IAM compiler rejects cross-tenant binding and unmanaged wildcard fragments", () => {
  const blueprint = createReferenceBlueprint("dedicated-data");
  const crossed: AwsIamProviderExtensions = {
    ...extensions(),
    resources: {
      ...extensions().resources,
      "tenant-a-data": {
        kind: "data",
        bucketArn: "arn:aws:s3:::tenant-a-data",
        prefixByTenant: { "tenant-b": "tenants/tenant-b/" },
        keyArnByTenant: {
          "tenant-b": "arn:aws:kms:us-east-1:123456789012:key/tenant-b-key",
        },
      },
    },
  };
  assert.throws(() => compileAwsIam(blueprint, crossed), /tenant-a/);

  const generic = createReferenceBlueprint("dedicated-data");
  generic.grants = generic.grants.map((grant) => ({
    ...grant,
    actions: ["role:pass"],
    conditions: { "aws:RequestedRegion": "us-east-1" },
  }));
  assert.throws(
    () =>
      compileAwsIam(generic, {
        ...extensions(),
        resources: {
          "tenant-a-data": {
            kind: "generic",
            resourceArns: ["arn:aws:iam::123456789012:role/deployment-*"],
            actionMap: { "role:pass": ["iam:PassRole"] },
          },
          "tenant-b-data": {
            kind: "generic",
            resourceArns: ["arn:aws:iam::123456789012:role/deployment-*"],
            actionMap: { "role:pass": ["iam:PassRole"] },
          },
        },
      }),
    /explicit resource and condition scopes/,
  );
});

test("AWS vendor trust requires a role, external ID, source bounds, source identity, and bounded session", () => {
  const blueprint = createReferenceBlueprint("dedicated-data");
  blueprint.identities = [
    ...blueprint.identities,
    { id: "warden-plugin-registry", kind: "vendor", shortLived: true },
  ];
  const configured = extensions();
  configured.identities = {
    ...configured.identities,
    "warden-plugin-registry": {
      roleArn: "arn:aws:iam::123456789012:role/warden-plugin-registry",
      principalArn: "arn:aws:iam::210987654321:role/platform-deployer",
      externalId: "warden-production-opaque-id",
      sourceAccount: "210987654321",
      sourceArn: "arn:aws:iam::210987654321:role/platform-deployer",
      sourceIdentityPattern: "platform-tenant-*",
      maxSessionDurationSeconds: 1800,
    },
  };
  const plan = compileAwsIam(blueprint, configured);
  const trust = plan.trustPolicies.find(
    (policy) => policy.identityId === "warden-plugin-registry",
  )!;
  assert.equal(trust.maxSessionDurationSeconds, 1800);
  assert.match(trust.canonicalJson, /sts:ExternalId/);
  assert.match(trust.canonicalJson, /aws:SourceAccount/);
  assert.match(trust.canonicalJson, /aws:SourceArn/);
  assert.match(trust.canonicalJson, /sts:SourceIdentity/);

  const invalidPrincipal: AwsIamProviderExtensions = {
    ...configured,
    identities: {
      ...configured.identities,
      "warden-plugin-registry": {
        ...configured.identities["warden-plugin-registry"],
        principalArn: "arn:aws:iam::210987654321:user/platform",
      },
    },
  };
  assert.throws(
    () => compileAwsIam(blueprint, invalidPrincipal),
    /must trust an IAM role principal/,
  );
});

test("AWS privilege-escalation actions require explicit resource and condition scopes", () => {
  const blueprint = createReferenceBlueprint("dedicated-data");
  blueprint.grants = blueprint.grants.map((grant) => ({
    ...grant,
    actions: ["role:pass"],
    conditions: { "aws:RequestedRegion": "us-east-1" },
  }));
  const plan = compileAwsIam(blueprint, {
    ...extensions(),
    resources: {
      "tenant-a-data": {
        kind: "generic",
        resourceArns: ["arn:aws:iam::123456789012:role/mind-deployer"],
        actionMap: { "role:pass": ["iam:PassRole"] },
      },
      "tenant-b-data": {
        kind: "generic",
        resourceArns: ["arn:aws:iam::123456789012:role/mind-deployer"],
        actionMap: { "role:pass": ["iam:PassRole"] },
      },
    },
  });
  assert.ok(
    plan.identityPolicies.every((policy) =>
      policy.document.Statement.every(
        (statement) =>
          (statement.Resource ===
            "arn:aws:iam::123456789012:role/mind-deployer" ||
            (Array.isArray(statement.Resource) &&
              statement.Resource.length === 1 &&
              statement.Resource[0] ===
                "arn:aws:iam::123456789012:role/mind-deployer")) &&
          statement.Condition !== undefined,
      ),
    ),
  );
});
