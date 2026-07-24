import test from "node:test";
import assert from "node:assert/strict";
import {
  compileAwsEksAccessGrants,
  hasAwsEksClusterAdministrator,
  type AwsEksAccessGrantConfig,
} from "../src/adapters/aws";

function grants(): AwsEksAccessGrantConfig[] {
  return [
    {
      id: "platform-admin",
      principal: {
        kind: "identity-center-permission-set",
        category: "workforce",
        permissionSetName: "PlatformPowerUser",
      },
      accessPolicy: "cluster-admin",
      scope: { type: "cluster" },
    },
    {
      id: "developer-edit",
      principal: {
        kind: "identity-center-permission-set",
        category: "workforce",
        permissionSetName: "Developer",
      },
      accessPolicy: "edit",
      scope: { type: "namespace", namespaces: ["workloads", "execution"] },
    },
    {
      id: "deployment-view",
      principal: {
        kind: "iam-role",
        category: "automation",
        roleArn: "arn:aws:iam::123456789012:role/deployment-observer",
      },
      accessPolicy: "view",
      scope: { type: "namespace", namespaces: ["workloads"] },
    },
    {
      id: "argocd-bootstrap",
      principal: {
        kind: "iam-role",
        category: "workforce",
        roleArn:
          "arn:aws:iam::123456789012:role/InfrastructureApplyNonProd-Workload",
      },
      accessPolicy: "cluster-admin",
      scope: { type: "cluster" },
    },
  ];
}

test("EKS access compiler resolves exact Identity Center selectors and least-privilege policies", () => {
  const plan = compileAwsEksAccessGrants(grants());
  assert.deepEqual(
    plan.map((grant) => grant.id),
    ["argocd-bootstrap", "deployment-view", "developer-edit", "platform-admin"],
  );
  const admin = plan.find((grant) => grant.id === "platform-admin")!;
  assert.deepEqual(admin.principal, {
    kind: "identity-center-permission-set",
    category: "workforce",
    permissionSetName: "PlatformPowerUser",
    roleNameRegex: "^AWSReservedSSO_PlatformPowerUser_[A-Fa-f0-9]{16}$",
    rolePathPrefix: "/aws-reserved/sso.amazonaws.com/",
  });
  assert.equal(
    admin.policyArn,
    "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
  );
  assert.equal(hasAwsEksClusterAdministrator(grants()), true);
  const bootstrap = plan.find((grant) => grant.id === "argocd-bootstrap")!;
  assert.equal(bootstrap.principal.category, "workforce");
  const edit = plan.find((grant) => grant.id === "developer-edit")!;
  assert.deepEqual(edit.scope, {
    type: "namespace",
    namespaces: ["execution", "workloads"],
  });
});

test("EKS access compiler rejects users, wildcards, duplicates, system namespaces, and automation admin", () => {
  const cases: Array<[AwsEksAccessGrantConfig[], RegExp]> = [
    [
      [
        {
          ...grants()[2],
          principal: {
            kind: "iam-role",
            category: "automation",
            roleArn: "arn:aws:iam::123456789012:user/not-a-role",
          },
        },
      ],
      /exact IAM role ARN/,
    ],
    [
      [
        {
          ...grants()[0],
          principal: {
            kind: "identity-center-permission-set",
            category: "workforce",
            permissionSetName: "Platform*",
          },
        },
      ],
      /permission-set name/,
    ],
    [
      [grants()[0], { ...grants()[0], id: "other" }],
      /more than one EKS access entry/,
    ],
    [
      [
        {
          ...grants()[1],
          scope: { type: "namespace", namespaces: ["kube-system"] },
        },
      ],
      /SYSTEM_NAMESPACE_DENIED/,
    ],
    [
      [
        {
          id: "automation-admin",
          principal: {
            kind: "iam-role",
            category: "automation",
            roleArn: "arn:aws:iam::123456789012:role/deployer",
          },
          accessPolicy: "cluster-admin",
          scope: { type: "cluster" },
        },
      ],
      /AUTOMATION_ADMIN_DENIED/,
    ],
    [
      [{ ...grants()[1], scope: { type: "cluster" } }],
      /must be namespace-scoped/,
    ],
  ];
  for (const [candidate, expected] of cases) {
    assert.throws(() => compileAwsEksAccessGrants(candidate), expected);
  }
});
