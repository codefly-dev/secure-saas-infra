import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  AWS_BOOTSTRAP_ACCESS_API_VERSION,
  awsApplyLaneIamRoleName,
  compileAwsBootstrapAccessPlan,
  compileAwsApplyLaneIamConstraint,
  createReferenceAwsBootstrapAccessPlan,
  parseAwsBootstrapAccessPlan,
} from "../src/adapters/aws";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("AWS bootstrap contract is generic, deterministic, and human-rooted", () => {
  const checked = JSON.parse(
    readFileSync("contracts/aws-bootstrap-access-v1alpha1.json", "utf8"),
  );
  const reference = createReferenceAwsBootstrapAccessPlan();
  assert.deepEqual(checked, reference);
  assert.deepEqual(parseAwsBootstrapAccessPlan(checked), reference);
  assert.equal(reference.apiVersion, AWS_BOOTSTRAP_ACCESS_API_VERSION);
  assert.equal(reference.management.automationAccess, false);
  assert.equal(reference.management.root.usedByAutomation, false);
  assert.equal(reference.management.root.usedByPulumi, false);
  assert.equal(reference.initialMemberHandoff.automationAssumable, false);
  assert.equal(reference.controller.managementAccountAccess, false);

  const first = compileAwsBootstrapAccessPlan(reference);
  const second = compileAwsBootstrapAccessPlan(structuredClone(reference));
  assert.deepEqual(first, second);
  assert.match(first.sourceDigest, /^[a-f0-9]{64}$/);
});

test("AWS bootstrap roles separate planning, capability-lane apply, and trust", () => {
  const plan = createReferenceAwsBootstrapAccessPlan();
  const compiled = compileAwsBootstrapAccessPlan(plan);
  const controllerArn = plan.controller.roleArn;

  assert.ok(plan.accounts.every((account) => !account.allowControllerPlan));
  assert.ok(plan.accounts.every((account) => !account.allowControllerApply));

  for (const role of compiled.roles) {
    assert.equal(role.destructiveMutation, false);
    assert.notEqual(role.roleName, role.permissionsBoundaryName);
    assert.match(role.sourceIdentityPattern, /^deus-/);
    const statements = (role.permissionsPolicy as any).Statement as any[];
    for (const statement of statements.filter(
      (entry) => entry.Effect === "Allow",
    )) {
      const actions = Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action];
      assert.ok(
        actions.every(
          (action: string) => action !== "*" && !action.endsWith(":*"),
        ),
        `${role.accountName}/${role.mode}/${role.actionSet ?? "all"}`,
      );
    }

    const account = plan.accounts.find(
      (entry) => entry.accountName === role.accountName,
    )!;
    const controllerExpected =
      (role.mode === "plan" && account.allowControllerPlan) ||
      (role.mode === "apply" && account.allowControllerApply);
    assert.equal(
      role.trustedPrincipalArns.includes(controllerArn),
      controllerExpected,
    );
    assert.equal(role.cloudMutation, role.mode === "apply");
    assert.equal(role.actionSet === null, role.mode === "plan");
  }
});

test("AWS database apply requires managed request tags for RDS Proxy creation and constrained PassRole", () => {
  const plan = createReferenceAwsBootstrapAccessPlan();
  const compiled = compileAwsBootstrapAccessPlan(plan);
  const databaseRole = compiled.roles.find(
    (role) =>
      role.mode === "apply" &&
      role.actionSet === "database" &&
      role.accountName === "platform-dev",
  );
  assert.ok(databaseRole);
  const rdsCreate = databaseRole.permissionsPolicy.Statement.find(
    (statement) => statement.Sid === "AllowRdsCreate",
  );
  assert.ok(rdsCreate);
  assert.ok(
    Array.isArray(rdsCreate.Action) &&
      rdsCreate.Action.includes("rds:CreateDBProxy"),
  );
  assert.equal(rdsCreate.Resource, "*");
  assert.deepEqual(rdsCreate.Condition?.StringEquals, {
    "aws:RequestTag/ManagedBy": "pulumi",
    "aws:RequestTag/Organization": "deus",
  });
  const broadProvisioning = databaseRole.permissionsPolicy.Statement.find(
    (statement) => statement.Sid === "AllowServices",
  );
  assert.ok(broadProvisioning);
  assert.equal(
    Array.isArray(broadProvisioning.Action) &&
      broadProvisioning.Action.some(
        (action) =>
          action.startsWith("rds:") && !/^rds:(Describe|List)/.test(action),
      ),
    false,
  );
  const passRole = databaseRole.permissionsPolicy.Statement.find(
    (statement) => statement.Sid === "AllowScopedPassRole",
  );
  assert.ok(passRole);
  assert.match(String(passRole.Resource), /deus-platform-dev-database-\*/);
  assert.deepEqual(passRole.Condition?.StringEquals?.["iam:PassedToService"], [
    "backup.amazonaws.com",
    "ec2.amazonaws.com",
    "eks.amazonaws.com",
    "rds.amazonaws.com",
    "vpc-flow-logs.amazonaws.com",
  ]);
});

test("AWS database role names and boundary are derived from the exact database apply lane", () => {
  const source = createReferenceAwsBootstrapAccessPlan();
  const constraint = compileAwsApplyLaneIamConstraint(
    source,
    "platform-dev",
    "database",
  );
  const compiled = compileAwsBootstrapAccessPlan(source);
  const lane = compiled.roles.find(
    (role) =>
      role.accountName === "platform-dev" && role.actionSet === "database",
  );
  assert.ok(lane);
  assert.ok(lane.delegatedRoleBoundary);
  assert.equal(
    constraint.permissionsBoundaryArn,
    lane.delegatedRoleBoundary.arn,
  );
  assert.notEqual(lane.permissionsBoundaryArn, lane.delegatedRoleBoundary.arn);
  const controllerAllows = lane.permissionsPolicy.Statement.filter(
    (statement) => statement.Effect === "Allow",
  ).flatMap((statement) =>
    Array.isArray(statement.Action) ? statement.Action : [statement.Action],
  );
  assert.equal(controllerAllows.includes("rds-db:connect"), false);
  assert.equal(
    controllerAllows.includes("secretsmanager:GetSecretValue"),
    false,
  );
  assert.equal(controllerAllows.includes("kms:Decrypt"), false);
  assert.equal(controllerAllows.includes("logs:PutLogEvents"), false);
  const delegatedAllows = lane.delegatedRoleBoundary.policy.Statement.filter(
    (statement) => statement.Effect === "Allow",
  ).flatMap((statement) =>
    Array.isArray(statement.Action) ? statement.Action : [statement.Action],
  );
  for (const action of [
    "rds-db:connect",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "logs:PutLogEvents",
  ]) {
    assert.ok(delegatedAllows.includes(action), action);
  }
  assert.equal(constraint.roleNamePrefix, "deus-platform-dev-database-");
  const first = awsApplyLaneIamRoleName(constraint, "warden-db-proxy");
  const second = awsApplyLaneIamRoleName(constraint, "warden-db-proxy");
  assert.equal(first, second);
  assert.match(first, /^deus-platform-dev-database-/);
  assert.ok(first.length <= 64);
  assert.throws(
    () => compileAwsApplyLaneIamConstraint(source, "platform-dev", "security"),
    /does not declare apply lane 'security'/,
  );
});

test("AWS database lane policy evaluates RDS ownership, account, region, and protected-tag attacks", () => {
  const role = compileAwsBootstrapAccessPlan(
    createReferenceAwsBootstrapAccessPlan(),
  ).roles.find(
    (candidate) =>
      candidate.accountName === "platform-dev" &&
      candidate.actionSet === "database",
  );
  assert.ok(role);
  const managedProxy =
    "arn:aws:rds:us-east-1:888877776666:db-proxy:prx-managed";
  const baseContext = {
    "aws:RequestedRegion": "us-east-1",
    "aws:ResourceTag/ManagedBy": "pulumi",
    "aws:ResourceTag/Organization": "deus",
  };
  assert.equal(
    evaluatePolicy(role.permissionsPolicy, "rds:CreateDBProxy", "*", {
      "aws:RequestedRegion": "us-east-1",
      "aws:RequestTag/ManagedBy": "pulumi",
      "aws:RequestTag/Organization": "deus",
      "aws:RequestTag/Name": "deus-platform-dev-control-db-proxy",
    }),
    "allow",
  );
  assert.equal(
    evaluatePolicy(role.permissionsPolicy, "rds:CreateDBProxy", "*", {
      "aws:RequestedRegion": "us-east-1",
    }),
    "implicit-deny",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:ModifyDBProxy",
      managedProxy,
      baseContext,
    ),
    "allow",
  );
  assert.equal(
    evaluatePolicy(role.permissionsPolicy, "rds:ModifyDBProxy", managedProxy, {
      "aws:RequestedRegion": "us-east-1",
    }),
    "implicit-deny",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:ModifyDBProxy",
      "arn:aws:rds:us-east-1:000000000000:db-proxy:prx-hostile",
      baseContext,
    ),
    "implicit-deny",
  );
  assert.equal(
    evaluatePolicy(role.permissionsPolicy, "rds:ModifyDBProxy", managedProxy, {
      ...baseContext,
      "aws:RequestedRegion": "eu-west-1",
    }),
    "explicit-deny",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:AddTagsToResource",
      managedProxy,
      {
        ...baseContext,
        "aws:TagKeys": ["CostCenter"],
      },
    ),
    "allow",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:AddTagsToResource",
      managedProxy,
      {
        ...baseContext,
        "aws:TagKeys": ["ManagedBy"],
      },
    ),
    "implicit-deny",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:AddTagsToResource",
      managedProxy,
      {
        "aws:RequestedRegion": "us-east-1",
        "aws:RequestTag/ManagedBy": "pulumi",
        "aws:RequestTag/Organization": "deus",
        "aws:RequestTag/Name": "deus-platform-dev-control-db-proxy",
        "aws:TagKeys": ["ManagedBy", "Organization", "Name"],
      },
    ),
    "implicit-deny",
  );
  assert.equal(
    evaluatePolicy(
      role.permissionsPolicy,
      "rds:RemoveTagsFromResource",
      managedProxy,
      {
        ...baseContext,
        "aws:TagKeys": ["Organization"],
      },
    ),
    "explicit-deny",
  );
});

test("AWS bootstrap parser denies automation at root, handoff, management, and every apply lane", () => {
  const cases: readonly [(plan: any) => void, RegExp][] = [
    [
      (plan) => {
        plan.management.automationAccess = true;
      },
      /automationAccess must be 'false'/,
    ],
    [
      (plan) => {
        plan.management.root.usedByAutomation = true;
      },
      /usedByAutomation must be 'false'/,
    ],
    [
      (plan) => {
        plan.initialMemberHandoff.automationAssumable = true;
      },
      /automationAssumable must be 'false'/,
    ],
    [
      (plan) => {
        plan.controller.managementAccountAccess = true;
      },
      /managementAccountAccess must be 'false'/,
    ],
    [
      (plan) => {
        plan.accounts.find(
          (account: any) => account.environmentClass === "nonproduction",
        ).allowControllerApply = true;
      },
      /must not grant direct controller apply authority until a separately reviewed execution identity and broker are installed/,
    ],
    [
      (plan) => {
        plan.accounts.find(
          (account: any) => account.environmentClass === "nonproduction",
        ).allowControllerPlan = true;
      },
      /must not trust the controller plan identity until its member-account role and EKS Pod Identity association have been independently materialized and verified/,
    ],
  ];

  for (const [mutate, expected] of cases) {
    const hostile: any = structuredClone(
      createReferenceAwsBootstrapAccessPlan(),
    );
    mutate(hostile);
    assert.throws(() => parseAwsBootstrapAccessPlan(hostile), expected);
  }
});

test("AWS bootstrap renderer is deterministic and offline", () => {
  const source = readFileSync(
    "scripts/render-aws-bootstrap-access.mjs",
    "utf8",
  );
  assert.doesNotMatch(source, /curl\s|fetch\(|https\.get/);
  const rendered = spawnSync(
    process.execPath,
    ["scripts/render-aws-bootstrap-access.mjs"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.deepEqual(
    JSON.parse(rendered.stdout),
    JSON.parse(
      readFileSync("contracts/aws-bootstrap-access-v1alpha1.json", "utf8"),
    ),
  );
});

test("AWS account-access materialization installs the separate database delegated-role boundary", async () => {
  const { resources } = await installPulumiMocks();
  const { createAwsBootstrapAccountAccess } =
    await import("../src/awsBootstrapAccess");
  const result = createAwsBootstrapAccountAccess(
    createReferenceAwsBootstrapAccessPlan(),
    "platform-dev",
  );
  await flushPulumiMocks();
  const database = result.roles.database;
  assert.ok(database);
  assert.ok(database.delegatedBoundary);
  assert.notEqual(database.boundary, database.delegatedBoundary);
  const policies = resourcesOfType(resources, "aws:iam/policy:Policy");
  const delegated = policies.find(
    (policy) =>
      policy.inputs.name ===
      "InfrastructureApplyBoundary-DatabaseDelegatedRoles",
  );
  assert.ok(delegated);
  assert.equal(delegated.inputs.tags.BoundaryPurpose, "delegated-service-role");
  assert.match(delegated.inputs.policy, /rds-db:connect/);
  assert.match(delegated.inputs.policy, /logs:PutLogEvents/);
  const applyRole = resourcesOfType(resources, "aws:iam/role:Role").find(
    (role) => role.inputs.name === "InfrastructureApplyNonProd-Database",
  );
  assert.ok(applyRole);
  assert.match(
    applyRole.inputs.permissionsBoundary,
    /bootstrap-access-platform-dev-database-boundary$/,
  );
  assert.doesNotMatch(applyRole.inputs.permissionsBoundary, /delegated/);
});

type EvaluationContext = Readonly<Record<string, string | readonly string[]>>;

function evaluatePolicy(
  policy: ReturnType<
    typeof compileAwsBootstrapAccessPlan
  >["roles"][number]["permissionsPolicy"],
  action: string,
  resource: string,
  context: EvaluationContext,
): "allow" | "implicit-deny" | "explicit-deny" {
  let allowed = false;
  for (const statement of policy.Statement) {
    const actions = Array.isArray(statement.Action)
      ? statement.Action
      : [statement.Action];
    const resources =
      statement.Resource === undefined
        ? ["*"]
        : Array.isArray(statement.Resource)
          ? statement.Resource
          : [statement.Resource];
    if (
      !actions.some((candidate) => wildcardMatch(candidate, action)) ||
      !resources.some((candidate) => wildcardMatch(candidate, resource)) ||
      !conditionsMatch(statement.Condition, context)
    ) {
      continue;
    }
    if (statement.Effect === "Deny") return "explicit-deny";
    allowed = true;
  }
  return allowed ? "allow" : "implicit-deny";
}

function wildcardMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replace(/\*/g, ".*")}$`).test(value);
}

function conditionsMatch(
  condition: Record<string, Record<string, unknown>> | undefined,
  context: EvaluationContext,
): boolean {
  if (!condition) return true;
  return Object.entries(condition).every(([operator, entries]) =>
    Object.entries(entries).every(([key, expected]) => {
      const actual = context[key];
      const actualValues =
        actual === undefined ? [] : Array.isArray(actual) ? actual : [actual];
      const expectedValues = Array.isArray(expected) ? expected : [expected];
      if (operator === "StringEquals" || operator === "ArnEquals") {
        return actualValues.some((value) => expectedValues.includes(value));
      }
      if (operator === "StringLike") {
        return actualValues.some((value) =>
          expectedValues.some((candidate) =>
            wildcardMatch(String(candidate), String(value)),
          ),
        );
      }
      if (operator === "StringNotEquals") {
        return !actualValues.some((value) => expectedValues.includes(value));
      }
      if (operator === "ForAnyValue:StringEquals") {
        return actualValues.some((value) => expectedValues.includes(value));
      }
      if (operator === "ForAllValues:StringNotEquals") {
        return actualValues.every((value) => !expectedValues.includes(value));
      }
      throw new Error(`Unsupported local IAM condition '${operator}'.`);
    }),
  );
}
