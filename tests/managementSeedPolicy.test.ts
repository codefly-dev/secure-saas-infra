import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { managementSeedPolicies } from "../policy/managementSeed";

async function findings(
  name: string,
  type: string,
  props: object,
  options: {
    resourceName?: string;
    protect?: boolean;
    ignoreChanges?: string[];
  } = {},
) {
  const policy = managementSeedPolicies.find((entry) => entry.name === name);
  assert.ok(policy && "validateResource" in policy);
  const messages: string[] = [];
  const validate = policy.validateResource as (
    args: unknown,
    report: (message: string) => void,
  ) => void | Promise<void>;
  await validate(
    {
      type,
      props,
      name: options.resourceName ?? "deus-management-test",
      opts: {
        protect: options.protect ?? true,
        ignoreChanges:
          options.ignoreChanges ??
          (type === "aws:organizations/account:Account" ? ["roleName"] : []),
      },
    } as never,
    (message: string) => messages.push(String(message)),
  );
  return messages;
}

async function stackFindings(resources: object[]) {
  const policy = managementSeedPolicies.find(
    (entry) => entry.name === "management-seed-exact-resource-graph",
  );
  assert.ok(policy && "validateStack" in policy);
  const messages: string[] = [];
  await policy.validateStack({ resources } as never, (message: string) =>
    messages.push(String(message)),
  );
  return messages;
}

test("management seed policy denies every unreviewed resource type", async () => {
  assert.equal(
    (
      await findings(
        "management-seed-resource-type-allowlist",
        "kubernetes:core/v1:Namespace",
        {},
      )
    ).length,
    1,
  );
  assert.equal(
    (
      await findings(
        "management-seed-resource-type-allowlist",
        "aws:organizations/account:Account",
        {},
      )
    ).length,
    0,
  );
  assert.equal(
    (
      await findings(
        "management-seed-resource-type-allowlist",
        "pulumi:providers:aws",
        {},
      )
    ).length,
    0,
  );
});

test("management seed policy requires rootless non-destructive account creation", async () => {
  const violations = await findings(
    "management-seed-account-rootless-handoff",
    "aws:organizations/account:Account",
    {
      roleName: "OrganizationAccountAccessRole",
      iamUserAccessToBilling: "ALLOW",
      closeOnDeletion: true,
    },
  );
  assert.equal(violations.length, 3);
});

test("management seed policy requires exact deletion protection options", async () => {
  assert.deepEqual(
    await findings(
      "management-seed-resource-options",
      "aws:organizations/organizationalUnit:OrganizationalUnit",
      {},
      { protect: false },
    ),
    ["Every management-seed resource must set protect=true."],
  );
  assert.deepEqual(
    await findings(
      "management-seed-resource-options",
      "aws:organizations/account:Account",
      {},
      { ignoreChanges: [] },
    ),
    ["Only management-seed accounts may ignore exactly roleName changes."],
  );
});

test("management seed policy rejects grants, unsupported types, and malformed S3 policy", async () => {
  const violations = await findings(
    "management-seed-policy-document",
    "aws:organizations/policy:Policy",
    {
      type: "TAG_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }],
      }),
    },
  );
  assert.equal(violations.length, 2);

  const malformedS3 = await findings(
    "management-seed-policy-document",
    "aws:organizations/policy:Policy",
    {
      type: "S3_POLICY",
      content: JSON.stringify({
        s3_attributes: {
          public_access_block_configuration: { "@@assign": "none" },
        },
      }),
    },
  );
  assert.deepEqual(malformedS3, [
    "S3_POLICY must enforce all four Block Public Access settings.",
  ]);
});

test("management seed policy enforces exact organization and trusted-access ownership", async () => {
  const organization = await findings(
    "management-seed-organization-all-features",
    "aws:organizations/organization:Organization",
    {
      featureSet: "ALL",
      enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
      awsServiceAccessPrincipals: ["ram.amazonaws.com"],
    },
  );
  assert.deepEqual(organization, [
    "Organization aggregate service access must remain unset; standalone resources are the single owner.",
  ]);

  const trustedAccess = await findings(
    "management-seed-trusted-service-access",
    "aws:organizations/awsServiceAccess:AwsServiceAccess",
    { servicePrincipal: "ram.amazonaws.com" },
  );
  assert.deepEqual(trustedAccess, [
    "Organizations trusted access contains an unreviewed or RAM principal.",
  ]);
});

test("management seed stack policy rejects extra allowed resources and graph drift", async () => {
  const exact = exactStackResources();
  assert.deepEqual(await stackFindings(exact), []);
  assert.deepEqual(await stackFindings([exact[0]]), []);
  for (const mutate of [
    (organization: any) => {
      organization.props.returnOrganizationOnly = true;
    },
    (organization: any) => {
      organization.dependencies = [organization];
    },
    (organization: any) => {
      organization.propertyDependencies.featureSet = [organization];
    },
  ]) {
    const organizationOnly = structuredClone(exact[0]);
    mutate(organizationOnly);
    assert.ok((await stackFindings([organizationOnly])).length > 0);
  }
  assert.ok(
    (
      await stackFindings([
        exact[0],
        resource(
          "aws:organizations/account:Account",
          "deus-management-account-attacker",
        ),
      ])
    ).length > 0,
  );

  for (const hostile of [
    [
      ...exact,
      resource(
        "aws:organizations/account:Account",
        "deus-management-account-attacker",
      ),
    ],
    [
      ...exact,
      resource(
        "aws:organizations/awsServiceAccess:AwsServiceAccess",
        "deus-management-service-access-attacker-amazonaws-com",
        { servicePrincipal: "cloudtrail.amazonaws.com" },
      ),
    ],
    [
      ...exact,
      resource(
        "aws:organizations/policyAttachment:PolicyAttachment",
        "deus-management-policy-attacker-attachment",
      ),
    ],
  ]) {
    assert.ok((await stackFindings(hostile)).length > 0);
  }

  const retargeted = structuredClone(exact) as any[];
  const rootS3 = retargeted.find((entry) =>
    entry.name.endsWith("enforce-s3-public-access-block-root-attachment"),
  );
  rootS3.propertyDependencies.targetId = [
    retargeted.find((entry) => entry.name.endsWith("-ou-security")),
  ];
  assert.ok((await stackFindings(retargeted)).length > 0);

  for (const mutate of [
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-ram-sharing-with-organization"),
      ).type = "aws:organizations/account:Account";
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-account-security-tooling"),
      ).props.email = "attacker@aws.deus.internal";
    },
    (resources: any[]) => {
      resources.find((entry) => entry.name.endsWith("-ou-nonprod")).props.name =
        "Prod";
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-account-security-tooling"),
      ).props.tags.AccountKind = "execution";
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-ram-sharing-with-organization"),
      ).dependencies = [];
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("service-access-cloudtrail-amazonaws-com"),
      ).dependencies = [];
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-account-shared-services"),
      ).dependencies = [];
    },
    (resources: any[]) => {
      const account = resources.find((entry) =>
        entry.name.endsWith("-account-security-tooling"),
      );
      account.propertyDependencies.parentId = [
        resources.find((entry) => entry.name.endsWith("-ou-infrastructure")),
      ];
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-scp-baseline-deny-guardrails"),
      ).props.tags.Name = "substituted";
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-account-security-tooling"),
      ).props.createGovcloud = true;
    },
    (resources: any[]) => {
      resources.find((entry) =>
        entry.name.endsWith("-scp-baseline-deny-guardrails"),
      ).props.skipDestroy = true;
    },
  ]) {
    const hostile = structuredClone(exact) as any[];
    mutate(hostile);
    assert.ok((await stackFindings(hostile)).length > 0);
  }
});

test("management seed policy rejects wildcard drift in the baseline SCP", async () => {
  const violations = await findings(
    "management-seed-policy-document",
    "aws:organizations/policy:Policy",
    {
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          { Sid: "DenyEverything", Effect: "Deny", Action: "*", Resource: "*" },
        ],
      }),
    },
    { resourceName: "deus-management-scp-baseline-deny-guardrails" },
  );
  assert.deepEqual(violations, [
    "Management-seed policies must match one exact canonical policy identity and document.",
  ]);
});

test("IAM policy gate rejects actions injected into both allow and absolute cap", () => {
  for (const [file, injectedAction] of [
    ["aws-management-seed-preview-policy.json", "iam:CreateUser"],
    ["aws-management-seed-apply-policy.json", "secretsmanager:GetSecretValue"],
  ] as const) {
    const root = mkdtempSync(join(tmpdir(), "seed-policy-hostile-"));
    const security = join(root, "security");
    mkdirSync(security);
    for (const policyFile of [
      "aws-management-seed-preview-policy.json",
      "aws-management-seed-apply-policy.json",
    ]) {
      const policy = JSON.parse(
        readFileSync(join(process.cwd(), "security", policyFile), "utf8"),
      );
      if (policyFile === file) {
        const allow = policy.Statement.find(
          (statement: any) => statement.Effect === "Allow",
        );
        allow.Action = Array.isArray(allow.Action)
          ? [...allow.Action, injectedAction]
          : [allow.Action, injectedAction];
        const cap = policy.Statement.find(
          (statement: any) => statement.NotAction !== undefined,
        );
        cap.NotAction = [...cap.NotAction, injectedAction];
      }
      writeFileSync(
        join(security, policyFile),
        `${JSON.stringify(policy, null, 2)}\n`,
      );
    }
    try {
      const result = spawnSync(
        process.execPath,
        [resolve("scripts/validate-management-seed-policies.mjs")],
        { cwd: root, encoding: "utf8" },
      );
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /action inventory drifted/);
      assert.match(
        result.stderr,
        new RegExp(injectedAction.replace(":", "\\:")),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("IAM policy gate rejects condition, resource, and statement-shape weakening", () => {
  for (const [label, mutate] of [
    [
      "extra condition operator",
      (policy: any) => {
        policy.Statement.find(
          (statement: any) =>
            statement.Sid === "DenyUnapprovedServiceLinkedRoles",
        ).Condition.Null = { "iam:AWSServiceName": "false" };
      },
    ],
    [
      "changed resource",
      (policy: any) => {
        policy.Statement.find(
          (statement: any) => statement.Sid === "DenyUnreviewedPolicyTypes",
        ).Resource = "arn:aws:organizations::*:account/*/*";
      },
    ],
    [
      "duplicate statement",
      (policy: any) => {
        policy.Statement.push(structuredClone(policy.Statement[0]));
      },
    ],
  ] as const) {
    const root = mkdtempSync(join(tmpdir(), "seed-policy-shape-hostile-"));
    const security = join(root, "security");
    mkdirSync(security);
    for (const policyFile of [
      "aws-management-seed-preview-policy.json",
      "aws-management-seed-apply-policy.json",
    ]) {
      const policy = JSON.parse(
        readFileSync(join(process.cwd(), "security", policyFile), "utf8"),
      );
      if (policyFile === "aws-management-seed-apply-policy.json") {
        mutate(policy);
      }
      writeFileSync(
        join(security, policyFile),
        `${JSON.stringify(policy, null, 2)}\n`,
      );
    }
    try {
      const result = spawnSync(
        process.execPath,
        [resolve("scripts/validate-management-seed-policies.mjs")],
        { cwd: root, encoding: "utf8" },
      );
      assert.notEqual(result.status, 0, label);
      assert.match(
        result.stderr,
        /statement structure drifted|exceeds the IAM managed-policy size limit/,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("IAM policy gate rejects account-wide IAM read scope", () => {
  const root = mkdtempSync(join(tmpdir(), "seed-policy-iam-scope-hostile-"));
  const security = join(root, "security");
  mkdirSync(security);
  for (const policyFile of [
    "aws-management-seed-preview-policy.json",
    "aws-management-seed-apply-policy.json",
  ]) {
    const policy = JSON.parse(
      readFileSync(join(process.cwd(), "security", policyFile), "utf8"),
    );
    if (policyFile === "aws-management-seed-apply-policy.json") {
      policy.Statement.find(
        (statement: any) => statement.Sid === "ReadExactBootstrapRoles",
      ).Resource = "*";
    }
    writeFileSync(
      join(security, policyFile),
      `${JSON.stringify(policy, null, 2)}\n`,
    );
  }
  try {
    const result = spawnSync(
      process.execPath,
      [resolve("scripts/validate-management-seed-policies.mjs")],
      { cwd: root, encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /IAM read scope drifted/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function exactStackResources(): any[] {
  const model = require("../scripts/management-seed-model.cjs");
  const policies = require("../scripts/management-seed-policy-model.cjs");
  const prefix = "deus-management";
  const result: any[] = [];
  const organization = resource(
    "aws:organizations/organization:Organization",
    `${prefix}-organization`,
    {
      featureSet: "ALL",
      enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
    },
  );
  result.push(organization);
  result.push(
    resource(
      "aws:ram/sharingWithOrganization:SharingWithOrganization",
      `${prefix}-ram-sharing-with-organization`,
      {},
      [organization],
    ),
  );
  for (const unit of model.ORGANIZATIONAL_UNITS as Array<{
    name: string;
    parent?: string;
  }>) {
    const parent = unit.parent
      ? result.find(
          (entry) => entry.name === `${prefix}-ou-${slug(unit.parent!)}`,
        )
      : organization;
    result.push(
      resource(
        "aws:organizations/organizationalUnit:OrganizationalUnit",
        `${prefix}-ou-${slug(unit.name)}`,
        {
          name: unit.name,
          tags: seedTags(prefix, `ou-${slug(unit.name)}`),
        },
        [parent],
        { parentId: [parent] },
      ),
    );
  }
  const accounts = (
    model.ACCOUNT_BASELINE as Array<{
      name: string;
      ou: string;
      kind: string;
      modular?: boolean;
    }>
  ).filter((account) => !account.modular);
  for (const [index, account] of accounts.entries()) {
    const parent = result.find(
      (entry) => entry.name === `${prefix}-ou-${slug(account.ou)}`,
    );
    const predecessor =
      index >= 3
        ? result.find(
            (entry) =>
              entry.name ===
              `${prefix}-account-${slug(accounts[index - 3].name)}`,
          )
        : undefined;
    result.push(
      resource(
        "aws:organizations/account:Account",
        `${prefix}-account-${slug(account.name)}`,
        {
          name: account.name,
          email: `${account.name}@aws.deus.internal`,
          roleName: "DeusOrganizationBootstrap",
          closeOnDeletion: false,
          iamUserAccessToBilling: "DENY",
          tags: seedTags(prefix, `account-${slug(account.name)}`, {
            AccountKind: account.kind,
            OrganizationalUnit: account.ou,
          }),
        },
        [parent, ...(predecessor ? [predecessor] : [])],
        { parentId: [parent] },
      ),
    );
  }
  for (const principal of model.SERVICE_ACCESS_PRINCIPALS as string[]) {
    result.push(
      resource(
        "aws:organizations/awsServiceAccess:AwsServiceAccess",
        `${prefix}-service-access-${slug(principal)}`,
        { servicePrincipal: principal },
        [organization],
      ),
    );
  }
  for (const [suffix, name, description, type, content] of [
    [
      "scp-baseline-deny-guardrails",
      "baseline-deny-guardrails",
      "Consolidated deny-only baseline for governed member-account OUs.",
      "SERVICE_CONTROL_POLICY",
      policies.BASELINE_SCP_DOCUMENT,
    ],
    [
      "s3-policy-enforce-public-access-block",
      "enforce-s3-public-access-block",
      "Enforces all four S3 Block Public Access settings through the native Organizations policy type.",
      "S3_POLICY",
      policies.S3_PUBLIC_ACCESS_BLOCK_DOCUMENT,
    ],
    [
      "scp-suspended-deny-all",
      "suspended-deny-all",
      "Denies every member-account action in the Suspended OU.",
      "SERVICE_CONTROL_POLICY",
      policies.SUSPENDED_SCP_DOCUMENT,
    ],
  ] as const) {
    result.push(
      resource(
        "aws:organizations/policy:Policy",
        `${prefix}-${suffix}`,
        {
          name: `${prefix}-${name}`,
          description,
          type,
          content: JSON.stringify(content),
          tags: seedTags(prefix, suffix),
        },
        [organization],
      ),
    );
  }
  for (const [name, policy, target] of [
    [
      "policy-baseline-deny-guardrails-security-attachment",
      "scp-baseline-deny-guardrails",
      "ou-security",
    ],
    [
      "policy-baseline-deny-guardrails-infrastructure-attachment",
      "scp-baseline-deny-guardrails",
      "ou-infrastructure",
    ],
    [
      "policy-baseline-deny-guardrails-workloads-attachment",
      "scp-baseline-deny-guardrails",
      "ou-workloads",
    ],
    [
      "policy-enforce-s3-public-access-block-root-attachment",
      "s3-policy-enforce-public-access-block",
      "organization",
    ],
    [
      "policy-suspended-deny-all-suspended-attachment",
      "scp-suspended-deny-all",
      "ou-suspended",
    ],
  ]) {
    const attachment = resource(
      "aws:organizations/policyAttachment:PolicyAttachment",
      `${prefix}-${name}`,
    );
    attachment.propertyDependencies = {
      policyId: [result.find((entry) => entry.name === `${prefix}-${policy}`)],
      targetId: [result.find((entry) => entry.name === `${prefix}-${target}`)],
    };
    attachment.dependencies = [
      ...attachment.propertyDependencies.policyId,
      ...attachment.propertyDependencies.targetId,
    ];
    result.push(attachment);
  }
  return result;
}

function resource(
  type: string,
  name: string,
  props: object = {},
  dependencies: any[] = [],
  propertyDependencies: Record<string, any[]> = {},
): any {
  return {
    type,
    name,
    props,
    opts: {
      protect: true,
      ignoreChanges:
        type === "aws:organizations/account:Account" ? ["roleName"] : [],
    },
    dependencies,
    propertyDependencies,
  };
}

function seedTags(
  prefix: string,
  suffix: string,
  extra: Record<string, string> = {},
) {
  return {
    Project: "secure-saas-infra",
    Stack: "management",
    Organization: prefix.replace(/-management$/, ""),
    Environment: "management",
    ManagedBy: "pulumi",
    Name: `${prefix}-${suffix}`,
    ...extra,
  };
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
