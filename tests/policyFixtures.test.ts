import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { resourcePolicies } from "../policy/index";

type Fixture = {
  policy: string;
  type: string;
  secure: Record<string, unknown>;
  hostile: Record<string, unknown>;
  secureName?: string;
  hostileName?: string;
};

test("Pulumi require() of the compiled policy entrypoint registers the real server", async () => {
  const child = spawn(
    process.execPath,
    ["-e", 'require("./dist-test/policy/main.js")'],
    {
      cwd: process.cwd(),
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "";
  let stderr = "";
  try {
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`policy server did not register; stderr: ${stderr}`));
      }, 5_000);
      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
        if (/^\d+\s*$/m.test(stdout)) {
          clearTimeout(timeout);
          resolve();
        }
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });
      child.once("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once("exit", (code) => {
        if (!/^\d+\s*$/m.test(stdout)) {
          clearTimeout(timeout);
          reject(
            new Error(
              `policy entrypoint exited before registration (${code}); stderr: ${stderr}`,
            ),
          );
        }
      });
    });
    assert.match(stdout, /^\d+\s*$/m);
  } finally {
    child.kill("SIGTERM");
  }
});

async function evaluate(
  policyName: string,
  type: string,
  props: Record<string, unknown>,
  name = "fixture",
): Promise<string[]> {
  const policy = resourcePolicies.find((entry) => entry.name === policyName);
  assert.ok(policy, `missing registered policy '${policyName}'`);
  const validators = Array.isArray(policy.validateResource)
    ? policy.validateResource
    : [policy.validateResource];
  const violations: string[] = [];
  for (const validator of validators) {
    assert.ok(validator, `policy '${policyName}' has no resource validator`);
    await validator(
      {
        type,
        props,
        name,
        urn: `urn:pulumi:test::iac::${type}::${name}`,
      } as any,
      (message) => violations.push(message),
    );
  }
  return violations;
}

const fixtures: Fixture[] = [
  {
    policy: "eks-private-api-and-secrets-encryption",
    type: "aws:eks/cluster:Cluster",
    secure: {
      vpcConfig: { endpointPublicAccess: false },
      encryptionConfig: { resources: ["secrets"] },
    },
    hostile: { vpcConfig: { endpointPublicAccess: true } },
  },
  {
    policy: "no-public-security-group-ingress",
    type: "aws:ec2/securityGroup:SecurityGroup",
    secure: { ingress: [{ cidrBlocks: ["10.0.0.0/8"] }] },
    hostile: { ingress: [{ ipv6CidrBlocks: ["::/0"] }] },
  },
  {
    policy: "spokes-have-no-direct-internet",
    type: "aws:ec2/natGateway:NatGateway",
    secure: { tags: { NetworkRole: "central-egress" } },
    hostile: {},
    secureName: "central-egress-nat",
    hostileName: "platform-spoke-nat",
  },
  {
    policy: "s3-public-access-block-required",
    type: "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
    secure: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
    hostile: { blockPublicAcls: false },
  },
  {
    policy: "audit-buckets-object-lock",
    type: "aws:s3/bucket:Bucket",
    secure: {
      objectLockEnabled: true,
      forceDestroy: false,
      tags: { DataClass: "audit" },
    },
    hostile: {
      objectLockEnabled: false,
      forceDestroy: true,
      tags: { DataClass: "audit" },
    },
    secureName: "renamed-secure-bucket",
    hostileName: "renamed-hostile-bucket",
  },
  {
    policy: "kms-rotation-required",
    type: "aws:kms/key:Key",
    secure: { enableKeyRotation: true },
    hostile: { enableKeyRotation: false },
  },
  {
    policy: "organization-cloudtrail-required-settings",
    type: "aws:cloudtrail/trail:Trail",
    secure: {
      isOrganizationTrail: true,
      isMultiRegionTrail: true,
      enableLogFileValidation: true,
    },
    hostile: {},
  },
  {
    policy: "vpc-endpoints-require-explicit-policies",
    type: "aws:ec2/vpcEndpoint:VpcEndpoint",
    secure: {
      policy: JSON.stringify({
        Statement: {
          Effect: "Allow",
          Action: "s3:GetObject",
          Condition: {
            StringEquals: { "aws:PrincipalAccount": "123456789012" },
          },
        },
      }),
    },
    hostile: { policy: JSON.stringify({ Statement: { Action: "*" } }) },
  },
  {
    policy: "vpc-flow-logs-capture-all-traffic",
    type: "aws:ec2/flowLog:FlowLog",
    secure: { trafficType: "ALL", logDestinationType: "s3" },
    hostile: { trafficType: "ACCEPT", logDestinationType: "plain-text" },
  },
  {
    policy: "network-firewall-flow-and-alert-logs",
    type: "aws:networkfirewall/loggingConfiguration:LoggingConfiguration",
    secure: {
      loggingConfiguration: {
        logDestinationConfigs: [{ logType: "FLOW" }, { logType: "ALERT" }],
      },
    },
    hostile: { loggingConfiguration: { logDestinationConfigs: [] } },
  },
  {
    policy: "cloudwatch-log-groups-retain-security-evidence",
    type: "aws:cloudwatch/logGroup:LogGroup",
    secure: { retentionInDays: 365 },
    hostile: { retentionInDays: 30 },
  },
  {
    policy: "secrets-manager-secrets-use-cmk",
    type: "aws:secretsmanager/secret:Secret",
    secure: { kmsKeyId: "arn:aws:kms:us-east-1:123456789012:key/key-id" },
    hostile: {},
  },
  {
    policy: "s3-encryption-uses-kms",
    type: "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
    secure: {
      rules: [
        {
          applyServerSideEncryptionByDefault: {
            sseAlgorithm: "aws:kms",
            kmsMasterKeyId: "key-id",
          },
          blockedEncryptionTypes: ["SSE-C"],
        },
      ],
    },
    hostile: { rules: [] },
  },
  {
    policy: "no-iam-users-or-access-keys",
    type: "aws:iam/accessKey:AccessKey",
    secure: {},
    hostile: {},
    secureName: "ignored",
    hostileName: "long-lived-key",
  },
  {
    policy: "ec2-instances-require-imdsv2",
    type: "aws:ec2/instance:Instance",
    secure: {
      metadataOptions: { httpTokens: "required", httpPutResponseHopLimit: 1 },
    },
    hostile: {
      metadataOptions: { httpTokens: "optional", httpPutResponseHopLimit: 2 },
    },
  },
  {
    policy: "rds-clusters-private-and-protected",
    type: "aws:rds/cluster:Cluster",
    secure: {
      storageEncrypted: true,
      kmsKeyId: "key-id",
      iamDatabaseAuthenticationEnabled: true,
      deletionProtection: true,
      backupRetentionPeriod: 14,
    },
    hostile: {},
  },
  {
    policy: "rds-proxies-require-end-to-end-iam-and-tls",
    type: "aws:rds/proxy:Proxy",
    secure: {
      requireTls: true,
      defaultAuthScheme: "IAM_AUTH",
      auths: [],
      roleArn: "arn:aws:iam::123456789012:role/rds-proxy",
    },
    hostile: { requireTls: false, defaultAuthScheme: "SECRETS", auths: [{}] },
  },
  {
    policy: "backup-vault-uses-cmk",
    type: "aws:backup/vault:Vault",
    secure: { kmsKeyArn: "arn:aws:kms:us-east-1:123456789012:key/key-id" },
    hostile: { forceDestroy: true },
  },
  {
    policy: "backup-plans-include-cross-region-copy",
    type: "aws:backup/plan:Plan",
    secure: {
      rules: [
        {
          ruleName: "daily",
          copyActions: [{}],
          lifecycle: { deleteAfter: 35 },
        },
      ],
    },
    hostile: {
      rules: [
        { ruleName: "daily", copyActions: [], lifecycle: { deleteAfter: 1 } },
      ],
    },
  },
  {
    policy: "wafv2-web-acl-has-rate-limit",
    type: "aws:wafv2/webAcl:WebAcl",
    secure: {
      rules: [{ statement: { rateBasedStatement: { limit: 100 } } }],
      visibilityConfig: { cloudwatchMetricsEnabled: true },
    },
    hostile: {
      rules: [],
      visibilityConfig: { cloudwatchMetricsEnabled: false },
    },
  },
  {
    policy: "macie-account-finding-frequency",
    type: "aws:macie2/account:Account",
    secure: {
      findingPublishingFrequency: "FIFTEEN_MINUTES",
      status: "ENABLED",
    },
    hostile: { findingPublishingFrequency: "SIX_HOURS", status: "PAUSED" },
  },
  {
    policy: "cloudfront-distribution-hardened",
    type: "aws:cloudfront/distribution:Distribution",
    secure: {
      viewerCertificate: { minimumProtocolVersion: "TLSv1.2_2021" },
      webAclId: "web-acl-id",
      loggingConfig: { bucket: "audit.example" },
      origins: [
        { originId: "private", vpcOriginConfig: { originReadTimeout: 30 } },
      ],
      defaultCacheBehavior: { viewerProtocolPolicy: "redirect-to-https" },
    },
    hostile: {
      viewerCertificate: { minimumProtocolVersion: "TLSv1" },
      origins: [{ originId: "public", customOriginConfig: {} }],
      defaultCacheBehavior: { viewerProtocolPolicy: "allow-all" },
    },
  },
  {
    policy: "acm-certificate-uses-dns-validation",
    type: "aws:acm/certificate:Certificate",
    secure: { validationMethod: "DNS" },
    hostile: { validationMethod: "EMAIL" },
  },
];

test("every registered resource policy executes compliant and hostile fixtures", async () => {
  const covered = new Set(fixtures.map((fixture) => fixture.policy));
  covered.add("iam-identity-policies-avoid-broad-admin");
  assert.deepEqual(
    [...covered].sort(),
    resourcePolicies.map((policy) => policy.name).sort(),
  );
  for (const fixture of fixtures) {
    const secureType =
      fixture.policy === "no-iam-users-or-access-keys"
        ? "aws:iam/role:Role"
        : fixture.type;
    assert.deepEqual(
      await evaluate(
        fixture.policy,
        secureType,
        fixture.secure,
        fixture.secureName,
      ),
      [],
      `${fixture.policy} rejected its secure fixture`,
    );
    assert.ok(
      (
        await evaluate(
          fixture.policy,
          fixture.type,
          fixture.hostile,
          fixture.hostileName,
        )
      ).length > 0,
      `${fixture.policy} accepted its hostile fixture`,
    );
  }
});

test("IAM policy callback rejects malformed and disguised broad authority", async () => {
  const policyName = "iam-identity-policies-avoid-broad-admin";
  const type = "aws:iam/policy:Policy";
  const secure = JSON.stringify({
    Statement: {
      Effect: "Allow",
      Action: ["s3:GetObject"],
      Resource: "arn:aws:s3:::tenant-a/*",
    },
  });
  assert.deepEqual(await evaluate(policyName, type, { policy: secure }), []);

  const hostile = [
    "not-json",
    JSON.stringify({
      Statement: { Effect: "Allow", Action: "*", Resource: "*" },
    }),
    JSON.stringify({
      Statement: { Effect: "Allow", Action: ["iam:PassRole"], Resource: "*" },
    }),
    JSON.stringify({
      Statement: { Effect: "Allow", NotAction: "s3:GetObject", Resource: "*" },
    }),
    JSON.stringify({
      Statement: {
        Effect: "Allow",
        Action: "s3:*",
        Resource: "*",
        Condition: { StringEquals: { "aws:PrincipalAccount": "123456789012" } },
      },
    }),
  ];
  for (const policy of hostile) {
    assert.ok((await evaluate(policyName, type, { policy })).length > 0);
  }
  assert.ok(
    (
      await evaluate(
        policyName,
        "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
        { policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" },
      )
    ).length > 0,
  );
  assert.deepEqual(
    await evaluate(
      policyName,
      "aws:ssoadmin/managedPolicyAttachment:ManagedPolicyAttachment",
      {
        managedPolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess",
      },
    ),
    [
      "IAM principals and Identity Center permission sets must not attach AdministratorAccess, PowerUserAccess, or IAMFullAccess. Use reviewed least-privilege policies.",
    ],
  );
});

test("VPC endpoint policy requires account scoping on every Allow statement", async () => {
  const policyName = "vpc-endpoints-require-explicit-policies";
  const type = "aws:ec2/vpcEndpoint:VpcEndpoint";
  const mixed = JSON.stringify({
    Statement: [
      {
        Effect: "Allow",
        Action: "s3:GetObject",
        Resource: "arn:aws:s3:::tenant-a/*",
        Condition: {
          StringEquals: { "aws:PrincipalAccount": "123456789012" },
        },
      },
      {
        Effect: "Allow",
        Action: "s3:ListBucket",
        Resource: "arn:aws:s3:::tenant-a",
      },
    ],
  });
  assert.deepEqual(await evaluate(policyName, type, { policy: mixed }), [
    "VPC endpoint policies must scope access with aws:PrincipalAccount.",
  ]);
  const malformedAccount = JSON.stringify({
    Statement: {
      Effect: "Allow",
      Action: "s3:GetObject",
      Resource: "arn:aws:s3:::tenant-a/*",
      Condition: { StringEquals: { "aws:PrincipalAccount": "*" } },
    },
  });
  assert.deepEqual(
    await evaluate(policyName, type, { policy: malformedAccount }),
    ["VPC endpoint policies must scope access with aws:PrincipalAccount."],
  );
});

test("security-group policy covers embedded, modern standalone, and legacy ingress rules", async () => {
  const policy = "no-public-security-group-ingress";
  const violation = [
    "Security group ingress must not allow 0.0.0.0/0 or ::/0.",
  ];
  assert.deepEqual(
    await evaluate(
      policy,
      "aws:ec2/securityGroupIngressRule:SecurityGroupIngressRule",
      { cidrIpv4: "0.0.0.0/0" },
    ),
    violation,
  );
  assert.deepEqual(
    await evaluate(
      policy,
      "aws:ec2/securityGroupIngressRule:SecurityGroupIngressRule",
      { cidrIpv6: "::/0" },
    ),
    violation,
  );
  assert.deepEqual(
    await evaluate(policy, "aws:ec2/securityGroupRule:SecurityGroupRule", {
      type: "ingress",
      cidrBlocks: ["0.0.0.0/0"],
    }),
    violation,
  );
  assert.deepEqual(
    await evaluate(policy, "aws:ec2/securityGroupRule:SecurityGroupRule", {
      type: "egress",
      cidrBlocks: ["0.0.0.0/0"],
    }),
    [],
  );
});

test("compound resource policies exercise every invariant independently", async () => {
  const cases: Array<{
    policy: string;
    type: string;
    secure: Record<string, any>;
    changes: Array<[Record<string, any>, string]>;
  }> = [
    {
      policy: "eks-private-api-and-secrets-encryption",
      type: "aws:eks/cluster:Cluster",
      secure: {
        vpcConfig: { endpointPublicAccess: false },
        encryptionConfig: { resources: ["secrets"] },
      },
      changes: [
        [
          { vpcConfig: { endpointPublicAccess: true } },
          "EKS public API access must be disabled.",
        ],
        [
          { encryptionConfig: { resources: [] } },
          "EKS clusters must encrypt Kubernetes secrets with KMS.",
        ],
      ],
    },
    {
      policy: "organization-cloudtrail-required-settings",
      type: "aws:cloudtrail/trail:Trail",
      secure: {
        isOrganizationTrail: true,
        isMultiRegionTrail: true,
        enableLogFileValidation: true,
      },
      changes: [
        [
          { isOrganizationTrail: false },
          "CloudTrail must be an organization trail.",
        ],
        [{ isMultiRegionTrail: false }, "CloudTrail must be multi-region."],
        [
          { enableLogFileValidation: false },
          "CloudTrail log file validation must be enabled.",
        ],
      ],
    },
    {
      policy: "rds-clusters-private-and-protected",
      type: "aws:rds/cluster:Cluster",
      secure: {
        storageEncrypted: true,
        kmsKeyId: "key-id",
        iamDatabaseAuthenticationEnabled: true,
        deletionProtection: true,
        backupRetentionPeriod: 14,
      },
      changes: [
        [
          { storageEncrypted: false },
          "RDS clusters must enable storage encryption.",
        ],
        [
          { kmsKeyId: undefined },
          "RDS clusters must encrypt with a customer-managed KMS key.",
        ],
        [
          { iamDatabaseAuthenticationEnabled: false },
          "RDS clusters must enable IAM database authentication.",
        ],
        [
          { deletionProtection: false },
          "RDS clusters must enable deletion protection.",
        ],
        [
          { backupRetentionPeriod: 6 },
          "RDS clusters must keep backups for at least 14 days.",
        ],
      ],
    },
  ];
  for (const entry of cases) {
    for (const [change, expected] of entry.changes) {
      assert.deepEqual(
        await evaluate(entry.policy, entry.type, {
          ...entry.secure,
          ...change,
        }),
        [expected],
        `${entry.policy} did not isolate '${expected}'`,
      );
    }
  }
});

test("RDS policy callback exercises instance-specific public exposure branches", async () => {
  const policy = "rds-clusters-private-and-protected";
  assert.ok(
    (
      await evaluate(policy, "aws:rds/clusterInstance:ClusterInstance", {
        publiclyAccessible: true,
        performanceInsightsEnabled: false,
      })
    ).length >= 2,
  );
  assert.ok(
    (
      await evaluate(policy, "aws:rds/instance:Instance", {
        publiclyAccessible: true,
        storageEncrypted: false,
        deletionProtection: false,
      })
    ).length >= 3,
  );
});
