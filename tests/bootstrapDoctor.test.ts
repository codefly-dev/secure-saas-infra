import test from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

function fixture(): { root: string; config: string } {
  const root = mkdtempSync(join(tmpdir(), "bootstrap-doctor-"));
  const config = join(root, "onboarding.local.json");
  writeFileSync(
    config,
    JSON.stringify({
      pulumiOrg: "deus",
      pulumiBackend: "pulumi-cloud",
      pulumiBackendUrl: "https://api.pulumi.com",
      pulumiProject: "secure-saas-infra",
      landingZoneOwner: "organizations",
      organizationName: "deus",
      accountEmailDomain: "aws.deus.internal",
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    }),
  );
  writeFileSync(
    join(root, "Pulumi.management.yaml"),
    `config:
  aws:region: us-east-1
  aws:allowedAccountIds:
    - "999988887777"
  secure-saas-infra:stackKind: management
  secure-saas-infra:deploymentMode: organization
  secure-saas-infra:environment: management
  secure-saas-infra:seedWave: organization-only
  secure-saas-infra:organizationName: deus
  secure-saas-infra:organization:
    createOrganization: true
    defaultAccountRoleName: DeusOrganizationBootstrap
    enableRamSharing: true
    enableSecurityDelegatedAdmin: false
    serviceAccessPrincipals:
      - cloudtrail.amazonaws.com
      - config.amazonaws.com
      - config-multiaccountsetup.amazonaws.com
      - guardduty.amazonaws.com
      - securityhub.amazonaws.com
      - inspector2.amazonaws.com
    enabledPolicyTypes:
      - SERVICE_CONTROL_POLICY
      - S3_POLICY
    organizationalUnits:
      - name: Security
      - name: Infrastructure
      - name: Workloads
      - name: NonProd
        parent: Workloads
      - name: PreProd
        parent: Workloads
      - name: Prod
        parent: Workloads
      - name: Suspended
    accounts:
      - name: security-tooling
        email: aws+security-tooling@aws.deus.internal
        ou: Security
        kind: security
      - name: log-archive
        email: aws+log-archive@aws.deus.internal
        ou: Security
        kind: log-archive
      - name: network
        email: aws+network@aws.deus.internal
        ou: Infrastructure
        kind: network
      - name: shared-services
        email: aws+shared-services@aws.deus.internal
        ou: Infrastructure
        kind: shared-services
      - name: platform-dev
        email: aws+platform-dev@aws.deus.internal
        ou: NonProd
        kind: workload
      - name: execution-dev
        email: aws+execution-dev@aws.deus.internal
        ou: NonProd
        kind: execution
      - name: platform-staging
        email: aws+platform-staging@aws.deus.internal
        ou: PreProd
        kind: workload
        create: false
      - name: execution-staging
        email: aws+execution-staging@aws.deus.internal
        ou: PreProd
        kind: execution
        create: false
      - name: platform-prod
        email: aws+platform-prod@aws.deus.internal
        ou: Prod
        kind: workload
      - name: execution-prod
        email: aws+execution-prod@aws.deus.internal
        ou: Prod
        kind: execution
    guardrailScpsEnabled: true
    guardrailTargetOuNames:
      - Security
      - Infrastructure
      - Workloads
`,
  );
  writeFileSync(
    join(root, "Pulumi.yaml"),
    `name: secure-saas-infra
runtime:
  name: nodejs
`,
  );
  return { root, config };
}

test("bootstrap doctor is offline, non-mutating, credential-free, and machine readable by default", () => {
  const source = readFileSync("scripts/bootstrap-doctor.mjs", "utf8");
  assert.doesNotMatch(source, /curl\s|fetch\(|https\.get|pulumi\s+up/);
  assert.doesNotMatch(source, /codefly/i);
  assert.match(source, /cloudMutation: false/);

  const { root, config } = fixture();
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.offline, true);
  assert.equal(report.cloudMutation, false);
  assert.equal(report.decisions.landingZoneOwner, "organizations");
  assert.equal(report.decisions.pulumiBackend, "pulumi-cloud");
  assert.equal(report.decisions.managementAccountId, "999988887777");
  assert.equal(report.summary.failures, 0);
  assert.ok(
    report.checks.some(
      (check: any) =>
        check.id === "config.management-stack" && check.status === "pass",
    ),
  );
  assert.ok(!result.stdout.includes("AWS_ACCESS_KEY_ID"));
});

test("bootstrap doctor reports signer, review, worktree, and native-host release readiness", () => {
  const { root, config } = fixture();
  mkdirSync(join(root, "security"));
  writeFileSync(
    join(root, "security", "bootstrap-qualification-trust.json"),
    JSON.stringify({
      apiVersion: "security.deus.dev/bootstrap-qualification-trust/v1",
      configured: false,
    }),
  );
  writeFileSync(
    join(root, "security", "adversarial-review-disposition.json"),
    JSON.stringify({
      approvedForLocalQualification: false,
      approvedForAwsMutation: false,
      reviews: [
        { discipline: "architecture", localFindings: "unresolved" },
        { discipline: "security", localFindings: "unresolved" },
        { discipline: "validation", localFindings: "unresolved" },
      ],
    }),
  );
  try {
    const pending = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--json",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(pending.status, 0);
    const pendingReport = JSON.parse(pending.stdout);
    assert.equal(
      pendingReport.checks.find(
        (check: any) => check.id === "release.signer-trust",
      ).status,
      "failure",
    );
    assert.equal(
      pendingReport.checks.find(
        (check: any) => check.id === "release.adversarial-review",
      ).status,
      "failure",
    );
    assert.equal(
      pendingReport.checks.find((check: any) => check.id === "release.worktree")
        .status,
      "warning",
    );
    assert.ok(
      pendingReport.checks.some(
        (check: any) => check.id === "release.production-host",
      ),
    );

    const { publicKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    writeFileSync(
      join(root, "security", "bootstrap-qualification-trust.json"),
      JSON.stringify({
        apiVersion: "security.deus.dev/bootstrap-qualification-trust/v1",
        configured: true,
        algorithm: "Ed25519",
        keyId: createHash("sha256").update(publicDer).digest("hex"),
        publicKeySpki: publicDer.toString("base64url"),
      }),
    );
    const configured = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--json",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    const configuredReport = JSON.parse(configured.stdout);
    assert.equal(
      configuredReport.checks.find(
        (check: any) => check.id === "release.signer-trust",
      ).status,
      "pass",
    );
    assert.equal(
      configuredReport.checks.find(
        (check: any) => check.id === "release.adversarial-review",
      ).status,
      "failure",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("bootstrap doctor rejects every alternate seed topology and identity drift", () => {
  for (const [label, mutate] of [
    [
      "existing organization mode",
      (root: string) =>
        replaceStack(
          root,
          "createOrganization: true",
          "createOrganization: false",
        ),
    ],
    [
      "RAM disabled",
      (root: string) =>
        replaceStack(root, "enableRamSharing: true", "enableRamSharing: false"),
    ],
    [
      "empty guardrail targets",
      (root: string) =>
        replaceStack(
          root,
          `guardrailTargetOuNames:
      - Security
      - Infrastructure
      - Workloads`,
          "guardrailTargetOuNames: []",
        ),
    ],
    [
      "destructive account lifecycle",
      (root: string) =>
        replaceStack(
          root,
          `name: security-tooling
        email:`,
          `name: security-tooling
        closeOnDeletion: true
        email:`,
        ),
    ],
    [
      "organization identity drift",
      (root: string) =>
        replaceStack(
          root,
          "secure-saas-infra:organizationName: deus",
          "secure-saas-infra:organizationName: attacker",
        ),
    ],
    [
      "project identity drift",
      (root: string) =>
        writeFileSync(
          join(root, "Pulumi.yaml"),
          "name: attacker\nruntime:\n  name: nodejs\n",
        ),
    ],
  ] as const) {
    const { root, config } = fixture();
    mutate(root);
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--json",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(result.status, 0, label);
    const report = JSON.parse(result.stdout);
    const management = report.checks.find(
      (check: any) => check.id === "config.management-stack",
    );
    assert.equal(management.status, "failure", label);
  }
});

test("bootstrap doctor fails closed for the unimplemented Control Tower owner", () => {
  const { root, config } = fixture();
  const onboarding = JSON.parse(readFileSync(config, "utf8"));
  writeFileSync(
    config,
    JSON.stringify({ ...onboarding, landingZoneOwner: "control-tower" }),
  );
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.ok(
    report.checks.some(
      (check: any) =>
        check.id === "config.onboarding" &&
        check.status === "failure" &&
        check.message.includes("control-tower is not implemented"),
    ),
  );
});

test("bootstrap doctor fails closed for self-managed seed backends", () => {
  const { root, config } = fixture();
  const onboarding = JSON.parse(readFileSync(config, "utf8"));
  writeFileSync(
    config,
    JSON.stringify({
      ...onboarding,
      pulumiBackend: "self-managed",
      pulumiBackendUrl: "s3://state-bucket",
    }),
  );
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stdout, /self-managed backend selection is deferred/);
});

test("bootstrap doctor rejects management stack authority and provider indirection", () => {
  const { root, config } = fixture();
  writeFileSync(
    join(root, "Pulumi.management.yaml"),
    `environment:
  - production
config:
  aws:allowedAccountIds:
    - "111122223333"
  aws:assumeRoles:
    - roleArn: arn:aws:iam::111122223333:role/Other
  secure-saas-infra:stackKind: workload
  secure-saas-infra:deploymentMode: workload
  secure-saas-infra:environment: production
`,
  );
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  const report = JSON.parse(result.stdout);
  const management = report.checks.find(
    (check: any) => check.id === "config.management-stack",
  );
  assert.equal(management.status, "failure");
  assert.match(management.message, /must not import Pulumi ESC/);
  assert.match(management.message, /stackKind must equal management/);
  assert.match(management.message, /allowedAccountIds/);
  assert.match(management.message, /aws:assumeRoles/);
});

test("bootstrap doctor rejects incomplete decisions, example values, and long-lived key environments", () => {
  const { root, config } = fixture();
  writeFileSync(
    config,
    JSON.stringify({
      pulumiOrg: "deus",
      pulumiProject: "secure-saas-infra",
      accountEmailDomain: "aws.example.com",
      managementAccountId: "111122223333",
    }),
  );
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--json",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        AWS_ACCESS_KEY_ID: "not-emitted",
        AWS_SECRET_ACCESS_KEY: "not-emitted",
        AWS_SESSION_TOKEN: "",
      },
    },
  );
  assert.notEqual(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.ok(report.summary.failures >= 2);
  assert.ok(
    report.checks.some(
      (check: any) =>
        check.id === "config.onboarding" &&
        check.message.includes("example value"),
    ),
  );
  assert.ok(
    report.checks.some(
      (check: any) =>
        check.id === "aws.credential-mode" && check.status === "failure",
    ),
  );
  assert.ok(!result.stdout.includes("not-emitted"));
});

test("bootstrap doctor rejects shared, wildcard, root, and cross-account access principals", () => {
  for (const [mutate, expected] of [
    [
      (value: any) => {
        value.managementApplyTrustedPrincipalArn =
          value.managementPreviewTrustedPrincipalArn;
      },
      /must all be distinct/,
    ],
    [
      (value: any) => {
        value.managementPreviewTrustedPrincipalArn =
          "arn:aws:iam::999988887777:role/Federated*";
      },
      /exact pre-organization SAML source role/,
    ],
    [
      (value: any) => {
        value.managementPreviewTrustedPrincipalArn =
          "arn:aws:iam::999988887777:root";
      },
      /exact pre-organization SAML source role/,
    ],
    [
      (value: any) => {
        value.managementPreviewTrustedPrincipalArn =
          "arn:aws:iam::999988887777:role/WorkloadServiceRole";
      },
      /exact pre-organization SAML source role/,
    ],
    [
      (value: any) => {
        value.managementPreviewTrustedPrincipalArn =
          "arn:aws:iam::888877776666:role/deus/bootstrap-source/ManagementSeedPreview";
      },
      /managementAccountId/,
    ],
    [
      (value: any) => {
        value.managementBootstrapSamlMetadataSha256 = "0".repeat(64);
      },
      /non-placeholder lowercase SHA-256/,
    ],
    [
      (value: any) => {
        for (const key of [
          "managementPreviewRoleArn",
          "managementApplyRoleArn",
          "managementPreviewTrustedPrincipalArn",
          "managementApplyTrustedPrincipalArn",
          "managementBootstrapSamlProviderArn",
          "managementProvisionerPrincipalArn",
        ]) {
          value[key] = value[key].replace("arn:aws:", "arn:aws-cn:");
        }
        value.managementAccessRegion = "cn-north-1";
      },
      /supports only the commercial aws partition/,
    ],
  ] as const) {
    const { root, config } = fixture();
    const onboarding = JSON.parse(readFileSync(config, "utf8"));
    mutate(onboarding);
    writeFileSync(config, JSON.stringify(onboarding));
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--json",
      ],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    const report = JSON.parse(result.stdout);
    const check = report.checks.find(
      (entry: any) => entry.id === "config.onboarding",
    );
    assert.equal(check.status, "failure");
    assert.match(check.message, expected);
  }
});

test("AWS caller check rejects root even in the exact configured management account", () => {
  const { root, config } = fixture();
  const bin = join(root, "bin");
  const mkdir = spawnSync("mkdir", ["-p", bin]);
  assert.equal(mkdir.status, 0);
  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "aws-cli/2.test"
  exit 0
fi
echo '{"UserId":"999988887777","Account":"999988887777","Arn":"arn:aws:iam::999988887777:root"}'
`,
  );
  chmodSync(aws, 0o700);

  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--check-aws-session",
      "--json",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
    },
  );
  assert.notEqual(result.status, 0);
  const report = JSON.parse(result.stdout);
  const caller = report.checks.find((check: any) => check.id === "aws.caller");
  assert.equal(caller.status, "failure");
  assert.match(caller.message, /root credentials are forbidden/);
});

test("AWS caller check accepts only the exact configured assumed role", () => {
  for (const [arn, expected] of [
    [
      "arn:aws:sts::999988887777:assumed-role/OrganizationSeedPreview/human-session",
      "pass",
    ],
    [
      "arn:aws:sts::999988887777:assumed-role/OtherBootstrap/human-session",
      "failure",
    ],
  ] as const) {
    const { root, config } = fixture();
    const bin = join(root, "bin");
    mkdirSync(bin);
    const aws = join(bin, "aws");
    writeFileSync(
      aws,
      `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "aws-cli/2.test"
  exit 0
fi
echo '${JSON.stringify({ UserId: "session", Account: "999988887777", Arn: arn })}'
`,
    );
    chmodSync(aws, 0o700);
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--check-aws-session",
        "--json",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      },
    );
    const report = JSON.parse(result.stdout);
    const caller = report.checks.find(
      (check: any) => check.id === "aws.caller",
    );
    assert.equal(caller.status, expected);
    assert.equal(result.status === 0, expected === "pass");
  }
});

test("AWS account audit is read-only, redacted, and bound to the preview role", () => {
  const { root, config } = fixture();
  const bin = installAwsAccountAuditStub(root);
  const cutoff = new Date(Math.floor((Date.now() - 60_000) / 1000) * 1000)
    .toISOString()
    .replace(".000Z", "Z");
  const result = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--check-aws-account-audit",
      "--root-activity-cutoff",
      cutoff,
      "--json",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        AWS_AUDIT_STUB_EVENT_TIME: new Date(Date.now() - 30_000).toISOString(),
        AWS_ENDPOINT_URL: "https://attacker.invalid",
        AWS_ENDPOINT_URL_IAM: "https://attacker.invalid",
      },
    },
  );
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(result.stdout);
  assert.equal(report.offline, false);
  assert.equal(report.cloudMutation, false);
  assert.equal(
    report.checks.find((check: any) => check.id === "aws.caller").status,
    "pass",
  );
  assert.deepEqual(
    report.checks.find(
      (check: any) => check.id === "aws.audit.root-credentials",
    ).evidence,
    { rootMfaEnabled: true, rootAccessKeyCount: 0 },
  );
  assert.deepEqual(
    report.checks.find(
      (check: any) => check.id === "aws.audit.account-contacts",
    ).evidence,
    {
      primaryContactPresent: true,
      primaryPhonePresent: true,
      alternateContactsPresent: {
        billing: true,
        operations: true,
        security: true,
      },
      rootEmailDelivery: "manual-verification-required",
    },
  );
  assert.deepEqual(
    report.checks.find((check: any) => check.id === "aws.audit.root-activity")
      .evidence,
    {
      enabledRegionsChecked: 2,
      rootEventsObserved: 0,
      rootActivityCutoff: cutoff,
      eventHistoryWindowDays: 90,
    },
  );
  for (const confidential of [
    "owner@example.invalid",
    "billing@example.invalid",
    "operations@example.invalid",
    "security@example.invalid",
    "+33123456789",
    "Private Operator",
  ]) {
    assert.equal(result.stdout.includes(confidential), false);
  }
});

test("AWS account audit fails closed on posture, contact, and history mutations", () => {
  const cutoff = new Date(Math.floor((Date.now() - 60_000) / 1000) * 1000)
    .toISOString()
    .replace(".000Z", "Z");
  for (const [mode, checkId] of [
    ["no-mfa", "aws.audit.root-credentials"],
    ["root-access-key", "aws.audit.root-credentials"],
    ["malformed-summary", "aws.audit.root-credentials"],
    ["missing-contact", "aws.audit.account-contacts"],
    ["malformed-regions", "aws.audit.root-activity"],
    ["truncated-history", "aws.audit.root-activity"],
    ["root-event", "aws.audit.root-activity"],
  ] as const) {
    const { root, config } = fixture();
    const bin = installAwsAccountAuditStub(root);
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--check-aws-account-audit",
        "--root-activity-cutoff",
        cutoff,
        "--json",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          AWS_AUDIT_STUB_MODE: mode,
          AWS_AUDIT_STUB_EVENT_TIME: new Date(
            Date.now() - 30_000,
          ).toISOString(),
        },
      },
    );
    assert.notEqual(result.status, 0, mode);
    const report = JSON.parse(result.stdout);
    const check = report.checks.find((entry: any) => entry.id === checkId);
    assert.equal(check.status, "failure", mode);
    assert.doesNotMatch(result.stdout, /owner@example\.invalid/, mode);
    assert.doesNotMatch(result.stdout, /Private Operator/, mode);
  }
});

test("AWS account audit rejects non-preview callers and invalid cutoffs", () => {
  const { root, config } = fixture();
  const bin = installAwsAccountAuditStub(root);
  const applyCaller = spawnSync(
    process.execPath,
    [
      "scripts/bootstrap-doctor.mjs",
      "--root",
      root,
      "--config",
      config,
      "--check-aws-account-audit",
      "--json",
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        AWS_AUDIT_STUB_ARN:
          "arn:aws:sts::999988887777:assumed-role/OrganizationSeedApply/human-session",
      },
    },
  );
  assert.notEqual(applyCaller.status, 0);
  const applyReport = JSON.parse(applyCaller.stdout);
  assert.equal(
    applyReport.checks.find(
      (entry: any) => entry.id === "aws.audit.precondition",
    ).status,
    "failure",
  );

  for (const invalidArgs of [
    ["--root-activity-cutoff", "2026-01-01T00:00:00Z"],
    ["--check-aws-account-audit", "--root-activity-cutoff", "not-a-timestamp"],
    ["--check-aws-account-audit", "--check-aws-account-audit"],
  ]) {
    const invalid = spawnSync(
      process.execPath,
      ["scripts/bootstrap-doctor.mjs", ...invalidArgs],
      { cwd: process.cwd(), encoding: "utf8" },
    );
    assert.equal(invalid.status, 2);
  }
});

test("bootstrap doctor exposes strict and explicit online checks", () => {
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  const result = spawnSync(
    process.execPath,
    ["scripts/bootstrap-doctor.mjs", "--help"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Offline by default/);
  assert.match(result.stdout, /--check-aws-session/);
  assert.match(result.stdout, /--check-aws-account-audit/);
  assert.match(result.stdout, /--root-activity-cutoff/);
  assert.match(result.stdout, /--check-pulumi-login/);
  assert.match(result.stdout, /--strict/);
  assert.match(result.stdout, /never writes files or changes AWS\/Pulumi/);
  assert.equal(
    packageJson.scripts["validate:aws-account"],
    "node scripts/bootstrap-doctor.mjs --check-aws-account-audit",
  );
});

test("management-seed access renderer is deterministic, offline, bounded, and content-addressed", () => {
  const source = [
    readFileSync("scripts/management-seed-access.mjs", "utf8"),
    readFileSync("scripts/render-management-seed-access.mjs", "utf8"),
    readFileSync("scripts/verify-management-seed-access.mjs", "utf8"),
  ].join("\n");
  assert.doesNotMatch(source, /spawnSync|execSync|fetch\(|curl\s|pulumi\s+up/);
  assert.match(source, /cloudMutationPerformed: false/);

  const directory = mkdtempSync(
    join(process.cwd(), "artifacts", "access-bundle-test-"),
  );
  const config = join(directory, "onboarding.local.json");
  const relativeConfig = config.slice(process.cwd().length + 1);
  writeFileSync(
    config,
    JSON.stringify({
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    }),
    { mode: 0o600 },
  );
  try {
    const first = runGuardedAccessScript([
      "scripts/render-management-seed-access.mjs",
      "--config",
      relativeConfig,
    ]);
    const second = runGuardedAccessScript([
      "scripts/render-management-seed-access.mjs",
      "--config",
      relativeConfig,
    ]);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(second.status, 0, second.stderr);
    assert.equal(first.stdout, second.stdout);

    const bundle = JSON.parse(first.stdout);
    assert.equal(bundle.cloudMutationPerformed, false);
    assert.equal(
      bundle.authorizationModel,
      "separate-preorganization-saml-principals",
    );
    assert.equal(
      bundle.provisioning.model,
      "preorganization-saml-administrator",
    );
    assert.equal(
      bundle.provisioning.principalArn,
      "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    );
    assert.equal(
      bundle.provisioning.active.inlinePolicyName,
      "ManagementSeedAccessProvisioner",
    );
    assert.equal(
      bundle.provisioning.active.inlinePolicyDocument.Statement.at(-1).Sid,
      "DenyEveryOtherProvisionerAction",
    );
    assert.deepEqual(bundle.provisioning.active.requiredAttachedPolicyArns, []);
    assert.equal(bundle.provisioning.active.permissionsBoundaryRequired, false);
    assert.equal(
      bundle.provisioning.retirement.principalArn,
      "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedRetirement",
    );
    assert.equal(
      bundle.provisioning.retirement.principalInlinePolicyName,
      "ManagementSeedProvisionerRetirement",
    );
    assert.equal(
      bundle.provisioning.retirement.principalPolicyDocument.Statement.at(-1)
        .Sid,
      "DenyEveryOtherRetirementAction",
    );
    const activeAllows =
      bundle.provisioning.active.inlinePolicyDocument.Statement.filter(
        (statement: any) => statement.Effect === "Allow",
      ).flatMap((statement: any) =>
        Array.isArray(statement.Action) ? statement.Action : [statement.Action],
      );
    assert.ok(!activeAllows.includes("*"));
    assert.ok(!activeAllows.includes("iam:AttachRolePolicy"));
    assert.ok(!activeAllows.includes("iam:CreatePolicy"));
    assert.ok(!activeAllows.includes("iam:CreateRole"));
    assert.ok(!activeAllows.includes("iam:CreateUser"));
    const activeReads =
      bundle.provisioning.active.inlinePolicyDocument.Statement.find(
        (statement: any) =>
          statement.Sid === "ReadExactBootstrapAccessResources",
      );
    assert.ok(activeReads.Action.includes("iam:GetSAMLProvider"));
    assert.ok(
      activeReads.Resource.includes(
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      ),
    );
    const retirementAllows =
      bundle.provisioning.retirement.principalPolicyDocument.Statement.filter(
        (statement: any) => statement.Effect === "Allow",
      ).flatMap((statement: any) =>
        Array.isArray(statement.Action) ? statement.Action : [statement.Action],
      );
    assert.ok(retirementAllows.includes("iam:PutRolePermissionsBoundary"));
    assert.ok(retirementAllows.includes("iam:DeleteRolePolicy"));
    assert.ok(!retirementAllows.includes("iam:PutRolePolicy"));
    assert.ok(!retirementAllows.includes("iam:DeleteRolePermissionsBoundary"));
    assert.equal(
      bundle.provisioning.retirement.permissionsBoundaryArn,
      "arn:aws:iam::999988887777:policy/deus/bootstrap/DeusManagementSeedProvisionerRetiredBoundary",
    );
    assert.deepEqual(
      bundle.provisioning.retirement.requiredInlinePolicyNames,
      [],
    );
    assert.deepEqual(
      bundle.provisioning.retirement.requiredAttachedPolicyArns,
      [],
    );
    assert.deepEqual(
      bundle.trustedPrincipalAssumeRolePolicies.preview.Statement[0],
      {
        Sid: "AssumeExactManagementSeedRole",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Resource: "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      },
    );
    assert.deepEqual(
      bundle.trustedPrincipalAssumeRolePolicies.apply.Statement[0],
      {
        Sid: "AssumeExactManagementSeedRole",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Resource: "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      },
    );
    for (const mode of ["preview", "apply"] as const) {
      const sourcePolicy =
        bundle.trustedPrincipalAssumeRolePolicies[mode].Statement;
      assert.deepEqual(sourcePolicy[1], {
        Sid: "DenyAssumingAnyOtherRole",
        Effect: "Deny",
        Action: "sts:AssumeRole",
        NotResource: bundle.targetRoles[mode],
      });
      assert.deepEqual(sourcePolicy[2], {
        Sid: "DenyEveryOtherSourceAction",
        Effect: "Deny",
        NotAction: "sts:AssumeRole",
        Resource: "*",
      });
    }
    const template = bundle.cloudFormationTemplate;
    const resources = template.Resources;
    assert.deepEqual(
      template.Conditions.ExpectedManagementAccountPartitionAndRegion,
      {
        "Fn::And": [
          {
            "Fn::Equals": [{ Ref: "AWS::AccountId" }, "999988887777"],
          },
          { "Fn::Equals": [{ Ref: "AWS::Partition" }, "aws"] },
          { "Fn::Equals": [{ Ref: "AWS::Region" }, "us-east-1"] },
        ],
      },
    );
    for (const resource of Object.values(resources) as any[]) {
      assert.equal(
        resource.Condition,
        "ExpectedManagementAccountPartitionAndRegion",
      );
      assert.equal(resource.DeletionPolicy, "Retain");
      assert.equal(resource.UpdateReplacePolicy, "Retain");
    }
    for (const output of Object.values(template.Outputs) as any[]) {
      assert.equal(
        output.Condition,
        "ExpectedManagementAccountPartitionAndRegion",
      );
    }
    assert.deepEqual(Object.keys(resources).sort(), [
      "ApplyRolePolicy",
      "PreviewRolePolicy",
    ]);
    for (const [mode, roleKey, boundaryKey, policyKey, trustedPrincipal] of [
      [
        "preview",
        "PreviewRole",
        "PreviewPermissionsBoundary",
        "PreviewRolePolicy",
        bundle.trustedPrincipals.preview,
      ],
      [
        "apply",
        "ApplyRole",
        "ApplyPermissionsBoundary",
        "ApplyRolePolicy",
        bundle.trustedPrincipals.apply,
      ],
    ] as const) {
      const role = bundle.precreatedFoundation[roleKey].Properties;
      const boundary = bundle.precreatedFoundation[boundaryKey].Properties;
      const inline = resources[policyKey].Properties;
      assert.equal(role.MaxSessionDuration, 3600);
      assert.equal(
        role.PermissionsBoundary,
        "arn:aws:iam::999988887777:policy/deus/bootstrap/" +
          boundary.ManagedPolicyName,
      );
      assert.deepEqual(role.Policies, []);
      assert.deepEqual(inline.PolicyDocument, boundary.PolicyDocument);
      const boundaryDocument = JSON.stringify(boundary.PolicyDocument);
      assert.doesNotMatch(boundaryDocument, /__DEUS_MANAGEMENT_ACCOUNT_ID__/);
      assert.match(boundaryDocument, /arn:aws:iam::999988887777:/);
      const iamAllows = boundary.PolicyDocument.Statement.filter(
        (statement: any) =>
          statement.Effect === "Allow" &&
          (Array.isArray(statement.Action)
            ? statement.Action
            : [statement.Action]
          ).some((action: string) => /^iam:(?:Get|List)/.test(action)),
      );
      assert.equal(iamAllows.length, 4);
      const auditRead = iamAllows.find(
        (statement: any) => statement.Sid === "ReadAccountAuditPosture",
      );
      assert.deepEqual(auditRead, {
        Sid: "ReadAccountAuditPosture",
        Effect: "Allow",
        Action: [
          "account:GetAlternateContact",
          "account:GetContactInformation",
          "cloudtrail:LookupEvents",
          "iam:GetAccountSummary",
        ],
        Resource: "*",
      });
      for (const statement of iamAllows.filter(
        (entry: any) => entry !== auditRead,
      )) {
        assert.notEqual(statement.Resource, "*");
        const resources = Array.isArray(statement.Resource)
          ? statement.Resource
          : [statement.Resource];
        assert.ok(
          resources.every((resource: string) =>
            resource.startsWith("arn:aws:iam::999988887777:"),
          ),
        );
      }
      const allowed = boundary.PolicyDocument.Statement.filter(
        (statement: any) => statement.Effect === "Allow",
      )
        .flatMap((statement: any) =>
          Array.isArray(statement.Action)
            ? statement.Action
            : [statement.Action],
        )
        .sort();
      const absoluteCaps = boundary.PolicyDocument.Statement.filter(
        (statement: any) =>
          statement.Sid ===
          `DenyUnreviewed${mode === "preview" ? "Preview" : "Apply"}Actions`,
      );
      assert.equal(absoluteCaps.length, 1);
      assert.deepEqual([...absoluteCaps[0].NotAction].sort(), allowed);
      const trust = role.AssumeRolePolicyDocument.Statement[0];
      assert.deepEqual(trust.Principal, {
        AWS: "arn:aws:iam::999988887777:root",
      });
      assert.equal(
        trust.Condition.ArnEquals["aws:PrincipalArn"],
        trustedPrincipal,
      );
      assert.equal(
        trust.Condition.StringEquals["aws:PrincipalAccount"],
        "999988887777",
      );
      assert.equal(
        role.Tags.find((tag: any) => tag.Key === "AccessMode").Value,
        mode,
      );
    }
    assert.notDeepEqual(
      resources.PreviewRolePolicy.Properties.PolicyDocument,
      resources.ApplyRolePolicy.Properties.PolicyDocument,
    );
    assert.equal(
      bundle.cloudFormationTemplateCanonicalSha256,
      sha256(canonicalJson(template)),
    );
    assert.equal(
      bundle.cloudFormationTemplateFileSha256,
      sha256(`${JSON.stringify(template, null, 2)}\n`),
    );
    const { bundleDigest, ...subject } = bundle;
    assert.equal(bundleDigest, sha256(canonicalJson(subject)));
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    const validateBundle = ajv.compile(
      JSON.parse(
        readFileSync(
          "schemas/management-seed-access-bundle-v1.schema.json",
          "utf8",
        ),
      ),
    );
    assert.equal(
      validateBundle(bundle),
      true,
      JSON.stringify(validateBundle.errors),
    );
    const crosswired = structuredClone(bundle);
    crosswired.precreatedFoundation.PreviewRole.Properties.RoleName =
      "OrganizationSeedApply";
    crosswired.precreatedFoundation.PreviewRole.Properties.PermissionsBoundary =
      crosswired.cloudFormationTemplate.Outputs.ApplyPermissionsBoundaryArn.Value;
    crosswired.cloudFormationTemplate.Outputs.PreviewRoleArn.Value =
      crosswired.targetRoles.apply;
    assert.equal(validateBundle(crosswired), false);
    const sourcePolicyCrosswire = structuredClone(bundle);
    sourcePolicyCrosswire.trustedPrincipalAssumeRolePolicies.preview.Statement[0].Resource =
      sourcePolicyCrosswire.targetRoles.apply;
    assert.equal(validateBundle(sourcePolicyCrosswire), false);

    const bundlePath = join(directory, "bundle.json");
    const templatePath = join(directory, "template.json");
    writeFileSync(bundlePath, first.stdout, { mode: 0o600 });
    writeFileSync(templatePath, `${JSON.stringify(template, null, 2)}\n`, {
      mode: 0o600,
    });
    const relativeBundle = bundlePath.slice(process.cwd().length + 1);
    const relativeTemplate = templatePath.slice(process.cwd().length + 1);
    const verified = runGuardedAccessScript([
      "scripts/verify-management-seed-access.mjs",
      "--config",
      relativeConfig,
      "--bundle",
      relativeBundle,
      "--template",
      relativeTemplate,
    ]);
    assert.equal(verified.status, 0, verified.stderr);
    const verification = JSON.parse(verified.stdout);
    assert.equal(verification.valid, true);
    assert.equal(verification.cloudMutationPerformed, false);

    bundle.trustedPrincipals.preview =
      "arn:aws:iam::999988887777:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Attacker_aaaaaaaaaaaaaaaa";
    bundle.precreatedFoundation.PreviewRole.Properties.AssumeRolePolicyDocument.Statement[0].Condition.ArnEquals[
      "aws:PrincipalArn"
    ] = bundle.trustedPrincipals.preview;
    bundle.cloudFormationTemplateCanonicalSha256 = sha256(
      canonicalJson(bundle.cloudFormationTemplate),
    );
    bundle.cloudFormationTemplateFileSha256 = sha256(
      `${JSON.stringify(bundle.cloudFormationTemplate, null, 2)}\n`,
    );
    const tamperedSubject = { ...bundle };
    delete tamperedSubject.bundleDigest;
    bundle.bundleDigest = sha256(canonicalJson(tamperedSubject));
    writeFileSync(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`, {
      mode: 0o600,
    });
    const rejected = runGuardedAccessScript([
      "scripts/verify-management-seed-access.mjs",
      "--config",
      relativeConfig,
      "--bundle",
      relativeBundle,
      "--template",
      relativeTemplate,
    ]);
    assert.notEqual(rejected.status, 0);
    assert.match(
      rejected.stderr,
      /does not exactly match governed source|failed strict schema validation/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("management-seed access renderer rejects role substitution before producing a template", () => {
  const directory = mkdtempSync(
    join(process.cwd(), "artifacts", "access-bundle-deny-"),
  );
  const config = join(directory, "onboarding.local.json");
  const relativeConfig = config.slice(process.cwd().length + 1);
  writeFileSync(
    config,
    JSON.stringify({
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn: "arn:aws:iam::999988887777:role/AdminPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    }),
    { mode: 0o600 },
  );
  try {
    const result = runGuardedAccessScript([
      "scripts/render-management-seed-access.mjs",
      "--config",
      relativeConfig,
    ]);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /OrganizationSeedPreview/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("live management access attestation accepts exact IAM state and rejects drift", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { createManagementSeedAccessBundle } from "./scripts/management-seed-access.mjs";
    import {
      attestManagementSeedAccessDeployment,
      attestManagementSeedAccessFoundation,
      attestManagementSeedAccessInstallationProgress,
      attestProvisionerRetirementProgress,
    } from "./scripts/management-seed-access-live.mjs";

    const onboarding = {
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn: "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn: "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn: "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256: "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    };
    const root = process.cwd();
    const bundle = createManagementSeedAccessBundle(root, onboarding);
    const modeForRole = (name) => name.includes("Preview") ? "preview" : "apply";
    const retirement = bundle.provisioning.retirement;
    const expected = {
      preview: {
        role: bundle.precreatedFoundation.PreviewRole.Properties,
        boundary: bundle.precreatedFoundation.PreviewPermissionsBoundary.Properties,
        inline: bundle.cloudFormationTemplate.Resources.PreviewRolePolicy.Properties,
      },
      apply: {
        role: bundle.precreatedFoundation.ApplyRole.Properties,
        boundary: bundle.precreatedFoundation.ApplyPermissionsBoundary.Properties,
        inline: bundle.cloudFormationTemplate.Resources.ApplyRolePolicy.Properties,
      },
    };
    const response = (args) => {
      const operation = args[1];
      const argument = (name) => args[args.indexOf(name) + 1];
      if (operation === "get-saml-provider") {
        return {
          AssertionEncryptionMode: "Allowed",
          PrivateKeyList: [],
          SAMLMetadataDocument: "exact-saml-metadata",
          Tags: [],
        };
      }
      if (operation === "get-role") {
        const roleName = argument("--role-name");
        if (roleName === "OrganizationSeedPreview" || roleName === "OrganizationSeedApply") {
          const mode = modeForRole(roleName);
          const value = expected[mode];
          return { Role: {
            RoleName: roleName,
            Arn: bundle.targetRoles[mode],
            Path: value.role.Path,
            MaxSessionDuration: value.role.MaxSessionDuration,
            PermissionsBoundary: {
              PermissionsBoundaryArn: "arn:aws:iam::999988887777:policy" + value.boundary.Path + value.boundary.ManagedPolicyName,
              PermissionsBoundaryType: "Policy",
            },
            AssumeRolePolicyDocument: value.role.AssumeRolePolicyDocument,
            Tags: value.role.Tags,
          }};
        }
        if (roleName === "ManagementSeedProvisioner") {
          return { Role: {
            RoleName: roleName,
            Arn: bundle.provisioning.principalArn,
            Path: "/deus/bootstrap-source/",
            MaxSessionDuration: 3600,
            PermissionsBoundary: {
              PermissionsBoundaryArn: retirement.permissionsBoundaryArn,
              PermissionsBoundaryType: "Policy",
            },
            AssumeRolePolicyDocument: bundle.bootstrapSourceTrustPolicy,
            Tags: retirement.requiredRoleTags,
          }};
        }
        if (roleName === "ManagementSeedRetirement") {
          return { Role: {
            RoleName: roleName,
            Arn: retirement.principalArn,
            Path: "/deus/bootstrap-source/",
            MaxSessionDuration: 3600,
            AssumeRolePolicyDocument: bundle.bootstrapSourceTrustPolicy,
          }};
        }
        const mode = modeForRole(roleName);
        const sourceArn = bundle.trustedPrincipals[mode];
        return { Role: {
          RoleName: roleName,
          Arn: sourceArn,
          Path: "/" + sourceArn.split(":role/")[1].slice(0, -(roleName.length)),
          MaxSessionDuration: 3600,
          AssumeRolePolicyDocument: bundle.bootstrapSourceTrustPolicy,
        }};
      }
      if (operation === "list-role-policies") {
        const roleName = argument("--role-name");
        if (roleName === "ManagementSeedProvisioner") return { PolicyNames: [] };
        if (roleName === "ManagementSeedRetirement") {
          return { PolicyNames: [retirement.principalInlinePolicyName] };
        }
        const mode = modeForRole(roleName);
        return { PolicyNames: roleName.startsWith("OrganizationSeed") ? [expected[mode].inline.PolicyName] : ["IdentityCenterInline"] };
      }
      if (operation === "get-role-policy") {
        const roleName = argument("--role-name");
        if (roleName === "ManagementSeedRetirement") {
          return { PolicyDocument: retirement.principalPolicyDocument };
        }
        const mode = modeForRole(roleName);
        return { PolicyDocument: roleName.startsWith("OrganizationSeed") ? expected[mode].inline.PolicyDocument : bundle.trustedPrincipalAssumeRolePolicies[mode] };
      }
      if (operation === "list-attached-role-policies") return { AttachedPolicies: [] };
      if (operation === "get-policy") {
        const arn = argument("--policy-arn");
        if (arn === retirement.permissionsBoundaryArn) {
          return { Policy: {
            Arn: arn,
            PolicyName: retirement.permissionsBoundaryName,
            Path: retirement.permissionsBoundaryPath,
            IsAttachable: true,
            AttachmentCount: 0,
            PermissionsBoundaryUsageCount: 1,
            DefaultVersionId: "v1",
          }};
        }
        const mode = modeForRole(arn);
        const value = expected[mode].boundary;
        return { Policy: {
          Arn: arn,
          PolicyName: value.ManagedPolicyName,
          Path: value.Path,
          IsAttachable: true,
          AttachmentCount: 0,
          PermissionsBoundaryUsageCount: 1,
          DefaultVersionId: "v1",
        }};
      }
      if (operation === "list-policy-versions") return { Versions: [{ VersionId: "v1", IsDefaultVersion: true }] };
      if (operation === "get-policy-version") {
        const arn = argument("--policy-arn");
        if (arn === retirement.permissionsBoundaryArn) {
          return { PolicyVersion: { VersionId: "v1", IsDefaultVersion: true, Document: retirement.permissionsBoundaryDocument } };
        }
        const mode = modeForRole(arn);
        return { PolicyVersion: { VersionId: "v1", IsDefaultVersion: true, Document: expected[mode].boundary.PolicyDocument } };
      }
      throw new Error("unexpected fake AWS command: " + args.join(" "));
    };
    const foundationResponse = (args) => {
      const value = structuredClone(response(args));
      if (
        args[1] === "list-role-policies" &&
        (args.includes("OrganizationSeedPreview") ||
          args.includes("OrganizationSeedApply"))
      ) {
        value.PolicyNames = [];
      }
      return value;
    };
    assert.equal(
      attestManagementSeedAccessFoundation(
        root,
        onboarding,
        foundationResponse,
      ).pass,
      true,
    );
    const progressResponse = (state) => (args) => {
      const value = structuredClone(response(args));
      const provisioner = args.includes("ManagementSeedProvisioner");
      if (args[1] === "get-role" && provisioner) {
        value.Role.Tags = state === "retired"
          ? retirement.requiredRoleTags
          : bundle.provisioning.active.requiredRoleTags;
        if (state === "active") delete value.Role.PermissionsBoundary;
      }
      if (args[1] === "list-role-policies" && provisioner) {
        value.PolicyNames = ["active", "bounded"].includes(state)
          ? [bundle.provisioning.active.inlinePolicyName]
          : [];
      }
      if (args[1] === "get-role-policy" && provisioner) {
        value.PolicyDocument = bundle.provisioning.active.inlinePolicyDocument;
      }
      if (
        args[1] === "get-policy" &&
        args.includes(retirement.permissionsBoundaryArn)
      ) {
        value.Policy.PermissionsBoundaryUsageCount = state === "active" ? 0 : 1;
      }
      return value;
    };
    for (const state of ["active", "bounded", "stripped", "retired"]) {
      assert.equal(
        attestProvisionerRetirementProgress(
          bundle,
          progressResponse(state),
        ).state,
        state,
      );
    }
    const nonMonotonic = (args) => {
      const value = progressResponse("bounded")(args);
      if (args[1] === "get-role" && args.includes("ManagementSeedProvisioner")) {
        value.Role.Tags = retirement.requiredRoleTags;
      }
      return value;
    };
    assert.throws(
      () => attestProvisionerRetirementProgress(bundle, nonMonotonic),
      /exact monotonic prefix/,
    );
    const attestation = attestManagementSeedAccessDeployment(root, onboarding, response);
    assert.equal(attestation.pass, true);
    assert.equal(attestation.observations.provisionerRetirement.required, true);
    assert.equal(attestation.observations.provisionerRetirement.observed, true);
    assert.match(attestation.attestationDigest, /^[a-f0-9]{64}$/);
    const drifted = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "list-attached-role-policies" && args.includes("OrganizationSeedPreview")) {
        value.AttachedPolicies = [{ PolicyName: "AdministratorAccess", PolicyArn: "arn:aws:iam::aws:policy/AdministratorAccess" }];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, drifted),
      /preview target role has attached policies/,
    );
    const widenedSourceTrust = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "get-role" && args.includes("ManagementSeedPreview")) {
        value.Role.AssumeRolePolicyDocument.Statement.push({
          Effect: "Allow",
          Principal: { AWS: "arn:aws:iam::999988887777:root" },
          Action: "sts:AssumeRole",
        });
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, widenedSourceTrust),
      /preview pre-organization source SAML-only trust/,
    );
    const activeProvisioner = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "list-role-policies" && args.includes("ManagementSeedProvisioner")) {
        value.PolicyNames = ["AdministratorAccess"];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, activeProvisioner),
      /provisioner retirement inline policy inventory/,
    );
    const missingRetirementBoundary = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "get-role" && args.includes("ManagementSeedProvisioner")) {
        delete value.Role.PermissionsBoundary;
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, missingRetirementBoundary),
      /provisioner retirement boundary usage count/,
    );
    const widenedRetirementBoundary = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "get-policy-version" && args.includes(retirement.permissionsBoundaryArn)) {
        value.PolicyVersion.Document.Statement[0].Effect = "Allow";
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, widenedRetirementBoundary),
      /provisioner retirement deny-all boundary document/,
    );
    const untaggedProvisioner = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "get-role" && args.includes("ManagementSeedProvisioner")) {
        value.Role.Tags = [];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(root, onboarding, untaggedProvisioner),
      /provisioner retirement tags/,
    );
    const activeResponse = (args) => {
      const value = structuredClone(response(args));
      if (args[1] === "get-role" && args.includes("ManagementSeedProvisioner")) {
        delete value.Role.PermissionsBoundary;
        value.Role.Tags = bundle.provisioning.active.requiredRoleTags;
      }
      if (args[1] === "list-role-policies" && args.includes("ManagementSeedProvisioner")) {
        value.PolicyNames = [bundle.provisioning.active.inlinePolicyName];
      }
      if (args[1] === "get-role-policy" && args.includes("ManagementSeedProvisioner")) {
        value.PolicyDocument = bundle.provisioning.active.inlinePolicyDocument;
      }
      if (
        args[1] === "get-policy" &&
        args.includes(retirement.permissionsBoundaryArn)
      ) {
        value.Policy.PermissionsBoundaryUsageCount = 0;
      }
      return value;
    };
    assert.equal(
      attestManagementSeedAccessInstallationProgress(
        root,
        onboarding,
        foundationResponse,
      ).state,
      "foundation",
    );
    assert.equal(
      attestManagementSeedAccessInstallationProgress(
        root,
        onboarding,
        activeResponse,
      ).state,
      "deployed",
    );
    const partialInstallation = (args) => {
      const value = structuredClone(activeResponse(args));
      if (
        args[1] === "list-role-policies" &&
        args.includes("OrganizationSeedPreview")
      ) {
        value.PolicyNames = [];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessInstallationProgress(
        root,
        onboarding,
        partialInstallation,
      ),
      /neither an exact empty foundation nor an exact deployment/,
    );
    const creationWindow = attestManagementSeedAccessDeployment(
      root,
      onboarding,
      activeResponse,
      { requireProvisionerRetired: false },
    );
    assert.equal(creationWindow.observations.provisionerRetirement.required, false);
    assert.equal(creationWindow.observations.provisionerRetirement.observed, true);
    assert.equal(creationWindow.observations.provisionerRetirement.state, "active");
    const changedSamlMetadata = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-saml-provider") {
        value.SAMLMetadataDocument = "substituted-saml-metadata";
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        changedSamlMetadata,
        { requireProvisionerRetired: false },
      ),
      /bootstrap SAML provider metadata SHA-256/,
    );
    const taggedSamlProvider = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-saml-provider") {
        value.Tags = [{ Key: "unreviewed", Value: "true" }];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        taggedSamlProvider,
        { requireProvisionerRetired: false },
      ),
      /bootstrap SAML provider tags/,
    );
    const encryptedSamlProvider = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-saml-provider") {
        value.AssertionEncryptionMode = "Required";
        value.PrivateKeyList = [{ KeyId: "SAMLATTACKERKEY" }];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        encryptedSamlProvider,
        { requireProvisionerRetired: false },
      ),
      /bootstrap SAML provider assertion encryption mode/,
    );
    const keyedSamlProvider = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-saml-provider") {
        value.PrivateKeyList = [{ KeyId: "SAMLATTACKERKEY" }];
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        keyedSamlProvider,
        { requireProvisionerRetired: false },
      ),
      /bootstrap SAML provider private key inventory/,
    );
    const missingActiveRetirementBoundary = (args) => {
      if (
        args[1] === "get-policy" &&
        args.includes(retirement.permissionsBoundaryArn)
      ) {
        throw new Error("NoSuchEntity: missing retirement boundary");
      }
      return structuredClone(activeResponse(args));
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        missingActiveRetirementBoundary,
        { requireProvisionerRetired: false },
      ),
      /missing retirement boundary/,
    );
    const widenedActiveRetirementBoundary = (args) => {
      const value = structuredClone(activeResponse(args));
      if (
        args[1] === "get-policy-version" &&
        args.includes(retirement.permissionsBoundaryArn)
      ) {
        value.PolicyVersion.Document.Statement[0].Effect = "Allow";
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        widenedActiveRetirementBoundary,
        { requireProvisionerRetired: false },
      ),
      /provisioner retirement deny-all boundary document/,
    );
    const widenedActiveGrant = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-role-policy" && args.includes("ManagementSeedProvisioner")) {
        value.PolicyDocument.Statement[0].Action = "*";
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        widenedActiveGrant,
        { requireProvisionerRetired: false },
      ),
      /active provisioner inline policy/,
    );
    const widenedRetirementAuthority = (args) => {
      const value = structuredClone(activeResponse(args));
      if (args[1] === "get-role-policy" && args.includes("ManagementSeedRetirement")) {
        value.PolicyDocument.Statement[0].Action = "*";
      }
      return value;
    };
    assert.throws(
      () => attestManagementSeedAccessDeployment(
        root,
        onboarding,
        widenedRetirementAuthority,
        { requireProvisionerRetired: false },
      ),
      /retirement authority inline policy/,
    );
  `;
  const result = runGuardedAccessScript(["--input-type=module", "-e", script]);
  assert.equal(result.status, 0, result.stderr);
});

test("access provisioning accepts only two bounded policies and resumable retirement", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { createManagementSeedAccessBundle } from "./scripts/management-seed-access.mjs";
    import { canonicalJson, sha256 } from "./scripts/management-seed-scope.mjs";
    import {
      accessChangeSetDescription,
      assertExactAccessChangeSet,
      assertFoundationObservationAwsCommand,
      createExecutedAccessReceipt,
      createFoundationObservationReceipt,
      createPreparedAccessReceipt,
      createProvisionerRetirementReceipt,
      executeAccessChangeSet,
      expectedAccessChangeSetName,
      observeCompletedAccessStack,
      prepareAccessChangeSet,
      performNextProvisionerRetirementOperation,
      reverifyAccessChangeSet,
    } from "./scripts/management-seed-access-provisioning.mjs";
    const onboarding = {
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn: "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn: "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn: "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256: "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn: "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    };
    const bundle = createManagementSeedAccessBundle(process.cwd(), onboarding);
    for (const command of [
      ["sts", "get-caller-identity"],
      ["iam", "get-saml-provider"],
      ["iam", "get-role"],
      ["iam", "list-role-policies"],
      ["iam", "get-role-policy"],
      ["iam", "list-attached-role-policies"],
      ["iam", "get-policy"],
      ["iam", "list-policy-versions"],
      ["iam", "get-policy-version"],
    ]) {
      assert.doesNotThrow(() => assertFoundationObservationAwsCommand(command));
    }
    for (const command of [
      ["cloudformation", "create-change-set"],
      ["iam", "put-role-policy"],
      ["iam", "tag-role"],
      ["s3", "list-buckets"],
      [],
    ]) {
      assert.throws(
        () => assertFoundationObservationAwsCommand(command),
        /foundation observation forbids AWS command/,
      );
    }
    const name = expectedAccessChangeSetName(bundle.bundleDigest);
    const description = {
      StackName: "deus-management-seed-access",
      ChangeSetName: name,
      ChangeSetId: "arn:aws:cloudformation:us-east-1:999988887777:changeSet/" + name + "/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      StackId: "arn:aws:cloudformation:us-east-1:999988887777:stack/deus-management-seed-access/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      Status: "CREATE_COMPLETE",
      ExecutionStatus: "AVAILABLE",
      ChangeSetType: "CREATE",
      Capabilities: [],
      Parameters: [],
      Tags: [],
      IncludeNestedStacks: false,
      Description: accessChangeSetDescription(bundle),
      Changes: [
        ["PreviewRolePolicy", "AWS::IAM::RolePolicy"],
        ["ApplyRolePolicy", "AWS::IAM::RolePolicy"],
      ].map(([LogicalResourceId, ResourceType]) => ({
        Type: "Resource",
        ResourceChange: { Action: "Add", LogicalResourceId, ResourceType },
      })),
    };
    const calls = [];
    const aws = {
      run(args) { calls.push(args); return {}; },
      json(args) {
        calls.push(args);
        if (args[1] === "validate-template") return { Capabilities: [] };
        if (args[1] === "create-change-set") return { Id: description.ChangeSetId, StackId: description.StackId };
        if (args[1] === "describe-change-set") return structuredClone(description);
        if (args[1] === "get-template") return { TemplateBody: structuredClone(bundle.cloudFormationTemplate) };
        if (args[1] === "describe-stacks") return { Stacks: [{ StackId: description.StackId, StackName: description.StackName, StackStatus: "CREATE_COMPLETE" }] };
        throw new Error("unexpected fake AWS command: " + args.join(" "));
      },
    };
    const preparedDescription = prepareAccessChangeSet(bundle, JSON.stringify(bundle.cloudFormationTemplate), aws);
    assert.equal(preparedDescription.ChangeSetId, description.ChangeSetId);
    assert.equal(reverifyAccessChangeSet(bundle, description.ChangeSetId, aws).ExecutionStatus, "AVAILABLE");
    assert.equal(executeAccessChangeSet(bundle, description.ChangeSetId, aws).StackStatus, "CREATE_COMPLETE");
    assert.equal(observeCompletedAccessStack(bundle, aws).StackStatus, "CREATE_COMPLETE");
    assert.ok(calls.some((args) => args[1] === "create-change-set" && !args.includes("--capabilities")));
    assert.ok(calls.some((args) => args[1] === "execute-change-set"));
    assert.equal(assertExactAccessChangeSet(bundle, description).length, 2);
    const capabilityClaimingAws = {
      ...aws,
      json(args) {
        if (args[1] === "validate-template") {
          return { Capabilities: ["CAPABILITY_NAMED_IAM"] };
        }
        return aws.json(args);
      },
    };
    assert.throws(
      () => prepareAccessChangeSet(
        bundle,
        JSON.stringify(bundle.cloudFormationTemplate),
        capabilityClaimingAws,
      ),
      /reported capabilities for the exact RolePolicy-only template/,
    );
    const callerArn = "arn:aws:sts::999988887777:assumed-role/ManagementSeedProvisioner/human";
    const candidateDigest = "a".repeat(64);
    const foundationSubject = {
      apiVersion: "security.deus.dev/management-seed-access-foundation-attestation/v1",
      managementAccountId: bundle.managementAccountId,
      awsPartition: bundle.awsPartition,
      managementAccessRegion: bundle.provisioning.region,
      bundleDigest: bundle.bundleDigest,
      observations: {},
      pass: true,
    };
    const foundationAttestation = {
      ...foundationSubject,
      attestationDigest: sha256(canonicalJson(foundationSubject)),
    };
    const observation = createFoundationObservationReceipt({
      bundle,
      candidateDigest,
      callerArn,
      attestation: foundationAttestation,
      generatedAt: "2026-07-20T00:00:00.000Z",
    });
    assert.equal(observation.cloudControlPlaneMutationPerformed, false);
    assert.equal(observation.iamMutationPerformed, false);
    assert.match(observation.receiptDigest, /^[a-f0-9]{64}$/);
    assert.throws(
      () => createFoundationObservationReceipt({
        bundle,
        candidateDigest,
        callerArn,
        attestation: { ...foundationAttestation, attestationDigest: "0".repeat(64) },
      }),
      /attestation is invalid/,
    );
    assert.throws(
      () => createFoundationObservationReceipt({
        bundle,
        candidateDigest,
        callerArn: "arn:aws:sts::999988887777:assumed-role/Admin/human",
        attestation: foundationAttestation,
      }),
      /caller is invalid/,
    );
    const prepared = createPreparedAccessReceipt({ bundle, candidateDigest, callerArn, description, generatedAt: "2026-07-20T00:00:00.000Z" });
    assert.equal(prepared.iamMutationPerformed, false);
    const attestation = { pass: true, bundleDigest: bundle.bundleDigest, attestationDigest: "b".repeat(64) };
    const executed = createExecutedAccessReceipt({
      prepared,
      candidateDigest,
      callerArn,
      stack: { StackId: description.StackId, StackName: description.StackName, StackStatus: "CREATE_COMPLETE" },
      attestation,
      generatedAt: "2026-07-20T00:01:00.000Z",
    });
    assert.equal(executed.iamMutationPerformed, true);
    assert.equal(executed.execution.provisionerAssignmentRetired, false);
    assert.equal(executed.execution.recoveredAfterPriorExecution, false);
    const completedDescription = structuredClone(description);
    completedDescription.ExecutionStatus = "EXECUTE_COMPLETE";
    assert.equal(
      assertExactAccessChangeSet(bundle, completedDescription, {
        executionStatus: "EXECUTE_COMPLETE",
      }).length,
      2,
    );
    assert.throws(
      () => assertExactAccessChangeSet(bundle, completedDescription),
      /execution status AVAILABLE/,
    );
    const recovered = createExecutedAccessReceipt({
      prepared,
      candidateDigest,
      callerArn,
      stack: { StackId: description.StackId, StackName: description.StackName, StackStatus: "CREATE_COMPLETE" },
      attestation,
      recoveredAfterPriorExecution: true,
      generatedAt: "2026-07-20T00:01:30.000Z",
    });
    assert.equal(recovered.execution.recoveredAfterPriorExecution, true);
    assert.equal(recovered.cloudControlPlaneMutationPerformed, false);
    assert.equal(recovered.iamMutationPerformed, false);
    const retirementCalls = [];
    const retirementAws = {
      run(args) { retirementCalls.push(args); return {}; },
    };
    const progress = (state, completedOperations) => {
      const subject = {
        required: state === "retired",
        observed: true,
        state,
        roleArn: bundle.provisioning.principalArn,
        boundaryArn: bundle.provisioning.retirement.permissionsBoundaryArn,
        completedOperations,
      };
      return { ...subject, progressDigest: sha256(canonicalJson(subject)) };
    };
    const first = performNextProvisionerRetirementOperation(
      bundle,
      progress("active", []),
      retirementAws,
    );
    const second = performNextProvisionerRetirementOperation(
      bundle,
      progress("bounded", [first.operation]),
      retirementAws,
    );
    const third = performNextProvisionerRetirementOperation(
      bundle,
      progress("stripped", [first.operation, second.operation]),
      retirementAws,
    );
    assert.equal(
      performNextProvisionerRetirementOperation(
        bundle,
        progress("retired", [first.operation, second.operation, third.operation]),
        retirementAws,
      ),
      null,
    );
    const operations = [first.operation, second.operation, third.operation];
    assert.deepEqual(operations, [
      "iam:PutRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
      "iam:TagRole",
    ]);
    assert.deepEqual(retirementCalls.map((args) => args[1]), [
      "put-role-permissions-boundary",
      "delete-role-policy",
      "tag-role",
    ]);
    const retirementAttestation = {
      pass: true,
      bundleDigest: bundle.bundleDigest,
      attestationDigest: "c".repeat(64),
      observations: { provisionerRetirement: { observed: true, state: "retired" } },
    };
    const retirementReceipt = createProvisionerRetirementReceipt({
      bundle,
      candidateDigest,
      callerArn: "arn:aws:sts::999988887777:assumed-role/ManagementSeedRetirement/human",
      executedAccessReceipt: executed,
      attestation: retirementAttestation,
      startingState: "active",
      performedOperations: operations,
      generatedAt: "2026-07-20T00:02:00.000Z",
    });
    assert.equal(retirementReceipt.accessMutationPerformed, true);
    assert.equal(retirementReceipt.upstreamIdpAssignmentRetired, false);
    assert.match(retirementReceipt.receiptDigest, /^[a-f0-9]{64}$/);
    const resumedReceipt = createProvisionerRetirementReceipt({
      bundle,
      candidateDigest,
      callerArn: retirementReceipt.callerArn,
      executedAccessReceipt: executed,
      attestation: retirementAttestation,
      startingState: "bounded",
      performedOperations: ["iam:DeleteRolePolicy", "iam:TagRole"],
    });
    assert.equal(resumedReceipt.startingState, "bounded");
    assert.equal(resumedReceipt.accessMutationPerformed, true);
    const alreadyRetiredReceipt = createProvisionerRetirementReceipt({
      bundle,
      candidateDigest,
      callerArn: retirementReceipt.callerArn,
      executedAccessReceipt: executed,
      attestation: retirementAttestation,
      startingState: "retired",
      performedOperations: [],
    });
    assert.equal(alreadyRetiredReceipt.accessMutationPerformed, false);
    assert.throws(
      () => createProvisionerRetirementReceipt({
        bundle,
        candidateDigest,
        callerArn: retirementReceipt.callerArn,
        executedAccessReceipt: executed,
        attestation: retirementAttestation,
        startingState: "active",
        performedOperations: [...operations].reverse(),
      }),
      /postcondition is invalid/,
    );
    const drifted = structuredClone(description);
    drifted.Changes[0].ResourceChange.Action = "Modify";
    assert.throws(() => assertExactAccessChangeSet(bundle, drifted), /unexpected IAM resource change/);
    const extra = structuredClone(description);
    extra.Changes.push({ Type: "Resource", ResourceChange: { Action: "Add", LogicalResourceId: "Admin", ResourceType: "AWS::IAM::Role" } });
    assert.throws(() => assertExactAccessChangeSet(bundle, extra), /unexpected IAM resource change/);
  `;
  const result = runGuardedAccessScript(["--input-type=module", "-e", script]);
  assert.equal(result.status, 0, result.stderr);
});

test("foundation observation mode parses before the credential boundary", () => {
  const result = runGuardedAccessScript([
    "scripts/provision-management-seed-access-main.mjs",
    "--observe-foundation",
    "--candidate",
    "artifacts/bootstrap-candidate.json",
    "--confirm-bundle-digest",
    "a".repeat(64),
  ]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /credentialed provisioning must start through/);
  assert.doesNotMatch(result.stderr, /choose exactly one/);
});

test("management-seed access renderer rejects a symlinked output ancestor before creating descendants", () => {
  const directory = mkdtempSync(
    join(process.cwd(), "artifacts", "access-bundle-output-deny-"),
  );
  const config = join(directory, "onboarding.local.json");
  const outside = join(directory, "outside");
  const linked = join(directory, "linked");
  mkdirSync(outside);
  symlinkSync(outside, linked, "dir");
  writeFileSync(
    config,
    JSON.stringify({
      managementAccessRegion: "us-east-1",
      managementAccountId: "999988887777",
      managementPreviewRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedPreview",
      managementApplyRoleArn:
        "arn:aws:iam::999988887777:role/OrganizationSeedApply",
      managementPreviewTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedPreview",
      managementApplyTrustedPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedApply",
      managementBootstrapSamlProviderArn:
        "arn:aws:iam::999988887777:saml-provider/DeusBootstrap",
      managementBootstrapSamlMetadataSha256:
        "caa51a7090f911cebbe039b71c1eb4812256108e4f85ee1dcc6245a88d51a8b3",
      managementProvisionerPrincipalArn:
        "arn:aws:iam::999988887777:role/deus/bootstrap-source/ManagementSeedProvisioner",
    }),
    { mode: 0o600 },
  );
  try {
    const originalConfig = readFileSync(config, "utf8");
    const overwrite = runGuardedAccessScript([
      "scripts/render-management-seed-access.mjs",
      "--config",
      config.slice(process.cwd().length + 1),
      "--output",
      config.slice(process.cwd().length + 1),
    ]);
    assert.notEqual(overwrite.status, 0);
    assert.match(overwrite.stderr, /must not overwrite/);
    assert.equal(readFileSync(config, "utf8"), originalConfig);

    const result = runGuardedAccessScript([
      "scripts/render-management-seed-access.mjs",
      "--config",
      config.slice(process.cwd().length + 1),
      "--output",
      join(linked, "new", "bundle.json").slice(process.cwd().length + 1),
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /must not traverse symbolic links/);
    assert.equal(existsSync(join(outside, "new")), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Pulumi readiness binds the exact backend URL and organization", () => {
  for (const [url, organizations, expected] of [
    ["https://api.pulumi.com", ["deus"], "pass"],
    ["https://attacker.invalid", ["deus"], "failure"],
    ["https://api.pulumi.com", ["attacker"], "failure"],
  ] as const) {
    const { root, config } = fixture();
    const bin = join(root, "bin");
    mkdirSync(bin);
    const pulumi = join(bin, "pulumi");
    writeFileSync(
      pulumi,
      `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "v3.253.0"
  exit 0
fi
echo '${JSON.stringify({ user: "operator", url, organizations })}'
`,
    );
    chmodSync(pulumi, 0o700);
    const result = spawnSync(
      process.execPath,
      [
        "scripts/bootstrap-doctor.mjs",
        "--root",
        root,
        "--config",
        config,
        "--check-pulumi-login",
        "--json",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
      },
    );
    const report = JSON.parse(result.stdout);
    const identity = report.checks.find(
      (check: any) => check.id === "pulumi.identity",
    );
    assert.equal(identity.status, expected);
    assert.equal(result.status === 0, expected === "pass");
  }
});

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function installAwsAccountAuditStub(root: string): string {
  const bin = join(root, "bin");
  mkdirSync(bin);
  const aws = join(bin, "aws");
  writeFileSync(
    aws,
    `#!/bin/sh
set -eu
mode="\${AWS_AUDIT_STUB_MODE:-pass}"
if [ "\${1:-}" = "--version" ]; then
  echo "aws-cli/2.test"
  exit 0
fi
if [ "\${AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:-}" != "true" ] ||
   [ -n "\${AWS_ENDPOINT_URL:-}" ] ||
   [ -n "\${AWS_ENDPOINT_URL_IAM:-}" ]; then
  exit 65
fi
case "\${1:-}:\${2:-}" in
  sts:get-caller-identity)
    printf '{"UserId":"session","Account":"999988887777","Arn":"%s"}\\n' \
      "\${AWS_AUDIT_STUB_ARN:-arn:aws:sts::999988887777:assumed-role/OrganizationSeedPreview/human-session}"
    ;;
  iam:get-account-summary)
    if [ "$mode" = "malformed-summary" ]; then
      printf '{\\n'
    elif [ "$mode" = "no-mfa" ]; then
      printf '{"SummaryMap":{"AccountMFAEnabled":0,"AccountAccessKeysPresent":0}}\\n'
    elif [ "$mode" = "root-access-key" ]; then
      printf '{"SummaryMap":{"AccountMFAEnabled":1,"AccountAccessKeysPresent":1}}\\n'
    else
      printf '{"SummaryMap":{"AccountMFAEnabled":1,"AccountAccessKeysPresent":0}}\\n'
    fi
    ;;
  account:get-contact-information)
    printf '%s\\n' '{"ContactInformation":{"FullName":"Private Operator","AddressLine1":"Private","City":"Paris","PostalCode":"75000","CountryCode":"FR","PhoneNumber":"+33123456789"}}'
    ;;
  account:get-alternate-contact)
    case " $* " in
      *" BILLING "*) contact_type="BILLING"; email="billing@example.invalid" ;;
      *" OPERATIONS "*) contact_type="OPERATIONS"; email="operations@example.invalid" ;;
      *" SECURITY "*)
        if [ "$mode" = "missing-contact" ]; then
          echo "owner@example.invalid" >&2
          exit 254
        fi
        contact_type="SECURITY"
        email="security@example.invalid"
        ;;
      *) exit 64 ;;
    esac
    printf '{"AlternateContact":{"AlternateContactType":"%s","EmailAddress":"%s","Name":"Private Operator","PhoneNumber":"+33123456789","Title":"Owner"}}\\n' "$contact_type" "$email"
    ;;
  ec2:describe-regions)
    if [ "$mode" = "malformed-regions" ]; then
      printf '{"Regions":[{"RegionName":"../invalid","OptInStatus":"opted-in"}]}\\n'
    else
      printf '%s\\n' '{"Regions":[{"RegionName":"eu-west-3","OptInStatus":"opted-in"},{"RegionName":"us-east-1","OptInStatus":"opt-in-not-required"},{"RegionName":"af-south-1","OptInStatus":"not-opted-in"}]}'
    fi
    ;;
  cloudtrail:lookup-events)
    if [ "$mode" = "truncated-history" ]; then
      printf '{"Events":[],"NextToken":"confidential-token"}\\n'
    elif [ "$mode" = "root-event" ]; then
      printf '{"Events":[{"EventId":"00000000-0000-4000-8000-000000000000","EventName":"ConsoleLogin","EventTime":"%s","Username":"root"}]}\\n' "\${AWS_AUDIT_STUB_EVENT_TIME}"
    else
      printf '{"Events":[]}\\n'
    fi
    ;;
  *)
    exit 64
    ;;
esac
`,
    { mode: 0o700 },
  );
  return bin;
}

function replaceStack(root: string, before: string, after: string) {
  const file = join(root, "Pulumi.management.yaml");
  const contents = readFileSync(file, "utf8");
  assert.ok(contents.includes(before), `fixture lacks ${before}`);
  writeFileSync(file, contents.replace(before, after));
}

function runGuardedAccessScript(args: string[]) {
  const scope = JSON.parse(
    readFileSync("security/management-seed-qualification-scope.json", "utf8"),
  );
  return spawnSync(
    process.execPath,
    [
      "--require",
      join(process.cwd(), "scripts/management-seed-test-runtime-guard.cjs"),
      ...args,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        MANAGEMENT_SEED_TEST_ROOT: process.cwd(),
        MANAGEMENT_SEED_TEST_ALLOWED_FILES: JSON.stringify(
          scope.tests.compiledOutputs,
        ),
        MANAGEMENT_SEED_TEST_ALLOWED_SOURCE_FILES: JSON.stringify(
          scope.sourceFiles.filter((entry: string) =>
            /^scripts\/.*\.(?:cjs|mjs)$/.test(entry),
          ),
        ),
      },
    },
  );
}
