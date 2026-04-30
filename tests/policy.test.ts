import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("policy pack blocks broad IAM identity access", () => {
  const policy = readFileSync("policy/index.ts", "utf8");

  assert.match(policy, /iam-identity-policies-avoid-broad-admin/);
  assert.match(policy, /AdministratorAccess/);
  assert.match(policy, /PowerUserAccess/);
  assert.match(policy, /IAMFullAccess/);
  assert.match(policy, /iam:PassRole/);
  assert.match(policy, /sts:AssumeRole/);
  assert.match(policy, /NotAction/);
});

test("policy pack requires encrypted evidence and no long-lived IAM users", () => {
  const policy = readFileSync("policy/index.ts", "utf8");

  assert.match(policy, /cloudwatch-log-groups-retain-security-evidence/);
  assert.match(policy, /retentionInDays to at least 365/);
  assert.match(policy, /secrets-manager-secrets-use-cmk/);
  assert.match(policy, /kmsKeyId/);
  assert.match(policy, /s3-encryption-uses-kms/);
  assert.match(policy, /blockedEncryptionTypes/);
  assert.match(policy, /no-iam-users-or-access-keys/);
  assert.match(policy, /aws:iam\/accessKey:AccessKey/);
  assert.match(policy, /ec2-instances-require-imdsv2/);
  assert.match(policy, /httpTokens/);
});

test("policy pack also inspects IAM Identity Center inline policies", () => {
  const policy = readFileSync("policy/index.ts", "utf8");

  assert.match(
    policy,
    /aws:ssoadmin\/permissionSetInlinePolicy:PermissionSetInlinePolicy/,
  );
  assert.match(policy, /isIdentityCenterInlinePolicyResource/);
  assert.match(policy, /args\.props\.inlinePolicy/);
});

test("policy pack covers RDS, AWS Backup, WAFv2, and Macie controls", () => {
  const policy = readFileSync("policy/index.ts", "utf8");

  for (const expected of [
    /rds-clusters-private-and-protected/,
    /iamDatabaseAuthenticationEnabled/,
    /backupRetentionPeriod/,
    /rds-proxies-require-tls/,
    /backup-vault-uses-cmk/,
    /backup-plans-include-cross-region-copy/,
    /lifecycle\.deleteAfter must be at least 35/,
    /wafv2-web-acl-has-rate-limit/,
    /rateBasedStatement/,
    /macie-account-finding-frequency/,
    /FIFTEEN_MINUTES/,
  ]) {
    assert.match(policy, expected);
  }
});
