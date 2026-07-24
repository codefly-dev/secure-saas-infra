import test from "node:test";
import assert from "node:assert/strict";
import {
  compileAwsPostgresBootstrapSecretPolicy,
  compileAwsRdsProxyConnectPolicy,
} from "../src/adapters/aws";
import { rdsProxyResourceIdFromArn } from "../src/database";

test("RDS Proxy IAM policy binds one proxy resource and one PostgreSQL login", () => {
  const policy = compileAwsRdsProxyConnectPolicy({
    partition: "aws",
    region: "us-east-1",
    accountId: "123456789012",
    proxyResourceId: "prx-0123456789abcdef0",
    databaseUser: "tenant_a_runtime_ro",
    role: "runtime",
  });
  assert.deepEqual(policy.Statement, [
    {
      Sid: "RuntimeDatabaseConnect",
      Effect: "Allow",
      Action: "rds-db:connect",
      Resource:
        "arn:aws:rds-db:us-east-1:123456789012:dbuser:prx-0123456789abcdef0/tenant_a_runtime_ro",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(policy), /cluster-|\/\*/);
});

test("RDS Proxy IAM policy rejects cluster IDs, wildcards, unsafe users, and invalid accounts", () => {
  const baseline = {
    partition: "aws" as const,
    region: "us-east-1",
    accountId: "123456789012",
    proxyResourceId: "prx-0123456789abcdef0",
    databaseUser: "tenant_a_runtime_rw",
    role: "runtime" as const,
  };
  for (const candidate of [
    { ...baseline, proxyResourceId: "cluster-ABCDEFGHIJK" },
    { ...baseline, proxyResourceId: "prx-*" },
    { ...baseline, databaseUser: "tenant-a;superuser" },
    { ...baseline, databaseUser: "*" },
    { ...baseline, accountId: "1234" },
    { ...baseline, region: "global" },
  ]) {
    assert.throws(
      () => compileAwsRdsProxyConnectPolicy(candidate),
      /requires an exact Region, account, Proxy resource ID, and PostgreSQL user/,
    );
  }
});

test("RDS Proxy resource ID is extracted only from an exact AWS Proxy ARN", () => {
  assert.equal(
    rdsProxyResourceIdFromArn(
      "arn:aws:rds:us-east-1:123456789012:db-proxy:prx-0123456789abcdef0",
    ),
    "prx-0123456789abcdef0",
  );
  assert.throws(
    () =>
      rdsProxyResourceIdFromArn(
        "arn:aws:rds:us-east-1:123456789012:cluster:cluster-example",
      ),
    /does not contain one exact Proxy resource ID/,
  );
  assert.throws(
    () => rdsProxyResourceIdFromArn("prx-0123456789abcdef0"),
    /does not contain one exact Proxy resource ID/,
  );
});

test("PostgreSQL bootstrap can read only the RDS-managed master secret through one VPC endpoint", () => {
  const policy = compileAwsPostgresBootstrapSecretPolicy({
    partition: "aws",
    region: "us-east-1",
    accountId: "123456789012",
    masterSecretArn:
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!cluster-012345-AbCdEf",
    kmsKeyArn:
      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
    secretsManagerVpcEndpointId: "vpce-0123456789abcdef0",
  });
  const rendered = JSON.stringify(policy);
  assert.match(rendered, /secretsmanager:GetSecretValue/);
  assert.match(rendered, /kms:EncryptionContext:SecretARN/);
  assert.match(rendered, /secretsmanager\.us-east-1\.amazonaws\.com/);
  assert.match(rendered, /vpce-0123456789abcdef0/);
  assert.doesNotMatch(rendered, /"Resource":"\*"|ListSecrets/);
});

test("PostgreSQL bootstrap rejects cross-account, wildcard, direct-KMS, and non-VPC secret access", () => {
  const baseline = {
    partition: "aws" as const,
    region: "us-east-1",
    accountId: "123456789012",
    masterSecretArn:
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:rds!cluster-012345-AbCdEf",
    kmsKeyArn:
      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
    secretsManagerVpcEndpointId: "vpce-0123456789abcdef0",
  };
  for (const candidate of [
    {
      ...baseline,
      masterSecretArn: baseline.masterSecretArn.replace(
        "123456789012",
        "210987654321",
      ),
    },
    { ...baseline, masterSecretArn: `${baseline.masterSecretArn}*` },
    {
      ...baseline,
      kmsKeyArn: baseline.kmsKeyArn.replace("123456789012", "210987654321"),
    },
    { ...baseline, secretsManagerVpcEndpointId: "*" },
  ]) {
    assert.throws(
      () => compileAwsPostgresBootstrapSecretPolicy(candidate),
      /requires exact same-account Secret, KMS key, Region, and Secrets Manager VPC endpoint/,
    );
  }
});
