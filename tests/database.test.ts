import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
  testDatabaseIamRoleConstraint,
} from "./helpers/pulumiMocks";

test("database module creates encrypted Aurora cluster with private posture, IAM auth, and an RDS Proxy", async () => {
  const { resources } = await installPulumiMocks();
  const { createDatabaseCluster } = await import("../src/database");

  createDatabaseCluster({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    config: {
      name: "control-plane",
      engine: "aurora-postgresql",
      engineVersion: "16.4",
      engineMajorVersion: "16",
      databaseName: "deus",
      masterUsername: "deus_admin",
      port: 5432,
      instanceClass: "db.r6g.large",
      instanceCount: 2,
      backupRetentionDays: 35,
      deletionProtection: true,
      createProxy: true,
    },
    vpcId: "vpc-test",
    privateSubnetIds: ["subnet-a", "subnet-b", "subnet-c"],
    accessBoundaryIds: {
      runtime: "warden-runtime-db-access",
      migration: "warden-migration-db-access",
      bootstrap: "warden-bootstrap-db-access",
    },
    databaseIdentityUsers: {
      runtime: "warden_runtime",
      migration: "warden_migration",
    },
  });

  await flushPulumiMocks();

  const clusters = resourcesOfType(resources, "aws:rds/cluster:Cluster");
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].inputs.storageEncrypted, true);
  assert.equal(clusters[0].inputs.iamDatabaseAuthenticationEnabled, true);
  assert.equal(clusters[0].inputs.manageMasterUserPassword, true);
  assert.ok(clusters[0].inputs.masterUserSecretKmsKeyId);
  assert.equal(clusters[0].inputs.masterPassword, undefined);
  assert.equal(clusters[0].inputs.deletionProtection, true);
  assert.equal(clusters[0].inputs.backupRetentionPeriod, 35);
  assert.match(clusters[0].inputs.finalSnapshotIdentifier, /-final$/);
  assert.doesNotMatch(clusters[0].inputs.finalSnapshotIdentifier, /\d{13}/);
  assert.deepEqual(clusters[0].inputs.enabledCloudwatchLogsExports, [
    "postgresql",
  ]);

  const instances = resourcesOfType(
    resources,
    "aws:rds/clusterInstance:ClusterInstance",
  );
  assert.equal(instances.length, 2);
  assert.ok(
    instances.every((instance) => instance.inputs.publiclyAccessible === false),
  );
  assert.ok(
    instances.every(
      (instance) => instance.inputs.performanceInsightsEnabled === true,
    ),
  );
  assert.ok(
    instances.every(
      (instance) => instance.inputs.caCertIdentifier === "rds-ca-rsa4096-g1",
    ),
  );

  const params = resourcesOfType(
    resources,
    "aws:rds/clusterParameterGroup:ClusterParameterGroup",
  )[0];
  const paramNames = params.inputs.parameters.map(
    (entry: { name: string }) => entry.name,
  );
  assert.ok(paramNames.includes("rds.force_ssl"));
  assert.ok(paramNames.includes("pgaudit.log"));

  const proxies = resourcesOfType(resources, "aws:rds/proxy:Proxy");
  assert.equal(proxies.length, 1);
  assert.equal(proxies[0].inputs.requireTls, true);
  assert.equal(proxies[0].inputs.defaultAuthScheme, "IAM_AUTH");
  assert.equal(proxies[0].inputs.auths, undefined);

  const proxyRole = resourcesOfType(resources, "aws:iam/role:Role").find(
    (resource) => resource.name.endsWith("db-proxy-role"),
  );
  assert.ok(proxyRole);
  assert.match(proxyRole.inputs.name, /^deus-platform-dev-database-/);
  assert.equal(
    proxyRole.inputs.permissionsBoundary,
    testDatabaseIamRoleConstraint().permissionsBoundaryArn,
  );
  const monitoringRole = resourcesOfType(resources, "aws:iam/role:Role").find(
    (resource) => resource.name.endsWith("db-monitoring-role"),
  );
  assert.ok(monitoringRole);
  assert.match(monitoringRole.inputs.name, /^deus-platform-dev-database-/);
  assert.equal(
    monitoringRole.inputs.permissionsBoundary,
    testDatabaseIamRoleConstraint().permissionsBoundaryArn,
  );
  const proxyTrust = JSON.parse(proxyRole.inputs.assumeRolePolicy);
  assert.equal(
    proxyTrust.Statement[0].Condition.StringEquals["aws:SourceAccount"],
    "111111111111",
  );
  assert.equal(
    proxyTrust.Statement[0].Condition.ArnLike["aws:SourceArn"],
    "arn:aws:rds:us-east-1:111111111111:db-proxy:*",
  );

  const databaseKey = resourcesOfType(resources, "aws:kms/key:Key")[0];
  const databaseKeyPolicy = JSON.parse(databaseKey.inputs.policy);
  assert.equal(databaseKeyPolicy.Statement.length, 1);
  assert.deepEqual(databaseKeyPolicy.Statement[0].Principal, {
    AWS: "arn:aws:iam::111111111111:root",
  });
  assert.doesNotMatch(databaseKey.inputs.policy, /rds\.amazonaws\.com/);

  assert.equal(
    resourcesOfType(resources, "aws:secretsmanager/secret:Secret").length,
    0,
  );
  assert.equal(
    resourcesOfType(resources, "aws:secretsmanager/secretVersion:SecretVersion")
      .length,
    0,
  );

  const proxyPolicy = resourcesOfType(
    resources,
    "aws:iam/rolePolicy:RolePolicy",
  ).find((resource) => resource.name.endsWith("db-proxy-connect"));
  assert.ok(proxyPolicy);
  assert.match(proxyPolicy.inputs.policy, /rds-db:connect/);
  assert.doesNotMatch(proxyPolicy.inputs.policy, /secretsmanager:/);
  assert.doesNotMatch(proxyPolicy.inputs.policy, /dbuser:[^" ]+\/\*/);
  assert.match(proxyPolicy.inputs.policy, /warden_runtime/);
  assert.match(proxyPolicy.inputs.policy, /warden_migration/);

  const securityGroups = resourcesOfType(
    resources,
    "aws:ec2/securityGroup:SecurityGroup",
  );
  assert.equal(securityGroups.length, 5);
  assert.ok(
    securityGroups.every(
      (securityGroup) =>
        securityGroup.inputs.ingress.length === 0 &&
        securityGroup.inputs.egress.length === 0,
    ),
  );
  assert.ok(
    securityGroups.every(
      (securityGroup) =>
        !JSON.stringify(securityGroup.inputs).includes("10.10.0.0/16"),
    ),
  );
  const ingressRules = resourcesOfType(
    resources,
    "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule",
  );
  const egressRules = resourcesOfType(
    resources,
    "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule",
  );
  assert.equal(ingressRules.length, 4);
  assert.equal(egressRules.length, 4);
  assert.ok(
    [...ingressRules, ...egressRules].every(
      (rule) =>
        rule.inputs.fromPort === 5432 &&
        rule.inputs.toPort === 5432 &&
        rule.inputs.referencedSecurityGroupId,
    ),
  );
  assert.ok(
    securityGroups.some(
      (securityGroup) =>
        securityGroup.inputs.tags.SemanticBoundaryId ===
        "warden-runtime-db-access",
    ),
  );
  assert.ok(
    securityGroups.some(
      (securityGroup) =>
        securityGroup.inputs.tags.AccessRole === "bootstrap" &&
        securityGroup.inputs.tags.SemanticBoundaryId ===
          "warden-bootstrap-db-access",
    ),
  );
  const bootstrapIngress = ingressRules.find((rule) =>
    rule.name.includes("bootstrap-to-database-ingress"),
  );
  const bootstrapEgress = egressRules.find((rule) =>
    rule.name.includes("bootstrap-to-database-egress"),
  );
  assert.ok(bootstrapIngress);
  assert.ok(bootstrapEgress);
  assert.equal(
    bootstrapIngress.inputs.securityGroupId,
    securityGroups.find(
      (securityGroup) =>
        securityGroup.inputs.tags.AccessRole === undefined &&
        securityGroup.inputs.description.includes("Database target boundary"),
    )?.name + "_id",
  );
  assert.equal(
    bootstrapEgress.inputs.securityGroupId,
    securityGroups.find(
      (securityGroup) => securityGroup.inputs.tags.AccessRole === "bootstrap",
    )?.name + "_id",
  );
});
