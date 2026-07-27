import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("database module creates encrypted Aurora cluster with private posture, IAM auth, and an RDS Proxy", async () => {
  const { resources } = await installPulumiMocks();
  const { createDatabaseCluster } = await import("../src/database.js");

  createDatabaseCluster({
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
    vpcCidr: "10.10.0.0/16",
    privateSubnetIds: ["subnet-a", "subnet-b", "subnet-c"],
  });

  await flushPulumiMocks();

  const clusters = resourcesOfType(resources, "aws:rds/cluster:Cluster");
  assert.equal(clusters.length, 1);
  assert.equal(clusters[0].inputs.storageEncrypted, true);
  assert.equal(clusters[0].inputs.iamDatabaseAuthenticationEnabled, true);
  assert.equal(clusters[0].inputs.deletionProtection, true);
  assert.equal(clusters[0].inputs.backupRetentionPeriod, 35);
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
  assert.equal(proxies[0].inputs.auths[0].iamAuth, "REQUIRED");

  const securityGroups = resourcesOfType(
    resources,
    "aws:ec2/securityGroup:SecurityGroup",
  );
  assert.equal(securityGroups.length, 1);
  assert.equal(securityGroups[0].inputs.ingress[0].fromPort, 5432);
});
