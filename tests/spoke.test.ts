import test from "node:test";
import assert from "node:assert/strict";
import * as pulumi from "@pulumi/pulumi";
import {
  installPulumiMocks,
  flushPulumiMocks,
  resourcesOfType,
  testDatabaseIamRoleConstraint,
} from "./helpers/pulumiMocks";
import { createReferenceBlueprint } from "../src/core";
import { readFileSync } from "node:fs";

test("detached spoke stacks stay private and attach to the shared Transit Gateway", async () => {
  const { resources } = await installPulumiMocks();
  const { createDetachedSpokeNetwork } = await import("../src/network");

  createDetachedSpokeNetwork({
    name: "platform-dev",
    kind: "platform",
    cidr: "10.10.0.0/16",
    createEks: true,
    azCount: 3,
    transitGatewayId: "tgw-shared",
  });

  await flushPulumiMocks();

  const internetGateways = resourcesOfType(
    resources,
    "aws:ec2/internetGateway:InternetGateway",
  );
  const natGateways = resourcesOfType(
    resources,
    "aws:ec2/natGateway:NatGateway",
  );
  const attachment = resourcesOfType(
    resources,
    "aws:ec2transitgateway/vpcAttachment:VpcAttachment",
  )[0];
  const flowLogs = resourcesOfType(resources, "aws:ec2/flowLog:FlowLog");
  const endpoints = resourcesOfType(
    resources,
    "aws:ec2/vpcEndpoint:VpcEndpoint",
  );
  const defaultRoutes = resourcesOfType(
    resources,
    "aws:ec2/route:Route",
  ).filter((route) => route.inputs.destinationCidrBlock === "0.0.0.0/0");

  assert.equal(
    internetGateways.length,
    0,
    "spoke accounts must not create Internet Gateways",
  );
  assert.equal(
    natGateways.length,
    0,
    "spoke accounts must not create NAT gateways",
  );
  assert.equal(attachment.inputs.transitGatewayId, "tgw-shared");
  assert.equal(
    attachment.inputs.transitGatewayDefaultRouteTableAssociation,
    undefined,
  );
  assert.equal(
    attachment.inputs.transitGatewayDefaultRouteTablePropagation,
    undefined,
  );
  assert.equal(flowLogs.length, 1, "detached spoke VPC must emit flow logs");
  assert.equal(flowLogs[0].inputs.trafficType, "ALL");
  assert.ok(
    endpoints.every((endpoint) => endpoint.inputs.policy),
    "spoke endpoints must use explicit policies",
  );
  assert.equal(
    defaultRoutes.length,
    3,
    "each private subnet should route default egress to the shared TGW",
  );
  assert.ok(
    defaultRoutes.every(
      (route) => route.inputs.transitGatewayId === "tgw-shared",
    ),
  );
});

test("blueprint-driven microVM spoke creates private EKS from neutral workload intent", async () => {
  const { resources } = await installPulumiMocks();
  const { createSpokeClusterStack } =
    await import("../src/stacks/spokeClusterStack");

  const result = createSpokeClusterStack({
    spokeConfig: {
      name: "tenant-a-execution-net",
      kind: "execution",
      cidr: "192.0.2.0/24",
      azCount: 2,
      createEks: false,
      networkStackRef: "",
      transitGatewayId: "tgw-shared",
      zoneId: "tenant-a-execution",
      networkDomainId: "tenant-a-execution-net",
    },
    eksConfig: {
      version: "1.33",
      endpointPublicAccess: false,
      autoModeNodePools: ["system"],
      networkPolicyMode: "strict",
      accessGrants: [],
    },
    securityConfig: { enableGuardDuty: false, enableSecurityHub: false },
    platformBlueprint: createReferenceBlueprint("microvm-fallback"),
  });

  await flushPulumiMocks();
  assert.equal(result.spoke.cidr, "10.30.0.0/16");
  assert.equal(result.workloadPlan?.deploymentKind, "private-eks-microvm");
  assert.equal(resourcesOfType(resources, "aws:eks/cluster:Cluster").length, 1);
  assert.equal(
    resourcesOfType(resources, "aws:ec2/internetGateway:InternetGateway")
      .length,
    0,
  );
});

test("blueprint-driven E2B spoke creates vendor access but no ordinary execution cluster", async () => {
  const { resources } = await installPulumiMocks();
  const { createSpokeClusterStack } =
    await import("../src/stacks/spokeClusterStack");

  const result = createSpokeClusterStack({
    spokeConfig: {
      name: "tenant-a-execution-net",
      kind: "execution",
      cidr: "10.30.0.0/16",
      azCount: 3,
      createEks: true,
      networkStackRef: "",
      transitGatewayId: "tgw-shared",
      zoneId: "tenant-a-execution",
      networkDomainId: "tenant-a-execution-net",
    },
    eksConfig: {
      version: "1.33",
      endpointPublicAccess: false,
      autoModeNodePools: ["system"],
      networkPolicyMode: "strict",
      accessGrants: [],
    },
    securityConfig: { enableGuardDuty: false, enableSecurityHub: false },
    platformBlueprint: createReferenceBlueprint("e2b-byoc"),
    e2bByocAccessConfig: {
      createVendorRole: true,
      vendorPrincipalArns: ["arn:aws:iam::123456789012:role/e2b-control-plane"],
      externalId: "reviewed-external-id-1234",
      managedPolicyArns: [],
    },
  });
  await flushPulumiMocks();
  assert.equal(result.workloadPlan?.deploymentKind, "e2b-byoc");
  assert.equal(resourcesOfType(resources, "aws:eks/cluster:Cluster").length, 0);
  assert.equal(
    resourcesOfType(resources, "aws:iam/role:Role").filter(
      (role) => role.inputs.tags?.AccessClass === "vendor-byoc",
    ).length,
    1,
  );
});

test("blueprint-driven data spoke creates Aurora from neutral relational recovery intent", async () => {
  const { resources } = await installPulumiMocks();
  const { createSpokeClusterStack } =
    await import("../src/stacks/spokeClusterStack");
  const blueprint = createReferenceBlueprint("dedicated-data");
  blueprint.dataBoundaries = blueprint.dataBoundaries.map((boundary) => ({
    ...boundary,
    services: ["object", "relational"] as const,
  }));

  const result = createSpokeClusterStack({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    spokeConfig: {
      name: "tenant-a-data-net",
      kind: "data",
      cidr: "10.40.0.0/16",
      azCount: 3,
      createEks: false,
      networkStackRef: "",
      transitGatewayId: "tgw-shared",
      zoneId: "tenant-a-data-zone",
      networkDomainId: "tenant-a-data-net",
    },
    eksConfig: {
      version: "1.33",
      endpointPublicAccess: false,
      autoModeNodePools: ["system"],
      networkPolicyMode: "strict",
      accessGrants: [],
    },
    securityConfig: { enableGuardDuty: false, enableSecurityHub: false },
    platformBlueprint: blueprint,
    databaseConfig: {
      name: "mind",
      engine: "aurora-postgresql",
      engineVersion: "16.4",
      engineMajorVersion: "16",
      databaseName: "mind",
      masterUsername: "mind_admin",
      port: 5432,
      instanceClass: "db.r6g.large",
      instanceCount: 2,
      backupRetentionDays: 35,
      deletionProtection: true,
      createProxy: true,
    },
  });
  await flushPulumiMocks();
  assert.equal(result.workloadPlan, undefined);
  assert.equal(result.databasePlans.length, 1);
  assert.equal(Object.keys(result.databases).length, 1);
  const cluster = resourcesOfType(resources, "aws:rds/cluster:Cluster")[0];
  assert.equal(cluster.inputs.tags.DataBoundaryId, "tenant-a-data");
  assert.equal(cluster.inputs.deletionProtection, true);
  assert.equal(resourcesOfType(resources, "aws:eks/cluster:Cluster").length, 0);
});

test("checked Warden/Mind managed PostgreSQL intent materializes three credential-free AWS bindings", async () => {
  const { resources } = await installPulumiMocks();
  const { createSpokeClusterStack } =
    await import("../src/stacks/spokeClusterStack");
  const { createWardenMindBlueprint, parseManagedPostgresIntent } =
    await import("../src/core");
  const blueprint = createWardenMindBlueprint({
    networkCidrs: {
      "egress-net": "10.0.0.0/16",
      "control-net": "10.10.0.0/16",
      "execution-shared-net": "10.20.0.0/16",
      "data-shared-net": "10.30.0.0/16",
    },
  });
  const intent = parseManagedPostgresIntent(
    JSON.parse(
      readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
    ),
    "development",
    blueprint,
  );

  const result = createSpokeClusterStack({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    spokeConfig: {
      name: "platform-dev",
      kind: "platform",
      cidr: "10.10.0.0/16",
      azCount: 3,
      createEks: true,
      networkStackRef: "",
      transitGatewayId: "tgw-shared",
      zoneId: "control",
      networkDomainId: "control-net",
    },
    eksConfig: {
      version: "1.33",
      endpointPublicAccess: false,
      autoModeNodePools: ["system", "general-purpose"],
      networkPolicyMode: "strict",
      accessGrants: [],
    },
    securityConfig: { enableGuardDuty: false, enableSecurityHub: false },
    platformBlueprint: blueprint,
    managedPostgresIntent: intent,
    awsOrganizationId: "o-example123456",
    awsAccountId: "111111111111",
    awsRegion: "us-east-1",
    e2bByocAccessConfig: {
      createVendorRole: true,
      vendorPrincipalArns: ["arn:aws:iam::123456789012:role/e2b-control-plane"],
      externalId: "reviewed-external-id-1234",
      managedPolicyArns: [],
    },
    databaseConfig: {
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
      replicaRegion: "us-west-2",
    },
  });
  let resolvedBindings: unknown;
  let resolvedMigrationBindings: unknown;
  let resolvedBootstrapBindings: unknown;
  pulumi.output(result.databaseBindings).apply((value) => {
    resolvedBindings = value;
    return value;
  });
  pulumi.output(result.databaseBootstrapBindings).apply((value) => {
    resolvedBootstrapBindings = value;
    return value;
  });
  pulumi.output(result.databaseMigrationBindings).apply((value) => {
    resolvedMigrationBindings = value;
    return value;
  });

  await flushPulumiMocks();

  assert.deepEqual(Object.keys(result.databases).sort(), [
    "mind-infra-state",
    "mind-users-state",
    "warden-saas-state",
  ]);
  assert.deepEqual(Object.keys(result.databaseBindings).sort(), [
    "mind-infra-postgres",
    "mind-users-postgres",
    "warden-saas-postgres",
  ]);
  assert.deepEqual(Object.keys(result.databaseBootstrapBindings).sort(), [
    "mind-infra-postgres",
    "mind-users-postgres",
    "warden-saas-postgres",
  ]);
  assert.deepEqual(Object.keys(result.databaseMigrationBindings).sort(), [
    "mind-infra-postgres",
    "mind-users-postgres",
    "warden-saas-postgres",
  ]);
  assert.deepEqual(Object.keys(result.databaseAccess).sort(), [
    "mind-infra-postgres",
    "mind-users-postgres",
    "warden-saas-postgres",
  ]);
  assert.equal(result.managedPostgresPlan?.claims.length, 3);
  assert.ok(
    result.managedPostgresPlan?.claims.every(
      (claim) =>
        claim.brokerClaim.generation === 1 &&
        claim.provider.accountId === "111111111111" &&
        claim.outputs.credentialValue === null,
    ),
  );
  assert.equal(resourcesOfType(resources, "aws:rds/cluster:Cluster").length, 3);
  assert.equal(resourcesOfType(resources, "aws:rds/proxy:Proxy").length, 3);
  assert.equal(
    resourcesOfType(
      resources,
      "aws:eks/podIdentityAssociation:PodIdentityAssociation",
    ).length,
    6,
  );
  const renderedBindings = JSON.stringify(resolvedBindings);
  assert.equal(
    /password|tokenValue|secretValue/i.test(renderedBindings),
    false,
  );
  assert.match(
    renderedBindings,
    /aws-rds:\/\/truststore\/global\/global-bundle\.pem/,
  );
  assert.match(renderedBindings, /per-physical-connection/);
  assert.match(renderedBindings, /desiredStateDigest/);
  assert.match(renderedBindings, /POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED/);
  assert.doesNotMatch(
    renderedBindings,
    /migrationIdentityId|migrationDatabaseUser|migrationAccessSecurityGroupId|bootstrapAccessSecurityGroupId|bootstrapEndpoint|bootstrapMasterSecretArn|masterSecretArn|codefly-system/i,
  );
  const renderedMigrationBindings = JSON.stringify(resolvedMigrationBindings);
  assert.match(renderedMigrationBindings, /migrationIdentityId/);
  assert.match(renderedMigrationBindings, /migrationDatabaseUser/);
  assert.doesNotMatch(
    renderedMigrationBindings,
    /runtimeIdentityId|runtimeDatabaseUser|masterSecretArn|bootstrapAccessSecurityGroupId|bootstrapEndpoint/i,
  );
  const renderedBootstrapBindings = JSON.stringify(resolvedBootstrapBindings);
  assert.match(renderedBootstrapBindings, /masterSecretArn/);
  assert.match(
    renderedBootstrapBindings,
    /POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED/,
  );
});
