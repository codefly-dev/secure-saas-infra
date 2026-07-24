import test from "node:test";
import assert from "node:assert/strict";
import {
  installPulumiMocks,
  flushPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("EKS Auto Mode clusters are private, encrypted, logged, and use scoped Identity Center access entries", async () => {
  const { resources, calls } = await installPulumiMocks();
  const { createCentralizedEgressNetwork } = await import("../src/network");
  const { createEksCluster } = await import("../src/eks");

  const network = createCentralizedEgressNetwork({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 2,
      networkFirewallEnabled: false,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: [],
    },
    spokes: [
      {
        name: "platform",
        cidr: "10.10.0.0/16",
        kind: "platform",
        createEks: true,
      },
    ],
  });

  createEksCluster(network.spokes.platform, {
    version: "1.33",
    endpointPublicAccess: false,
    autoModeNodePools: ["system", "general-purpose"],
    networkPolicyMode: "strict",
    accessGrants: [
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
        id: "developer-view",
        principal: {
          kind: "identity-center-permission-set",
          category: "workforce",
          permissionSetName: "ReadOnly",
        },
        accessPolicy: "view",
        scope: { type: "namespace", namespaces: ["workloads"] },
      },
    ],
  });

  await flushPulumiMocks();

  const cluster = resourcesOfType(resources, "aws:eks/cluster:Cluster")[0];
  assert.equal(cluster.inputs.vpcConfig.endpointPrivateAccess, true);
  assert.equal(cluster.inputs.vpcConfig.endpointPublicAccess, false);
  assert.deepEqual(cluster.inputs.accessConfig, {
    authenticationMode: "API",
    bootstrapClusterCreatorAdminPermissions: false,
  });
  assert.deepEqual(cluster.inputs.encryptionConfig.resources, ["secrets"]);
  assert.equal(cluster.inputs.computeConfig.enabled, true);
  assert.deepEqual(cluster.inputs.computeConfig.nodePools, [
    "system",
    "general-purpose",
  ]);

  const policyArns = resourcesOfType(
    resources,
    "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
  ).map((attachment) => attachment.inputs.policyArn);
  assert.ok(
    policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"),
  );
  assert.ok(
    policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSComputePolicy"),
  );
  assert.ok(
    policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy"),
  );
  assert.ok(
    policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy"),
  );
  assert.ok(
    policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy"),
  );
  assert.ok(
    policyArns.includes(
      "arn:aws:iam::aws:policy/AmazonEKSWorkerNodeMinimalPolicy",
    ),
  );
  assert.ok(
    policyArns.includes(
      "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
    ),
  );

  const kmsKeys = resourcesOfType(resources, "aws:kms/key:Key");
  const logGroups = resourcesOfType(
    resources,
    "aws:cloudwatch/logGroup:LogGroup",
  );
  assert.equal(kmsKeys.length, 1);
  assert.equal(kmsKeys[0].inputs.enableKeyRotation, true);
  assert.equal(logGroups[0].inputs.retentionInDays, 365);

  assert.equal(
    resourcesOfType(resources, "aws:eks/addon:Addon").length,
    0,
    "Auto Mode owns Pod Identity and VPC networking; legacy add-on settings do not apply",
  );

  const accessEntries = resourcesOfType(
    resources,
    "aws:eks/accessEntry:AccessEntry",
  );
  assert.equal(accessEntries.length, 3);
  assert.ok(
    accessEntries.every(
      (entry) => !String(entry.inputs.principalArn).includes("user/"),
    ),
  );
  const associations = resourcesOfType(
    resources,
    "aws:eks/accessPolicyAssociation:AccessPolicyAssociation",
  );
  assert.equal(associations.length, 3);
  assert.ok(
    associations.some(
      (association) =>
        association.inputs.policyArn.endsWith("AmazonEKSAutoNodePolicy") &&
        association.inputs.accessScope.type === "cluster",
    ),
  );
  assert.ok(
    associations.some(
      (association) =>
        association.inputs.policyArn.endsWith("AmazonEKSClusterAdminPolicy") &&
        association.inputs.accessScope.type === "cluster",
    ),
  );
  assert.ok(
    associations.some(
      (association) =>
        association.inputs.policyArn.endsWith("AmazonEKSViewPolicy") &&
        association.inputs.accessScope.type === "namespace" &&
        association.inputs.accessScope.namespaces[0] === "workloads",
    ),
  );
  assert.equal(
    calls.filter((call) => call.token.includes("getRoles")).length,
    2,
  );
});
