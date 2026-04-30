import test from "node:test";
import assert from "node:assert/strict";
import { installPulumiMocks, flushPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("EKS Auto Mode clusters are private, encrypted, logged, and use required IAM policies", async () => {
  const { resources } = await installPulumiMocks();
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
    spokes: [{ name: "platform", cidr: "10.10.0.0/16", kind: "platform", createEks: true }],
  });

  createEksCluster(network.spokes.platform, {
    version: "1.33",
    endpointPublicAccess: false,
    autoModeNodePools: ["system", "general-purpose"],
    networkPolicyMode: "strict",
  });

  await flushPulumiMocks();

  const cluster = resourcesOfType(resources, "aws:eks/cluster:Cluster")[0];
  assert.equal(cluster.inputs.vpcConfig.endpointPrivateAccess, true);
  assert.equal(cluster.inputs.vpcConfig.endpointPublicAccess, false);
  assert.deepEqual(cluster.inputs.encryptionConfig.resources, ["secrets"]);
  assert.equal(cluster.inputs.computeConfig.enabled, true);
  assert.deepEqual(cluster.inputs.computeConfig.nodePools, ["system", "general-purpose"]);

  const policyArns = resourcesOfType(resources, "aws:iam/rolePolicyAttachment:RolePolicyAttachment").map(
    (attachment) => attachment.inputs.policyArn,
  );
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSComputePolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEKSWorkerNodeMinimalPolicy"));
  assert.ok(policyArns.includes("arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"));

  const kmsKeys = resourcesOfType(resources, "aws:kms/key:Key");
  const logGroups = resourcesOfType(resources, "aws:cloudwatch/logGroup:LogGroup");
  assert.equal(kmsKeys.length, 1);
  assert.equal(kmsKeys[0].inputs.enableKeyRotation, true);
  assert.equal(logGroups[0].inputs.retentionInDays, 365);

  const vpcCniAddon = resourcesOfType(resources, "aws:eks/addon:Addon").find(
    (addon) => addon.inputs.addonName === "vpc-cni",
  );
  assert.ok(vpcCniAddon);
  assert.match(vpcCniAddon!.inputs.configurationValues, /NETWORK_POLICY_ENFORCING_MODE/);
  assert.match(vpcCniAddon!.inputs.configurationValues, /strict/);
});
