import test from "node:test";
import assert from "node:assert/strict";
import {
  installPulumiMocks,
  flushPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("centralized egress network keeps internet access only in the egress VPC", async () => {
  const { resources } = await installPulumiMocks();
  const { createCentralizedEgressNetwork } = await import("../src/network.js");

  createCentralizedEgressNetwork({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 3,
      networkFirewallEnabled: true,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: ["github.com", "api.github.com"],
    },
    spokes: [
      {
        name: "platform",
        cidr: "10.10.0.0/16",
        kind: "platform",
        createEks: true,
      },
      {
        name: "execution",
        cidr: "10.20.0.0/16",
        kind: "execution",
        createEks: true,
      },
    ],
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
  const publicSubnets = resourcesOfType(
    resources,
    "aws:ec2/subnet:Subnet",
  ).filter((subnet) => subnet.inputs.mapPublicIpOnLaunch === true);

  assert.equal(
    internetGateways.length,
    1,
    "only the egress VPC should have an Internet Gateway",
  );
  assert.equal(
    natGateways.length,
    3,
    "NAT gateways should exist only in egress public subnets",
  );
  assert.equal(
    publicSubnets.length,
    3,
    "only the egress VPC should have public subnets",
  );
  assert.ok(
    publicSubnets.every((subnet) => subnet.name.includes("egress-public")),
  );
});

test("centralized egress network creates exactly one TGW default route from spokes to egress", async () => {
  const { resources } = await installPulumiMocks();
  const { createCentralizedEgressNetwork } = await import("../src/network.js");

  createCentralizedEgressNetwork({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 3,
      networkFirewallEnabled: false,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: [],
    },
    spokes: [
      { name: "platform", cidr: "10.10.0.0/16", kind: "platform" },
      { name: "execution", cidr: "10.20.0.0/16", kind: "execution" },
    ],
  });

  await flushPulumiMocks();

  const defaultTgwRoutes = resourcesOfType(
    resources,
    "aws:ec2transitgateway/route:Route",
  ).filter((route) => route.inputs.destinationCidrBlock === "0.0.0.0/0");

  assert.equal(defaultTgwRoutes.length, 1);
  assert.equal(
    defaultTgwRoutes[0].name,
    "deus-unit-spokes-default-to-egress-tgw-route",
  );
});

test("spoke private route tables default to Transit Gateway and AWS APIs use VPC endpoints", async () => {
  const { resources } = await installPulumiMocks();
  const { createCentralizedEgressNetwork } = await import("../src/network.js");

  createCentralizedEgressNetwork({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 2,
      networkFirewallEnabled: false,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: [],
    },
    spokes: [{ name: "platform", cidr: "10.10.0.0/16", kind: "platform" }],
  });

  await flushPulumiMocks();

  const defaultEc2Routes = resourcesOfType(
    resources,
    "aws:ec2/route:Route",
  ).filter(
    (route) =>
      route.inputs.destinationCidrBlock === "0.0.0.0/0" &&
      route.inputs.transitGatewayId,
  );
  const endpoints = resourcesOfType(
    resources,
    "aws:ec2/vpcEndpoint:VpcEndpoint",
  );
  const serviceNames = endpoints.map((endpoint) => endpoint.inputs.serviceName);
  const endpointPolicies = endpoints.map((endpoint) =>
    JSON.parse(endpoint.inputs.policy),
  );
  const stsEndpoint = endpoints.find((endpoint) =>
    String(endpoint.inputs.serviceName).endsWith(".sts"),
  );
  const secretsEndpoint = endpoints.find((endpoint) =>
    String(endpoint.inputs.serviceName).endsWith(".secretsmanager"),
  );
  const s3Endpoint = endpoints.find((endpoint) =>
    String(endpoint.inputs.serviceName).endsWith(".s3"),
  );
  assert.ok(stsEndpoint);
  assert.ok(secretsEndpoint);
  assert.ok(s3Endpoint);

  assert.equal(
    defaultEc2Routes.length,
    2,
    "one private default route per AZ should point to TGW",
  );
  assert.ok(
    serviceNames.some((name) => String(name).endsWith(".s3")),
    "S3 gateway endpoint should exist",
  );
  assert.ok(
    serviceNames.some((name) => String(name).endsWith(".ecr.api")),
    "ECR API endpoint should exist",
  );
  assert.ok(
    serviceNames.some((name) => String(name).endsWith(".sts")),
    "STS endpoint should exist",
  );
  assert.ok(
    serviceNames.some((name) => String(name).endsWith(".eks-auth")),
    "EKS Pod Identity endpoint should exist",
  );
  assert.ok(
    endpointPolicies.every((policy) => policy.Statement[0].Action !== "*"),
    "endpoint policies must not be full access",
  );
  assert.ok(
    endpointPolicies.every(
      (policy) =>
        policy.Statement[0].Condition.StringEquals["aws:PrincipalAccount"] ===
          "111111111111" &&
        policy.Statement[0].Condition.StringEqualsIfExists[
          "aws:ResourceAccount"
        ] === "111111111111",
    ),
    "endpoint policies must scope use to same-account principals and resources",
  );
  assert.ok(
    JSON.parse(stsEndpoint.inputs.policy).Statement[0].Action.includes(
      "sts:AssumeRoleWithWebIdentity",
    ),
  );
  assert.ok(
    JSON.parse(secretsEndpoint.inputs.policy).Statement[0].Action.includes(
      "secretsmanager:GetSecretValue",
    ),
  );
  assert.ok(
    !JSON.parse(s3Endpoint.inputs.policy).Statement[0].Action.includes("s3:*"),
  );
});

test("centralized egress network emits flow logs and Network Firewall logs", async () => {
  const { resources } = await installPulumiMocks();
  const { createCentralizedEgressNetwork } = await import("../src/network.js");

  createCentralizedEgressNetwork({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 2,
      networkFirewallEnabled: true,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: ["github.com"],
    },
    spokes: [
      { name: "platform", cidr: "10.10.0.0/16", kind: "platform" },
      { name: "execution", cidr: "10.20.0.0/16", kind: "execution" },
    ],
  });

  await flushPulumiMocks();

  const flowLogs = resourcesOfType(resources, "aws:ec2/flowLog:FlowLog");
  const firewallLogging = resourcesOfType(
    resources,
    "aws:networkfirewall/loggingConfiguration:LoggingConfiguration",
  )[0];
  const firewallLogTypes =
    firewallLogging.inputs.loggingConfiguration.logDestinationConfigs.map(
      (config: { logType: string }) => config.logType,
    );

  assert.equal(
    flowLogs.length,
    3,
    "egress plus two spoke VPCs should emit flow logs",
  );
  assert.ok(flowLogs.every((flowLog) => flowLog.inputs.trafficType === "ALL"));
  assert.ok(
    flowLogs.every(
      (flowLog) => flowLog.inputs.logDestinationType === "cloud-watch-logs",
    ),
  );
  assert.ok(firewallLogTypes.includes("FLOW"));
  assert.ok(firewallLogTypes.includes("ALERT"));
  assert.equal(firewallLogging.inputs.enableMonitoringDashboard, true);
});
