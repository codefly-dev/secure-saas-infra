import test from "node:test";
import assert from "node:assert/strict";
import {
  installPulumiMocks,
  flushPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("detached spoke stacks stay private and attach to the shared Transit Gateway", async () => {
  const { resources } = await installPulumiMocks();
  const { createDetachedSpokeNetwork } = await import("../src/network.js");

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
