import test from "node:test";
import assert from "node:assert/strict";
import type { PolicyResource } from "@pulumi/policy";
import { stackPolicies } from "../policy/stackRules";

function resource(
  type: string,
  name: string,
  props: Record<string, unknown> = {},
  propertyDependencies: Record<string, PolicyResource[]> = {},
): PolicyResource {
  return {
    type,
    name,
    props,
    urn: `urn:pulumi:test::iac::${type}::${name}`,
    opts: {} as any,
    dependencies: [...new Set(Object.values(propertyDependencies).flat())],
    propertyDependencies,
  } as PolicyResource;
}

async function evaluate(
  policyName: string,
  resources: PolicyResource[],
): Promise<string[]> {
  const policy = stackPolicies.find((entry) => entry.name === policyName);
  assert.ok(policy, `missing stack policy '${policyName}'`);
  const violations: string[] = [];
  await policy.validateStack(
    {
      resources,
      stackTags: new Map(),
      getConfig: <T extends object>() => ({}) as T,
      notApplicable: () => {
        throw new Error("unexpected notApplicable");
      },
    },
    (message) => violations.push(message),
  );
  return violations;
}

test("stack policies execute exact relationship graphs and reject substitutions", async () => {
  const vpc = resource("aws:ec2/vpc:Vpc", "private", {
    tags: { NetworkRole: "private-spoke" },
  });
  const otherVpc = resource("aws:ec2/vpc:Vpc", "other");
  const flow = resource(
    "aws:ec2/flowLog:FlowLog",
    "flow",
    {},
    { vpcId: [vpc] },
  );
  const dns = resource(
    "aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation",
    "dns",
    {},
    { resourceId: [vpc] },
  );
  assert.deepEqual(
    await evaluate("vpcs-bind-flow-and-dns-query-logging", [vpc, flow, dns]),
    [],
  );
  assert.ok(
    (
      await evaluate("vpcs-bind-flow-and-dns-query-logging", [
        vpc,
        flow,
        resource(
          "aws:route53/resolverQueryLogConfigAssociation:ResolverQueryLogConfigAssociation",
          "substituted-dns",
          {},
          { resourceId: [otherVpc] },
        ),
      ])
    ).length > 0,
  );

  const bucket = resource("aws:s3/bucket:Bucket", "data", {
    tags: { DataClass: "confidential", EvidenceSinkId: "audit-log" },
  });
  const publicBlock = resource(
    "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
    "block",
    {},
    { bucket: [bucket] },
  );
  const encryption = resource(
    "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
    "encryption",
    {},
    { bucket: [bucket] },
  );
  const versioning = resource(
    "aws:s3/bucketVersioning:BucketVersioning",
    "versioning",
    { versioningConfiguration: { status: "Enabled" } },
    { bucket: [bucket] },
  );
  assert.deepEqual(
    await evaluate("s3-buckets-bind-security-companions", [
      bucket,
      publicBlock,
      encryption,
      versioning,
    ]),
    [],
  );
  assert.ok(
    (
      await evaluate("s3-buckets-bind-security-companions", [
        bucket,
        publicBlock,
        encryption,
      ])
    ).length > 0,
  );
  const suspended = resource(
    "aws:s3/bucketVersioning:BucketVersioning",
    "suspended-versioning",
    { versioningConfiguration: { status: "Suspended" } },
    { bucket: [bucket] },
  );
  assert.deepEqual(
    await evaluate("s3-buckets-bind-security-companions", [
      bucket,
      publicBlock,
      encryption,
      suspended,
    ]),
    [
      "Data or evidence S3 bucket is missing its exact versioning relationship.",
    ],
  );

  assert.deepEqual(
    await evaluate("confidential-resources-bind-evidence-sinks", [
      resource("aws:rds/cluster:Cluster", "substituted-sink", {
        tags: { DataClass: "platform-database", EvidenceSinkId: "attacker" },
      }),
    ]),
    [
      "Confidential resource is not bound to the reviewed audit-log evidence sink.",
    ],
  );

  const firewall = resource(
    "aws:networkfirewall/firewall:Firewall",
    "firewall",
  );
  const logging = resource(
    "aws:networkfirewall/loggingConfiguration:LoggingConfiguration",
    "logging",
    {
      loggingConfiguration: {
        logDestinationConfigs: [{ logType: "FLOW" }, { logType: "ALERT" }],
      },
    },
    { firewallArn: [firewall] },
  );
  assert.deepEqual(
    await evaluate("network-firewalls-bind-flow-and-alert-logging", [
      firewall,
      logging,
    ]),
    [],
  );
  const wrongLogging = resource(
    "aws:networkfirewall/loggingConfiguration:LoggingConfiguration",
    "wrong-logging",
    logging.props,
    { firewallArn: [otherVpc] },
  );
  assert.ok(
    (
      await evaluate("network-firewalls-bind-flow-and-alert-logging", [
        firewall,
        wrongLogging,
      ])
    ).length > 0,
  );
});

test("stack fixture registry exactly covers every registered stack policy", () => {
  assert.deepEqual(stackPolicies.map((policy) => policy.name).sort(), [
    "confidential-resources-bind-evidence-sinks",
    "internet-gateways-bind-central-egress-vpc",
    "network-firewalls-bind-flow-and-alert-logging",
    "private-spoke-default-routes-use-transit-gateway",
    "s3-buckets-bind-security-companions",
    "vpcs-bind-flow-and-dns-query-logging",
  ]);
});

test("stack policies execute semantic evidence, route, and egress topology checks", async () => {
  const confidential = resource("aws:rds/cluster:Cluster", "database", {
    tags: { DataClass: "platform-database", EvidenceSinkId: "audit-log" },
  });
  assert.deepEqual(
    await evaluate("confidential-resources-bind-evidence-sinks", [
      confidential,
    ]),
    [],
  );
  assert.ok(
    (
      await evaluate("confidential-resources-bind-evidence-sinks", [
        resource("aws:rds/cluster:Cluster", "unbound", {
          tags: { DataClass: "platform-database" },
        }),
      ])
    ).length > 0,
  );
  const table = resource("aws:ec2/routeTable:RouteTable", "private", {
    tags: { NetworkRole: "private-spoke" },
  });
  const transitRoute = resource(
    "aws:ec2/route:Route",
    "default",
    { destinationCidrBlock: "0.0.0.0/0", transitGatewayId: "tgw-id" },
    { routeTableId: [table] },
  );
  assert.deepEqual(
    await evaluate("private-spoke-default-routes-use-transit-gateway", [
      table,
      transitRoute,
    ]),
    [],
  );
  const natRoute = resource(
    "aws:ec2/route:Route",
    "bypass",
    { destinationCidrBlock: "0.0.0.0/0", natGatewayId: "nat-id" },
    { routeTableId: [table] },
  );
  assert.ok(
    (
      await evaluate("private-spoke-default-routes-use-transit-gateway", [
        table,
        natRoute,
      ])
    ).length > 0,
  );
  const ipv6InternetRoute = resource(
    "aws:ec2/route:Route",
    "ipv6-bypass",
    { destinationIpv6CidrBlock: "::/0", gatewayId: "igw-id" },
    { routeTableId: [table] },
  );
  assert.deepEqual(
    await evaluate("private-spoke-default-routes-use-transit-gateway", [
      table,
      transitRoute,
      ipv6InternetRoute,
    ]),
    [
      "Private-spoke route table defaults must use only Transit Gateway for IPv4 and IPv6.",
    ],
  );

  const egressVpc = resource("aws:ec2/vpc:Vpc", "egress", {
    tags: { NetworkRole: "central-egress" },
  });
  const subnet = resource(
    "aws:ec2/subnet:Subnet",
    "public",
    {},
    { vpcId: [egressVpc] },
  );
  const igw = resource(
    "aws:ec2/internetGateway:InternetGateway",
    "internet",
    {},
    { vpcId: [egressVpc] },
  );
  const nat = resource(
    "aws:ec2/natGateway:NatGateway",
    "nat",
    {},
    { subnetId: [subnet] },
  );
  assert.deepEqual(
    await evaluate("internet-gateways-bind-central-egress-vpc", [
      egressVpc,
      subnet,
      igw,
      nat,
    ]),
    [],
  );
  const spokeVpc = resource("aws:ec2/vpc:Vpc", "spoke", {
    tags: { NetworkRole: "private-spoke" },
  });
  const spokeIgw = resource(
    "aws:ec2/internetGateway:InternetGateway",
    "name-contains-egress-but-wrong",
    {},
    { vpcId: [spokeVpc] },
  );
  assert.ok(
    (
      await evaluate("internet-gateways-bind-central-egress-vpc", [
        spokeVpc,
        spokeIgw,
      ])
    ).length > 0,
  );
});
