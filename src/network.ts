import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { cidrSubnet } from "./cidr";
import {
  NetworkConfig,
  SpokeConfig,
  baseTags,
  named,
  awsRegion,
} from "./config";

interface SubnetSet {
  public: aws.ec2.Subnet[];
  firewall: aws.ec2.Subnet[];
  private: aws.ec2.Subnet[];
  endpoints: aws.ec2.Subnet[];
  transit: aws.ec2.Subnet[];
}

export interface SpokeNetwork {
  name: string;
  kind: string;
  cidr: string;
  vpc: aws.ec2.Vpc;
  privateSubnets: aws.ec2.Subnet[];
  endpointSubnets: aws.ec2.Subnet[];
  transitSubnets: aws.ec2.Subnet[];
  privateRouteTables: aws.ec2.RouteTable[];
  attachment: aws.ec2transitgateway.VpcAttachment;
}

export interface CentralizedEgressNetwork {
  transitGateway: aws.ec2transitgateway.TransitGateway;
  spokeTransitGatewayRouteTable: aws.ec2transitgateway.RouteTable;
  egressTransitGatewayRouteTable: aws.ec2transitgateway.RouteTable;
  egressVpc: aws.ec2.Vpc;
  egressAttachment: aws.ec2transitgateway.VpcAttachment;
  egressPublicSubnets: aws.ec2.Subnet[];
  egressPublicRouteTables: aws.ec2.RouteTable[];
  egressFirewallRouteTables: aws.ec2.RouteTable[];
  networkFirewall?: aws.networkfirewall.Firewall;
  spokes: Record<string, SpokeNetwork>;
}

export interface DetachedSpokeConfig extends SpokeConfig {
  transitGatewayId: pulumi.Input<string>;
  azCount: number;
}

export function createCentralizedEgressNetwork(
  config: NetworkConfig,
): CentralizedEgressNetwork {
  const azs = aws
    .getAvailabilityZonesOutput({ state: "available" })
    .names.apply((names) => names.slice(0, config.egress.azCount));

  const transitGateway = new aws.ec2transitgateway.TransitGateway(
    named("core-tgw"),
    {
      description:
        "Central transit gateway for centralized inspection and egress.",
      amazonSideAsn: 64512,
      defaultRouteTableAssociation: "disable",
      defaultRouteTablePropagation: "disable",
      autoAcceptSharedAttachments: "enable",
      dnsSupport: "enable",
      vpnEcmpSupport: "enable",
      tags: tag("core-tgw", { NetworkRole: "transit" }),
    },
  );

  if (config.egress.shareTransitGatewayWithOrganization) {
    shareTransitGatewayWithOrganization(transitGateway);
  }

  const spokeRouteTable = new aws.ec2transitgateway.RouteTable(
    named("spoke-tgw-rt"),
    {
      transitGatewayId: transitGateway.id,
      tags: tag("spoke-tgw-rt", { NetworkRole: "spoke-routing" }),
    },
  );

  const egressRouteTable = new aws.ec2transitgateway.RouteTable(
    named("egress-tgw-rt"),
    {
      transitGatewayId: transitGateway.id,
      tags: tag("egress-tgw-rt", { NetworkRole: "egress-routing" }),
    },
  );

  const egressVpc = new aws.ec2.Vpc(named("egress-vpc"), {
    cidrBlock: config.egress.cidr,
    enableDnsHostnames: true,
    enableDnsSupport: true,
    tags: tag("egress-vpc", { NetworkRole: "central-egress" }),
  });
  createVpcFlowLogs("egress", egressVpc);
  createDnsQueryLog("egress", egressVpc);

  const egressSubnets = createSubnets({
    vpc: egressVpc,
    name: "egress",
    cidr: config.egress.cidr,
    azs,
    includePublic: true,
    includeFirewall: true,
    includePrivate: false,
    includeEndpoints: false,
    includeTransit: true,
    azCount: config.egress.azCount,
  });

  const internetGateway = new aws.ec2.InternetGateway(named("egress-igw"), {
    vpcId: egressVpc.id,
    tags: tag("egress-igw", { NetworkRole: "central-egress" }),
  });

  const egressAttachment = new aws.ec2transitgateway.VpcAttachment(
    named("egress-tgw-attachment"),
    {
      transitGatewayId: transitGateway.id,
      vpcId: egressVpc.id,
      subnetIds: egressSubnets.transit.map((subnet) => subnet.id),
      applianceModeSupport: "enable",
      dnsSupport: "enable",
      tags: tag("egress-tgw-attachment", { NetworkRole: "central-egress" }),
    },
  );

  new aws.ec2transitgateway.RouteTableAssociation(
    named("egress-tgw-association"),
    {
      transitGatewayAttachmentId: egressAttachment.id,
      transitGatewayRouteTableId: egressRouteTable.id,
    },
  );

  const publicRouteTables = egressSubnets.public.map(
    (subnet, index) =>
      new aws.ec2.RouteTable(named(`egress-public-${index + 1}-rt`), {
        vpcId: egressVpc.id,
        routes: [
          {
            cidrBlock: "0.0.0.0/0",
            gatewayId: internetGateway.id,
          },
        ],
        tags: tag(`egress-public-${index + 1}-rt`, {
          NetworkRole: "central-egress-public",
        }),
      }),
  );

  publicRouteTables.forEach((routeTable, index) => {
    new aws.ec2.RouteTableAssociation(named(`egress-public-${index + 1}-rta`), {
      subnetId: egressSubnets.public[index].id,
      routeTableId: routeTable.id,
    });
  });

  const natGateways = egressSubnets.public.map((subnet, index) => {
    const eip = new aws.ec2.Eip(named(`egress-nat-${index + 1}-eip`), {
      domain: "vpc",
      tags: tag(`egress-nat-${index + 1}-eip`, {
        NetworkRole: "central-egress",
      }),
    });

    return new aws.ec2.NatGateway(
      named(`egress-nat-${index + 1}`),
      {
        allocationId: eip.id,
        subnetId: subnet.id,
        tags: tag(`egress-nat-${index + 1}`, { NetworkRole: "central-egress" }),
      },
      { dependsOn: internetGateway },
    );
  });

  const firewall = config.egress.networkFirewallEnabled
    ? createNetworkFirewall(
        egressVpc,
        egressSubnets.firewall,
        config.egress.allowedDomains,
      )
    : undefined;

  const firewallRouteTables = egressSubnets.firewall.map(
    (subnet, index) =>
      new aws.ec2.RouteTable(named(`egress-firewall-${index + 1}-rt`), {
        vpcId: egressVpc.id,
        routes: [
          {
            cidrBlock: "0.0.0.0/0",
            natGatewayId: natGateways[index].id,
          },
        ],
        tags: tag(`egress-firewall-${index + 1}-rt`, {
          NetworkRole: "central-egress-firewall",
        }),
      }),
  );

  firewallRouteTables.forEach((routeTable, index) => {
    new aws.ec2.RouteTableAssociation(
      named(`egress-firewall-${index + 1}-rta`),
      {
        subnetId: egressSubnets.firewall[index].id,
        routeTableId: routeTable.id,
      },
    );
  });

  const transitRouteTables = egressSubnets.transit.map((subnet, index) => {
    const route = firewall
      ? {
          cidrBlock: "0.0.0.0/0",
          vpcEndpointId: firewallEndpointForAz(
            firewall,
            subnet.availabilityZone,
          ),
        }
      : {
          cidrBlock: "0.0.0.0/0",
          natGatewayId: natGateways[index].id,
        };

    return new aws.ec2.RouteTable(named(`egress-transit-${index + 1}-rt`), {
      vpcId: egressVpc.id,
      routes: [route],
      tags: tag(`egress-transit-${index + 1}-rt`, {
        NetworkRole: "central-egress-transit",
      }),
    });
  });

  transitRouteTables.forEach((routeTable, index) => {
    new aws.ec2.RouteTableAssociation(
      named(`egress-transit-${index + 1}-rta`),
      {
        subnetId: egressSubnets.transit[index].id,
        routeTableId: routeTable.id,
      },
    );
  });

  new aws.ec2transitgateway.Route(named("spokes-default-to-egress-tgw-route"), {
    destinationCidrBlock: "0.0.0.0/0",
    transitGatewayAttachmentId: egressAttachment.id,
    transitGatewayRouteTableId: spokeRouteTable.id,
  });

  const spokes: Record<string, SpokeNetwork> = {};

  for (const spokeConfig of config.spokes) {
    const vpc = new aws.ec2.Vpc(named(`${spokeConfig.name}-vpc`), {
      cidrBlock: spokeConfig.cidr,
      enableDnsHostnames: true,
      enableDnsSupport: true,
      tags: tag(`${spokeConfig.name}-vpc`, {
        NetworkRole: "private-spoke",
        SpokeKind: spokeConfig.kind,
      }),
    });
    createVpcFlowLogs(spokeConfig.name, vpc);
    createDnsQueryLog(spokeConfig.name, vpc);

    const subnets = createSubnets({
      vpc,
      name: spokeConfig.name,
      cidr: spokeConfig.cidr,
      azs,
      includePublic: false,
      includeFirewall: false,
      includePrivate: true,
      includeEndpoints: true,
      includeTransit: true,
      azCount: config.egress.azCount,
    });

    const attachment = new aws.ec2transitgateway.VpcAttachment(
      named(`${spokeConfig.name}-tgw-attachment`),
      {
        transitGatewayId: transitGateway.id,
        vpcId: vpc.id,
        subnetIds: subnets.transit.map((subnet) => subnet.id),
        dnsSupport: "enable",
        tags: tag(`${spokeConfig.name}-tgw-attachment`, {
          NetworkRole: "private-spoke",
          SpokeKind: spokeConfig.kind,
        }),
      },
    );

    new aws.ec2transitgateway.RouteTableAssociation(
      named(`${spokeConfig.name}-tgw-association`),
      {
        transitGatewayAttachmentId: attachment.id,
        transitGatewayRouteTableId: spokeRouteTable.id,
      },
    );

    new aws.ec2transitgateway.Route(
      named(`egress-to-${spokeConfig.name}-tgw-route`),
      {
        destinationCidrBlock: spokeConfig.cidr,
        transitGatewayAttachmentId: attachment.id,
        transitGatewayRouteTableId: egressRouteTable.id,
      },
    );

    const privateRouteTables = subnets.private.map(
      (subnet, index) =>
        new aws.ec2.RouteTable(
          named(`${spokeConfig.name}-private-${index + 1}-rt`),
          {
            vpcId: vpc.id,
            tags: tag(`${spokeConfig.name}-private-${index + 1}-rt`, {
              NetworkRole: "private-spoke",
              SpokeKind: spokeConfig.kind,
            }),
          },
        ),
    );

    privateRouteTables.forEach((routeTable, index) => {
      new aws.ec2.RouteTableAssociation(
        named(`${spokeConfig.name}-private-${index + 1}-rta`),
        {
          subnetId: subnets.private[index].id,
          routeTableId: routeTable.id,
        },
      );

      new aws.ec2.Route(
        named(`${spokeConfig.name}-private-${index + 1}-default-to-tgw`),
        {
          routeTableId: routeTable.id,
          destinationCidrBlock: "0.0.0.0/0",
          transitGatewayId: transitGateway.id,
        },
        { dependsOn: attachment },
      );
    });

    createAwsServiceEndpoints(
      spokeConfig.name,
      spokeConfig.cidr,
      vpc,
      subnets.endpoints,
      privateRouteTables,
    );

    publicRouteTables.forEach((routeTable, publicIndex) => {
      const routeTarget = firewall
        ? {
            vpcEndpointId: firewallEndpointForAz(
              firewall,
              egressSubnets.public[publicIndex].availabilityZone,
            ),
          }
        : { transitGatewayId: transitGateway.id };

      new aws.ec2.Route(
        named(`egress-public-${publicIndex + 1}-to-${spokeConfig.name}`),
        {
          routeTableId: routeTable.id,
          destinationCidrBlock: spokeConfig.cidr,
          ...routeTarget,
        },
      );
    });

    firewallRouteTables.forEach((routeTable, firewallIndex) => {
      new aws.ec2.Route(
        named(`egress-firewall-${firewallIndex + 1}-to-${spokeConfig.name}`),
        {
          routeTableId: routeTable.id,
          destinationCidrBlock: spokeConfig.cidr,
          transitGatewayId: transitGateway.id,
        },
      );
    });

    spokes[spokeConfig.name] = {
      name: spokeConfig.name,
      kind: spokeConfig.kind,
      cidr: spokeConfig.cidr,
      vpc,
      privateSubnets: subnets.private,
      endpointSubnets: subnets.endpoints,
      transitSubnets: subnets.transit,
      privateRouteTables,
      attachment,
    };
  }

  return {
    transitGateway,
    spokeTransitGatewayRouteTable: spokeRouteTable,
    egressTransitGatewayRouteTable: egressRouteTable,
    egressVpc,
    egressAttachment,
    egressPublicSubnets: egressSubnets.public,
    egressPublicRouteTables: publicRouteTables,
    egressFirewallRouteTables: firewallRouteTables,
    networkFirewall: firewall,
    spokes,
  };
}

export function createDetachedSpokeNetwork(
  config: DetachedSpokeConfig,
): SpokeNetwork {
  const azs = aws
    .getAvailabilityZonesOutput({ state: "available" })
    .names.apply((names) => names.slice(0, config.azCount));

  const vpc = new aws.ec2.Vpc(named(`${config.name}-vpc`), {
    cidrBlock: config.cidr,
    enableDnsHostnames: true,
    enableDnsSupport: true,
    tags: tag(`${config.name}-vpc`, {
      NetworkRole: "private-spoke",
      SpokeKind: config.kind,
    }),
  });
  createVpcFlowLogs(config.name, vpc);
  createDnsQueryLog(config.name, vpc);

  const subnets = createSubnets({
    vpc,
    name: config.name,
    cidr: config.cidr,
    azs,
    includePublic: false,
    includeFirewall: false,
    includePrivate: true,
    includeEndpoints: true,
    includeTransit: true,
    azCount: config.azCount,
  });

  const attachment = new aws.ec2transitgateway.VpcAttachment(
    named(`${config.name}-tgw-attachment`),
    {
      transitGatewayId: config.transitGatewayId,
      vpcId: vpc.id,
      subnetIds: subnets.transit.map((subnet) => subnet.id),
      dnsSupport: "enable",
      tags: tag(`${config.name}-tgw-attachment`, {
        NetworkRole: "private-spoke",
        SpokeKind: config.kind,
      }),
    },
  );

  const privateRouteTables = subnets.private.map(
    (subnet, index) =>
      new aws.ec2.RouteTable(named(`${config.name}-private-${index + 1}-rt`), {
        vpcId: vpc.id,
        tags: tag(`${config.name}-private-${index + 1}-rt`, {
          NetworkRole: "private-spoke",
          SpokeKind: config.kind,
        }),
      }),
  );

  privateRouteTables.forEach((routeTable, index) => {
    new aws.ec2.RouteTableAssociation(
      named(`${config.name}-private-${index + 1}-rta`),
      {
        subnetId: subnets.private[index].id,
        routeTableId: routeTable.id,
      },
    );

    new aws.ec2.Route(
      named(`${config.name}-private-${index + 1}-default-to-tgw`),
      {
        routeTableId: routeTable.id,
        destinationCidrBlock: "0.0.0.0/0",
        transitGatewayId: config.transitGatewayId,
      },
      { dependsOn: attachment },
    );
  });

  createAwsServiceEndpoints(
    config.name,
    config.cidr,
    vpc,
    subnets.endpoints,
    privateRouteTables,
  );

  return {
    name: config.name,
    kind: config.kind,
    cidr: config.cidr,
    vpc,
    privateSubnets: subnets.private,
    endpointSubnets: subnets.endpoints,
    transitSubnets: subnets.transit,
    privateRouteTables,
    attachment,
  };
}

function createSubnets(args: {
  vpc: aws.ec2.Vpc;
  name: string;
  cidr: string;
  azs: pulumi.Output<string[]>;
  includePublic: boolean;
  includeFirewall: boolean;
  includePrivate: boolean;
  includeEndpoints: boolean;
  includeTransit: boolean;
  azCount: number;
}): SubnetSet {
  const publicSubnets: aws.ec2.Subnet[] = [];
  const firewallSubnets: aws.ec2.Subnet[] = [];
  const privateSubnets: aws.ec2.Subnet[] = [];
  const endpointSubnets: aws.ec2.Subnet[] = [];
  const transitSubnets: aws.ec2.Subnet[] = [];

  const create = (
    tier: string,
    tierIndex: number,
    azIndex: number,
    az: pulumi.Output<string>,
  ) =>
    new aws.ec2.Subnet(named(`${args.name}-${tier}-${azIndex + 1}`), {
      vpcId: args.vpc.id,
      cidrBlock: cidrSubnet(args.cidr, 8, tierIndex * 16 + azIndex),
      availabilityZone: az,
      mapPublicIpOnLaunch: tier === "public",
      tags: tag(`${args.name}-${tier}-${azIndex + 1}`, {
        NetworkRole:
          args.name === "egress" ? "central-egress" : "private-spoke",
        Tier: tier,
      }),
    });

  for (let index = 0; index < args.azCount; index++) {
    const az = args.azs.apply((zones) => zones[index]);
    if (args.includePublic) publicSubnets.push(create("public", 0, index, az));
    if (args.includeFirewall)
      firewallSubnets.push(create("firewall", 1, index, az));
    if (args.includePrivate)
      privateSubnets.push(create("private", 2, index, az));
    if (args.includeEndpoints)
      endpointSubnets.push(create("endpoints", 3, index, az));
    if (args.includeTransit)
      transitSubnets.push(create("transit", 4, index, az));
  }

  return {
    public: publicSubnets,
    firewall: firewallSubnets,
    private: privateSubnets,
    endpoints: endpointSubnets,
    transit: transitSubnets,
  };
}

function createDnsQueryLog(name: string, vpc: aws.ec2.Vpc) {
  const logGroup = new aws.cloudwatch.LogGroup(named(`${name}-dns-query-logs`), {
    name: `/aws/route53/${named(name)}/resolver`,
    retentionInDays: 365,
    tags: tag(`${name}-dns-query-logs`, { EvidenceClass: "dns-query" }),
  });

  const config = new aws.route53.ResolverQueryLogConfig(
    named(`${name}-dns-log-config`),
    {
      name: named(`${name}-dns-log-config`),
      destinationArn: logGroup.arn,
      tags: tag(`${name}-dns-log-config`, { EvidenceClass: "dns-query" }),
    },
  );

  new aws.route53.ResolverQueryLogConfigAssociation(
    named(`${name}-dns-log-assoc`),
    {
      resolverQueryLogConfigId: config.id,
      resourceId: vpc.id,
    },
  );
}

function createVpcFlowLogs(name: string, vpc: aws.ec2.Vpc) {
  const logGroup = new aws.cloudwatch.LogGroup(named(`${name}-vpc-flow-logs`), {
    name: `/aws/vpc/${named(name)}/flow-logs`,
    retentionInDays: 365,
    tags: tag(`${name}-vpc-flow-logs`, { EvidenceClass: "network-flow" }),
  });

  const role = new aws.iam.Role(named(`${name}-vpc-flow-logs-role`), {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
      Service: "vpc-flow-logs.amazonaws.com",
    }),
    tags: tag(`${name}-vpc-flow-logs-role`, { EvidenceClass: "network-flow" }),
  });

  new aws.iam.RolePolicy(named(`${name}-vpc-flow-logs-policy`), {
    role: role.id,
    policy: logGroup.arn.apply((logGroupArn) =>
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["logs:DescribeLogGroups"],
            Resource: "*",
          },
          {
            Effect: "Allow",
            Action: [
              "logs:CreateLogStream",
              "logs:DescribeLogStreams",
              "logs:PutLogEvents",
            ],
            Resource: [logGroupArn, `${logGroupArn}:*`],
          },
        ],
      }),
    ),
  });

  new aws.ec2.FlowLog(named(`${name}-vpc-flow-log`), {
    iamRoleArn: role.arn,
    logDestination: logGroup.arn,
    logDestinationType: "cloud-watch-logs",
    trafficType: "ALL",
    vpcId: vpc.id,
    tags: tag(`${name}-vpc-flow-log`, { EvidenceClass: "network-flow" }),
  });
}

function createNetworkFirewall(
  vpc: aws.ec2.Vpc,
  firewallSubnets: aws.ec2.Subnet[],
  allowedDomains: string[],
) {
  const domainAllowList = new aws.networkfirewall.RuleGroup(
    named("egress-domain-allowlist"),
    {
      capacity: 100,
      type: "STATEFUL",
      ruleGroup: {
        rulesSource: {
          rulesSourceList: {
            generatedRulesType: "ALLOWLIST",
            targetTypes: ["TLS_SNI", "HTTP_HOST"],
            targets: allowedDomains,
          },
        },
      },
      tags: tag("egress-domain-allowlist", { NetworkRole: "central-egress" }),
    },
  );

  const policy = new aws.networkfirewall.FirewallPolicy(
    named("egress-firewall-policy"),
    {
      firewallPolicy: {
        statelessDefaultActions: ["aws:forward_to_sfe"],
        statelessFragmentDefaultActions: ["aws:forward_to_sfe"],
        statefulRuleGroupReferences: [
          {
            resourceArn: domainAllowList.arn,
          },
        ],
      },
      tags: tag("egress-firewall-policy", { NetworkRole: "central-egress" }),
    },
  );

  const firewall = new aws.networkfirewall.Firewall(named("egress-firewall"), {
    firewallPolicyArn: policy.arn,
    vpcId: vpc.id,
    subnetMappings: firewallSubnets.map((subnet) => ({ subnetId: subnet.id })),
    deleteProtection: true,
    firewallPolicyChangeProtection: true,
    subnetChangeProtection: true,
    tags: tag("egress-firewall", { NetworkRole: "central-egress" }),
  });

  createNetworkFirewallLogging(firewall);
  return firewall;
}

function createNetworkFirewallLogging(firewall: aws.networkfirewall.Firewall) {
  const flowLogGroup = new aws.cloudwatch.LogGroup(
    named("egress-firewall-flow-logs"),
    {
      name: `/aws/network-firewall/${named("egress-firewall")}/flow`,
      retentionInDays: 365,
      tags: tag("egress-firewall-flow-logs", {
        EvidenceClass: "network-firewall-flow",
      }),
    },
  );

  const alertLogGroup = new aws.cloudwatch.LogGroup(
    named("egress-firewall-alert-logs"),
    {
      name: `/aws/network-firewall/${named("egress-firewall")}/alert`,
      retentionInDays: 365,
      tags: tag("egress-firewall-alert-logs", {
        EvidenceClass: "network-firewall-alert",
      }),
    },
  );

  new aws.networkfirewall.LoggingConfiguration(
    named("egress-firewall-logging"),
    {
      firewallArn: firewall.arn,
      enableMonitoringDashboard: true,
      loggingConfiguration: {
        logDestinationConfigs: [
          {
            logDestination: {
              logGroup: flowLogGroup.name,
            },
            logDestinationType: "CloudWatchLogs",
            logType: "FLOW",
          },
          {
            logDestination: {
              logGroup: alertLogGroup.name,
            },
            logDestinationType: "CloudWatchLogs",
            logType: "ALERT",
          },
        ],
      },
    },
    { dependsOn: [firewall, flowLogGroup, alertLogGroup] },
  );
}

export function firewallEndpointForAz(
  firewall: aws.networkfirewall.Firewall,
  availabilityZone: pulumi.Output<string>,
): pulumi.Output<string> {
  return pulumi
    .all([firewall.firewallStatuses, availabilityZone])
    .apply(([statuses, az]) => {
      const syncStates = statuses.flatMap((status) => status.syncStates ?? []);
      const match = syncStates.find((state) => state.availabilityZone === az);
      const endpointId = match?.attachments?.[0]?.endpointId;

      if (!endpointId) {
        throw new Error(
          `No AWS Network Firewall endpoint found for availability zone ${az}`,
        );
      }

      return endpointId;
    });
}

function createAwsServiceEndpoints(
  name: string,
  cidr: string,
  vpc: aws.ec2.Vpc,
  endpointSubnets: aws.ec2.Subnet[],
  privateRouteTables: aws.ec2.RouteTable[],
) {
  const currentAccountId = aws.getCallerIdentityOutput({}).accountId;
  const endpointSecurityGroup = new aws.ec2.SecurityGroup(
    named(`${name}-endpoints-sg`),
    {
      vpcId: vpc.id,
      description: "Allows private VPC endpoint access from the workload VPC.",
      ingress: [
        {
          protocol: "tcp",
          fromPort: 443,
          toPort: 443,
          cidrBlocks: [cidr],
          description: "HTTPS from workload VPC",
        },
      ],
      egress: [],
      tags: tag(`${name}-endpoints-sg`, { NetworkRole: "private-spoke" }),
    },
  );

  const interfaceServices = [
    "ec2",
    "ecr.api",
    "ecr.dkr",
    "eks",
    "eks-auth",
    "elasticloadbalancing",
    "ec2messages",
    "kms",
    "logs",
    "monitoring",
    "secretsmanager",
    "ssm",
    "ssmmessages",
    "sts",
  ];

  for (const service of interfaceServices) {
    new aws.ec2.VpcEndpoint(
      named(`${name}-${service.replace(".", "-")}-vpce`),
      {
        vpcId: vpc.id,
        serviceName: `com.amazonaws.${awsRegion}.${service}`,
        vpcEndpointType: "Interface",
        subnetIds: endpointSubnets.map((subnet) => subnet.id),
        privateDnsEnabled: true,
        policy: endpointPolicy(service, currentAccountId),
        securityGroupIds: [endpointSecurityGroup.id],
        tags: tag(`${name}-${service.replace(".", "-")}-vpce`, {
          NetworkRole: "private-spoke",
        }),
      },
    );
  }

  new aws.ec2.VpcEndpoint(named(`${name}-s3-vpce`), {
    vpcId: vpc.id,
    serviceName: `com.amazonaws.${awsRegion}.s3`,
    vpcEndpointType: "Gateway",
    routeTableIds: privateRouteTables.map((routeTable) => routeTable.id),
    policy: endpointPolicy("s3", currentAccountId),
    tags: tag(`${name}-s3-vpce`, { NetworkRole: "private-spoke" }),
  });
}

function endpointPolicy(service: string, accountId: pulumi.Input<string>) {
  const actions = endpointPolicyActions(service);
  return pulumi.output(accountId).apply((resolvedAccountId) =>
    JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowRequiredPrivateEndpointActionsFromThisAccount",
          Effect: "Allow",
          Principal: "*",
          Action: actions,
          Resource: "*",
          Condition: {
            StringEquals: {
              "aws:PrincipalAccount": resolvedAccountId,
            },
            StringEqualsIfExists: {
              "aws:ResourceAccount": resolvedAccountId,
            },
          },
        },
      ],
    }),
  );
}

function endpointPolicyActions(service: string) {
  const actions: Record<string, string[]> = {
    ec2: [
      "ec2:AssignPrivateIpAddresses",
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:CreateTags",
      "ec2:DeleteNetworkInterface",
      "ec2:Describe*",
      "ec2:DetachNetworkInterface",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:UnassignPrivateIpAddresses",
    ],
    "ecr.api": [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
    ],
    "ecr.dkr": [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
    ],
    eks: ["eks:DescribeCluster", "eks:ListClusters"],
    "eks-auth": ["eks-auth:AssumeRoleForPodIdentity"],
    elasticloadbalancing: ["elasticloadbalancing:Describe*"],
    ec2messages: [
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
    ],
    kms: [
      "kms:CreateGrant",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ListGrants",
      "kms:ReEncrypt*",
      "kms:RetireGrant",
    ],
    logs: [
      "logs:CreateLogStream",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ],
    monitoring: [
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
      "cloudwatch:PutMetricData",
    ],
    s3: [
      "s3:AbortMultipartUpload",
      "s3:GetBucketLocation",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:PutObject",
    ],
    secretsmanager: [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ],
    ssm: [
      "ssm:DescribeInstanceInformation",
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:UpdateInstanceInformation",
    ],
    ssmmessages: [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ],
    sts: [
      "sts:AssumeRole",
      "sts:AssumeRoleWithWebIdentity",
      "sts:GetCallerIdentity",
    ],
  };

  const serviceActions = actions[service];
  if (!serviceActions) {
    throw new Error(`No VPC endpoint policy action set defined for ${service}`);
  }
  return serviceActions;
}

function shareTransitGatewayWithOrganization(
  transitGateway: aws.ec2transitgateway.TransitGateway,
) {
  const organization = aws.organizations.getOrganizationOutput({
    returnOrganizationOnly: true,
  });

  const share = new aws.ram.ResourceShare(named("core-tgw-org-share"), {
    name: named("core-tgw-org-share"),
    allowExternalPrincipals: false,
    tags: tag("core-tgw-org-share", { NetworkRole: "transit" }),
  });

  new aws.ram.ResourceAssociation(named("core-tgw-org-share-resource"), {
    resourceArn: transitGateway.arn,
    resourceShareArn: share.arn,
  });

  new aws.ram.PrincipalAssociation(named("core-tgw-org-share-principal"), {
    principal: organization.arn,
    resourceShareArn: share.arn,
  });
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
