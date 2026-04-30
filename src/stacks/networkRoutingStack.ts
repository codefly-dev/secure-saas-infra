import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { NetworkRoutingConfig, baseTags, named } from "../config";

export function createNetworkRoutingStack(config: NetworkRoutingConfig) {
  const network = new pulumi.StackReference("network-hub", { name: config.networkStackRef });
  const transitGatewayId = network.requireOutput("transitGatewayId");
  const spokeRouteTableId = network.requireOutput("spokeTransitGatewayRouteTableId");
  const egressRouteTableId = network.requireOutput("egressTransitGatewayRouteTableId");
  const publicRouteTableIds = network.requireOutput("egressPublicRouteTableIds") as pulumi.Output<string[]>;
  const firewallRouteTableIds = network.requireOutput("egressFirewallRouteTableIds") as pulumi.Output<string[]>;
  const firewallEndpointIds = config.networkFirewallEnabled
    ? (network.requireOutput("egressFirewallEndpointIdsForPublicRoutes") as pulumi.Output<string[]>)
    : undefined;

  const routedSpokes = config.spokeStackRefs.map((stackRefName, index) => {
    const suffix = sanitizeStackRefName(stackRefName, index + 1);
    const spoke = new pulumi.StackReference(`${suffix}-spoke`, { name: stackRefName });
    const attachmentId = spoke.requireOutput("spokeTransitGatewayAttachmentId");
    const cidr = spoke.requireOutput("spokeCidr");
    const name = spoke.requireOutput("spokeName");

    const accepter = new aws.ec2transitgateway.VpcAttachmentAccepter(named(`${suffix}-tgw-accepter`), {
      transitGatewayAttachmentId: attachmentId,
      transitGatewayDefaultRouteTableAssociation: false,
      transitGatewayDefaultRouteTablePropagation: false,
      tags: tag(`${suffix}-tgw-accepter`, { NetworkRole: "private-spoke", SpokeName: name }),
    });

    new aws.ec2transitgateway.RouteTableAssociation(
      named(`${suffix}-spoke-tgw-association`),
      {
        transitGatewayAttachmentId: accepter.id,
        transitGatewayRouteTableId: spokeRouteTableId,
        replaceExistingAssociation: true,
      },
      { dependsOn: accepter },
    );

    new aws.ec2transitgateway.Route(
      named(`egress-to-${suffix}-tgw-route`),
      {
        destinationCidrBlock: cidr,
        transitGatewayAttachmentId: accepter.id,
        transitGatewayRouteTableId: egressRouteTableId,
      },
      { dependsOn: accepter },
    );

    for (let azIndex = 0; azIndex < config.azCount; azIndex++) {
      const routeTarget = config.networkFirewallEnabled
        ? { vpcEndpointId: firewallEndpointIds!.apply((ids) => ids[azIndex]) }
        : { transitGatewayId };

      new aws.ec2.Route(named(`egress-public-${azIndex + 1}-to-${suffix}`), {
        routeTableId: publicRouteTableIds.apply((ids) => ids[azIndex]),
        destinationCidrBlock: cidr,
        ...routeTarget,
      });

      new aws.ec2.Route(named(`egress-firewall-${azIndex + 1}-to-${suffix}`), {
        routeTableId: firewallRouteTableIds.apply((ids) => ids[azIndex]),
        destinationCidrBlock: cidr,
        transitGatewayId,
      });
    }

    return {
      name,
      cidr,
      transitGatewayAttachmentId: accepter.id,
    };
  });

  return { routedSpokes };
}

function sanitizeStackRefName(stackRefName: string, fallback: number) {
  const lastSegment = stackRefName.split("/").filter(Boolean).at(-1) ?? `spoke-${fallback}`;
  return lastSegment.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

function tag(name: string, extra: Record<string, pulumi.Input<string>> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
