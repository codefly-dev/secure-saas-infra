import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { NetworkRoutingConfig, baseTags, named } from "../config";
import type { PlatformBlueprint } from "../core";
import {
  type AwsSpokeNetworkPlan,
  compileAwsNetworkBlueprint,
  requireAwsSpokePlan,
  validateAwsSpokeStackOutputs,
} from "../adapters/aws";

export function createNetworkRoutingStack(
  config: NetworkRoutingConfig,
  blueprint?: PlatformBlueprint,
) {
  const network = new pulumi.StackReference("network-hub", {
    name: config.networkStackRef,
  });
  const transitGatewayId = network.requireOutput("transitGatewayId");
  const spokeRouteTableId = network.requireOutput(
    "spokeTransitGatewayRouteTableId",
  );
  const egressRouteTableId = network.requireOutput(
    "egressTransitGatewayRouteTableId",
  );
  const publicRouteTableIds = network.requireOutput(
    "egressPublicRouteTableIds",
  ) as pulumi.Output<string[]>;
  const firewallRouteTableIds = network.requireOutput(
    "egressFirewallRouteTableIds",
  ) as pulumi.Output<string[]>;
  const firewallEndpointIds = config.networkFirewallEnabled
    ? (network.requireOutput(
        "egressFirewallEndpointIdsForPublicRoutes",
      ) as pulumi.Output<string[]>)
    : undefined;

  const bindings: Array<{
    stackRef: string;
    expected?: AwsSpokeNetworkPlan;
  }> = blueprint
    ? requireBindings(config, blueprint)
    : config.spokeStackRefs.map((stackRef) => ({ stackRef }));
  const routedSpokes = bindings.map((binding, index) => {
    const stackRefName = binding.stackRef;
    const suffix = sanitizeStackRefName(stackRefName, index + 1);
    const spoke = new pulumi.StackReference(`${suffix}-spoke`, {
      name: stackRefName,
    });
    const attachmentId = spoke.requireOutput("spokeTransitGatewayAttachmentId");
    const rawCidr = spoke.requireOutput("spokeCidr");
    const name = spoke.requireOutput("spokeName");
    const cidr =
      binding.expected === undefined
        ? rawCidr
        : pulumi
            .all([
              spoke.requireOutput("spokeZoneId"),
              spoke.requireOutput("spokeNetworkDomainId"),
              rawCidr,
            ])
            .apply(([zoneId, networkDomainId, resolvedCidr]) => {
              validateAwsSpokeStackOutputs(binding.expected!, {
                zoneId: String(zoneId),
                networkDomainId: String(networkDomainId),
                cidr: String(resolvedCidr),
              });
              return String(resolvedCidr);
            });

    const accepter = new aws.ec2transitgateway.VpcAttachmentAccepter(
      named(`${suffix}-tgw-accepter`),
      {
        transitGatewayAttachmentId: attachmentId,
        transitGatewayDefaultRouteTableAssociation: false,
        transitGatewayDefaultRouteTablePropagation: false,
        tags: tag(`${suffix}-tgw-accepter`, {
          NetworkRole: "private-spoke",
          SpokeName: name,
        }),
      },
    );

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

function requireBindings(
  config: NetworkRoutingConfig,
  blueprint: PlatformBlueprint,
) {
  if (
    !config.spokeBindings ||
    config.spokeBindings.length === 0 ||
    config.spokeBindings.length !== config.spokeStackRefs.length
  ) {
    throw new Error(
      "networkRouting.spokeBindings must bind every stack reference to neutral zone and network-domain IDs when platformBlueprint is configured.",
    );
  }
  const plan = compileAwsNetworkBlueprint(blueprint, {
    shareTransitGatewayWithOrganization: true,
    createEksByZoneId: {},
    spokeKindByZoneId: {},
  });
  const configuredRefs = new Set(config.spokeStackRefs);
  const boundRefs = new Set(
    config.spokeBindings.map((binding) => binding.stackRef),
  );
  if (
    configuredRefs.size !== config.spokeStackRefs.length ||
    boundRefs.size !== config.spokeBindings.length ||
    [...configuredRefs].some((stackRef) => !boundRefs.has(stackRef))
  ) {
    throw new Error(
      "networkRouting.spokeBindings must contain each spoke stack reference exactly once.",
    );
  }
  return config.spokeBindings.map((binding) => {
    if (!config.spokeStackRefs.includes(binding.stackRef)) {
      throw new Error(
        `Network routing binding references undeclared spoke stack '${binding.stackRef}'.`,
      );
    }
    return {
      stackRef: binding.stackRef,
      expected: requireAwsSpokePlan(
        plan,
        binding.zoneId,
        binding.networkDomainId,
      ),
    };
  });
}

function sanitizeStackRefName(stackRefName: string, fallback: number) {
  const lastSegment =
    stackRefName.split("/").filter(Boolean).at(-1) ?? `spoke-${fallback}`;
  return lastSegment.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

function tag(name: string, extra: Record<string, pulumi.Input<string>> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
