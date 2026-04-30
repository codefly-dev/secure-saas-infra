import * as pulumi from "@pulumi/pulumi";
import { createEksCluster } from "../eks";
import { createDetachedSpokeNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import { EksConfig, SecurityConfig, SpokeStackConfig } from "../config";

export function createSpokeClusterStack(args: {
  spokeConfig: SpokeStackConfig;
  eksConfig: EksConfig;
  securityConfig: SecurityConfig;
}) {
  createAccountSecurityBaseline(args.securityConfig);

  const transitGatewayId =
    args.spokeConfig.transitGatewayId ??
    new pulumi.StackReference("network-hub", { name: args.spokeConfig.networkStackRef }).requireOutput(
      "transitGatewayId",
    );

  const spoke = createDetachedSpokeNetwork({
    name: args.spokeConfig.name,
    kind: args.spokeConfig.kind,
    cidr: args.spokeConfig.cidr,
    createEks: args.spokeConfig.createEks,
    azCount: args.spokeConfig.azCount,
    transitGatewayId,
  });

  const cluster = args.spokeConfig.createEks ? createEksCluster(spoke, args.eksConfig) : undefined;
  const clusters = cluster
    ? {
        [args.spokeConfig.name]: {
          name: cluster.cluster.name,
          endpoint: cluster.cluster.endpoint,
          certificateAuthority: cluster.cluster.certificateAuthority,
          nodeRoleArn: cluster.nodeRole.arn,
        },
      }
    : {};

  return { spoke, clusters };
}
