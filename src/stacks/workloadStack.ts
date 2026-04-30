import { createEksCluster } from "../eks";
import { createCentralizedEgressNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import { EksConfig, NetworkConfig, SecurityConfig } from "../config";

export function createWorkloadStack(args: {
  networkConfig: NetworkConfig;
  eksConfig: EksConfig;
  securityConfig: SecurityConfig;
}) {
  createAccountSecurityBaseline(args.securityConfig);

  const network = createCentralizedEgressNetwork(args.networkConfig);

  const clusters = Object.fromEntries(
    args.networkConfig.spokes
      .filter((spoke) => spoke.createEks)
      .map((spoke) => {
        const spokeNetwork = network.spokes[spoke.name];
        const cluster = createEksCluster(spokeNetwork, args.eksConfig);

        return [
          spoke.name,
          {
            name: cluster.cluster.name,
            endpoint: cluster.cluster.endpoint,
            certificateAuthority: cluster.cluster.certificateAuthority,
            nodeRoleArn: cluster.nodeRole.arn,
          },
        ];
      }),
  );

  return { network, clusters };
}
