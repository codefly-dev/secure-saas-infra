import { createCentralizedEgressNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import { NetworkConfig, SecurityConfig } from "../config";
import {
  compileAwsNetworkBlueprint,
  validateAndCompileAwsNetwork,
} from "../adapters/aws";
import type { PlatformBlueprint } from "../core";

export function createNetworkHubStack(args: {
  networkConfig: NetworkConfig;
  securityConfig: SecurityConfig;
  platformBlueprint?: PlatformBlueprint;
}) {
  createAccountSecurityBaseline(args.securityConfig);

  const plan = args.platformBlueprint
    ? compileAwsNetworkBlueprint(args.platformBlueprint, {
        shareTransitGatewayWithOrganization:
          args.networkConfig.egress.shareTransitGatewayWithOrganization ??
          false,
        createEksByZoneId: {},
        spokeKindByZoneId: {},
      })
    : validateAndCompileAwsNetwork(
        { egress: args.networkConfig.egress, spokes: [] },
        {
          name: "network-hub",
          environment: "deployment",
          requireInspectedEgress:
            args.networkConfig.egress.networkFirewallEnabled,
        },
      );
  const network = createCentralizedEgressNetwork({
    ...plan.networkConfig,
    spokes: [],
  });

  return { network, semanticIds: plan.egress };
}
