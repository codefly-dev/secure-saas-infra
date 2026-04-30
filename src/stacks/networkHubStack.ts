import { createCentralizedEgressNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import { NetworkConfig, SecurityConfig } from "../config";

export function createNetworkHubStack(args: {
  networkConfig: NetworkConfig;
  securityConfig: SecurityConfig;
}) {
  createAccountSecurityBaseline(args.securityConfig);

  const network = createCentralizedEgressNetwork({
    egress: args.networkConfig.egress,
    spokes: [],
  });

  return { network };
}
