import { WafConfig } from "../config";
import { createPublicWebAcl } from "../waf";

export function createWafStack(config: WafConfig) {
  return createPublicWebAcl(config);
}
