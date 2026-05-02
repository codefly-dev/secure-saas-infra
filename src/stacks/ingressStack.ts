import { IngressConfig } from "../config";
import { createPublicIngress } from "../ingress";

export function createIngressStack(config: IngressConfig) {
  return createPublicIngress(config);
}
