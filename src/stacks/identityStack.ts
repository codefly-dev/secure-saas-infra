import { IdentityCenterConfig } from "../config";
import { createIdentityCenter } from "../identity";

export function createIdentityStack(config: IdentityCenterConfig) {
  return createIdentityCenter(config);
}
