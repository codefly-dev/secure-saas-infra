import { SharedServicesConfig } from "../config";
import { createSharedServices } from "../sharedServices";

export function createSharedServicesStack(config: SharedServicesConfig) {
  return createSharedServices(config);
}
