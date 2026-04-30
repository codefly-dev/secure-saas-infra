import { SecurityToolingConfig } from "../config";
import { createSecurityTooling } from "../securityTooling";

export function createSecurityToolingStack(config: SecurityToolingConfig) {
  return createSecurityTooling(config);
}
