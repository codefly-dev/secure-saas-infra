import { createAccountSecurityBaseline } from "../security";
import { SecurityConfig } from "../config";

export function createAccountBaselineStack(config: SecurityConfig) {
  createAccountSecurityBaseline(config);
  return {};
}
