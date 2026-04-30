import { ComplianceConfig } from "../config";
import { createComplianceBaseline } from "../compliance";

export function createComplianceStack(config: ComplianceConfig) {
  return createComplianceBaseline(config);
}
