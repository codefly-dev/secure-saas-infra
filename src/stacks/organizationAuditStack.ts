import { OrganizationAuditConfig } from "../config";
import { createOrganizationAudit } from "../organizationAudit";

export function createOrganizationAuditStack(config: OrganizationAuditConfig) {
  return createOrganizationAudit(config);
}
