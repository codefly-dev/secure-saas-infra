import { createOrganizationFoundation } from "../organization";
import { OrganizationConfig } from "../config";

export function createOrganizationStack(config: OrganizationConfig) {
  return createOrganizationFoundation(config);
}
