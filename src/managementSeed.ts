import {
  organizationConfig,
  seedWave,
  validateManagementSeedConfig,
} from "./managementSeedConfig";
import { createOrganizationFoundation } from "./organization";

validateManagementSeedConfig();

const organization = createOrganizationFoundation(organizationConfig, seedWave);

export const organizationArn = organization.organizationArn;
export const organizationRootId = organization.rootId;
export const organizationalUnitIds = organization.organizationalUnitIds;
export const organizationAccountIds = organization.accountIds;
