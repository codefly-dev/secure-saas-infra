import test from "node:test";
import assert from "node:assert/strict";
import { installPulumiMocks, flushPulumiMocks, resourcesOfType } from "./helpers/pulumiMocks";

test("security tooling enables organization-wide detection and aggregation", async () => {
  const { resources } = await installPulumiMocks();
  const { createSecurityTooling } = await import("../src/securityTooling.js");

  createSecurityTooling({
    enableGuardDutyOrganization: true,
    enableSecurityHubOrganization: true,
    enableInspectorOrganization: true,
    enableConfigAggregator: true,
    configAggregatorAllRegions: true,
    inspectorAccountIds: ["111111111111"],
  });

  await flushPulumiMocks();

  assert.equal(resourcesOfType(resources, "aws:guardduty/detector:Detector").length, 1);
  assert.equal(resourcesOfType(resources, "aws:guardduty/organizationConfiguration:OrganizationConfiguration").length, 1);
  assert.ok(
    resourcesOfType(resources, "aws:guardduty/organizationConfigurationFeature:OrganizationConfigurationFeature")
      .length >= 6,
  );
  assert.equal(resourcesOfType(resources, "aws:securityhub/account:Account").length, 1);
  assert.equal(resourcesOfType(resources, "aws:securityhub/findingAggregator:FindingAggregator")[0].inputs.linkingMode, "ALL_REGIONS");
  assert.equal(resourcesOfType(resources, "aws:securityhub/organizationConfiguration:OrganizationConfiguration")[0].inputs.autoEnable, true);
  assert.equal(resourcesOfType(resources, "aws:inspector2/organizationConfiguration:OrganizationConfiguration").length, 1);
  assert.equal(resourcesOfType(resources, "aws:inspector2/enabler:Enabler")[0].inputs.resourceTypes.includes("LAMBDA_CODE"), true);
  assert.equal(
    resourcesOfType(resources, "aws:cfg/configurationAggregator:ConfigurationAggregator")[0].inputs
      .organizationAggregationSource.allRegions,
    true,
  );
});
