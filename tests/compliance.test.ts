import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("compliance stack deploys CIS conformance pack", async () => {
  const { resources } = await installPulumiMocks();
  const { createComplianceBaseline } = await import("../src/compliance");

  createComplianceBaseline({
    deployConformancePack: true,
    createAuditManagerAssessment: false,
    auditManagerAccountIds: [],
    auditManagerRoleArns: [],
  });

  await flushPulumiMocks();

  const conformancePack = resourcesOfType(
    resources,
    "aws:cfg/conformancePack:ConformancePack",
  )[0];
  assert.ok(conformancePack);
  assert.match(conformancePack.inputs.templateBody, /CLOUD_TRAIL_ENABLED/);
  assert.match(
    conformancePack.inputs.templateBody,
    /RDS_INSTANCE_PUBLIC_ACCESS_CHECK/,
  );
  assert.match(
    conformancePack.inputs.templateBody,
    /EKS_ENDPOINT_NO_PUBLIC_ACCESS/,
  );
  assert.match(
    conformancePack.inputs.templateBody,
    /CMK_BACKING_KEY_ROTATION_ENABLED/,
  );
});
