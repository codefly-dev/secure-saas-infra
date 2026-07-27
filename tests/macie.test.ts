import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("macie stack enables sensitive data discovery and weekly classification jobs", async () => {
  const { resources } = await installPulumiMocks();
  const { createMacieBaseline } = await import("../src/macie.js");

  createMacieBaseline({
    classificationJobs: [
      {
        accountId: "111122223333",
        buckets: ["deus-customer-artifacts", "deus-vault-backups"],
        dayOfWeek: "MONDAY",
      },
    ],
  });

  await flushPulumiMocks();

  const account = resourcesOfType(resources, "aws:macie2/account:Account")[0];
  assert.equal(account.inputs.findingPublishingFrequency, "FIFTEEN_MINUTES");
  assert.equal(account.inputs.status, "ENABLED");

  const jobs = resourcesOfType(
    resources,
    "aws:macie2/classificationJob:ClassificationJob",
  );
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].inputs.jobType, "SCHEDULED");
  assert.equal(jobs[0].inputs.scheduleFrequency.weeklySchedule, "MONDAY");
  assert.deepEqual(jobs[0].inputs.s3JobDefinition.bucketDefinitions[0].buckets, [
    "deus-customer-artifacts",
    "deus-vault-backups",
  ]);
});
