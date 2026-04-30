import * as aws from "@pulumi/aws";
import { MacieConfig, baseTags, named } from "./config";

export interface MacieResult {
  account: aws.macie2.Account;
  classificationJobs: aws.macie2.ClassificationJob[];
}

export function createMacieBaseline(config: MacieConfig): MacieResult {
  const account = new aws.macie2.Account(named("macie"), {
    findingPublishingFrequency: "FIFTEEN_MINUTES",
    status: "ENABLED",
  });

  const classificationJobs = config.classificationJobs.map(
    (entry, index) =>
      new aws.macie2.ClassificationJob(
        named(`macie-job-${index + 1}`),
        {
          jobType: "SCHEDULED",
          name: named(`macie-job-${index + 1}`),
          scheduleFrequency: { weeklySchedule: entry.dayOfWeek },
          s3JobDefinition: {
            bucketDefinitions: [
              {
                accountId: entry.accountId,
                buckets: entry.buckets,
              },
            ],
          },
          tags: tag(`macie-job-${index + 1}`, {
            DataClass: "sensitive-data-discovery",
          }),
        },
        { dependsOn: account },
      ),
  );

  return { account, classificationJobs };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
