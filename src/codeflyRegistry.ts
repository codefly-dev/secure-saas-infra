import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import {
  type CodeflyRegistryConfig,
  baseTags,
  named,
  validateCodeflyRegistryConfig,
} from "./config";

export interface CodeflyRegistryResult {
  kmsKey: aws.kms.Key;
  repositories: Readonly<Record<string, aws.ecr.Repository>>;
}

export function createCodeflyRegistry(
  config: CodeflyRegistryConfig,
): CodeflyRegistryResult {
  validateCodeflyRegistryConfig(config);
  if (!config.enabled) {
    throw new Error("Codefly registry creation requires enabled: true.");
  }
  const kmsKey = new aws.kms.Key(named("codefly-registry-key"), {
    description:
      "Customer-managed encryption key for immutable Codefly images.",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    tags: tag("codefly-registry-key", { DataClass: "build-artifacts" }),
  });
  new aws.kms.Alias(named("codefly-registry-key-alias"), {
    name: `alias/${named("codefly-registry")}`,
    targetKeyId: kmsKey.keyId,
  });

  const repositories = Object.fromEntries(
    [...config.repositories].sort().map((logicalName) => {
      const resourceName = named(`codefly-${logicalName.replaceAll("/", "-")}`);
      const repository = new aws.ecr.Repository(resourceName, {
        name: named(`codefly/${logicalName}`),
        encryptionConfigurations: [
          {
            encryptionType: "KMS",
            kmsKey: kmsKey.arn,
          },
        ],
        imageScanningConfiguration: { scanOnPush: true },
        imageTagMutability: "IMMUTABLE",
        forceDelete: false,
        tags: tag(resourceName, {
          DataClass: "build-artifacts",
          SupplyChain: "codefly",
        }),
      });
      new aws.ecr.LifecyclePolicy(`${resourceName}-lifecycle`, {
        repository: repository.name,
        policy: JSON.stringify({
          rules: [
            {
              rulePriority: 1,
              description:
                "Expire abandoned untagged images after review window",
              selection: {
                tagStatus: "untagged",
                countType: "sinceImagePushed",
                countUnit: "days",
                countNumber: config.untaggedRetentionDays,
              },
              action: { type: "expire" },
            },
            {
              rulePriority: 2,
              description: "Retain bounded immutable release history",
              selection: {
                tagStatus: "any",
                countType: "imageCountMoreThan",
                countNumber: config.retainImageCount,
              },
              action: { type: "expire" },
            },
          ],
        }),
      });
      new aws.ecr.RepositoryPolicy(`${resourceName}-transport-policy`, {
        repository: repository.name,
        policy: pulumi.jsonStringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "DenyInsecureTransport",
              Effect: "Deny",
              Principal: "*",
              Action: "ecr:*",
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        }),
      });
      return [logicalName, repository];
    }),
  );
  return { kmsKey, repositories };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return { ...baseTags, Name: name, ...extra };
}
