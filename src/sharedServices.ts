import * as aws from "@pulumi/aws";
import { SharedServicesConfig, baseTags, named } from "./config";

export function createSharedServices(config: SharedServicesConfig) {
  const vaultKey = config.createVaultAutoUnsealKey
    ? new aws.kms.Key(named("vault-auto-unseal-key"), {
        description: "KMS key for Vault auto-unseal.",
        enableKeyRotation: true,
        deletionWindowInDays: 30,
        tags: tag("vault-auto-unseal-key"),
      })
    : undefined;

  if (vaultKey) {
    new aws.kms.Alias(named("vault-auto-unseal-key-alias"), {
      name: `alias/${named("vault-auto-unseal")}`,
      targetKeyId: vaultKey.keyId,
    });
  }

  const backupBucket = config.createVaultBackupBucket
    ? new aws.s3.Bucket(named("vault-backups"), {
        forceDestroy: false,
        objectLockEnabled: true,
        tags: tag("vault-backups", { DataClass: "secrets-backup" }),
      })
    : undefined;

  if (backupBucket) {
    new aws.s3.BucketPublicAccessBlock(named("vault-backups-public-access-block"), {
      bucket: backupBucket.id,
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    });

    new aws.s3.BucketVersioning(named("vault-backups-versioning"), {
      bucket: backupBucket.id,
      versioningConfiguration: {
        status: "Enabled",
      },
    });

    new aws.s3.BucketServerSideEncryptionConfiguration(named("vault-backups-encryption"), {
      bucket: backupBucket.id,
      rules: [
        {
          applyServerSideEncryptionByDefault: {
            kmsMasterKeyId: vaultKey?.arn,
            sseAlgorithm: vaultKey ? "aws:kms" : "AES256",
          },
          bucketKeyEnabled: Boolean(vaultKey),
          blockedEncryptionTypes: ["SSE-C"],
        },
      ],
    });

    new aws.s3.BucketLifecycleConfiguration(named("vault-backups-lifecycle"), {
      bucket: backupBucket.id,
      rules: [
        {
          id: "retain-vault-backups",
          status: "Enabled",
          filter: {},
          noncurrentVersionExpiration: {
            noncurrentDays: config.vaultBackupRetentionDays,
          },
          abortIncompleteMultipartUpload: {
            daysAfterInitiation: 7,
          },
        },
      ],
    });
  }

  if (config.createTailscaleBootstrapSecrets) {
    for (const secretName of ["tailscale-oauth-client-id", "tailscale-oauth-client-secret"]) {
      new aws.secretsmanager.Secret(named(secretName), {
        name: named(secretName),
        description: "Bootstrap placeholder. Put the real Tailscale OAuth value after stack creation.",
        kmsKeyId: vaultKey?.arn,
        recoveryWindowInDays: 30,
        tags: tag(secretName, { SecretClass: "bootstrap" }),
      });
    }
  }

  return { vaultKey, backupBucket };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
