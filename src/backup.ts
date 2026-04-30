import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { BackupConfig, baseTags, named } from "./config";

export interface BackupResult {
  primaryVault: aws.backup.Vault;
  primaryVaultLock?: aws.backup.VaultLockConfiguration;
  primaryKmsKey: aws.kms.Key;
  replicaKmsKey?: aws.kms.ReplicaKey;
  replicaVault?: aws.backup.Vault;
  replicaVaultLock?: aws.backup.VaultLockConfiguration;
  plan?: aws.backup.Plan;
  selection?: aws.backup.Selection;
}

export function createBackupStack(config: BackupConfig): BackupResult {
  const partition = aws.getPartitionOutput({});
  const current = aws.getCallerIdentityOutput({});

  const primaryKmsKey = new aws.kms.Key(named("backup-primary-key"), {
    description: "Multi-region primary KMS key for AWS Backup vaults.",
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    multiRegion: true,
    policy: pulumi
      .all([current.accountId, partition.partition])
      .apply(([accountId, partitionName]) =>
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "EnableRootAccountAdministration",
              Effect: "Allow",
              Principal: { AWS: `arn:${partitionName}:iam::${accountId}:root` },
              Action: "kms:*",
              Resource: "*",
            },
            {
              Sid: "AllowAwsBackupService",
              Effect: "Allow",
              Principal: { Service: "backup.amazonaws.com" },
              Action: [
                "kms:CreateGrant",
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:ReEncrypt*",
              ],
              Resource: "*",
            },
          ],
        }),
      ),
    tags: tag("backup-primary-key"),
  });

  new aws.kms.Alias(named("backup-primary-key-alias"), {
    name: `alias/${named("backup-primary")}`,
    targetKeyId: primaryKmsKey.keyId,
  });

  const primaryVault = new aws.backup.Vault(named("backup-primary-vault"), {
    name: named("backup-primary-vault"),
    kmsKeyArn: primaryKmsKey.arn,
    forceDestroy: false,
    tags: tag("backup-primary-vault", { EvidenceClass: "backup" }),
  });

  const primaryVaultLock = config.vaultLockEnabled
    ? new aws.backup.VaultLockConfiguration(
        named("backup-primary-vault-lock"),
        {
          backupVaultName: primaryVault.name,
          minRetentionDays: config.vaultLockMinRetentionDays,
          maxRetentionDays: config.vaultLockMaxRetentionDays,
          changeableForDays: config.vaultLockChangeableForDays,
        },
      )
    : undefined;

  let replicaKmsKey: aws.kms.ReplicaKey | undefined;
  let replicaVault: aws.backup.Vault | undefined;
  let replicaVaultLock: aws.backup.VaultLockConfiguration | undefined;

  if (config.replicaRegion) {
    const replicaProvider = new aws.Provider(
      named("backup-replica-provider"),
      {
        region: config.replicaRegion as aws.Region,
      },
    );

    replicaKmsKey = new aws.kms.ReplicaKey(
      named("backup-replica-key"),
      {
        primaryKeyArn: primaryKmsKey.arn,
        description: "Replica KMS key for AWS Backup cross-region copies.",
        deletionWindowInDays: 30,
        policy: pulumi
          .all([current.accountId, partition.partition])
          .apply(([accountId, partitionName]) =>
            JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "EnableRootAccountAdministration",
                  Effect: "Allow",
                  Principal: {
                    AWS: `arn:${partitionName}:iam::${accountId}:root`,
                  },
                  Action: "kms:*",
                  Resource: "*",
                },
                {
                  Sid: "AllowAwsBackupService",
                  Effect: "Allow",
                  Principal: { Service: "backup.amazonaws.com" },
                  Action: [
                    "kms:CreateGrant",
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*",
                  ],
                  Resource: "*",
                },
              ],
            }),
          ),
        tags: tag("backup-replica-key"),
      },
      { provider: replicaProvider },
    );

    replicaVault = new aws.backup.Vault(
      named("backup-replica-vault"),
      {
        name: named("backup-replica-vault"),
        kmsKeyArn: replicaKmsKey.arn,
        forceDestroy: false,
        tags: tag("backup-replica-vault", { EvidenceClass: "backup" }),
      },
      { provider: replicaProvider },
    );

    replicaVaultLock = config.vaultLockEnabled
      ? new aws.backup.VaultLockConfiguration(
          named("backup-replica-vault-lock"),
          {
            backupVaultName: replicaVault.name,
            minRetentionDays: config.vaultLockMinRetentionDays,
            maxRetentionDays: config.vaultLockMaxRetentionDays,
            changeableForDays: config.vaultLockChangeableForDays,
          },
          { provider: replicaProvider },
        )
      : undefined;
  }

  let plan: aws.backup.Plan | undefined;
  let selection: aws.backup.Selection | undefined;

  if (config.createPlan) {
    const replicaVaultArn = replicaVault?.arn;

    plan = new aws.backup.Plan(named("backup-plan"), {
      name: named("backup-plan"),
      rules: [
        {
          ruleName: "daily-with-cross-region-copy",
          targetVaultName: primaryVault.name,
          schedule: config.dailyScheduleExpression,
          startWindow: 60,
          completionWindow: 360,
          enableContinuousBackup: true,
          lifecycle: {
            coldStorageAfter: config.coldStorageAfterDays,
            deleteAfter: config.deleteAfterDays,
          },
          ...(replicaVaultArn
            ? {
                copyActions: [
                  {
                    destinationVaultArn: replicaVaultArn,
                    lifecycle: {
                      coldStorageAfter: config.coldStorageAfterDays,
                      deleteAfter: config.deleteAfterDays,
                    },
                  },
                ],
              }
            : {}),
        },
      ],
      tags: tag("backup-plan"),
    });

    const selectionRole = new aws.iam.Role(
      named("backup-selection-role"),
      {
        assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
          Service: "backup.amazonaws.com",
        }),
        tags: tag("backup-selection-role"),
      },
    );

    new aws.iam.RolePolicyAttachment(
      named("backup-selection-role-backup-policy"),
      {
        role: selectionRole.name,
        policyArn:
          "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup",
      },
    );

    new aws.iam.RolePolicyAttachment(
      named("backup-selection-role-restore-policy"),
      {
        role: selectionRole.name,
        policyArn:
          "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores",
      },
    );

    selection = new aws.backup.Selection(named("backup-selection"), {
      name: named("backup-selection"),
      iamRoleArn: selectionRole.arn,
      planId: plan.id,
      selectionTags: config.selectionTags.map((entry) => ({
        type: "STRINGEQUALS",
        key: entry.key,
        value: entry.value,
      })),
    });
  }

  return {
    primaryVault,
    primaryVaultLock,
    primaryKmsKey,
    replicaKmsKey,
    replicaVault,
    replicaVaultLock,
    plan,
    selection,
  };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
