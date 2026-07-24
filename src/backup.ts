import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { BackupConfig, baseTags, named } from "./config";
import type { PlatformBlueprint } from "./core";
import { AwsBackupCompilation, compileAwsBackups } from "./adapters/aws";

export interface BackupResult {
  primaryVault: aws.backup.Vault;
  primaryVaultLock?: aws.backup.VaultLockConfiguration;
  primaryKmsKey: aws.kms.Key;
  replicaKmsKey?: aws.kms.ReplicaKey;
  replicaVault?: aws.backup.Vault;
  replicaVaultLock?: aws.backup.VaultLockConfiguration;
  plan?: aws.backup.Plan;
  selection?: aws.backup.Selection;
  restoreTestingPlans: aws.backup.RestoreTestingPlan[];
  restoreTestingSelections: aws.backup.RestoreTestingSelection[];
  backupIntent?: AwsBackupCompilation;
}

export function createBackupStack(
  config: BackupConfig,
  blueprint?: PlatformBlueprint,
): BackupResult {
  const backupIntent = blueprint
    ? compileAwsBackups(blueprint, {
        vaultLockEnabled: config.vaultLockEnabled,
        backupIntervalMinutes: config.backupIntervalMinutes,
        coldStorageAfterDays: config.coldStorageAfterDays,
        deleteAfterDays: config.deleteAfterDays,
        replicaRegion: config.replicaRegion,
      })
    : undefined;
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
    const replicaProvider = new aws.Provider(named("backup-replica-provider"), {
      region: config.replicaRegion as aws.Region,
    });

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
  const restoreTestingPlans: aws.backup.RestoreTestingPlan[] = [];
  const restoreTestingSelections: aws.backup.RestoreTestingSelection[] = [];

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

    const selectionRole = new aws.iam.Role(named("backup-selection-role"), {
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "backup.amazonaws.com",
      }),
      tags: tag("backup-selection-role"),
    });

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

    const restoreCadences = backupIntent?.backups.length
      ? [
          ...new Set(
            backupIntent.backups.map(
              (boundary) => boundary.restoreTestIntervalDays,
            ),
          ),
        ]
      : [config.restoreTestIntervalDays];
    for (const intervalDays of restoreCadences.sort((a, b) => a - b)) {
      const restoreTestingPlan = new aws.backup.RestoreTestingPlan(
        named(`backup-restore-test-${intervalDays}d`),
        {
          name: restoreTestingName(intervalDays),
          recoveryPointSelection: {
            algorithm: "LATEST_WITHIN_WINDOW",
            includeVaults: [primaryVault.arn],
            recoveryPointTypes: ["CONTINUOUS", "SNAPSHOT"],
            selectionWindowDays: Math.min(intervalDays, 365),
          },
          scheduleExpression: restoreSchedule(intervalDays),
          startWindowHours: 24,
          tags: tag(`backup-restore-test-${intervalDays}d`, {
            EvidenceClass: "restore-test",
          }),
        },
      );
      restoreTestingPlans.push(restoreTestingPlan);
      const protectedResourceTypes = backupIntent?.backups.length
        ? [
            ...new Set(
              backupIntent.backups
                .filter(
                  (boundary) =>
                    boundary.restoreTestIntervalDays === intervalDays,
                )
                .flatMap((boundary) => boundary.protectedResourceTypes),
            ),
          ].sort()
        : ["Aurora"];
      for (const resourceType of protectedResourceTypes) {
        restoreTestingSelections.push(
          new aws.backup.RestoreTestingSelection(
            named(
              `backup-restore-${intervalDays}d-${resourceType.toLowerCase()}`,
            ),
            {
              name: restoreSelectionName(intervalDays, resourceType),
              restoreTestingPlanName: restoreTestingPlan.name,
              protectedResourceType: resourceType,
              iamRoleArn: selectionRole.arn,
              protectedResourceConditions: {
                stringEquals: [
                  { key: "aws:ResourceTag/Backup", value: "required" },
                ],
              },
              validationWindowHours: 24,
            },
          ),
        );
      }
    }
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
    restoreTestingPlans,
    restoreTestingSelections,
    backupIntent,
  };
}

function restoreTestingName(intervalDays: number) {
  return named(`backup_restore_test_${intervalDays}d`).replace(/-/g, "_");
}

function restoreSelectionName(intervalDays: number, resourceType: string) {
  return named(`restore_${intervalDays}d_${resourceType}`).replace(/-/g, "_");
}

function restoreSchedule(intervalDays: number) {
  if (intervalDays <= 1) return "cron(0 6 * * ? *)";
  if (intervalDays <= 7) return "cron(0 6 ? * SUN *)";
  return "cron(0 6 1 * ? *)";
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
