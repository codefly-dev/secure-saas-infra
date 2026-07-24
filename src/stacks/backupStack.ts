import { BackupConfig } from "../config";
import { createBackupStack } from "../backup";
import type { PlatformBlueprint } from "../core";

export function createBackupAccountStack(
  config: BackupConfig,
  blueprint?: PlatformBlueprint,
) {
  return createBackupStack(config, blueprint);
}
