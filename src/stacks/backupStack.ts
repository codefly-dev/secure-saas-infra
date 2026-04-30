import { BackupConfig } from "../config";
import { createBackupStack } from "../backup";

export function createBackupAccountStack(config: BackupConfig) {
  return createBackupStack(config);
}
