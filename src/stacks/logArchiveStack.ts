import { LogArchiveConfig } from "../config";
import { createLogArchive } from "../logArchive";

export function createLogArchiveStack(config: LogArchiveConfig) {
  return createLogArchive(config);
}
