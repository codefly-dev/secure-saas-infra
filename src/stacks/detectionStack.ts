import { DetectionConfig } from "../config";
import { createDetectionRules } from "../detection";

export function createDetectionStack(config: DetectionConfig) {
  return createDetectionRules(config);
}
