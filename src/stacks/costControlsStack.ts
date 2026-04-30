import { CostControlsConfig } from "../config";
import { createCostControls } from "../costControls";

export function createCostControlsStack(config: CostControlsConfig) {
  return createCostControls(config);
}
