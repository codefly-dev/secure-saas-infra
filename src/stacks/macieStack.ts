import { MacieConfig } from "../config";
import { createMacieBaseline } from "../macie";

export function createMacieStack(config: MacieConfig) {
  return createMacieBaseline(config);
}
