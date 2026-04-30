import { E2bByocAccessConfig } from "../config";
import { createE2bByocAccess } from "../e2bByoc";

export function createE2bByocStack(config: E2bByocAccessConfig) {
  return createE2bByocAccess(config);
}
