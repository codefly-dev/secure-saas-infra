import { readFileSync } from "node:fs";
import path from "node:path";
import {
  parseManagedPostgresIntent,
  type ManagedPostgresEnvironment,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
} from "./core";

export function loadManagedPostgresContract(
  relativePath: string,
  environment: ManagedPostgresEnvironment,
  blueprint: PlatformBlueprint,
): ManagedPostgresIntent {
  if (!/^contracts\/[a-z0-9][a-z0-9.-]*\.json$/.test(relativePath)) {
    throw new Error(
      "managedPostgresContractPath must name an exact JSON file under contracts/.",
    );
  }
  const root = path.resolve(process.cwd());
  const resolved = path.resolve(root, relativePath);
  if (!resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error("managedPostgresContractPath escapes the project root.");
  }
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(resolved, "utf8"));
  } catch (error) {
    throw new Error(
      `Cannot load Managed Postgres contract '${relativePath}': ${error instanceof Error ? error.message : String(error)}.`,
    );
  }
  return parseManagedPostgresIntent(value, environment, blueprint);
}
