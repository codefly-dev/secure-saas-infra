import { PlatformBlueprint } from "./model";
import { BlueprintSchemaError, parsePlatformBlueprint } from "./schema";

export const currentBlueprintApiVersion = "security.deus.dev/v1alpha1" as const;

export interface BlueprintMigrationReport {
  sourceVersion: string;
  targetVersion: typeof currentBlueprintApiVersion;
  migrated: boolean;
  changes: readonly string[];
}

export interface LoadedPlatformBlueprint {
  blueprint: PlatformBlueprint;
  migrationReport: BlueprintMigrationReport;
}

export function loadPlatformBlueprint(value: unknown): LoadedPlatformBlueprint {
  const source = asObject(value);
  const sourceVersion = source.apiVersion;
  if (typeof sourceVersion !== "string") {
    throw new BlueprintSchemaError(
      "platformBlueprint.apiVersion",
      "must be a version string",
    );
  }

  if (sourceVersion === currentBlueprintApiVersion) {
    return {
      blueprint: parsePlatformBlueprint(value),
      migrationReport: {
        sourceVersion,
        targetVersion: currentBlueprintApiVersion,
        migrated: false,
        changes: [],
      },
    };
  }

  if (sourceVersion === "security.deus.dev/v1alpha0") {
    const migrated = {
      ...source,
      apiVersion: currentBlueprintApiVersion,
      workloadPlanes: source.workloadPlanes ?? [],
      applications: source.applications ?? [],
      identityDelegations: source.identityDelegations ?? [],
    };
    return {
      blueprint: parsePlatformBlueprint(migrated),
      migrationReport: {
        sourceVersion,
        targetVersion: currentBlueprintApiVersion,
        migrated: true,
        changes: [
          "Added workloadPlanes as an empty collection when absent.",
          "Added applications as an empty collection when absent.",
          "Added identityDelegations as an empty collection when absent.",
          `Updated apiVersion to ${currentBlueprintApiVersion}.`,
        ],
      },
    };
  }

  throw new BlueprintSchemaError(
    "platformBlueprint.apiVersion",
    `unsupported version '${sourceVersion}'; supported versions are security.deus.dev/v1alpha0 and ${currentBlueprintApiVersion}`,
  );
}

function asObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BlueprintSchemaError("platformBlueprint", "must be an object");
  }
  return value as Record<string, unknown>;
}
