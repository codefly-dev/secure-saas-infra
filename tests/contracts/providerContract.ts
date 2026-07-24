import assert from "node:assert/strict";
import test from "node:test";
import type { PlatformBlueprint, ReferenceBlueprintName } from "../../src/core";
import {
  createHostileReferenceBlueprints,
  createReferenceBlueprint,
  parsePlatformBlueprint,
} from "../../src/core";

export const PROVIDER_CONTRACT_VERSION =
  "security.deus.dev/provider-contract/v1alpha1";

export interface NormalizedProviderPlan {
  contractVersion: typeof PROVIDER_CONTRACT_VERSION;
  provider: string;
  networkDomainIds: readonly string[];
  privateWorkloadPlaneIds: readonly string[];
  dataBoundaryIds: readonly string[];
  backupBoundaryIds: readonly string[];
  identityIds: readonly string[];
  evidenceSinkIds: readonly string[];
}

export interface ProviderContractAdapter {
  name: string;
  compile(blueprint: PlatformBlueprint): NormalizedProviderPlan;
}

const references: ReferenceBlueprintName[] = [
  "pooled",
  "dedicated-data",
  "dedicated-network",
  "dedicated-account",
  "e2b-byoc",
  "microvm-fallback",
];

export function registerProviderContract(adapter: ProviderContractAdapter) {
  for (const name of references) {
    test(`${adapter.name} conforms for neutral '${name}' intent`, () => {
      const fixture = JSON.parse(
        JSON.stringify(createReferenceBlueprint(name)),
      ) as unknown;
      const blueprint = parsePlatformBlueprint(fixture);
      const plan = adapter.compile(blueprint);
      assert.equal(plan.contractVersion, PROVIDER_CONTRACT_VERSION);
      assert.equal(plan.provider, adapter.name);
      assert.deepEqual(
        plan.networkDomainIds,
        blueprint.networkDomains.map((domain) => domain.id).sort(),
      );
      assert.deepEqual(
        plan.privateWorkloadPlaneIds,
        blueprint.workloadPlanes.map((plane) => plane.id).sort(),
      );
      assert.deepEqual(
        plan.dataBoundaryIds,
        blueprint.dataBoundaries.map((boundary) => boundary.id).sort(),
      );
      assert.deepEqual(
        plan.backupBoundaryIds,
        blueprint.dataBoundaries
          .filter((boundary) => boundary.recovery.backupRequired)
          .map((boundary) => boundary.id)
          .sort(),
      );
      assert.deepEqual(
        plan.identityIds,
        blueprint.identities.map((identity) => identity.id).sort(),
      );
      assert.deepEqual(
        plan.evidenceSinkIds,
        blueprint.evidenceSinks.map((sink) => sink.id).sort(),
      );
    });
  }

  for (const [name, hostile] of Object.entries(
    createHostileReferenceBlueprints(),
  )) {
    test(`${adapter.name} rejects hostile neutral '${name}' intent`, () => {
      assert.throws(
        () => adapter.compile(hostile.blueprint),
        new RegExp(hostile.expectedCode),
      );
    });
  }
}
