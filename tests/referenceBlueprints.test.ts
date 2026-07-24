import test from "node:test";
import assert from "node:assert/strict";
import {
  ReferenceBlueprintName,
  createHostileReferenceBlueprints,
  createReferenceBlueprint,
  evaluateBlueprint,
  parsePlatformBlueprint,
} from "../src/core";

const references: ReferenceBlueprintName[] = [
  "pooled",
  "dedicated-data",
  "dedicated-network",
  "dedicated-account",
  "e2b-byoc",
  "microvm-fallback",
];

for (const name of references) {
  test(`reference blueprint '${name}' is schema-valid and policy-compliant`, () => {
    const blueprint = createReferenceBlueprint(name);
    const reparsed = parsePlatformBlueprint(
      JSON.parse(JSON.stringify(blueprint)),
    );
    assert.deepEqual(evaluateBlueprint(reparsed), []);
  });
}

test("reference isolation tiers express distinct placement boundaries", () => {
  const pooled = createReferenceBlueprint("pooled");
  const dedicatedData = createReferenceBlueprint("dedicated-data");
  const dedicatedNetwork = createReferenceBlueprint("dedicated-network");
  const dedicatedAccount = createReferenceBlueprint("dedicated-account");

  assert.equal(
    pooled.trustZones.filter((zone) => zone.kind === "execution").length,
    1,
  );
  assert.equal(
    dedicatedData.dataBoundaries.filter(
      (boundary) => boundary.tenantScope.mode === "dedicated",
    ).length,
    2,
  );
  assert.equal(
    dedicatedNetwork.trustZones.filter((zone) => zone.kind === "execution")
      .length,
    2,
  );
  assert.ok(
    dedicatedAccount.trustZones
      .filter((zone) => zone.tenantScope.mode === "dedicated")
      .every((zone) => zone.isolationBoundary?.endsWith("-account")),
  );
});

test("E2B and microVM references select distinct runtime capabilities", () => {
  const e2b = createReferenceBlueprint("e2b-byoc");
  const microvm = createReferenceBlueprint("microvm-fallback");
  assert.ok(e2b.requiredCapabilities.includes("external-sandbox"));
  assert.ok(
    e2b.workloadPlanes.every(
      (workload) => workload.orchestrator === "external-sandbox",
    ),
  );
  assert.ok(microvm.requiredCapabilities.includes("microvm-runtime"));
  assert.ok(
    microvm.workloadPlanes.every(
      (workload) => workload.runtimeIsolation === "microvm",
    ),
  );
});

for (const [name, hostile] of Object.entries(
  createHostileReferenceBlueprints(),
)) {
  test(`hostile reference '${name}' fails with ${hostile.expectedCode}`, () => {
    const codes = evaluateBlueprint(hostile.blueprint).map(
      (entry) => entry.code,
    );
    assert.ok(
      codes.includes(hostile.expectedCode),
      `expected ${hostile.expectedCode}, received ${codes.join(", ")}`,
    );
  });
}
