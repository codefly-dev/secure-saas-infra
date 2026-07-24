import test from "node:test";
import assert from "node:assert/strict";
import {
  compileAwsWorkloads,
  type AwsWorkloadProviderExtensions,
} from "../src/adapters/aws";
import { createReferenceBlueprint } from "../src/core";

function extensions(): AwsWorkloadProviderExtensions {
  return {
    eks: {
      version: "1.33",
      endpointPublicAccess: false,
      autoModeNodePools: ["system", "general-purpose"],
      networkPolicyMode: "strict",
      secretsEncryption: true,
      controlPlaneLogTypes: [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
      ],
    },
    e2b: { vendorRoleConfigured: true, externalIdConfigured: true },
    microvm: {
      enabled: true,
      runtimeClassName: "deus-microvm",
      nodeIsolationLabel: "deus.dev/sandbox-runtime=microvm",
    },
  };
}

test("AWS workload compilation is deterministic for E2B BYOC", () => {
  const blueprint = createReferenceBlueprint("e2b-byoc");
  const first = compileAwsWorkloads(blueprint, extensions());
  const second = compileAwsWorkloads(blueprint, extensions());
  assert.deepEqual(first, second);
  assert.ok(first.planes.length > 0);
  assert.ok(first.planes.every((plane) => plane.deploymentKind === "e2b-byoc"));
  assert.ok(first.planes.every((plane) => plane.credentialMode === "brokered"));
});

test("AWS workload compilation selects the explicit microVM fallback", () => {
  const plan = compileAwsWorkloads(
    createReferenceBlueprint("microvm-fallback"),
    extensions(),
  );
  assert.ok(
    plan.planes.every(
      (plane) =>
        plane.deploymentKind === "private-eks-microvm" &&
        plane.runtimeClassName === "deus-microvm",
    ),
  );
});

test("AWS workload compilation produces private EKS for trusted platform intent", () => {
  const blueprint = createReferenceBlueprint("e2b-byoc");
  blueprint.workloadPlanes = blueprint.workloadPlanes.map((plane) => ({
    ...plane,
    executionTrust: "trusted" as const,
    orchestrator: "managed-kubernetes" as const,
    runtimeIsolation: "container" as const,
    credentialMode: "workload-identity" as const,
    maxExecutionMinutes: undefined,
  }));
  blueprint.requiredCapabilities = [
    ...blueprint.requiredCapabilities.filter(
      (capability) => capability !== "external-sandbox",
    ),
    "private-control-plane",
  ];
  const plan = compileAwsWorkloads(blueprint, extensions());
  assert.ok(
    plan.planes.every((plane) => plane.deploymentKind === "private-eks"),
  );
  assert.ok(plan.planes.every((plane) => plane.privateControlPlane));
});

test("AWS workload compilation fails before resources for weak or unconfigured isolation", () => {
  const e2bExtensions = extensions();
  e2bExtensions.e2b.vendorRoleConfigured = false;
  assert.throws(
    () =>
      compileAwsWorkloads(createReferenceBlueprint("e2b-byoc"), e2bExtensions),
    /requires a configured vendor role/,
  );

  const weak = createReferenceBlueprint("e2b-byoc");
  weak.workloadPlanes = weak.workloadPlanes.map((plane) => ({
    ...plane,
    orchestrator: "managed-kubernetes" as const,
    runtimeIsolation: "container" as const,
  }));
  assert.throws(
    () => compileAwsWorkloads(weak, extensions()),
    /WORKLOAD_WEAK_RUNTIME_ISOLATION/,
  );
});

test("AWS workload compilation requires a network domain and the complete EKS log set", () => {
  const missingNetwork = createReferenceBlueprint("e2b-byoc");
  const zoneId = missingNetwork.workloadPlanes[0].zoneId;
  missingNetwork.networkDomains = missingNetwork.networkDomains.filter(
    (domain) => domain.zoneId !== zoneId,
  );
  assert.throws(
    () => compileAwsWorkloads(missingNetwork, extensions()),
    /has no network domain/,
  );

  const trusted = createReferenceBlueprint("e2b-byoc");
  trusted.workloadPlanes = trusted.workloadPlanes.map((plane) => ({
    ...plane,
    executionTrust: "trusted" as const,
    orchestrator: "managed-kubernetes" as const,
    runtimeIsolation: "container" as const,
    credentialMode: "workload-identity" as const,
  }));
  trusted.requiredCapabilities = [
    ...trusted.requiredCapabilities.filter(
      (capability) => capability !== "external-sandbox",
    ),
    "private-control-plane",
  ];
  const incompleteLogs = extensions();
  incompleteLogs.eks.controlPlaneLogTypes = [
    "api",
    "api",
    "audit",
    "authenticator",
    "scheduler",
  ];
  assert.throws(
    () => compileAwsWorkloads(trusted, incompleteLogs),
    /all control-plane logs/,
  );
});
