import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformBlueprint,
  WorkloadPlane,
  evaluateBlueprint,
} from "../src/core";

function workloadBlueprint(workload: WorkloadPlane): PlatformBlueprint {
  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: "workload-plane",
    environment: "test",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: false,
      requireImmutableAudit: false,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities:
      workload.orchestrator === "microvm"
        ? ["workload-identity", "microvm-runtime"]
        : ["workload-identity", "private-control-plane"],
    trustZones: [
      {
        id: workload.zoneId,
        kind:
          workload.executionTrust === "untrusted" ? "execution" : "workload",
        publicAccess: false,
        tenantScope: workload.tenantScope,
      },
    ],
    networkDomains: [],
    flows: [],
    workloadPlanes: [workload],
    applications: [],
    tenants: [],
    dataBoundaries: [],
    identities: [],
    identityDelegations: [],
    grants: [],
    evidenceSinks: [],
    evidenceRequirements: [],
  };
}

test("trusted private Kubernetes plane satisfies workload invariants", () => {
  const blueprint = workloadBlueprint({
    id: "platform-eks",
    zoneId: "platform",
    tenantScope: { mode: "platform" },
    executionTrust: "trusted",
    orchestrator: "managed-kubernetes",
    runtimeIsolation: "container",
    controlPlanePublic: false,
    workloadIdentity: true,
    credentialMode: "workload-identity",
  });
  assert.deepEqual(evaluateBlueprint(blueprint), []);
});

test("untrusted microVM fallback satisfies workload invariants", () => {
  const blueprint = workloadBlueprint({
    id: "execution-microvm",
    zoneId: "execution",
    tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
    executionTrust: "untrusted",
    orchestrator: "microvm",
    runtimeIsolation: "microvm",
    controlPlanePublic: false,
    workloadIdentity: true,
    credentialMode: "brokered",
    maxExecutionMinutes: 30,
  });
  assert.deepEqual(evaluateBlueprint(blueprint), []);
});
