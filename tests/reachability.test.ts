import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformBlueprint,
  evaluateBlueprint,
  findNetworkPaths,
} from "../src/core";

function reachabilityBlueprint(): PlatformBlueprint {
  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: "reachability",
    environment: "test",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: true,
      requireImmutableAudit: false,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: ["private-network", "managed-firewall"],
    trustZones: [
      {
        id: "execution",
        kind: "execution",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
      },
      {
        id: "bridge",
        kind: "workload",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
      },
      {
        id: "data",
        kind: "data",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
      },
      {
        id: "egress",
        kind: "egress",
        publicAccess: true,
        tenantScope: { mode: "platform" },
      },
      {
        id: "internet",
        kind: "external",
        publicAccess: true,
        tenantScope: { mode: "platform" },
      },
    ],
    networkDomains: [
      {
        id: "execution-net",
        zoneId: "execution",
        cidrs: ["10.10.0.0/16"],
        availabilityZoneCount: 2,
        directInternetAccess: false,
        inspectedEgress: false,
      },
      {
        id: "bridge-net",
        zoneId: "bridge",
        cidrs: ["10.20.0.0/16"],
        availabilityZoneCount: 2,
        directInternetAccess: false,
        inspectedEgress: false,
      },
      {
        id: "data-net",
        zoneId: "data",
        cidrs: ["10.30.0.0/16"],
        availabilityZoneCount: 2,
        directInternetAccess: false,
        inspectedEgress: false,
      },
      {
        id: "egress-net",
        zoneId: "egress",
        cidrs: ["10.40.0.0/16"],
        availabilityZoneCount: 2,
        directInternetAccess: true,
        inspectedEgress: true,
      },
    ],
    flows: [
      {
        id: "execution-to-bridge",
        fromZoneId: "execution",
        toZoneId: "bridge",
        protocol: "https",
        purpose: "Hidden first hop",
        authorization: "direct",
      },
      {
        id: "bridge-to-data",
        fromZoneId: "bridge",
        toZoneId: "data",
        protocol: "https",
        purpose: "Hidden second hop",
        authorization: "direct",
      },
      {
        id: "bridge-cycle",
        fromZoneId: "bridge",
        toZoneId: "execution",
        protocol: "https",
        purpose: "Cycle",
        authorization: "direct",
      },
      {
        id: "approved-egress",
        fromZoneId: "execution",
        toZoneId: "internet",
        viaZoneIds: ["egress"],
        externalDestinations: ["example.com"],
        protocol: "https",
        purpose: "Approved dependency",
        authorization: "brokered",
      },
    ],
    workloadPlanes: [],
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

test("reachability expands declared hops and terminates in cyclic graphs", () => {
  const paths = findNetworkPaths(reachabilityBlueprint(), "execution");
  assert.ok(
    paths.some(
      (path) => path.zoneIds.join(" -> ") === "execution -> bridge -> data",
    ),
  );
  assert.ok(
    paths.some(
      (path) => path.zoneIds.join(" -> ") === "execution -> egress -> internet",
    ),
  );
  assert.ok(paths.length < 20, "cycles must not create unbounded paths");
});

test("policy engine rejects a hidden execution-to-data path", () => {
  const violations = evaluateBlueprint(reachabilityBlueprint());
  const bypass = violations.find(
    (entry) => entry.code === "NET_TRANSITIVE_EXECUTION_BYPASS",
  );
  assert.equal(bypass?.path, "execution -> bridge -> data");
});

test("transitive egress proof requires an inspected zone on the actual path", () => {
  const blueprint = reachabilityBlueprint();
  blueprint.flows = blueprint.flows.map((flow) =>
    flow.id === "approved-egress" ? { ...flow, viaZoneIds: [] } : flow,
  );
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("NET_TRANSITIVE_UNINSPECTED_EGRESS"));
});

test("reachability fails closed instead of truncating excessive paths", () => {
  assert.throws(
    () =>
      findNetworkPaths(reachabilityBlueprint(), "execution", { maxPaths: 1 }),
    /exceeded 1 paths/,
  );
});
