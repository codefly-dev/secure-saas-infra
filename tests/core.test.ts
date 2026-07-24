import test from "node:test";
import assert from "node:assert/strict";
import {
  CloudAdapter,
  PlatformBlueprint,
  PlatformCapability,
  buildSecurityGraph,
  compileBlueprint,
  evaluateBlueprint,
} from "../src/core";

function secureBlueprint(): PlatformBlueprint {
  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: "secure-platform",
    environment: "production",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: true,
      requireImmutableAudit: true,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: [
      "private-network",
      "centralized-egress",
      "managed-firewall",
      "workload-identity",
      "external-sandbox",
    ],
    trustZones: [
      {
        id: "internet",
        kind: "external",
        publicAccess: true,
        tenantScope: { mode: "platform" },
      },
      {
        id: "egress",
        kind: "egress",
        publicAccess: true,
        tenantScope: { mode: "platform" },
        isolationBoundary: "network-account",
      },
      {
        id: "control",
        kind: "control-plane",
        publicAccess: false,
        tenantScope: { mode: "platform" },
        isolationBoundary: "platform-account",
      },
      {
        id: "tenant-a-execution",
        kind: "execution",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
        isolationBoundary: "tenant-a-account",
      },
      {
        id: "tenant-a-data-zone",
        kind: "data",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
        isolationBoundary: "tenant-a-account",
      },
    ],
    networkDomains: [
      {
        id: "egress-net",
        zoneId: "egress",
        cidrs: ["10.0.0.0/16"],
        availabilityZoneCount: 3,
        directInternetAccess: true,
        inspectedEgress: true,
      },
      {
        id: "control-net",
        zoneId: "control",
        cidrs: ["10.10.0.0/16"],
        availabilityZoneCount: 3,
        directInternetAccess: false,
        inspectedEgress: false,
      },
      {
        id: "tenant-a-net",
        zoneId: "tenant-a-execution",
        cidrs: ["10.20.0.0/16"],
        availabilityZoneCount: 3,
        directInternetAccess: false,
        inspectedEgress: false,
      },
      {
        id: "tenant-a-data-net",
        zoneId: "tenant-a-data-zone",
        cidrs: ["10.30.0.0/16"],
        availabilityZoneCount: 3,
        directInternetAccess: false,
        inspectedEgress: false,
      },
    ],
    flows: [
      {
        id: "tenant-a-to-broker",
        fromZoneId: "tenant-a-execution",
        toZoneId: "control",
        protocol: "https",
        ports: [443],
        purpose: "Broker API",
        authorization: "brokered",
      },
      {
        id: "tenant-a-egress",
        fromZoneId: "tenant-a-execution",
        toZoneId: "internet",
        protocol: "https",
        ports: [443],
        purpose: "Approved dependencies",
        authorization: "brokered",
        viaZoneIds: ["egress"],
        externalDestinations: ["api.github.com"],
      },
    ],
    workloadPlanes: [
      {
        id: "tenant-a-sandbox",
        zoneId: "tenant-a-execution",
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
        executionTrust: "untrusted",
        orchestrator: "external-sandbox",
        runtimeIsolation: "dedicated-vm",
        controlPlanePublic: false,
        workloadIdentity: true,
        credentialMode: "brokered",
        maxExecutionMinutes: 60,
      },
    ],
    applications: [],
    tenants: [
      {
        tenantId: "tenant-a",
        isolationTier: "dedicated-account",
        zoneIds: ["tenant-a-execution", "tenant-a-data-zone"],
        dataBoundaryIds: ["tenant-a-data"],
        identityIds: ["tenant-a-workload"],
      },
    ],
    dataBoundaries: [
      {
        id: "tenant-a-data",
        zoneId: "tenant-a-data-zone",
        classification: "regulated",
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
        services: ["object"],
        encryption: {
          customerManagedKey: true,
          dedicatedPerTenant: true,
          rotationRequired: true,
        },
        recovery: {
          backupRequired: true,
          rpoMinutes: 60,
          rtoMinutes: 240,
          multiAzRequired: true,
          deletionProtectionRequired: true,
          finalSnapshotRequired: true,
          restoreTestIntervalDays: 30,
        },
        retentionDays: 365,
        versioningRequired: true,
        replicationRequired: false,
        objectAuditRequired: true,
        deletionEvidenceRequired: true,
        exportEvidenceRequired: true,
      },
    ],
    identities: [
      {
        id: "tenant-a-workload",
        kind: "workload",
        tenantId: "tenant-a",
        shortLived: true,
      },
    ],
    identityDelegations: [],
    grants: [
      {
        id: "tenant-a-data-access",
        identityId: "tenant-a-workload",
        resourceIds: ["tenant-a-data"],
        actions: ["data:read", "data:write"],
        effect: "allow",
        tenantId: "tenant-a",
        conditions: { brokered: "true" },
      },
    ],
    evidenceSinks: [
      {
        id: "audit-log",
        immutable: true,
        retentionDays: 2555,
        tenantScope: { mode: "platform" },
      },
    ],
    evidenceRequirements: [
      {
        id: "tenant-a-data-audit",
        sourceIds: ["tenant-a-data"],
        sinkId: "audit-log",
        eventTypes: ["read", "write", "delete"],
      },
    ],
  };
}

test("cloud-neutral policies accept a secure dedicated-tenant blueprint", () => {
  assert.deepEqual(evaluateBlueprint(secureBlueprint()), []);
});

test("cloud-neutral policies reject execution bypass and uninspected egress", () => {
  const blueprint = secureBlueprint();
  blueprint.flows = blueprint.flows.map((flow) =>
    flow.id === "tenant-a-to-broker"
      ? { ...flow, authorization: "direct" as const }
      : flow.id === "tenant-a-egress"
        ? { ...flow, viaZoneIds: [] }
        : flow,
  );
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("NET_EXECUTION_BYPASS"));
  assert.ok(codes.includes("NET_UNINSPECTED_EGRESS"));
});

test("cloud-neutral policies reject shared keys and cross-tenant grants", () => {
  const blueprint = secureBlueprint();
  blueprint.dataBoundaries = blueprint.dataBoundaries.map((boundary) => ({
    ...boundary,
    encryption: { ...boundary.encryption, dedicatedPerTenant: false },
  }));
  blueprint.grants = blueprint.grants.map((grant) => ({
    ...grant,
    tenantId: "tenant-b",
  }));
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("DATA_REGULATED_SHARED_KEY"));
  assert.ok(codes.includes("TENANT_DEDICATED_KEY_MISSING"));
  assert.ok(codes.includes("IDENTITY_GRANT_SCOPE_MISMATCH"));
  assert.ok(codes.includes("IDENTITY_CROSS_TENANT_GRANT"));
});

test("cloud-neutral policies reject wildcard grants and empty egress allowlists", () => {
  const blueprint = secureBlueprint();
  blueprint.grants = blueprint.grants.map((grant) => ({
    ...grant,
    actions: ["data:*"],
  }));
  blueprint.flows = blueprint.flows.map((flow) =>
    flow.id === "tenant-a-egress"
      ? { ...flow, externalDestinations: [] }
      : flow,
  );
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("IDENTITY_WILDCARD_GRANT"));
  assert.ok(codes.includes("NET_EMPTY_EGRESS_ALLOWLIST"));
});

test("cloud-neutral policies reject ordinary containers for untrusted execution", () => {
  const blueprint = secureBlueprint();
  blueprint.workloadPlanes = blueprint.workloadPlanes.map((workload) => ({
    ...workload,
    orchestrator: "managed-kubernetes" as const,
    runtimeIsolation: "container" as const,
    controlPlanePublic: true,
    workloadIdentity: false,
    credentialMode: "ambient" as const,
    maxExecutionMinutes: undefined,
  }));
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("WORKLOAD_PUBLIC_CONTROL_PLANE"));
  assert.ok(codes.includes("WORKLOAD_IDENTITY_MISSING"));
  assert.ok(codes.includes("WORKLOAD_UNBROKERED_CREDENTIALS"));
  assert.ok(codes.includes("WORKLOAD_WEAK_RUNTIME_ISOLATION"));
  assert.ok(codes.includes("WORKLOAD_UNBOUNDED_EXECUTION"));
});

test("security graph makes reachability, access, and evidence edges explicit", () => {
  const graph = buildSecurityGraph(secureBlueprint());
  assert.ok(
    graph.edges.some(
      (edge) => edge.kind === "can-reach" && edge.from === "tenant-a-execution",
    ),
  );
  assert.ok(
    graph.edges.some(
      (edge) => edge.kind === "can-access" && edge.to === "tenant-a-data",
    ),
  );
  assert.ok(
    graph.edges.some(
      (edge) => edge.kind === "audits-to" && edge.to === "audit-log",
    ),
  );
});

test("adapter capability negotiation fails closed", () => {
  const adapter: CloudAdapter<string> = {
    descriptor: {
      cloud: "gcp",
      name: "incomplete-test-adapter",
      capabilities: new Set<PlatformCapability>(["private-network"]),
    },
    compile: () => "should-not-compile",
  };
  assert.throws(
    () => compileBlueprint(secureBlueprint(), adapter),
    /does not support required capabilities/,
  );
});
