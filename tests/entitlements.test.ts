import test from "node:test";
import assert from "node:assert/strict";
import {
  PlatformBlueprint,
  analyzeEntitlements,
  evaluateBlueprint,
} from "../src/core";

function entitlementBlueprint(): PlatformBlueprint {
  return {
    apiVersion: "security.deus.dev/v1alpha1",
    name: "entitlements",
    environment: "test",
    posture: {
      forbidPublicControlPlanes: true,
      requireInspectedEgress: false,
      requireImmutableAudit: false,
      minimumAuditRetentionDays: 365,
    },
    requiredCapabilities: [],
    trustZones: [
      {
        id: "data-a-zone",
        kind: "data",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-a" },
      },
      {
        id: "data-b-zone",
        kind: "data",
        publicAccess: false,
        tenantScope: { mode: "dedicated", tenantId: "tenant-b" },
      },
    ],
    networkDomains: [],
    flows: [],
    workloadPlanes: [],
    applications: [],
    tenants: [],
    dataBoundaries: [
      {
        id: "data-a",
        zoneId: "data-a-zone",
        classification: "internal",
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
      {
        id: "data-b",
        zoneId: "data-b-zone",
        classification: "internal",
        tenantScope: { mode: "dedicated", tenantId: "tenant-b" },
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
        id: "tenant-a-user",
        kind: "workload",
        tenantId: "tenant-a",
        shortLived: true,
      },
      {
        id: "tenant-b-reader",
        kind: "workload",
        tenantId: "tenant-b",
        shortLived: true,
      },
    ],
    identityDelegations: [
      {
        id: "a-assumes-b",
        fromIdentityId: "tenant-a-user",
        toIdentityId: "tenant-b-reader",
        conditions: { brokered: "true" },
      },
    ],
    grants: [
      {
        id: "b-read",
        identityId: "tenant-b-reader",
        resourceIds: ["data-b"],
        actions: ["data:read"],
        effect: "allow",
        tenantId: "tenant-b",
      },
    ],
    evidenceSinks: [],
    evidenceRequirements: [],
  };
}

test("entitlement analysis expands delegated identity paths", () => {
  const analysis = analyzeEntitlements(entitlementBlueprint());
  const inherited = analysis.entitlements.find(
    (entry) =>
      entry.principalId === "tenant-a-user" && entry.resourceId === "data-b",
  );
  assert.ok(inherited);
  assert.deepEqual(inherited.viaIdentityIds, [
    "tenant-a-user",
    "tenant-b-reader",
  ]);
  assert.deepEqual(inherited.delegationIds, ["a-assumes-b"]);
  assert.equal(inherited.decision, "allow");
});

test("policy engine rejects cross-tenant access reached through delegation", () => {
  const codes = evaluateBlueprint(entitlementBlueprint()).map(
    (entry) => entry.code,
  );
  assert.ok(codes.includes("IDENTITY_CROSS_TENANT_PATH"));
});

test("explicit deny removes an inherited effective allow", () => {
  const blueprint = entitlementBlueprint();
  blueprint.grants = [
    ...blueprint.grants,
    {
      id: "b-deny",
      identityId: "tenant-b-reader",
      resourceIds: ["data-b"],
      actions: ["data:read"],
      effect: "deny",
      tenantId: "tenant-b",
    },
  ];
  const inherited = analyzeEntitlements(blueprint).entitlements.find(
    (entry) =>
      entry.principalId === "tenant-a-user" && entry.resourceId === "data-b",
  );
  assert.equal(inherited?.decision, "deny");
  assert.deepEqual(inherited?.deniedByGrantIds, ["b-deny"]);
  assert.ok(
    !evaluateBlueprint(blueprint)
      .map((entry) => entry.code)
      .includes("IDENTITY_CROSS_TENANT_PATH"),
  );
});

test("a reviewed, unexpired, audited exception permits an explicit cross-tenant path", () => {
  const blueprint = entitlementBlueprint();
  blueprint.evidenceSinks = [
    {
      id: "audit",
      immutable: true,
      retentionDays: 365,
      tenantScope: { mode: "platform" },
    },
  ];
  blueprint.evidenceRequirements = [
    {
      id: "cross-tenant-audit",
      sourceIds: ["data-b"],
      sinkId: "audit",
      eventTypes: ["read"],
    },
  ];
  blueprint.grants = blueprint.grants.map((grant) => ({
    ...grant,
    exception: {
      owner: "platform-security",
      reason: "Reviewed support path",
      expiresAt: "2999-01-01T00:00:00.000Z",
      auditRequirementId: "cross-tenant-audit",
    },
  }));
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(!codes.includes("IDENTITY_CROSS_TENANT_PATH"));
});

test("vendor delegations require confused-deputy bindings", () => {
  const blueprint = entitlementBlueprint();
  blueprint.identities = [
    ...blueprint.identities,
    { id: "vendor", kind: "vendor", shortLived: true },
  ];
  blueprint.identityDelegations = [
    ...blueprint.identityDelegations,
    {
      id: "vendor-assumes-reader",
      fromIdentityId: "vendor",
      toIdentityId: "tenant-b-reader",
    },
  ];
  const codes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(codes.includes("IDENTITY_VENDOR_CONFUSED_DEPUTY"));

  blueprint.identityDelegations = blueprint.identityDelegations.map((entry) =>
    entry.id === "vendor-assumes-reader"
      ? {
          ...entry,
          conditions: {
            audience: "deus-byoc",
            externalSubject: "vendor-account",
          },
        }
      : entry,
  );
  const fixedCodes = evaluateBlueprint(blueprint).map((entry) => entry.code);
  assert.ok(!fixedCodes.includes("IDENTITY_VENDOR_CONFUSED_DEPUTY"));
});
