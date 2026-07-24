import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  createWardenMindBlueprint,
  parseManagedPostgresIntent,
  parsePostgresAccessProfile,
} from "../src/core";
import { compileAwsPostgresAccessProfile } from "../src/postgresAccessProfile";
import {
  awsDatabaseAccessBindingDigest,
  type AwsDatabaseWorkloadManifest,
} from "../src/databaseAccess";

function fixture(): any {
  return JSON.parse(
    readFileSync("contracts/postgres-access-profile-v1alpha1.json", "utf8"),
  );
}

test("checked PostgreSQL access profile is complete, credential-free, and pending observed evidence", () => {
  const profile = parsePostgresAccessProfile(fixture());
  assert.equal(profile.authentication.kind, "aws-rds-iam");
  assert.equal(profile.authentication.target, "rds-proxy");
  assert.equal(profile.authentication.tokenDelivery, "per-physical-connection");
  assert.equal(profile.connection.tls.mode, "verify-full");
  assert.equal(profile.network.sourceBoundaryMode, "exact-pod-security-group");
  assert.equal(profile.readiness.ready, false);
  assert.deepEqual(profile.readiness.blockers, [
    "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
    "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
    "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
  ]);
  assert.equal(profile.credentials, null);
});

test("PostgreSQL access profile rejects credential material and unsupported readiness claims", () => {
  assert.throws(
    () =>
      parsePostgresAccessProfile({
        ...fixture(),
        connection: { ...fixture().connection, password: "forbidden" },
      }),
    /forbidden credential material/,
  );
  assert.throws(
    () =>
      parsePostgresAccessProfile({
        ...fixture(),
        readiness: {
          state: "ready",
          ready: true,
          blockers: [],
          evidenceRefs: [],
        },
      }),
    /readiness.state must equal pending-infrastructure/,
  );
  assert.throws(
    () =>
      parsePostgresAccessProfile({
        ...fixture(),
        enforcement: {
          ...fixture().enforcement,
          bindingDigest: "3".repeat(64),
        },
      }),
    /exact workload identity binding digest/,
  );
  assert.throws(
    () =>
      parsePostgresAccessProfile({
        ...fixture(),
        connection: {
          ...fixture().connection,
          endpoint: "mutated.proxy-abcdefghijkl.us-east-1.rds.amazonaws.com",
        },
      }),
    /profileSpecDigest must bind the exact/,
  );
});

test("PostgreSQL access profile parser matches schema string bounds and Kubernetes DNS labels", () => {
  const base = fixture();
  for (const mutate of [
    (value: any) => {
      value.connection.tls.caCertIdentifier = "x".repeat(129);
    },
    (value: any) => {
      value.identity.podIdentityAssociationId = "x".repeat(129);
    },
    (value: any) => {
      value.enforcement.requiredPodScheduling.tolerations[0].key = "x".repeat(
        254,
      );
    },
    (value: any) => {
      value.enforcement.requiredPodScheduling.tolerations[0].value = "x".repeat(
        64,
      );
    },
    (value: any) => {
      value.enforcement.requiredPodLabels.example = "x".repeat(513);
    },
    (value: any) => {
      value.identity.namespace = "invalid.namespace";
    },
  ]) {
    const candidate = structuredClone(base);
    mutate(candidate);
    assert.throws(() => parsePostgresAccessProfile(candidate));
  }
});

test("AWS PostgreSQL access-profile compiler binds the exact ManagedPostgres service and access class", () => {
  const intent = parseManagedPostgresIntent(
    JSON.parse(
      readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
    ),
    "development",
    createWardenMindBlueprint(),
  );
  const binding = intent.bindings.find(
    (candidate) => candidate.id === "warden-saas-postgres",
  );
  assert.ok(binding);
  const source = fixture();
  const workloadManifest = testWorkloadManifest(source);
  const input = profileInput(binding, source, workloadManifest);
  const profile = compileAwsPostgresAccessProfile(input);
  assert.equal(profile.application.applicationId, "warden");
  assert.equal(profile.application.componentId, "saas");
  assert.equal(profile.application.serviceRef, "warden-platform/saas/store");
  assert.equal(profile.identity.semanticIdentityId, "warden-saas-service");

  assert.throws(
    () =>
      compileAwsPostgresAccessProfile({
        ...input,
        semanticIdentityId: binding.access.migrationIdentityId,
      }),
    /exact runtime identity/,
  );
  assert.throws(
    () =>
      compileAwsPostgresAccessProfile({
        ...input,
        databaseName: "wrong_database",
      }),
    /database name does not match/,
  );
  assert.throws(
    () =>
      compileAwsPostgresAccessProfile({
        ...input,
        databaseUser: "wrong_user",
      }),
    /database user does not match/,
  );
  assert.throws(
    () =>
      compileAwsPostgresAccessProfile({
        ...input,
        workloadBundleDigest: "f".repeat(64),
      }),
    /workload bundle digest does not match/,
  );
});

function profileInput(
  binding: ReturnType<typeof parseManagedPostgresIntent>["bindings"][number],
  source: any,
  workloadManifest: AwsDatabaseWorkloadManifest,
) {
  return {
    binding,
    accessClass: "runtime" as const,
    endpoint: source.connection.endpoint,
    port: source.connection.port,
    databaseName: binding.database.name,
    caCertIdentifier: source.connection.tls.caCertIdentifier,
    caBundleRef: source.connection.tls.caBundleRef,
    region: source.authentication.region,
    proxyResourceId: source.authentication.resourceId,
    databaseUser: "warden_saas_service",
    semanticIdentityId: binding.access.runtimeIdentityId,
    roleArn: source.identity.roleArn,
    namespace: source.identity.namespace,
    serviceAccount: source.identity.serviceAccount,
    podIdentityAssociationId: source.identity.podIdentityAssociationId,
    securityGroupId: source.network.securityGroupId,
    bindingDigest: source.enforcement.bindingDigest,
    workloadBundleDigest: awsDatabaseAccessBindingDigest(workloadManifest),
    workloadManifest,
  };
}

function testWorkloadManifest(source: any): AwsDatabaseWorkloadManifest {
  const nodePoolName = Object.values(
    source.enforcement.requiredPodScheduling.nodeSelector,
  )[0] as string;
  return {
    namespace: {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: source.identity.namespace,
        labels: { "pod-security.kubernetes.io/enforce": "restricted" },
      },
    },
    serviceAccount: {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: {
        namespace: source.identity.namespace,
        name: source.identity.serviceAccount,
        labels: source.enforcement.requiredPodLabels,
        annotations: source.enforcement.requiredPodAnnotations,
      },
      automountServiceAccountToken: false,
    },
    admissionPolicy: {
      apiVersion: "kyverno.io/v1",
      kind: "ClusterPolicy",
      metadata: {
        name: "test-database-access",
        annotations: {
          "pod-policies.kyverno.io/autogen-controllers": "none",
        },
      },
      spec: {
        admission: true,
        background: false,
        failurePolicy: "Fail",
        validationFailureAction: "Enforce",
        rules: [],
      },
    },
    applicationNetworkPolicy: {
      apiVersion: "networking.k8s.aws/v1alpha1",
      kind: "ApplicationNetworkPolicy",
      metadata: {
        name: "test-database-access",
        namespace: source.identity.namespace,
      },
      spec: {
        podSelector: {
          matchLabels: source.enforcement.requiredPodLabels,
        },
        policyTypes: ["Ingress", "Egress"],
        ingress: [],
        egress: [],
      },
    },
    nodeClass: {
      apiVersion: "eks.amazonaws.com/v1",
      kind: "NodeClass",
      metadata: { name: nodePoolName },
      spec: {
        role: "test-node-role",
        subnetSelectorTerms: [{ id: "subnet-0123456789abcdef0" }],
        securityGroupSelectorTerms: [{ tags: { test: "true" } }],
        podSubnetSelectorTerms: [{ id: "subnet-0123456789abcdef0" }],
        podSecurityGroupSelectorTerms: [{ id: source.network.securityGroupId }],
        snatPolicy: "Disabled",
        networkPolicy: "DefaultDeny",
        networkPolicyEventLogs: "Enabled",
        advancedNetworking: { associatePublicIPAddress: false },
      },
    },
    nodePool: {
      apiVersion: "karpenter.sh/v1",
      kind: "NodePool",
      metadata: { name: nodePoolName },
      spec: {
        template: {
          metadata: {
            labels: source.enforcement.requiredPodScheduling.nodeSelector,
          },
          spec: {
            nodeClassRef: {
              group: "eks.amazonaws.com",
              kind: "NodeClass",
              name: nodePoolName,
            },
            taints: [
              {
                key: "security.deus.dev/database-access",
                value: nodePoolName,
                effect: "NoSchedule",
              },
            ],
            requirements: [
              {
                key: "kubernetes.io/arch",
                operator: "In",
                values: ["amd64"],
              },
            ],
            expireAfter: "336h",
          },
        },
        limits: { cpu: "64", memory: "256Gi" },
        disruption: {
          consolidationPolicy: "WhenEmptyOrUnderutilized",
          consolidateAfter: "5m",
        },
      },
    },
    requiredPodLabels: source.enforcement.requiredPodLabels,
    requiredPodAnnotations: source.enforcement.requiredPodAnnotations,
    requiredPodScheduling: source.enforcement.requiredPodScheduling,
  };
}
