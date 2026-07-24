import test from "node:test";
import assert from "node:assert/strict";
import type { ManagedPostgresBinding } from "../src/core";
import type { DatabaseConfig } from "../src/config";
import { awsDatabaseAccessBindingDigest } from "../src/databaseAccess";
import { assertAwsManagedPostgresMaterialization } from "../src/stacks/databaseBindings";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
  testDatabaseIamRoleConstraint,
} from "./helpers/pulumiMocks";

const binding: ManagedPostgresBinding = {
  id: "warden-saas-postgres",
  tenantId: "warden",
  dataBoundaryId: "warden-saas-state",
  codefly: {
    workspace: "deus",
    module: "warden-saas",
    service: "postgres",
  },
  database: {
    name: "warden",
    engine: "postgresql",
    majorVersion: "16",
    port: 5432,
    extensions: ["pgcrypto"],
  },
  provisioning: {
    requestedBy: "codefly-postgres-plugin",
    owner: "provider-adapter",
    serviceClass: "managed-postgresql",
    networkExposure: "private",
    multiZone: true,
    customerManagedEncryption: true,
    deletionProtection: true,
    pointInTimeRecovery: true,
    backupRetentionDays: 35,
    restoreTestIntervalDays: 30,
  },
  access: {
    runtimeIdentityId: "warden-saas-service",
    migrationIdentityId: "warden-saas-migration",
    networkAccess: {
      mode: "explicit-source-boundaries",
      runtimeBoundaryId: "warden-runtime-db-access",
      migrationBoundaryId: "warden-migration-db-access",
      separateBoundaries: true,
      allowNetworkCidr: false,
    },
    authentication: "workload-identity",
    tlsMode: "verify-full",
    credentialDelivery: "reference-only",
    adminCredentialsExposed: false,
    separateMigrationIdentity: true,
  },
  outputs: {
    endpoint: "reference",
    port: "value",
    databaseName: "value",
    caBundle: "reference",
    runtimeIdentity: "reference",
    migrationIdentity: "reference",
    credentials: "never",
  },
  audit: {
    immutable: true,
    denialEvents: true,
    accessEvidence: true,
    provisioningEvidence: true,
  },
};

const databaseConfig: DatabaseConfig = {
  name: "warden",
  engine: "aurora-postgresql",
  engineVersion: "16.4",
  engineMajorVersion: "16",
  databaseName: "ignored-by-managed-binding",
  masterUsername: "warden_admin",
  port: 5432,
  instanceClass: "db.r6g.large",
  instanceCount: 2,
  backupRetentionDays: 35,
  deletionProtection: true,
  createProxy: true,
  replicaRegion: "us-west-2",
};

test("managed PostgreSQL materialization rejects generic database substitutions before Pulumi", () => {
  assert.doesNotThrow(() =>
    assertAwsManagedPostgresMaterialization([binding], databaseConfig),
  );
  const cases: Array<[DatabaseConfig, RegExp]> = [
    [{ ...databaseConfig, engine: "aurora-mysql" }, /aurora-postgresql/],
    [{ ...databaseConfig, engineVersion: "15.8" }, /requires PostgreSQL major/],
    [
      { ...databaseConfig, engineMajorVersion: "15" },
      /requires PostgreSQL major/,
    ],
    [{ ...databaseConfig, port: 5433 }, /requires port 5432/],
    [{ ...databaseConfig, createProxy: false }, /end-to-end IAM RDS Proxy/],
    [{ ...databaseConfig, replicaRegion: undefined }, /recovery-copy target/],
    [{ ...databaseConfig, backupRetentionDays: 34 }, /at least 35 backup days/],
  ];
  for (const [candidate, error] of cases) {
    assert.throws(
      () => assertAwsManagedPostgresMaterialization([binding], candidate),
      error,
    );
  }
  assert.throws(
    () =>
      assertAwsManagedPostgresMaterialization(
        [
          {
            ...binding,
            database: { ...binding.database, extensions: ["hstore"] },
          },
        ],
        databaseConfig,
      ),
    /unsupported Aurora PostgreSQL extensions: hstore/,
  );
});

test("database access binding digest covers effective IAM and Kubernetes enforcement", () => {
  const subject = {
    identity: { roleArn: "arn:aws:iam::111111111111:role/runtime" },
    iam: {
      trustPolicy: { Resource: "exact-cluster" },
      permissionPolicy: { Resource: "exact-db-user" },
    },
    enforcement: {
      nodeClass: { networkPolicy: "DefaultDeny" },
      scheduling: { nodeSelector: "runtime-only" },
    },
  };
  const baseline = awsDatabaseAccessBindingDigest(subject);
  assert.equal(
    baseline,
    awsDatabaseAccessBindingDigest({
      enforcement: subject.enforcement,
      iam: subject.iam,
      identity: subject.identity,
    }),
    "object-key ordering must not change the canonical digest",
  );
  for (const candidate of [
    {
      ...subject,
      iam: {
        ...subject.iam,
        permissionPolicy: { Resource: "*" },
      },
    },
    {
      ...subject,
      iam: { ...subject.iam, trustPolicy: { Resource: "other-cluster" } },
    },
    {
      ...subject,
      enforcement: {
        ...subject.enforcement,
        nodeClass: { networkPolicy: "DefaultAllow" },
      },
    },
    {
      ...subject,
      enforcement: {
        ...subject.enforcement,
        scheduling: { nodeSelector: "migration" },
      },
    },
  ]) {
    assert.notEqual(awsDatabaseAccessBindingDigest(candidate), baseline);
  }
});

test("managed PostgreSQL access materializes exact Pod Identity, RDS IAM, network, and bootstrap bindings", async () => {
  const { resources } = await installPulumiMocks();
  const { createDatabaseCluster } = await import("../src/database");
  const {
    createAwsManagedPostgresAccess,
    materializeAwsDatabaseInfrastructureHandoff,
  } = await import("../src/databaseAccess");

  const database = createDatabaseCluster({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    config: {
      name: "warden",
      engine: "aurora-postgresql",
      engineVersion: "16.4",
      engineMajorVersion: "16",
      databaseName: "warden",
      masterUsername: "warden_admin",
      port: 5432,
      instanceClass: "db.r6g.large",
      instanceCount: 2,
      backupRetentionDays: 35,
      deletionProtection: true,
      createProxy: true,
    },
    vpcId: "vpc-test",
    privateSubnetIds: ["subnet-a", "subnet-b", "subnet-c"],
    accessBoundaryIds: {
      runtime: binding.access.networkAccess.runtimeBoundaryId,
      migration: binding.access.networkAccess.migrationBoundaryId,
      bootstrap: "warden-bootstrap-db-access",
    },
    databaseIdentityUsers: {
      runtime: "warden_saas_service",
      migration: "warden_saas_migration",
    },
  });
  const access = createAwsManagedPostgresAccess({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    organizationId: "o-example123456",
    environment: "development",
    clusterName: "platform-dev",
    clusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/platform-dev",
    nodeRoleName: "platform-auto-node-role",
    podSubnetIds: ["subnet-a", "subnet-b", "subnet-c"],
    binding,
    database,
    secretsManagerVpcEndpointId: "vpce-0123456789abcdef0",
    secretsManagerVpcEndpointSecurityGroupId: "sg-secrets-endpoint",
  });
  const manifests: Record<string, any> = {};
  access.runtime.workloadManifest.apply((value) => {
    manifests.runtime = value;
    return value;
  });
  access.migration.workloadManifest.apply((value) => {
    manifests.migration = value;
    return value;
  });
  access.bootstrap.workloadManifest.apply((value) => {
    manifests.bootstrap = value;
    return value;
  });
  let handoff: any;
  materializeAwsDatabaseInfrastructureHandoff(binding.id, access).apply(
    (value) => {
      handoff = value;
      return value;
    },
  );

  await flushPulumiMocks();

  const associations = resourcesOfType(
    resources,
    "aws:eks/podIdentityAssociation:PodIdentityAssociation",
  );
  assert.equal(associations.length, 2);
  assert.deepEqual(
    associations
      .map((association) => ({
        accessClass: association.inputs.tags.AccessClass,
        namespace: association.inputs.namespace,
        serviceAccount: association.inputs.serviceAccount,
        disableSessionTags: association.inputs.disableSessionTags,
      }))
      .sort((left, right) => left.accessClass.localeCompare(right.accessClass)),
    [
      {
        accessClass: "migration",
        namespace: "codefly-db-migration-warden-saas-postgres-development",
        serviceAccount: "warden-saas-migration",
        disableSessionTags: false,
      },
      {
        accessClass: "runtime",
        namespace: "codefly-db-runtime-warden-saas-postgres-development",
        serviceAccount: "warden-saas-service",
        disableSessionTags: false,
      },
    ],
  );
  assert.equal(
    associations.some(
      (association) => association.inputs.tags.AccessClass === "bootstrap",
    ),
    false,
    "bootstrap Pod Identity association must require just-in-time authorization",
  );
  assert.equal(handoff.owner, "external-iac");
  assert.equal(handoff.authorizedConsumer, "infrastructure-controller");
  assert.equal(handoff.applicationMutationAllowed, false);
  const { handoffSpecDigest, ...handoffSubject } = handoff;
  assert.equal(
    handoffSpecDigest,
    awsDatabaseAccessBindingDigest(handoffSubject),
  );
  assert.deepEqual(handoff.deploymentAuthorization, {
    state: "pending-identity-binding",
    directPodCreationAllowed: false,
    namespaceWriteAccess: "exclusive-controller",
    allowedWorkloadKinds: {
      runtime: ["Deployment"],
      migration: ["Job"],
      bootstrap: ["Job"],
    },
    requiredActorEvidence: [
      "exact-controller-service-account",
      "exact-source-repository-and-path",
      "namespace-rbac-denial-matrix",
      "direct-pod-creation-denied",
    ],
  });
  assert.equal(handoff.readiness.state, "pending-application");
  assert.equal(handoff.readiness.reason, "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED");
  assert.equal(handoff.accessClasses.runtime.activationMode, "persistent");
  assert.match(
    handoff.accessClasses.runtime.podIdentityAssociationId,
    /associationId$/,
  );
  assert.equal(handoff.accessClasses.bootstrap.activationMode, "just-in-time");
  assert.equal(handoff.accessClasses.bootstrap.podIdentityAssociationId, null);
  for (const value of Object.values(handoff.accessClasses) as any[]) {
    assert.match(value.bindingDigest, /^[a-f0-9]{64}$/);
    assert.match(value.workloadBundleDigest, /^[a-f0-9]{64}$/);
    assert.equal(
      awsDatabaseAccessBindingDigest(value.manifests),
      value.workloadBundleDigest,
    );
  }

  const accessRoles = resourcesOfType(resources, "aws:iam/role:Role").filter(
    (role) => role.inputs.tags?.AccessClass,
  );
  assert.equal(accessRoles.length, 3);
  for (const role of accessRoles) {
    assert.match(role.inputs.name, /^deus-platform-dev-database-/);
    assert.equal(
      role.inputs.permissionsBoundary,
      testDatabaseIamRoleConstraint().permissionsBoundaryArn,
    );
    const trust = JSON.parse(role.inputs.assumeRolePolicy);
    assert.deepEqual(trust.Statement[0].Principal, {
      Service: "pods.eks.amazonaws.com",
    });
    assert.deepEqual(trust.Statement[0].Action, [
      "sts:AssumeRole",
      "sts:TagSession",
    ]);
    assert.equal(
      trust.Statement[0].Condition.StringEquals["aws:SourceOrgId"],
      "o-example123456",
    );
    assert.equal(
      trust.Statement[0].Condition.StringEquals[
        "aws:RequestTag/eks-cluster-arn"
      ],
      "arn:aws:eks:us-east-1:111111111111:cluster/platform-dev",
    );
    assert.equal(
      trust.Statement[0].Condition.StringEquals[
        "aws:RequestTag/kubernetes-namespace"
      ],
      role.inputs.tags.KubernetesNamespace,
    );
    assert.equal(
      trust.Statement[0].Condition.StringEquals[
        "aws:RequestTag/kubernetes-service-account"
      ],
      role.inputs.tags.KubernetesServiceAccount,
    );
  }

  const policies = resourcesOfType(resources, "aws:iam/rolePolicy:RolePolicy");
  const runtimePolicy = policies.find((policy) =>
    policy.name.includes("warden-saas-service-runtime-postgres-access"),
  );
  const migrationPolicy = policies.find((policy) =>
    policy.name.includes("warden-saas-migration-migration-postgres-access"),
  );
  const bootstrapPolicy = policies.find((policy) =>
    policy.name.includes(
      "warden-saas-postgres-bootstrap-bootstrap-postgres-access",
    ),
  );
  assert.ok(runtimePolicy);
  assert.ok(migrationPolicy);
  assert.ok(bootstrapPolicy);
  assert.match(
    runtimePolicy.inputs.policy,
    /dbuser:prx-0123456789abcdef0\/warden_saas_service/,
  );
  assert.match(
    migrationPolicy.inputs.policy,
    /dbuser:prx-0123456789abcdef0\/warden_saas_migration/,
  );
  assert.doesNotMatch(runtimePolicy.inputs.policy, /secretsmanager:|\/\*/);
  assert.doesNotMatch(migrationPolicy.inputs.policy, /secretsmanager:|\/\*/);
  assert.match(bootstrapPolicy.inputs.policy, /secretsmanager:GetSecretValue/);
  assert.match(bootstrapPolicy.inputs.policy, /kms:Decrypt/);
  assert.match(bootstrapPolicy.inputs.policy, /vpce-0123456789abcdef0/);
  assert.doesNotMatch(
    bootstrapPolicy.inputs.policy,
    /rds-db:connect|"Resource":"\*"/,
  );
  const endpointEgress = resourcesOfType(
    resources,
    "aws:vpc/securityGroupEgressRule:SecurityGroupEgressRule",
  ).find((rule) => rule.name.includes("bootstrap-to-secrets-manager-egress"));
  const endpointIngress = resourcesOfType(
    resources,
    "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule",
  ).find((rule) => rule.name.includes("bootstrap-to-secrets-manager-ingress"));
  assert.ok(endpointEgress);
  assert.ok(endpointIngress);
  assert.equal(endpointEgress.inputs.fromPort, 443);
  assert.equal(endpointEgress.inputs.toPort, 443);
  assert.equal(
    endpointEgress.inputs.referencedSecurityGroupId,
    "sg-secrets-endpoint",
  );
  assert.equal(endpointIngress.inputs.securityGroupId, "sg-secrets-endpoint");
  const bootstrapSecurityGroup = resourcesOfType(
    resources,
    "aws:ec2/securityGroup:SecurityGroup",
  ).find(
    (securityGroup) => securityGroup.inputs.tags?.AccessRole === "bootstrap",
  );
  assert.ok(bootstrapSecurityGroup);
  assert.equal(
    endpointIngress.inputs.referencedSecurityGroupId,
    `${bootstrapSecurityGroup.name}_id`,
  );

  assert.equal(
    new Set(
      Object.values(manifests).map(
        (manifest) => manifest.serviceAccount.metadata.namespace,
      ),
    ).size,
    3,
    "runtime, migration, and bootstrap identities require separate namespaces",
  );
  for (const [accessClass, manifest] of Object.entries(manifests)) {
    assert.equal(
      manifest.namespace.metadata.name,
      manifest.serviceAccount.metadata.namespace,
    );
    assert.equal(
      manifest.namespace.metadata.labels["pod-security.kubernetes.io/enforce"],
      "restricted",
    );
    assert.equal(
      manifest.namespace.metadata.labels[
        "security.deus.dev/database-access-class"
      ],
      accessClass,
    );
    assert.equal(manifest.serviceAccount.automountServiceAccountToken, false);
    assert.equal(
      "eks.amazonaws.com/role-arn" in
        manifest.serviceAccount.metadata.annotations,
      false,
    );
    assert.equal(
      manifest.serviceAccount.metadata.annotations[
        "security.deus.dev/workload-identity-mode"
      ],
      "eks-pod-identity",
    );
    assert.match(
      manifest.serviceAccount.metadata.annotations[
        "security.deus.dev/workload-identity-binding-digest"
      ],
      /^[a-f0-9]{64}$/,
    );
    assert.equal(manifest.admissionPolicy.spec.failurePolicy, "Fail");
    assert.equal(
      manifest.admissionPolicy.spec.validationFailureAction,
      "Enforce",
    );
    const admissionRule = manifest.admissionPolicy.spec.rules[0];
    assert.deepEqual(admissionRule.match.any[0].resources.namespaces, [
      manifest.namespace.metadata.name,
    ]);
    assert.equal(
      admissionRule.validate.message,
      "SEC_DATABASE_ACCESS_BINDING_DENIED",
    );
    assert.equal(
      admissionRule.validate.pattern.spec.serviceAccountName,
      manifest.serviceAccount.metadata.name,
    );
    assert.equal(
      admissionRule.validate.pattern.spec.automountServiceAccountToken,
      false,
    );
    assert.deepEqual(
      admissionRule.validate.pattern.metadata.labels,
      manifest.requiredPodLabels,
    );
    assert.deepEqual(
      admissionRule.validate.pattern.metadata.annotations,
      manifest.requiredPodAnnotations,
    );
    assert.deepEqual(
      admissionRule.validate.pattern.spec.nodeSelector,
      manifest.requiredPodScheduling.nodeSelector,
    );
    assert.deepEqual(
      admissionRule.validate.pattern.spec["^(tolerations)"],
      manifest.requiredPodScheduling.tolerations,
    );
    assert.equal(
      manifest.admissionPolicy.metadata.annotations[
        "pod-policies.kyverno.io/autogen-controllers"
      ],
      "none",
    );
    const reservationRule = manifest.admissionPolicy.spec.rules.find(
      (rule: any) => rule.name === "reserve-database-node-pool",
    );
    assert.ok(reservationRule);
    assert.equal(
      reservationRule.match.any[0].resources.namespaces,
      undefined,
      "database NodePool reservation must match Pods cluster-wide",
    );
    assert.equal(
      reservationRule.preconditions.any[0].value,
      Object.values(manifest.requiredPodScheduling.nodeSelector)[0],
    );
    assert.equal(
      reservationRule.validate.message,
      "SEC_DATABASE_NODE_POOL_RESERVED",
    );
    assert.equal(
      reservationRule.validate.deny.conditions.all[0].value,
      manifest.namespace.metadata.name,
    );
    const ownerRule = manifest.admissionPolicy.spec.rules.find(
      (rule: any) => rule.name === "require-database-pod-controller-owner",
    );
    assert.ok(ownerRule);
    assert.equal(
      ownerRule.validate.pattern.metadata.ownerReferences[0].kind,
      accessClass === "runtime" ? "ReplicaSet" : "Job",
    );
    assert.equal(ownerRule.validate.message, "SEC_DATABASE_POD_OWNER_DENIED");
    const kindRule = manifest.admissionPolicy.spec.rules.find(
      (rule: any) => rule.name === "restrict-database-workload-kind",
    );
    assert.ok(kindRule);
    assert.equal(
      kindRule.match.any[0].resources.kinds.includes(
        accessClass === "runtime" ? "Job" : "Deployment",
      ),
      true,
    );
    assert.equal(
      kindRule.validate.message,
      "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    );
    assert.equal(manifest.nodeClass.apiVersion, "eks.amazonaws.com/v1");
    assert.equal(manifest.nodeClass.kind, "NodeClass");
    assert.equal(manifest.nodeClass.spec.role, "platform-auto-node-role");
    assert.deepEqual(manifest.nodeClass.spec.subnetSelectorTerms, [
      { id: "subnet-a" },
      { id: "subnet-b" },
      { id: "subnet-c" },
    ]);
    assert.deepEqual(manifest.nodeClass.spec.podSubnetSelectorTerms, [
      { id: "subnet-a" },
      { id: "subnet-b" },
      { id: "subnet-c" },
    ]);
    assert.deepEqual(manifest.nodeClass.spec.securityGroupSelectorTerms, [
      { tags: { "aws:eks:cluster-name": "platform-dev" } },
    ]);
    assert.equal(
      manifest.nodeClass.spec.podSecurityGroupSelectorTerms.length,
      1,
    );
    assert.match(
      manifest.nodeClass.spec.podSecurityGroupSelectorTerms[0].id,
      /_id$/,
    );
    assert.equal(manifest.nodeClass.spec.networkPolicy, "DefaultDeny");
    assert.equal(manifest.nodeClass.spec.networkPolicyEventLogs, "Enabled");
    assert.equal(manifest.nodeClass.spec.snatPolicy, "Disabled");
    assert.equal(
      manifest.nodeClass.spec.advancedNetworking.associatePublicIPAddress,
      false,
    );
    assert.equal(manifest.nodePool.apiVersion, "karpenter.sh/v1");
    assert.equal(manifest.nodePool.kind, "NodePool");
    assert.deepEqual(manifest.nodePool.spec.template.spec.nodeClassRef, {
      group: "eks.amazonaws.com",
      kind: "NodeClass",
      name: manifest.nodeClass.metadata.name,
    });
    assert.equal(
      manifest.nodePool.spec.template.spec.requirements.some(
        ({ key }: any) => key === "kubernetes.io/os",
      ),
      false,
      "EKS Auto Mode does not support kubernetes.io/os as a NodePool requirement",
    );
    assert.deepEqual(
      manifest.nodePool.spec.template.metadata.labels,
      manifest.requiredPodScheduling.nodeSelector,
    );
    assert.deepEqual(
      manifest.applicationNetworkPolicy.spec.podSelector.matchLabels,
      manifest.requiredPodLabels,
    );
    assert.deepEqual(manifest.applicationNetworkPolicy.spec.policyTypes, [
      "Ingress",
      "Egress",
    ]);
    assert.deepEqual(manifest.applicationNetworkPolicy.spec.ingress, []);
    const identityAgentRules =
      manifest.applicationNetworkPolicy.spec.egress.filter(
        (rule: any) => rule.to[0]?.ipBlock?.cidr === "169.254.170.23/32",
      );
    assert.deepEqual(identityAgentRules, [
      {
        to: [{ ipBlock: { cidr: "169.254.170.23/32" } }],
        ports: [{ protocol: "TCP", port: 80 }],
      },
    ]);
    const domainRules = manifest.applicationNetworkPolicy.spec.egress.filter(
      (rule: any) => rule.to[0]?.domainNames,
    );
    assert.equal(domainRules.length, accessClass === "bootstrap" ? 2 : 1);
    for (const rule of domainRules) {
      assert.equal(rule.to[0].domainNames.length, 1);
      assert.doesNotMatch(rule.to[0].domainNames[0], /\*/);
    }
    assert.equal(
      domainRules.some((rule: any) =>
        rule.to[0].domainNames.includes(
          "secretsmanager.us-east-1.amazonaws.com",
        ),
      ),
      accessClass === "bootstrap",
    );
    assert.deepEqual(
      manifest.nodePool.spec.template.spec.taints.map(
        ({ key, value, effect }: any) => ({ key, value, effect }),
      ),
      manifest.requiredPodScheduling.tolerations.map(
        ({ key, value, effect }: any) => ({ key, value, effect }),
      ),
    );
    assert.equal(
      JSON.stringify(manifest).includes("SecurityGroupPolicy"),
      false,
      `${accessClass} manifest must use the EKS Auto Mode NodeClass network attachment`,
    );
    assert.equal(
      JSON.stringify(manifest).includes("password"),
      false,
      `${accessClass} manifest must not contain a password`,
    );
    assert.equal(
      /tokenValue|accessToken|bearerToken/i.test(JSON.stringify(manifest)),
      false,
      `${accessClass} manifest must not contain token material`,
    );
  }
});

test("managed PostgreSQL access rejects weak identity bindings before creating access roles", async () => {
  const { resources } = await installPulumiMocks();
  const { createDatabaseCluster } = await import("../src/database");
  const {
    compileAwsEksPodIdentityTrustPolicy,
    createAwsManagedPostgresAccess,
  } = await import("../src/databaseAccess");
  const database = createDatabaseCluster({
    iamRoleConstraint: testDatabaseIamRoleConstraint(),
    config: {
      name: "warden-reject",
      engine: "aurora-postgresql",
      engineVersion: "16.4",
      engineMajorVersion: "16",
      databaseName: "warden",
      masterUsername: "warden_admin",
      port: 5432,
      instanceClass: "db.r6g.large",
      instanceCount: 1,
      backupRetentionDays: 14,
      deletionProtection: true,
      createProxy: true,
    },
    vpcId: "vpc-test",
    privateSubnetIds: ["subnet-a", "subnet-b"],
    databaseIdentityUsers: {
      runtime: "wrong_runtime_user",
      migration: "warden_saas_migration",
    },
  });

  assert.throws(
    () =>
      createAwsManagedPostgresAccess({
        iamRoleConstraint: testDatabaseIamRoleConstraint(),
        organizationId: "o-example123456",
        environment: "development",
        clusterName: "platform-dev",
        clusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/platform-dev",
        nodeRoleName: "platform-auto-node-role",
        podSubnetIds: ["subnet-a", "subnet-b"],
        binding,
        database,
        secretsManagerVpcEndpointId: "vpce-0123456789abcdef0",
        secretsManagerVpcEndpointSecurityGroupId: "sg-secrets-endpoint",
      }),
    /database users do not match/,
  );
  assert.equal(
    resourcesOfType(resources, "aws:iam/role:Role").filter(
      (role) => role.inputs.tags?.AccessClass,
    ).length,
    0,
  );
  assert.throws(
    () =>
      compileAwsEksPodIdentityTrustPolicy({
        organizationId: "*",
        clusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/platform-dev",
        namespace: "warden",
        serviceAccount: "runtime",
      }),
    /one exact AWS Organizations ID/,
  );
  assert.throws(
    () =>
      compileAwsEksPodIdentityTrustPolicy({
        organizationId: "o-example123456",
        clusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/platform-dev",
        namespace: "warden/other",
        serviceAccount: "runtime",
      }),
    /exact DNS-safe/,
  );
  assert.throws(
    () =>
      compileAwsEksPodIdentityTrustPolicy({
        organizationId: "o-example123456",
        clusterArn: "arn:aws:eks:us-east-1:111111111111:cluster/*",
        namespace: "warden",
        serviceAccount: "runtime",
      }),
    /one exact EKS cluster ARN/,
  );
});
