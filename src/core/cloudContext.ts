import { createHash } from "node:crypto";
import type { ManagedPostgresIntent } from "./managedPostgres";
import type {
  PlatformBlueprint,
  RuntimeIsolation,
  WorkloadOrchestrator,
} from "./model";
import { assertBlueprint } from "./policy";

export const CLOUD_CONTEXT_API_VERSION =
  "security.deus.dev/cloud-context/v1alpha1" as const;

export type CloudContextEnvironment = "development" | "staging" | "production";

export interface CloudContextStatus {
  phase: "planned" | "ready" | "degraded" | "unavailable";
  generation: number;
  observedGeneration: number;
  verifiedAt: string | null;
  evidenceRef: string | null;
}

export interface CloudRuntimeCapability {
  id: string;
  workloadPlaneIds: readonly string[];
  orchestrator: WorkloadOrchestrator;
  executionTrust: "trusted" | "semi-trusted" | "untrusted";
  runtimeIsolation: RuntimeIsolation;
  credentialMode: "workload-identity" | "brokered";
  privateControlPlane: true;
  workloadIdentity: true;
  directHostAccess: false;
  reference: string;
}

export interface CloudNetworkCapability {
  id: string;
  networkDomainIds: readonly string[];
  private: true;
  directInternetAccess: false;
  inspectedEgress: true;
  brokeredEgress: true;
  reference: string;
}

export interface CloudRegistryCapability {
  id: string;
  immutableDigestsOnly: true;
  signatureVerification: true;
  provenanceVerification: true;
  reference: string;
}

export interface CloudDnsCapability {
  id: string;
  visibility: "private" | "public";
  managedRecordsOnly: true;
  reference: string;
}

export interface CloudIdentityCapability {
  id: string;
  mode: "workload-identity";
  allowedIdentityIds: readonly string[];
  shortLived: true;
  administrator: false;
  maxSessionMinutes: number;
  reference: string;
}

export interface CloudObservabilityCapability {
  id: string;
  immutableAudit: true;
  auditRetentionDays: number;
  auditRef: string;
  logsRef: string;
  metricsRef: string;
  tracesRef: string;
}

export interface CloudManagedPostgresBinding {
  id: string;
  kind: "ManagedPostgres";
  lifecycle: "pre-provisioned";
  applicationId: string;
  componentId: string;
  serviceRef: string;
  dataBoundaryId: string;
  providerResourceRef: string;
  network: {
    runtimeBoundaryId: string;
    migrationBoundaryId: string;
    separateBoundaries: true;
    allowNetworkCidr: false;
  };
  identities: {
    runtimeIdentityId: string;
    migrationIdentityId: string;
    separate: true;
  };
  outputs: {
    endpointRef: string;
    port: 5432;
    databaseName: string;
    caBundleRef: string;
    runtimeIdentityRef: string;
    migrationIdentityRef: string;
    credentialValue: null;
  };
  status: CloudContextStatus;
}

export interface CloudContext {
  id: string;
  environment: CloudContextEnvironment;
  provider: {
    kind: "aws" | "gcp" | "azure";
    boundaryRef: string;
    location: string;
  };
  provisioning: {
    mode: "pre-provisioned";
    owner: "external-iac";
    physicalMutationFromCodefly: false;
  };
  posture: {
    privateNetworking: true;
    inspectedEgress: true;
    immutableAudit: true;
    credentialDelivery: "reference-only";
    directProviderCredentials: false;
  };
  capabilities: {
    runtimes: readonly CloudRuntimeCapability[];
    networks: readonly CloudNetworkCapability[];
    registries: readonly CloudRegistryCapability[];
    dns: readonly CloudDnsCapability[];
    identities: readonly CloudIdentityCapability[];
    observability: readonly CloudObservabilityCapability[];
  };
  resourceBindings: readonly CloudManagedPostgresBinding[];
  status: CloudContextStatus;
}

export interface CloudContextPlacement {
  applicationId: string;
  componentId: string;
  contextId: string;
  runtimeCapabilityId: string;
  networkCapabilityId: string;
  registryCapabilityId: string;
  identityCapabilityId: string;
  observabilityCapabilityId: string;
  dnsCapabilityIds: readonly string[];
  resourceBindingIds: readonly string[];
  delegatedRuntimes: readonly {
    contextId: string;
    runtimeCapabilityId: string;
    purpose: "customer-code-execution";
  }[];
}

export interface CloudContextCatalog {
  apiVersion: typeof CLOUD_CONTEXT_API_VERSION;
  kind: "CloudContextCatalog";
  name: string;
  environment: CloudContextEnvironment;
  contexts: readonly CloudContext[];
  placements: readonly CloudContextPlacement[];
}

export function parseCloudContextCatalog(
  value: unknown,
  blueprint?: PlatformBlueprint,
  managedPostgres?: ManagedPostgresIntent,
): CloudContextCatalog {
  const root = objectValue(value, "cloudContextCatalog", [
    "apiVersion",
    "kind",
    "name",
    "environment",
    "contexts",
    "placements",
  ]);
  const catalog: CloudContextCatalog = {
    apiVersion: literalValue(
      root.apiVersion,
      "apiVersion",
      CLOUD_CONTEXT_API_VERSION,
    ),
    kind: literalValue(root.kind, "kind", "CloudContextCatalog"),
    name: nameValue(root.name, "name"),
    environment: enumValue(root.environment, "environment", [
      "development",
      "staging",
      "production",
    ]),
    contexts: arrayValue(root.contexts, "contexts", parseContext),
    placements: arrayValue(root.placements, "placements", parsePlacement),
  };
  assertCloudContextCatalog(catalog, blueprint, managedPostgres);
  return catalog;
}

export function assertCloudContextCatalog(
  catalog: CloudContextCatalog,
  blueprint?: PlatformBlueprint,
  managedPostgres?: ManagedPostgresIntent,
): void {
  if (catalog.contexts.length === 0) {
    throw new Error("Cloud context catalog requires at least one context.");
  }
  const contexts = uniqueMap(catalog.contexts, "cloud context");
  const allBindings = new Map<string, CloudManagedPostgresBinding>();
  const bindingContexts = new Map<string, string>();
  for (const context of catalog.contexts) {
    if (context.environment !== catalog.environment) {
      throw new Error(
        `Cloud context '${context.id}' environment does not match the catalog.`,
      );
    }
    assertStatus(context.status, `cloud context '${context.id}'`);
    for (const [kind, capabilities] of Object.entries(context.capabilities)) {
      if (capabilities.length === 0) {
        throw new Error(
          `Cloud context '${context.id}' requires at least one ${kind} capability.`,
        );
      }
    }
    const runtimes = uniqueMap(
      context.capabilities.runtimes,
      `runtime capability in '${context.id}'`,
    );
    uniqueMap(
      context.capabilities.networks,
      `network capability in '${context.id}'`,
    );
    uniqueMap(
      context.capabilities.registries,
      `registry capability in '${context.id}'`,
    );
    uniqueMap(context.capabilities.dns, `DNS capability in '${context.id}'`);
    uniqueMap(
      context.capabilities.identities,
      `identity capability in '${context.id}'`,
    );
    uniqueMap(
      context.capabilities.observability,
      `observability capability in '${context.id}'`,
    );
    for (const runtime of runtimes.values()) {
      if (
        runtime.executionTrust === "untrusted" &&
        runtime.credentialMode !== "brokered"
      ) {
        throw new Error(
          `Cloud context runtime '${context.id}/${runtime.id}' must broker credentials for untrusted execution.`,
        );
      }
      if (
        runtime.executionTrust === "untrusted" &&
        runtime.runtimeIsolation !== "microvm" &&
        runtime.runtimeIsolation !== "dedicated-vm"
      ) {
        throw new Error(
          `Cloud context runtime '${context.id}/${runtime.id}' has weak isolation for untrusted execution.`,
        );
      }
    }
    for (const binding of context.resourceBindings) {
      if (allBindings.has(binding.id)) {
        throw new Error(
          `Cloud context resource binding '${binding.id}' is duplicated.`,
        );
      }
      assertStatus(binding.status, `resource binding '${binding.id}'`);
      if (
        binding.identities.runtimeIdentityId ===
        binding.identities.migrationIdentityId
      ) {
        throw new Error(
          `Cloud context resource binding '${binding.id}' must separate runtime and migration identities.`,
        );
      }
      if (
        binding.network.runtimeBoundaryId ===
        binding.network.migrationBoundaryId
      ) {
        throw new Error(
          `Cloud context resource binding '${binding.id}' must separate runtime and migration network boundaries.`,
        );
      }
      allBindings.set(binding.id, binding);
      bindingContexts.set(binding.id, context.id);
    }
  }

  const placementKeys = new Set<string>();
  const usedBindings = new Set<string>();
  for (const placement of catalog.placements) {
    const key = `${placement.applicationId}/${placement.componentId}`;
    if (placementKeys.has(key)) {
      throw new Error(`Cloud context placement '${key}' is duplicated.`);
    }
    placementKeys.add(key);
    const context = contexts.get(placement.contextId);
    if (!context) {
      throw new Error(
        `Cloud context placement '${key}' references unknown context '${placement.contextId}'.`,
      );
    }
    const runtime = requireCapability(
      context.capabilities.runtimes,
      placement.runtimeCapabilityId,
      key,
      "runtime",
    );
    requireCapability(
      context.capabilities.networks,
      placement.networkCapabilityId,
      key,
      "network",
    );
    requireCapability(
      context.capabilities.registries,
      placement.registryCapabilityId,
      key,
      "registry",
    );
    const identity = requireCapability(
      context.capabilities.identities,
      placement.identityCapabilityId,
      key,
      "identity",
    );
    requireCapability(
      context.capabilities.observability,
      placement.observabilityCapabilityId,
      key,
      "observability",
    );
    for (const dnsId of placement.dnsCapabilityIds) {
      requireCapability(context.capabilities.dns, dnsId, key, "DNS");
    }
    for (const bindingId of placement.resourceBindingIds) {
      const binding = allBindings.get(bindingId);
      if (!binding) {
        throw new Error(
          `Cloud context placement '${key}' references unknown resource binding '${bindingId}'.`,
        );
      }
      if (
        binding.applicationId !== placement.applicationId ||
        binding.componentId !== placement.componentId
      ) {
        throw new Error(
          `Cloud context placement '${key}' cannot consume resource binding '${bindingId}' owned by '${binding.applicationId}/${binding.componentId}'.`,
        );
      }
      if (bindingContexts.get(bindingId) !== placement.contextId) {
        throw new Error(
          `CLOUD_BINDING_CONTEXT_MISMATCH: Cloud context placement '${key}' cannot consume resource binding '${bindingId}' from context '${bindingContexts.get(bindingId)}'.`,
        );
      }
      if (usedBindings.has(bindingId)) {
        throw new Error(
          `Cloud context resource binding '${bindingId}' is assigned more than once.`,
        );
      }
      usedBindings.add(bindingId);
    }
    for (const delegated of placement.delegatedRuntimes) {
      const delegatedContext = contexts.get(delegated.contextId);
      if (!delegatedContext) {
        throw new Error(
          `Cloud context placement '${key}' delegates to unknown context '${delegated.contextId}'.`,
        );
      }
      const delegatedRuntime = requireCapability(
        delegatedContext.capabilities.runtimes,
        delegated.runtimeCapabilityId,
        key,
        "delegated runtime",
      );
      if (
        delegatedRuntime.executionTrust !== "untrusted" ||
        delegatedRuntime.credentialMode !== "brokered" ||
        (delegatedRuntime.runtimeIsolation !== "microvm" &&
          delegatedRuntime.runtimeIsolation !== "dedicated-vm")
      ) {
        throw new Error(
          `Cloud context placement '${key}' delegates customer code to an unsafe runtime.`,
        );
      }
    }
    if (runtime.executionTrust === "untrusted") {
      throw new Error(
        `Cloud context placement '${key}' cannot run an application control service on an untrusted runtime.`,
      );
    }
    if (identity.administrator) {
      throw new Error(
        `Cloud context placement '${key}' cannot use an administrator identity capability.`,
      );
    }
  }
  if (usedBindings.size !== allBindings.size) {
    const unused = [...allBindings.keys()].filter(
      (binding) => !usedBindings.has(binding),
    );
    throw new Error(
      `Cloud context resource binding(s) are not placed: ${unused.sort().join(", ")}.`,
    );
  }

  if (blueprint) {
    assertBlueprint(blueprint);
    assertBlueprintPlacements(catalog, blueprint, contexts);
  }
  if (managedPostgres) {
    assertManagedPostgresBindings(catalog, managedPostgres, allBindings);
  }
}

export function assertDeployableCloudContextCatalog(
  catalog: CloudContextCatalog,
  blueprint?: PlatformBlueprint,
  managedPostgres?: ManagedPostgresIntent,
): void {
  assertCloudContextCatalog(catalog, blueprint, managedPostgres);
  for (const context of catalog.contexts) {
    assertReadyStatus(context.status, `cloud context '${context.id}'`);
    for (const binding of context.resourceBindings) {
      assertReadyStatus(binding.status, `resource binding '${binding.id}'`);
    }
  }
}

export function cloudContextCatalogDigest(
  catalog: CloudContextCatalog,
): string {
  assertCloudContextCatalog(catalog);
  return createHash("sha256").update(stableJson(catalog)).digest("hex");
}

function assertBlueprintPlacements(
  catalog: CloudContextCatalog,
  blueprint: PlatformBlueprint,
  contexts: Map<string, CloudContext>,
) {
  const expected = new Map(
    blueprint.applications.flatMap((application) =>
      application.components.map(
        (component) =>
          [
            `${application.id}/${component.id}`,
            { application, component },
          ] as const,
      ),
    ),
  );
  const observed = new Set(
    catalog.placements.map(
      (placement) => `${placement.applicationId}/${placement.componentId}`,
    ),
  );
  if (
    expected.size !== observed.size ||
    [...expected.keys()].some((key) => !observed.has(key))
  ) {
    throw new Error(
      `Cloud context placements must exactly cover blueprint components; expected [${[...expected.keys()].sort().join(", ")}], observed [${[...observed].sort().join(", ")}].`,
    );
  }
  for (const placement of catalog.placements) {
    const target = expected.get(
      `${placement.applicationId}/${placement.componentId}`,
    )!;
    const context = contexts.get(placement.contextId)!;
    const runtime = context.capabilities.runtimes.find(
      (candidate) => candidate.id === placement.runtimeCapabilityId,
    )!;
    if (!runtime.workloadPlaneIds.includes(target.component.workloadPlaneId)) {
      throw new Error(
        `Cloud context placement '${placement.applicationId}/${placement.componentId}' runtime does not support workload plane '${target.component.workloadPlaneId}'.`,
      );
    }
    const identity = context.capabilities.identities.find(
      (candidate) => candidate.id === placement.identityCapabilityId,
    )!;
    if (
      !identity.allowedIdentityIds.includes(target.component.serviceIdentityId)
    ) {
      throw new Error(
        `Cloud context placement '${placement.applicationId}/${placement.componentId}' identity capability does not allow '${target.component.serviceIdentityId}'.`,
      );
    }
  }
}

function assertManagedPostgresBindings(
  catalog: CloudContextCatalog,
  intent: ManagedPostgresIntent,
  bindings: Map<string, CloudManagedPostgresBinding>,
) {
  if (intent.environment !== catalog.environment) {
    throw new Error(
      "Cloud context catalog and Managed Postgres intent environments must match.",
    );
  }
  const expected = new Set(intent.bindings.map((binding) => binding.id));
  if (
    expected.size !== bindings.size ||
    [...expected].some((binding) => !bindings.has(binding))
  ) {
    throw new Error(
      `Cloud context Managed Postgres bindings must exactly match intent; expected [${[...expected].sort().join(", ")}], observed [${[...bindings.keys()].sort().join(", ")}].`,
    );
  }
  for (const intentBinding of intent.bindings) {
    const binding = bindings.get(intentBinding.id)!;
    const expectedService = `${intentBinding.codefly.workspace}/${intentBinding.codefly.module}/${intentBinding.codefly.service}`;
    if (
      binding.applicationId !== intentBinding.tenantId ||
      binding.componentId !== intentBinding.codefly.module ||
      binding.serviceRef !== expectedService ||
      binding.dataBoundaryId !== intentBinding.dataBoundaryId ||
      binding.network.runtimeBoundaryId !==
        intentBinding.access.networkAccess.runtimeBoundaryId ||
      binding.network.migrationBoundaryId !==
        intentBinding.access.networkAccess.migrationBoundaryId ||
      binding.identities.runtimeIdentityId !==
        intentBinding.access.runtimeIdentityId ||
      binding.identities.migrationIdentityId !==
        intentBinding.access.migrationIdentityId ||
      binding.outputs.databaseName !== intentBinding.database.name
    ) {
      throw new Error(
        `Cloud context resource binding '${binding.id}' does not match its Managed Postgres intent.`,
      );
    }
  }
}

function assertStatus(status: CloudContextStatus, label: string) {
  if (
    !Number.isInteger(status.generation) ||
    status.generation < 1 ||
    !Number.isInteger(status.observedGeneration) ||
    status.observedGeneration < 0 ||
    status.observedGeneration > status.generation
  ) {
    throw new Error(`${label} has an invalid observed generation.`);
  }
  if (status.phase === "planned") {
    if (
      status.observedGeneration !== 0 ||
      status.verifiedAt !== null ||
      status.evidenceRef !== null
    ) {
      throw new Error(`${label} planned status cannot claim verification.`);
    }
    return;
  }
  if (
    status.observedGeneration < 1 ||
    !status.verifiedAt ||
    !status.evidenceRef
  ) {
    throw new Error(`${label} observed status requires verification evidence.`);
  }
  isoTimestamp(status.verifiedAt, `${label}.verifiedAt`);
  referenceValue(status.evidenceRef, `${label}.evidenceRef`);
}

function assertReadyStatus(status: CloudContextStatus, label: string) {
  if (
    status.phase !== "ready" ||
    status.observedGeneration !== status.generation ||
    !status.verifiedAt ||
    !status.evidenceRef
  ) {
    throw new Error(`${label} is not deployable and fully observed.`);
  }
}

function parseContext(value: unknown, path: string): CloudContext {
  const input = objectValue(value, path, [
    "id",
    "environment",
    "provider",
    "provisioning",
    "posture",
    "capabilities",
    "resourceBindings",
    "status",
  ]);
  const provider = objectValue(input.provider, `${path}.provider`, [
    "kind",
    "boundaryRef",
    "location",
  ]);
  const provisioning = objectValue(input.provisioning, `${path}.provisioning`, [
    "mode",
    "owner",
    "physicalMutationFromCodefly",
  ]);
  const posture = objectValue(input.posture, `${path}.posture`, [
    "privateNetworking",
    "inspectedEgress",
    "immutableAudit",
    "credentialDelivery",
    "directProviderCredentials",
  ]);
  const capabilities = objectValue(input.capabilities, `${path}.capabilities`, [
    "runtimes",
    "networks",
    "registries",
    "dns",
    "identities",
    "observability",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    environment: enumValue(input.environment, `${path}.environment`, [
      "development",
      "staging",
      "production",
    ]),
    provider: {
      kind: enumValue(provider.kind, `${path}.provider.kind`, [
        "aws",
        "gcp",
        "azure",
      ]),
      boundaryRef: referenceValue(
        provider.boundaryRef,
        `${path}.provider.boundaryRef`,
      ),
      location: locationValue(provider.location, `${path}.provider.location`),
    },
    provisioning: {
      mode: literalValue(
        provisioning.mode,
        `${path}.provisioning.mode`,
        "pre-provisioned",
      ),
      owner: literalValue(
        provisioning.owner,
        `${path}.provisioning.owner`,
        "external-iac",
      ),
      physicalMutationFromCodefly: falseValue(
        provisioning.physicalMutationFromCodefly,
        `${path}.provisioning.physicalMutationFromCodefly`,
      ),
    },
    posture: {
      privateNetworking: trueValue(
        posture.privateNetworking,
        `${path}.posture.privateNetworking`,
      ),
      inspectedEgress: trueValue(
        posture.inspectedEgress,
        `${path}.posture.inspectedEgress`,
      ),
      immutableAudit: trueValue(
        posture.immutableAudit,
        `${path}.posture.immutableAudit`,
      ),
      credentialDelivery: literalValue(
        posture.credentialDelivery,
        `${path}.posture.credentialDelivery`,
        "reference-only",
      ),
      directProviderCredentials: falseValue(
        posture.directProviderCredentials,
        `${path}.posture.directProviderCredentials`,
      ),
    },
    capabilities: {
      runtimes: arrayValue(
        capabilities.runtimes,
        `${path}.capabilities.runtimes`,
        parseRuntime,
      ),
      networks: arrayValue(
        capabilities.networks,
        `${path}.capabilities.networks`,
        parseNetwork,
      ),
      registries: arrayValue(
        capabilities.registries,
        `${path}.capabilities.registries`,
        parseRegistry,
      ),
      dns: arrayValue(capabilities.dns, `${path}.capabilities.dns`, parseDns),
      identities: arrayValue(
        capabilities.identities,
        `${path}.capabilities.identities`,
        parseIdentity,
      ),
      observability: arrayValue(
        capabilities.observability,
        `${path}.capabilities.observability`,
        parseObservability,
      ),
    },
    resourceBindings: arrayValue(
      input.resourceBindings,
      `${path}.resourceBindings`,
      parseResourceBinding,
    ),
    status: parseStatus(input.status, `${path}.status`),
  };
}

function parseRuntime(value: unknown, path: string): CloudRuntimeCapability {
  const input = objectValue(value, path, [
    "id",
    "workloadPlaneIds",
    "orchestrator",
    "executionTrust",
    "runtimeIsolation",
    "credentialMode",
    "privateControlPlane",
    "workloadIdentity",
    "directHostAccess",
    "reference",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    workloadPlaneIds: stringArray(
      input.workloadPlaneIds,
      `${path}.workloadPlaneIds`,
    ),
    orchestrator: enumValue(input.orchestrator, `${path}.orchestrator`, [
      "managed-kubernetes",
      "serverless",
      "microvm",
      "external-sandbox",
    ]),
    executionTrust: enumValue(input.executionTrust, `${path}.executionTrust`, [
      "trusted",
      "semi-trusted",
      "untrusted",
    ]),
    runtimeIsolation: enumValue(
      input.runtimeIsolation,
      `${path}.runtimeIsolation`,
      ["process", "container", "microvm", "dedicated-vm"],
    ),
    credentialMode: enumValue(input.credentialMode, `${path}.credentialMode`, [
      "workload-identity",
      "brokered",
    ]),
    privateControlPlane: trueValue(
      input.privateControlPlane,
      `${path}.privateControlPlane`,
    ),
    workloadIdentity: trueValue(
      input.workloadIdentity,
      `${path}.workloadIdentity`,
    ),
    directHostAccess: falseValue(
      input.directHostAccess,
      `${path}.directHostAccess`,
    ),
    reference: referenceValue(input.reference, `${path}.reference`),
  };
}

function parseNetwork(value: unknown, path: string): CloudNetworkCapability {
  const input = objectValue(value, path, [
    "id",
    "networkDomainIds",
    "private",
    "directInternetAccess",
    "inspectedEgress",
    "brokeredEgress",
    "reference",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    networkDomainIds: stringArray(
      input.networkDomainIds,
      `${path}.networkDomainIds`,
    ),
    private: trueValue(input.private, `${path}.private`),
    directInternetAccess: falseValue(
      input.directInternetAccess,
      `${path}.directInternetAccess`,
    ),
    inspectedEgress: trueValue(
      input.inspectedEgress,
      `${path}.inspectedEgress`,
    ),
    brokeredEgress: trueValue(input.brokeredEgress, `${path}.brokeredEgress`),
    reference: referenceValue(input.reference, `${path}.reference`),
  };
}

function parseRegistry(value: unknown, path: string): CloudRegistryCapability {
  const input = objectValue(value, path, [
    "id",
    "immutableDigestsOnly",
    "signatureVerification",
    "provenanceVerification",
    "reference",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    immutableDigestsOnly: trueValue(
      input.immutableDigestsOnly,
      `${path}.immutableDigestsOnly`,
    ),
    signatureVerification: trueValue(
      input.signatureVerification,
      `${path}.signatureVerification`,
    ),
    provenanceVerification: trueValue(
      input.provenanceVerification,
      `${path}.provenanceVerification`,
    ),
    reference: referenceValue(input.reference, `${path}.reference`),
  };
}

function parseDns(value: unknown, path: string): CloudDnsCapability {
  const input = objectValue(value, path, [
    "id",
    "visibility",
    "managedRecordsOnly",
    "reference",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    visibility: enumValue(input.visibility, `${path}.visibility`, [
      "private",
      "public",
    ]),
    managedRecordsOnly: trueValue(
      input.managedRecordsOnly,
      `${path}.managedRecordsOnly`,
    ),
    reference: referenceValue(input.reference, `${path}.reference`),
  };
}

function parseIdentity(value: unknown, path: string): CloudIdentityCapability {
  const input = objectValue(value, path, [
    "id",
    "mode",
    "allowedIdentityIds",
    "shortLived",
    "administrator",
    "maxSessionMinutes",
    "reference",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    mode: literalValue(input.mode, `${path}.mode`, "workload-identity"),
    allowedIdentityIds: stringArray(
      input.allowedIdentityIds,
      `${path}.allowedIdentityIds`,
    ),
    shortLived: trueValue(input.shortLived, `${path}.shortLived`),
    administrator: falseValue(input.administrator, `${path}.administrator`),
    maxSessionMinutes: integerValue(
      input.maxSessionMinutes,
      `${path}.maxSessionMinutes`,
      1,
      60,
    ),
    reference: referenceValue(input.reference, `${path}.reference`),
  };
}

function parseObservability(
  value: unknown,
  path: string,
): CloudObservabilityCapability {
  const input = objectValue(value, path, [
    "id",
    "immutableAudit",
    "auditRetentionDays",
    "auditRef",
    "logsRef",
    "metricsRef",
    "tracesRef",
  ]);
  return {
    id: nameValue(input.id, `${path}.id`),
    immutableAudit: trueValue(input.immutableAudit, `${path}.immutableAudit`),
    auditRetentionDays: integerValue(
      input.auditRetentionDays,
      `${path}.auditRetentionDays`,
      365,
      3650,
    ),
    auditRef: referenceValue(input.auditRef, `${path}.auditRef`),
    logsRef: referenceValue(input.logsRef, `${path}.logsRef`),
    metricsRef: referenceValue(input.metricsRef, `${path}.metricsRef`),
    tracesRef: referenceValue(input.tracesRef, `${path}.tracesRef`),
  };
}

function parseResourceBinding(
  value: unknown,
  path: string,
): CloudManagedPostgresBinding {
  const input = objectValue(value, path, [
    "id",
    "kind",
    "lifecycle",
    "applicationId",
    "componentId",
    "serviceRef",
    "dataBoundaryId",
    "providerResourceRef",
    "network",
    "identities",
    "outputs",
    "status",
  ]);
  const network = objectValue(input.network, `${path}.network`, [
    "runtimeBoundaryId",
    "migrationBoundaryId",
    "separateBoundaries",
    "allowNetworkCidr",
  ]);
  const identities = objectValue(input.identities, `${path}.identities`, [
    "runtimeIdentityId",
    "migrationIdentityId",
    "separate",
  ]);
  const outputs = objectValue(input.outputs, `${path}.outputs`, [
    "endpointRef",
    "port",
    "databaseName",
    "caBundleRef",
    "runtimeIdentityRef",
    "migrationIdentityRef",
    "credentialValue",
  ]);
  if (outputs.credentialValue !== null) {
    throw new Error(`${path}.outputs.credentialValue must be null.`);
  }
  return {
    id: nameValue(input.id, `${path}.id`),
    kind: literalValue(input.kind, `${path}.kind`, "ManagedPostgres"),
    lifecycle: literalValue(
      input.lifecycle,
      `${path}.lifecycle`,
      "pre-provisioned",
    ),
    applicationId: nameValue(input.applicationId, `${path}.applicationId`),
    componentId: nameValue(input.componentId, `${path}.componentId`),
    serviceRef: serviceReference(input.serviceRef, `${path}.serviceRef`),
    dataBoundaryId: nameValue(input.dataBoundaryId, `${path}.dataBoundaryId`),
    providerResourceRef: referenceValue(
      input.providerResourceRef,
      `${path}.providerResourceRef`,
    ),
    network: {
      runtimeBoundaryId: nameValue(
        network.runtimeBoundaryId,
        `${path}.network.runtimeBoundaryId`,
      ),
      migrationBoundaryId: nameValue(
        network.migrationBoundaryId,
        `${path}.network.migrationBoundaryId`,
      ),
      separateBoundaries: trueValue(
        network.separateBoundaries,
        `${path}.network.separateBoundaries`,
      ),
      allowNetworkCidr: falseValue(
        network.allowNetworkCidr,
        `${path}.network.allowNetworkCidr`,
      ),
    },
    identities: {
      runtimeIdentityId: nameValue(
        identities.runtimeIdentityId,
        `${path}.identities.runtimeIdentityId`,
      ),
      migrationIdentityId: nameValue(
        identities.migrationIdentityId,
        `${path}.identities.migrationIdentityId`,
      ),
      separate: trueValue(identities.separate, `${path}.identities.separate`),
    },
    outputs: {
      endpointRef: referenceValue(
        outputs.endpointRef,
        `${path}.outputs.endpointRef`,
      ),
      port: literalValue(outputs.port, `${path}.outputs.port`, 5432),
      databaseName: databaseName(
        outputs.databaseName,
        `${path}.outputs.databaseName`,
      ),
      caBundleRef: referenceValue(
        outputs.caBundleRef,
        `${path}.outputs.caBundleRef`,
      ),
      runtimeIdentityRef: referenceValue(
        outputs.runtimeIdentityRef,
        `${path}.outputs.runtimeIdentityRef`,
      ),
      migrationIdentityRef: referenceValue(
        outputs.migrationIdentityRef,
        `${path}.outputs.migrationIdentityRef`,
      ),
      credentialValue: null,
    },
    status: parseStatus(input.status, `${path}.status`),
  };
}

function parsePlacement(value: unknown, path: string): CloudContextPlacement {
  const input = objectValue(value, path, [
    "applicationId",
    "componentId",
    "contextId",
    "runtimeCapabilityId",
    "networkCapabilityId",
    "registryCapabilityId",
    "identityCapabilityId",
    "observabilityCapabilityId",
    "dnsCapabilityIds",
    "resourceBindingIds",
    "delegatedRuntimes",
  ]);
  const delegatedRuntimes = arrayValue(
    input.delegatedRuntimes,
    `${path}.delegatedRuntimes`,
    (entry, entryPath) => {
      const delegated = objectValue(entry, entryPath, [
        "contextId",
        "runtimeCapabilityId",
        "purpose",
      ]);
      return {
        contextId: nameValue(delegated.contextId, `${entryPath}.contextId`),
        runtimeCapabilityId: nameValue(
          delegated.runtimeCapabilityId,
          `${entryPath}.runtimeCapabilityId`,
        ),
        purpose: literalValue(
          delegated.purpose,
          `${entryPath}.purpose`,
          "customer-code-execution",
        ),
      };
    },
  );
  const delegatedKeys = delegatedRuntimes.map(
    (entry) =>
      `${entry.contextId}\u0000${entry.runtimeCapabilityId}\u0000${entry.purpose}`,
  );
  if (new Set(delegatedKeys).size !== delegatedKeys.length) {
    throw new Error(`${path}.delegatedRuntimes must contain unique entries.`);
  }
  return {
    applicationId: nameValue(input.applicationId, `${path}.applicationId`),
    componentId: nameValue(input.componentId, `${path}.componentId`),
    contextId: nameValue(input.contextId, `${path}.contextId`),
    runtimeCapabilityId: nameValue(
      input.runtimeCapabilityId,
      `${path}.runtimeCapabilityId`,
    ),
    networkCapabilityId: nameValue(
      input.networkCapabilityId,
      `${path}.networkCapabilityId`,
    ),
    registryCapabilityId: nameValue(
      input.registryCapabilityId,
      `${path}.registryCapabilityId`,
    ),
    identityCapabilityId: nameValue(
      input.identityCapabilityId,
      `${path}.identityCapabilityId`,
    ),
    observabilityCapabilityId: nameValue(
      input.observabilityCapabilityId,
      `${path}.observabilityCapabilityId`,
    ),
    dnsCapabilityIds: stringArray(
      input.dnsCapabilityIds,
      `${path}.dnsCapabilityIds`,
      true,
    ),
    resourceBindingIds: stringArray(
      input.resourceBindingIds,
      `${path}.resourceBindingIds`,
      true,
    ),
    delegatedRuntimes,
  };
}

function parseStatus(value: unknown, path: string): CloudContextStatus {
  const input = objectValue(value, path, [
    "phase",
    "generation",
    "observedGeneration",
    "verifiedAt",
    "evidenceRef",
  ]);
  const status: CloudContextStatus = {
    phase: enumValue(input.phase, `${path}.phase`, [
      "planned",
      "ready",
      "degraded",
      "unavailable",
    ]),
    generation: integerValue(
      input.generation,
      `${path}.generation`,
      1,
      1_000_000,
    ),
    observedGeneration: integerValue(
      input.observedGeneration,
      `${path}.observedGeneration`,
      0,
      1_000_000,
    ),
    verifiedAt:
      input.verifiedAt === null
        ? null
        : isoTimestamp(input.verifiedAt, `${path}.verifiedAt`),
    evidenceRef:
      input.evidenceRef === null
        ? null
        : referenceValue(input.evidenceRef, `${path}.evidenceRef`),
  };
  assertStatus(status, path);
  return status;
}

function requireCapability<T extends { id: string }>(
  capabilities: readonly T[],
  id: string,
  placement: string,
  kind: string,
): T {
  const capability = capabilities.find((candidate) => candidate.id === id);
  if (!capability) {
    throw new Error(
      `Cloud context placement '${placement}' references unknown ${kind} capability '${id}'.`,
    );
  }
  return capability;
}

function uniqueMap<T extends { id: string }>(
  values: readonly T[],
  label: string,
): Map<string, T> {
  const result = new Map<string, T>();
  for (const value of values) {
    if (result.has(value.id)) {
      throw new Error(`${label} '${value.id}' is duplicated.`);
    }
    result.set(value.id, value);
  }
  return result;
}

function objectValue(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const result = value as Record<string, unknown>;
  const unknown = Object.keys(result).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(
      `${path} contains unknown field(s): ${unknown.sort().join(", ")}.`,
    );
  }
  for (const key of allowed) {
    if (!(key in result)) throw new Error(`${path}.${key} is required.`);
  }
  return result;
}

function arrayValue<T>(
  value: unknown,
  path: string,
  parser: (entry: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) throw new Error(`${path} must be an array.`);
  return value.map((entry, index) => parser(entry, `${path}[${index}]`));
}

function stringArray(
  value: unknown,
  path: string,
  allowEmpty = false,
): string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0)) {
    throw new Error(
      `${path} must be ${allowEmpty ? "an" : "a non-empty"} array.`,
    );
  }
  const result = value.map((entry, index) =>
    nameValue(entry, `${path}[${index}]`),
  );
  if (new Set(result).size !== result.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return result;
}

function literalValue<T extends string | number | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) throw new Error(`${path} must be '${expected}'.`);
  return expected;
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function trueValue(value: unknown, path: string): true {
  if (value !== true) throw new Error(`${path} must be true.`);
  return true;
}

function falseValue(value: unknown, path: string): false {
  if (value !== false) throw new Error(`${path} must be false.`);
  return false;
}

function integerValue(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number {
  if (
    !Number.isInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new Error(
      `${path} must be an integer from ${minimum} to ${maximum}.`,
    );
  }
  return value as number;
}

function nameValue(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$/.test(value) ||
    value.length > 128
  ) {
    throw new Error(`${path} must be a safe non-wildcard identifier.`);
  }
  return value;
}

function databaseName(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-z_][a-z0-9_]{0,62}$/.test(value)) {
    throw new Error(`${path} must be a safe PostgreSQL database name.`);
  }
  return value;
}

function locationValue(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[a-z0-9-]{2,64}$/.test(value)) {
    throw new Error(`${path} must be a safe provider location.`);
  }
  return value;
}

function serviceReference(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/.test(value)
  ) {
    throw new Error(
      `${path} must be an exact workspace/module/service reference.`,
    );
  }
  return value;
}

function referenceValue(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    !/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~:/-]+$/.test(value) ||
    /(?:credential|password|secret|access[_-]?key|session[_-]?token)/i.test(
      value,
    ) ||
    value.includes("@") ||
    value.includes("?") ||
    value.includes("#") ||
    value.includes("*")
  ) {
    throw new Error(`${path} must be a credential-free exact reference URI.`);
  }
  return value;
}

function isoTimestamp(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(`${path} must be an ISO-8601 UTC timestamp.`);
  }
  return value;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
