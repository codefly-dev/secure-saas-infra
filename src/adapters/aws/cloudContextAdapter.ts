import {
  CLOUD_CONTEXT_API_VERSION,
  assertCloudContextCatalog,
  assertManagedPostgresIntent,
  type CloudContext,
  type CloudContextCatalog,
  type CloudContextStatus,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
} from "../../core";

export interface AwsCloudContextExtensions {
  partition: "aws" | "aws-us-gov" | "aws-cn";
  platformAccountId: string;
  executionAccountId: string;
  region: string;
  applicationContextId: string;
  executionContextId: string;
  platformStackRef: string;
  executionStackRef: string;
  registryRef: string;
  publicDnsRef: string;
  privateDnsRef: string;
  platformIdentityRef: string;
  executionIdentityRef: string;
  auditRef: string;
  logsRef: string;
  metricsRef: string;
  tracesRef: string;
}

export function compileAwsCloudContextCatalog(
  blueprint: PlatformBlueprint,
  managedPostgres: ManagedPostgresIntent,
  extensions: AwsCloudContextExtensions,
): CloudContextCatalog {
  assertManagedPostgresIntent(managedPostgres, blueprint);
  validateExtensions(extensions);
  const platformPlane = requiredPlane(blueprint, "platform-applications");
  const executionPlane = blueprint.workloadPlanes.find(
    (plane) => plane.executionTrust === "untrusted",
  );
  if (!executionPlane) {
    throw new Error(
      "AWS cloud context catalog requires an untrusted execution workload plane.",
    );
  }
  const componentIdentities = blueprint.applications.flatMap((application) =>
    application.components.map((component) => component.serviceIdentityId),
  );
  const databaseIdentities = managedPostgres.bindings.flatMap((binding) => [
    binding.access.runtimeIdentityId,
    binding.access.migrationIdentityId,
  ]);
  const planned = plannedStatus();
  const applicationContext: CloudContext = {
    id: extensions.applicationContextId,
    environment: managedPostgres.environment,
    provider: {
      kind: "aws",
      boundaryRef: `provider-boundary://${extensions.partition}/${extensions.platformAccountId}`,
      location: extensions.region,
    },
    provisioning: {
      mode: "pre-provisioned",
      owner: "external-iac",
      physicalMutationFromCodefly: false,
    },
    posture: {
      privateNetworking: true,
      inspectedEgress: true,
      immutableAudit: true,
      credentialDelivery: "reference-only",
      directProviderCredentials: false,
    },
    capabilities: {
      runtimes: [
        {
          id: "platform-runtime",
          workloadPlaneIds: [platformPlane.id],
          orchestrator: platformPlane.orchestrator,
          executionTrust: platformPlane.executionTrust,
          runtimeIsolation: platformPlane.runtimeIsolation,
          credentialMode: "workload-identity",
          privateControlPlane: true,
          workloadIdentity: true,
          directHostAccess: false,
          reference: stackOutputRef(extensions.platformStackRef, "eksClusters"),
        },
      ],
      networks: [
        {
          id: "platform-private-network",
          networkDomainIds: networkDomainsForPlane(blueprint, platformPlane.id),
          private: true,
          directInternetAccess: false,
          inspectedEgress: true,
          brokeredEgress: true,
          reference: stackOutputRef(extensions.platformStackRef, "spokeVpcId"),
        },
      ],
      registries: [
        {
          id: "platform-registry",
          immutableDigestsOnly: true,
          signatureVerification: true,
          provenanceVerification: true,
          reference: extensions.registryRef,
        },
      ],
      dns: [
        {
          id: "platform-private-dns",
          visibility: "private",
          managedRecordsOnly: true,
          reference: extensions.privateDnsRef,
        },
        {
          id: "platform-public-dns",
          visibility: "public",
          managedRecordsOnly: true,
          reference: extensions.publicDnsRef,
        },
      ],
      identities: [
        {
          id: "platform-workload-identities",
          mode: "workload-identity",
          allowedIdentityIds: unique([
            ...componentIdentities,
            ...databaseIdentities,
          ]),
          shortLived: true,
          administrator: false,
          maxSessionMinutes: 15,
          reference: extensions.platformIdentityRef,
        },
      ],
      observability: [
        {
          id: "platform-observability",
          immutableAudit: true,
          auditRetentionDays: blueprint.posture.minimumAuditRetentionDays,
          auditRef: extensions.auditRef,
          logsRef: extensions.logsRef,
          metricsRef: extensions.metricsRef,
          tracesRef: extensions.tracesRef,
        },
      ],
    },
    resourceBindings: managedPostgres.bindings
      .map((binding) => ({
        id: binding.id,
        kind: "ManagedPostgres" as const,
        lifecycle: "pre-provisioned" as const,
        applicationId: binding.tenantId,
        componentId: binding.codefly.module,
        serviceRef: `${binding.codefly.workspace}/${binding.codefly.module}/${binding.codefly.service}`,
        dataBoundaryId: binding.dataBoundaryId,
        providerResourceRef: stackOutputRef(
          extensions.platformStackRef,
          `databaseBindings/${binding.id}/clusterResourceId`,
        ),
        network: {
          runtimeBoundaryId: binding.access.networkAccess.runtimeBoundaryId,
          migrationBoundaryId: binding.access.networkAccess.migrationBoundaryId,
          separateBoundaries: true as const,
          allowNetworkCidr: false as const,
        },
        identities: {
          runtimeIdentityId: binding.access.runtimeIdentityId,
          migrationIdentityId: binding.access.migrationIdentityId,
          separate: true as const,
        },
        outputs: {
          endpointRef: stackOutputRef(
            extensions.platformStackRef,
            `databaseBindings/${binding.id}/endpoint`,
          ),
          port: 5432 as const,
          databaseName: binding.database.name,
          caBundleRef: `provider-reference://${extensions.partition}/rds/${extensions.region}/ca-bundle`,
          runtimeIdentityRef: `identity://${binding.access.runtimeIdentityId}`,
          migrationIdentityRef: `identity://${binding.access.migrationIdentityId}`,
          credentialValue: null,
        },
        status: plannedStatus(),
      }))
      .sort((left, right) => left.id.localeCompare(right.id)),
    status: planned,
  };
  const executionContext: CloudContext = {
    id: extensions.executionContextId,
    environment: managedPostgres.environment,
    provider: {
      kind: "aws",
      boundaryRef: `provider-boundary://${extensions.partition}/${extensions.executionAccountId}`,
      location: extensions.region,
    },
    provisioning: {
      mode: "pre-provisioned",
      owner: "external-iac",
      physicalMutationFromCodefly: false,
    },
    posture: {
      privateNetworking: true,
      inspectedEgress: true,
      immutableAudit: true,
      credentialDelivery: "reference-only",
      directProviderCredentials: false,
    },
    capabilities: {
      runtimes: [
        {
          id: "isolated-execution-runtime",
          workloadPlaneIds: [executionPlane.id],
          orchestrator: executionPlane.orchestrator,
          executionTrust: "untrusted",
          runtimeIsolation: executionPlane.runtimeIsolation,
          credentialMode: "brokered",
          privateControlPlane: true,
          workloadIdentity: true,
          directHostAccess: false,
          reference: stackOutputRef(
            extensions.executionStackRef,
            executionPlane.orchestrator === "external-sandbox"
              ? "e2bByocVendorRoleArn"
              : "eksClusters",
          ),
        },
      ],
      networks: [
        {
          id: "isolated-execution-network",
          networkDomainIds: networkDomainsForPlane(
            blueprint,
            executionPlane.id,
          ),
          private: true,
          directInternetAccess: false,
          inspectedEgress: true,
          brokeredEgress: true,
          reference: stackOutputRef(extensions.executionStackRef, "spokeVpcId"),
        },
      ],
      registries: [
        {
          id: "execution-registry",
          immutableDigestsOnly: true,
          signatureVerification: true,
          provenanceVerification: true,
          reference: extensions.registryRef,
        },
      ],
      dns: [
        {
          id: "execution-private-dns",
          visibility: "private",
          managedRecordsOnly: true,
          reference: extensions.privateDnsRef,
        },
      ],
      identities: [
        {
          id: "execution-brokered-identities",
          mode: "workload-identity",
          allowedIdentityIds: unique([
            "mind-execution-service",
            ...blueprint.identities
              .filter((identity) => identity.tenantId)
              .map((identity) => identity.id),
          ]),
          shortLived: true,
          administrator: false,
          maxSessionMinutes: 15,
          reference: extensions.executionIdentityRef,
        },
      ],
      observability: [
        {
          id: "execution-observability",
          immutableAudit: true,
          auditRetentionDays: blueprint.posture.minimumAuditRetentionDays,
          auditRef: extensions.auditRef,
          logsRef: extensions.logsRef,
          metricsRef: extensions.metricsRef,
          tracesRef: extensions.tracesRef,
        },
      ],
    },
    resourceBindings: [],
    status: plannedStatus(),
  };
  const catalog: CloudContextCatalog = {
    apiVersion: CLOUD_CONTEXT_API_VERSION,
    kind: "CloudContextCatalog",
    name: "warden-mind-aws",
    environment: managedPostgres.environment,
    contexts: [applicationContext, executionContext].sort((left, right) =>
      left.id.localeCompare(right.id),
    ),
    placements: blueprint.applications
      .flatMap((application) =>
        application.components.map((component) => ({
          applicationId: application.id,
          componentId: component.id,
          contextId: extensions.applicationContextId,
          runtimeCapabilityId: "platform-runtime",
          networkCapabilityId: "platform-private-network",
          registryCapabilityId: "platform-registry",
          identityCapabilityId: "platform-workload-identities",
          observabilityCapabilityId: "platform-observability",
          dnsCapabilityIds:
            component.ingress === "public"
              ? ["platform-private-dns", "platform-public-dns"]
              : ["platform-private-dns"],
          resourceBindingIds: managedPostgres.bindings
            .filter(
              (binding) =>
                binding.tenantId === application.id &&
                binding.codefly.module === component.id,
            )
            .map((binding) => binding.id)
            .sort(),
          delegatedRuntimes:
            application.id === "mind" && component.id === "execution"
              ? [
                  {
                    contextId: extensions.executionContextId,
                    runtimeCapabilityId: "isolated-execution-runtime",
                    purpose: "customer-code-execution" as const,
                  },
                ]
              : [],
        })),
      )
      .sort((left, right) =>
        `${left.applicationId}/${left.componentId}`.localeCompare(
          `${right.applicationId}/${right.componentId}`,
        ),
      ),
  };
  assertCloudContextCatalog(catalog, blueprint, managedPostgres);
  return catalog;
}

function requiredPlane(blueprint: PlatformBlueprint, id: string) {
  const plane = blueprint.workloadPlanes.find(
    (candidate) => candidate.id === id,
  );
  if (!plane)
    throw new Error(`AWS cloud context requires workload plane '${id}'.`);
  return plane;
}

function networkDomainsForPlane(
  blueprint: PlatformBlueprint,
  workloadPlaneId: string,
): string[] {
  const plane = requiredPlane(blueprint, workloadPlaneId);
  const domains = blueprint.networkDomains
    .filter((domain) => domain.zoneId === plane.zoneId)
    .map((domain) => domain.id)
    .sort();
  if (domains.length === 0) {
    throw new Error(
      `AWS cloud context workload plane '${workloadPlaneId}' has no network domain.`,
    );
  }
  return domains;
}

function plannedStatus(): CloudContextStatus {
  return {
    phase: "planned",
    generation: 1,
    observedGeneration: 0,
    verifiedAt: null,
    evidenceRef: null,
  };
}

function stackOutputRef(stackRef: string, output: string): string {
  return `stack-output://${stackRef}/${output}`;
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function validateExtensions(extensions: AwsCloudContextExtensions) {
  for (const [label, accountId] of Object.entries({
    platformAccountId: extensions.platformAccountId,
    executionAccountId: extensions.executionAccountId,
  })) {
    if (!/^\d{12}$/.test(accountId)) {
      throw new Error(`AWS cloud context ${label} must be exactly 12 digits.`);
    }
  }
  if (extensions.platformAccountId === extensions.executionAccountId) {
    throw new Error(
      "AWS platform and execution cloud contexts require separate accounts.",
    );
  }
  if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(extensions.region)) {
    throw new Error("AWS cloud context region is invalid.");
  }
  if (extensions.applicationContextId === extensions.executionContextId) {
    throw new Error(
      "AWS application and execution cloud contexts must be separate.",
    );
  }
  for (const [label, value] of Object.entries({
    platformStackRef: extensions.platformStackRef,
    executionStackRef: extensions.executionStackRef,
  })) {
    if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(value)) {
      throw new Error(
        `AWS cloud context ${label} must be an exact Pulumi stack reference.`,
      );
    }
  }
  for (const [label, value] of Object.entries({
    registryRef: extensions.registryRef,
    publicDnsRef: extensions.publicDnsRef,
    privateDnsRef: extensions.privateDnsRef,
    platformIdentityRef: extensions.platformIdentityRef,
    executionIdentityRef: extensions.executionIdentityRef,
    auditRef: extensions.auditRef,
    logsRef: extensions.logsRef,
    metricsRef: extensions.metricsRef,
    tracesRef: extensions.tracesRef,
  })) {
    if (
      !/^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~:/-]+$/.test(value) ||
      /(?:credential|password|secret|access[_-]?key|session[_-]?token)/i.test(
        value,
      ) ||
      /[@?#*]/.test(value)
    ) {
      throw new Error(
        `AWS cloud context ${label} must be a credential-free exact reference URI.`,
      );
    }
  }
}
