import { createHash } from "node:crypto";
import type {
  ApplicationDeployment,
  PlatformBlueprint,
  TenantScope,
} from "../../core";
import { assertBlueprint } from "../../core";

export type CodeflyClusterKind = "k3d" | "eks" | "gke" | "aks";

export interface CodeflyEnvironmentExtension {
  name: string;
  clusterKind: CodeflyClusterKind;
  registry: string;
  namespacePrefix: string;
  kubeconfig?: string;
  kubeContext?: string;
  registryAuth?: "ecr" | "gcr" | "gar" | "ghcr";
  ingressNamespace?: string;
  gitopsRepository?: string;
  gitopsPath?: string;
  gitopsBranch?: string;
}

export interface CodeflyAgentExtension {
  name: string;
  version: string;
  publisher: string;
}

export interface CodeflyEndpointExtension {
  name: string;
  api: "http" | "rest" | "grpc" | "connect" | "tcp";
  visibility: "private" | "module" | "public";
}

export interface CodeflyServiceExtension {
  agent: CodeflyAgentExtension;
  endpoints: readonly CodeflyEndpointExtension[];
  internalDependencies?: readonly string[];
}

export interface CodeflyModuleInterfaceExtension {
  service: string;
  endpoint: string;
  visibility: "module" | "public";
}

export interface CodeflyDeploymentExtension {
  moduleName: string;
  services: readonly string[];
  images: Readonly<Record<string, string>>;
  serviceDefinitions: Readonly<Record<string, CodeflyServiceExtension>>;
  interfaceEndpoints: readonly CodeflyModuleInterfaceExtension[];
  dependencyConsumerService: string;
  serviceAccountAnnotations?: Readonly<Record<string, string>>;
}

export interface CodeflyProviderExtensions {
  environment: CodeflyEnvironmentExtension;
  deployments: Readonly<Record<string, CodeflyDeploymentExtension>>;
}

export interface CodeflyDependencyPlan {
  deploymentId: string;
  fromComponentId: string;
  toComponentId: string;
  endpoint: string;
  protocol: "https" | "grpc";
  authorization: "workload-identity" | "capability";
  audience: string;
  actions: readonly string[];
  moduleName: string;
  serviceName: string;
  endpointName: string;
}

export interface CodeflyServicePlan {
  name: string;
  image: string;
  agent: CodeflyAgentExtension;
  endpoints: readonly CodeflyEndpointExtension[];
  internalDependencies: readonly string[];
  externalDependencies: readonly {
    moduleName: string;
    serviceName: string;
    endpointName: string;
  }[];
}

export interface CodeflyDeploymentPlan {
  deploymentId: string;
  moduleName: string;
  environmentName: string;
  clusterKind: CodeflyClusterKind;
  namespace: string;
  serviceAccountName: string;
  workloadPlaneId: string;
  tenantScope: TenantScope;
  dataBoundaryIds: readonly string[];
  services: readonly string[];
  servicePlans: readonly CodeflyServicePlan[];
  images: Readonly<Record<string, string>>;
  interfaceEndpoints: readonly CodeflyModuleInterfaceExtension[];
  serviceAccountAnnotations: Readonly<Record<string, string>>;
  ingress: ApplicationDeployment["ingress"];
  dependencies: readonly CodeflyDependencyPlan[];
  minimumReplicas: number;
  maximumUnavailable: number;
  defaultDenyIngress: true;
  defaultDenyEgress: true;
  workloadIdentityRequired: true;
  signatureVerificationRequired: true;
  provenanceVerificationRequired: true;
  rollbackRequired: true;
  semanticLabels: Readonly<Record<string, string>>;
}

export interface CodeflyPaasPlan {
  apiVersion: "paas.codefly.dev/v1alpha1";
  blueprintDigest: string;
  environment: CodeflyEnvironmentExtension;
  deployments: readonly CodeflyDeploymentPlan[];
}

export function compileCodeflyApplications(
  blueprint: PlatformBlueprint,
  extensions: CodeflyProviderExtensions,
): CodeflyPaasPlan {
  assertBlueprint(blueprint);
  validateEnvironment(extensions.environment);
  const blueprintDigest = digest(blueprint);
  const deployments = [...blueprint.applications]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((application) =>
      compileApplication(application, blueprintDigest, extensions),
    );
  if (
    new Set(deployments.map((deployment) => deployment.namespace)).size !==
    deployments.length
  ) {
    throw new Error(
      "Codefly deployments must compile to independent namespaces.",
    );
  }
  if (
    deployments.some((deployment) => deployment.ingress === "public") &&
    !extensions.environment.ingressNamespace
  ) {
    throw new Error(
      "Codefly public deployments require an explicit ingress namespace.",
    );
  }
  return {
    apiVersion: "paas.codefly.dev/v1alpha1",
    blueprintDigest,
    environment: { ...extensions.environment },
    deployments,
  };
}

function compileApplication(
  application: ApplicationDeployment,
  blueprintDigest: string,
  extensions: CodeflyProviderExtensions,
): CodeflyDeploymentPlan {
  const extension = extensions.deployments[application.id];
  if (!extension) {
    throw new Error(
      `Codefly deployment '${application.id}' has no provider extension.`,
    );
  }
  if (extension.services.length === 0) {
    throw new Error(
      `Codefly deployment '${application.id}' must contain at least one service.`,
    );
  }
  const services = [...new Set(extension.services)].sort();
  if (
    Object.keys(extension.serviceDefinitions).some(
      (service) => !services.includes(service),
    )
  ) {
    throw new Error(
      `Codefly deployment '${application.id}' defines an undeclared service.`,
    );
  }
  if (
    Object.keys(extension.images).some((service) => !services.includes(service))
  ) {
    throw new Error(
      `Codefly deployment '${application.id}' has an image for an undeclared service.`,
    );
  }
  for (const service of services) {
    const image = extension.images[service];
    if (!image || !/@sha256:[a-f0-9]{64}$/.test(image)) {
      throw new Error(
        `Codefly service '${application.id}/${service}' requires a digest-pinned image.`,
      );
    }
    const definition = extension.serviceDefinitions[service];
    if (!definition) {
      throw new Error(
        `Codefly service '${application.id}/${service}' requires a service definition.`,
      );
    }
    if (!/^\d+\.\d+\.\d+$/.test(definition.agent.version)) {
      throw new Error(
        `Codefly service '${application.id}/${service}' requires a pinned agent version.`,
      );
    }
    for (const dependency of definition.internalDependencies ?? []) {
      if (!services.includes(dependency) || dependency === service) {
        throw new Error(
          `Codefly service '${application.id}/${service}' has an invalid internal dependency '${dependency}'.`,
        );
      }
    }
  }
  if (!services.includes(extension.dependencyConsumerService)) {
    throw new Error(
      `Codefly deployment '${application.id}' has an invalid dependency consumer service.`,
    );
  }
  for (const exposed of extension.interfaceEndpoints) {
    const definition = extension.serviceDefinitions[exposed.service];
    if (
      !definition ||
      !definition.endpoints.some(
        (endpoint) => endpoint.name === exposed.endpoint,
      )
    ) {
      throw new Error(
        `Codefly deployment '${application.id}' exposes an undeclared module endpoint.`,
      );
    }
  }
  if (
    application.ingress === "public" &&
    !extension.interfaceEndpoints.some(
      (endpoint) => endpoint.visibility === "public",
    )
  ) {
    throw new Error(
      `Codefly public deployment '${application.id}' requires an explicit public module endpoint.`,
    );
  }
  const environment = extensions.environment;
  const namespace = dnsLabel(
    `${environment.namespacePrefix}-${extension.moduleName}-${environment.name}`,
  );
  const dependencies = application.dependencies
    .map((dependency) => {
      const target = extensions.deployments[dependency.deploymentId];
      if (!target) {
        throw new Error(
          `Codefly dependency '${application.id}' -> '${dependency.deploymentId}' has no target extension.`,
        );
      }
      const expectedApis =
        dependency.protocol === "grpc"
          ? new Set(["grpc"])
          : new Set(["http", "rest", "connect"]);
      const endpoint = target.interfaceEndpoints.find((candidate) => {
        const definition = target.serviceDefinitions[candidate.service];
        return definition?.endpoints.some(
          (serviceEndpoint) =>
            serviceEndpoint.name === candidate.endpoint &&
            expectedApis.has(serviceEndpoint.api),
        );
      });
      if (!endpoint) {
        throw new Error(
          `Codefly dependency '${application.id}' -> '${dependency.deploymentId}' has no '${dependency.protocol}' module interface.`,
        );
      }
      const targetNamespace = dnsLabel(
        `${environment.namespacePrefix}-${target.moduleName}-${environment.name}`,
      );
      return {
        ...dependency,
        actions: [...dependency.actions].sort(),
        moduleName: target.moduleName,
        serviceName: endpoint.service,
        endpointName: endpoint.endpoint,
        endpoint: `${endpoint.service}.${targetNamespace}.svc.cluster.local`,
      };
    })
    .sort((left, right) => left.deploymentId.localeCompare(right.deploymentId));
  return {
    deploymentId: application.id,
    moduleName: extension.moduleName,
    environmentName: environment.name,
    clusterKind: environment.clusterKind,
    namespace,
    serviceAccountName: dnsLabel(`${application.id}-service`),
    workloadPlaneId: application.workloadPlaneId,
    tenantScope: application.tenantScope,
    dataBoundaryIds: [...application.dataBoundaryIds].sort(),
    services,
    servicePlans: services.map((service) => {
      const definition = extension.serviceDefinitions[service];
      const externalDependencies =
        service === extension.dependencyConsumerService
          ? dependencies.map((dependency) => ({
              moduleName: dependency.moduleName,
              serviceName: dependency.serviceName,
              endpointName: dependency.endpointName,
            }))
          : [];
      return {
        name: service,
        image: extension.images[service],
        agent: definition.agent,
        endpoints: [...definition.endpoints].sort((left, right) =>
          left.name.localeCompare(right.name),
        ),
        internalDependencies: [
          ...(definition.internalDependencies ?? []),
        ].sort(),
        externalDependencies,
      };
    }),
    images: Object.fromEntries(
      Object.entries(extension.images).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
    ingress: application.ingress,
    interfaceEndpoints: [...extension.interfaceEndpoints].sort((left, right) =>
      `${left.service}:${left.endpoint}`.localeCompare(
        `${right.service}:${right.endpoint}`,
      ),
    ),
    serviceAccountAnnotations: Object.fromEntries(
      Object.entries(extension.serviceAccountAnnotations ?? {}).sort(
        ([left], [right]) => left.localeCompare(right),
      ),
    ),
    dependencies,
    minimumReplicas: application.availability.minimumReplicas,
    maximumUnavailable: application.availability.maximumUnavailable,
    defaultDenyIngress: true,
    defaultDenyEgress: true,
    workloadIdentityRequired: true,
    signatureVerificationRequired: true,
    provenanceVerificationRequired: true,
    rollbackRequired: true,
    semanticLabels: {
      "security.deus.dev/application": application.id,
      "security.deus.dev/identity": application.serviceIdentityId,
      "security.deus.dev/workload-plane": application.workloadPlaneId,
      "security.deus.dev/blueprint-digest": blueprintDigest,
    },
  };
}

function validateEnvironment(environment: CodeflyEnvironmentExtension) {
  if (!environment.name.trim() || !environment.registry.trim()) {
    throw new Error("Codefly environment requires a name and registry.");
  }
  if (!environment.namespacePrefix.trim()) {
    throw new Error("Codefly environment requires a namespace prefix.");
  }
}

function digest(blueprint: PlatformBlueprint) {
  return createHash("sha256")
    .update(JSON.stringify(sortObject(blueprint)))
    .digest("hex");
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, entry]) => [key, sortObject(entry)]),
    );
  }
  return value;
}

function dnsLabel(value: string) {
  const label = value
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!label || label.length > 63)
    throw new Error(`Codefly DNS label '${value}' is invalid.`);
  return label;
}
