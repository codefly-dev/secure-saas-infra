import type { CodeflyProviderExtensions } from "./codeflyAdapter";

export interface WardenMindImageSet {
  wardenApi: string;
  wardenFrontend: string;
  mindApi: string;
}

export interface WardenMindCodeflyOptions {
  environmentName: string;
  clusterKind: "k3d" | "eks" | "gke" | "aks";
  registry: string;
  images: WardenMindImageSet;
  namespacePrefix?: string;
  ingressNamespace: string;
  kubeconfig?: string;
  kubeContext?: string;
  registryAuth?: "ecr" | "gcr" | "gar" | "ghcr";
  gitopsRepository?: string;
  gitopsPath?: string;
  gitopsBranch?: string;
  wardenServiceRoleArn?: string;
  mindServiceRoleArn?: string;
}

export function createWardenMindCodeflyExtensions(
  options: WardenMindCodeflyOptions,
): CodeflyProviderExtensions {
  return {
    environment: {
      name: options.environmentName,
      clusterKind: options.clusterKind,
      registry: options.registry,
      namespacePrefix: options.namespacePrefix ?? "deus",
      ingressNamespace: options.ingressNamespace,
      kubeconfig: options.kubeconfig,
      kubeContext: options.kubeContext,
      registryAuth: options.registryAuth,
      gitopsRepository: options.gitopsRepository,
      gitopsPath: options.gitopsPath,
      gitopsBranch: options.gitopsBranch,
    },
    deployments: {
      warden: {
        moduleName: "warden",
        services: ["frontend", "api"],
        images: {
          api: options.images.wardenApi,
          frontend: options.images.wardenFrontend,
        },
        serviceDefinitions: {
          api: {
            agent: {
              name: "go-grpc",
              version: "0.1.6",
              publisher: "codefly.dev",
            },
            endpoints: [
              { name: "grpc", api: "grpc", visibility: "module" },
              { name: "rest", api: "rest", visibility: "module" },
            ],
          },
          frontend: {
            agent: {
              name: "nextjs",
              version: "0.0.110",
              publisher: "codefly.dev",
            },
            endpoints: [{ name: "http", api: "http", visibility: "public" }],
            internalDependencies: ["api"],
          },
        },
        interfaceEndpoints: [
          { service: "frontend", endpoint: "http", visibility: "public" },
          { service: "api", endpoint: "grpc", visibility: "module" },
        ],
        dependencyConsumerService: "api",
        serviceAccountAnnotations: roleAnnotation(options.wardenServiceRoleArn),
      },
      mind: {
        moduleName: "mind",
        services: ["api"],
        images: { api: options.images.mindApi },
        serviceDefinitions: {
          api: {
            agent: {
              name: "go-grpc",
              version: "0.1.6",
              publisher: "codefly.dev",
            },
            endpoints: [
              { name: "grpc", api: "grpc", visibility: "module" },
              { name: "rest", api: "rest", visibility: "public" },
            ],
          },
        },
        interfaceEndpoints: [
          { service: "api", endpoint: "rest", visibility: "public" },
          { service: "api", endpoint: "grpc", visibility: "module" },
        ],
        dependencyConsumerService: "api",
        serviceAccountAnnotations: roleAnnotation(options.mindServiceRoleArn),
      },
    },
  };
}

function roleAnnotation(roleArn: string | undefined) {
  return roleArn
    ? { "eks.amazonaws.com/role-arn": roleArn }
    : ({} as Record<string, string>);
}
