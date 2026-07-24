import {
  assertCloudContextCatalog,
  cloudContextCatalogDigest,
  type CloudContextCatalog,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
} from "../../core";
import type { CodeflyProductTopologyPlan } from "./productTopology";

export const CODEFLY_CLOUD_CONTEXT_PLAN_API_VERSION =
  "paas.codefly.dev/cloud-context-plan/v1alpha1" as const;

export interface CodeflyCloudContextPlan {
  apiVersion: typeof CODEFLY_CLOUD_CONTEXT_PLAN_API_VERSION;
  cloudContextApiVersion: CloudContextCatalog["apiVersion"];
  catalogName: string;
  environment: CloudContextCatalog["environment"];
  catalogDigest: string;
  deploymentAdmission: "require-ready-contexts";
  deployable: boolean;
  contexts: readonly {
    id: string;
    provider: CloudContextCatalog["contexts"][number]["provider"];
    phase: CloudContextCatalog["contexts"][number]["status"]["phase"];
    generation: number;
    runtimeCapabilityIds: readonly string[];
    resourceBindingIds: readonly string[];
  }[];
  workspaces: readonly {
    deploymentId: string;
    workspaceName: string;
    components: readonly {
      componentId: string;
      serviceIdentityId: string;
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
    }[];
  }[];
}

export function compileCodeflyCloudContextPlan(
  topology: CodeflyProductTopologyPlan,
  catalog: CloudContextCatalog,
  blueprint: PlatformBlueprint,
  managedPostgres: ManagedPostgresIntent,
): CodeflyCloudContextPlan {
  assertCloudContextCatalog(catalog, blueprint, managedPostgres);
  const placements = new Map(
    catalog.placements.map((placement) => [
      `${placement.applicationId}/${placement.componentId}`,
      placement,
    ]),
  );
  const bindings = new Map(
    catalog.contexts.flatMap((context) =>
      context.resourceBindings.map((binding) => [binding.id, binding] as const),
    ),
  );
  const topologyComponents = topology.workspaces.flatMap((workspace) =>
    workspace.components.map(
      (component) => `${workspace.deploymentId}/${component.componentId}`,
    ),
  );
  if (
    topologyComponents.length !== placements.size ||
    topologyComponents.some((component) => !placements.has(component))
  ) {
    throw new Error(
      "Codefly cloud context placements must exactly cover the product topology.",
    );
  }
  const workspaces = topology.workspaces.map((workspace) => ({
    deploymentId: workspace.deploymentId,
    workspaceName: workspace.workspaceName,
    components: workspace.components.map((component) => {
      const placement = placements.get(
        `${workspace.deploymentId}/${component.componentId}`,
      );
      if (!placement) {
        throw new Error(
          `Codefly component '${workspace.deploymentId}/${component.componentId}' has no cloud context placement.`,
        );
      }
      for (const bindingId of placement.resourceBindingIds) {
        const binding = bindings.get(bindingId);
        if (!binding) {
          throw new Error(
            `Codefly component '${workspace.deploymentId}/${component.componentId}' references unknown binding '${bindingId}'.`,
          );
        }
        const service = binding.serviceRef.split("/")[2];
        if (
          !component.services.some((candidate) => candidate.name === service)
        ) {
          throw new Error(
            `Codefly resource binding '${bindingId}' targets service '${service}' outside component '${workspace.deploymentId}/${component.componentId}'.`,
          );
        }
      }
      return {
        componentId: component.componentId,
        serviceIdentityId: component.serviceIdentityId,
        contextId: placement.contextId,
        runtimeCapabilityId: placement.runtimeCapabilityId,
        networkCapabilityId: placement.networkCapabilityId,
        registryCapabilityId: placement.registryCapabilityId,
        identityCapabilityId: placement.identityCapabilityId,
        observabilityCapabilityId: placement.observabilityCapabilityId,
        dnsCapabilityIds: [...placement.dnsCapabilityIds],
        resourceBindingIds: [...placement.resourceBindingIds],
        delegatedRuntimes: placement.delegatedRuntimes.map((delegated) => ({
          ...delegated,
        })),
      };
    }),
  }));
  return {
    apiVersion: CODEFLY_CLOUD_CONTEXT_PLAN_API_VERSION,
    cloudContextApiVersion: catalog.apiVersion,
    catalogName: catalog.name,
    environment: catalog.environment,
    catalogDigest: cloudContextCatalogDigest(catalog),
    deploymentAdmission: "require-ready-contexts",
    deployable: catalog.contexts.every(
      (context) =>
        context.status.phase === "ready" &&
        context.status.observedGeneration === context.status.generation &&
        context.resourceBindings.every(
          (binding) =>
            binding.status.phase === "ready" &&
            binding.status.observedGeneration === binding.status.generation,
        ),
    ),
    contexts: catalog.contexts.map((context) => ({
      id: context.id,
      provider: { ...context.provider },
      phase: context.status.phase,
      generation: context.status.generation,
      runtimeCapabilityIds: context.capabilities.runtimes.map(
        (runtime) => runtime.id,
      ),
      resourceBindingIds: context.resourceBindings.map((binding) => binding.id),
    })),
    workspaces,
  };
}
