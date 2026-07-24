import type { PlatformBlueprint, TenantScope } from "../../core";
import { assertBlueprint } from "../../core";

export interface CodeflyProductAgentContract {
  publisher: string;
  agent: string;
  version: string;
}

export interface CodeflyProductContract {
  apiVersion: "contracts.security.deus.dev/codefly-products/v1";
  products: Readonly<
    Record<
      string,
      {
        workspaceName: string;
        modules: Readonly<
          Record<
            string,
            {
              services: Readonly<Record<string, CodeflyProductAgentContract>>;
            }
          >
        >;
      }
    >
  >;
}

export interface CodeflyProductComponentPlan {
  componentId: string;
  moduleName: string;
  workloadPlaneId: string;
  serviceIdentityId: string;
  dataBoundaryIds: readonly string[];
  tenantScope: TenantScope;
  ingress: "none" | "private" | "public";
  minimumReplicas: number;
  maximumUnavailable: number;
  release: {
    digestPinnedImages: boolean;
    signatureVerification: boolean;
    provenanceVerification: boolean;
    rollbackRequired: boolean;
  };
  services: readonly {
    name: string;
    agent: CodeflyProductAgentContract;
  }[];
}

export interface CodeflyProductWorkspacePlan {
  deploymentId: string;
  workspaceName: string;
  deploymentIdentityId: string;
  components: readonly CodeflyProductComponentPlan[];
  componentDependencies: readonly {
    fromComponentId: string;
    toComponentId: string;
    protocol: "https" | "grpc";
    authorization: "workload-identity" | "capability";
    audience: string;
    actions: readonly string[];
  }[];
  dependencies: readonly {
    fromComponentId: string;
    toDeploymentId: string;
    toComponentId: string;
    protocol: "https" | "grpc";
    authorization: "workload-identity" | "capability";
    audience: string;
    actions: readonly string[];
  }[];
}

export interface CodeflyProductTopologyPlan {
  apiVersion: "paas.codefly.dev/product-topology/v1alpha1";
  workspaces: readonly CodeflyProductWorkspacePlan[];
}

export function compileCodeflyProductTopology(
  blueprint: PlatformBlueprint,
  contract: CodeflyProductContract,
): CodeflyProductTopologyPlan {
  assertBlueprint(blueprint);
  assertStrictProductContract(contract);
  if (
    contract.apiVersion !== "contracts.security.deus.dev/codefly-products/v1"
  ) {
    throw new Error(
      `Unsupported Codefly product contract '${String(contract.apiVersion)}'.`,
    );
  }
  const applicationIds = blueprint.applications.map(
    (application) => application.id,
  );
  assertSameNames(
    "product deployments",
    Object.keys(contract.products),
    applicationIds,
  );
  return {
    apiVersion: "paas.codefly.dev/product-topology/v1alpha1",
    workspaces: [...blueprint.applications]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((application) => {
        const product = contract.products[application.id];
        const componentIds = application.components.map(
          (component) => component.id,
        );
        assertSameNames(
          `components for '${application.id}'`,
          Object.keys(product.modules),
          componentIds,
        );
        return {
          deploymentId: application.id,
          workspaceName: product.workspaceName,
          deploymentIdentityId: application.serviceIdentityId,
          components: [...application.components]
            .sort((left, right) => left.id.localeCompare(right.id))
            .map((component) => ({
              componentId: component.id,
              moduleName: component.id,
              workloadPlaneId: component.workloadPlaneId,
              serviceIdentityId: component.serviceIdentityId,
              dataBoundaryIds: [...component.dataBoundaryIds].sort(),
              tenantScope: application.tenantScope,
              ingress: component.ingress,
              minimumReplicas: component.availability.minimumReplicas,
              maximumUnavailable: component.availability.maximumUnavailable,
              release: { ...application.release },
              services: Object.entries(product.modules[component.id].services)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([name, agent]) => {
                  validateAgent(application.id, component.id, name, agent);
                  return { name, agent: { ...agent } };
                }),
            })),
          componentDependencies: application.componentDependencies
            .map((dependency) => ({
              fromComponentId: dependency.fromComponentId,
              toComponentId: dependency.toComponentId,
              protocol: dependency.protocol,
              authorization: dependency.authorization,
              audience: dependency.audience,
              actions: [...dependency.actions].sort(),
            }))
            .sort((left, right) =>
              `${left.fromComponentId}:${left.toComponentId}`.localeCompare(
                `${right.fromComponentId}:${right.toComponentId}`,
              ),
            ),
          dependencies: application.dependencies
            .map((dependency) => ({
              fromComponentId: dependency.fromComponentId,
              toDeploymentId: dependency.deploymentId,
              toComponentId: dependency.toComponentId,
              protocol: dependency.protocol,
              authorization: dependency.authorization,
              audience: dependency.audience,
              actions: [...dependency.actions].sort(),
            }))
            .sort((left, right) =>
              `${left.fromComponentId}:${left.toDeploymentId}:${left.toComponentId}`.localeCompare(
                `${right.fromComponentId}:${right.toDeploymentId}:${right.toComponentId}`,
              ),
            ),
        };
      }),
  };
}

function assertStrictProductContract(contract: CodeflyProductContract) {
  assertObjectKeys("contract", contract, ["apiVersion", "products"]);
  if (
    !isRecord(contract.products) ||
    Object.keys(contract.products).length === 0
  ) {
    throw new Error("Codefly product contract requires at least one product.");
  }
  for (const [productName, product] of Object.entries(contract.products)) {
    assertObjectKeys(`product '${productName}'`, product, [
      "workspaceName",
      "modules",
    ]);
    if (!product.workspaceName?.trim() || !isRecord(product.modules)) {
      throw new Error(
        `Codefly product contract has an invalid product '${productName}'.`,
      );
    }
    for (const [moduleName, module] of Object.entries(product.modules)) {
      assertObjectKeys(`module '${productName}/${moduleName}'`, module, [
        "services",
      ]);
      if (
        !isRecord(module.services) ||
        Object.keys(module.services).length === 0
      ) {
        throw new Error(
          `Codefly product contract module '${productName}/${moduleName}' requires services.`,
        );
      }
      for (const [serviceName, agent] of Object.entries(module.services)) {
        assertObjectKeys(
          `agent '${productName}/${moduleName}/${serviceName}'`,
          agent,
          ["publisher", "agent", "version"],
        );
      }
    }
  }
}

function validateAgent(
  product: string,
  moduleName: string,
  service: string,
  agent: CodeflyProductAgentContract,
) {
  if (
    !agent.publisher.trim() ||
    !agent.agent.trim() ||
    !/^\d+\.\d+\.\d+$/.test(agent.version) ||
    agent.version === "latest"
  ) {
    throw new Error(
      `Codefly product '${product}/${moduleName}/${service}' requires an exact agent contract.`,
    );
  }
}

function assertSameNames(
  label: string,
  expected: readonly string[],
  observed: readonly string[],
) {
  const left = [...new Set(expected)].sort();
  const right = [...new Set(observed)].sort();
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error(
      `Codefly ${label} mismatch; expected [${left.join(", ")}], observed [${right.join(", ")}].`,
    );
  }
}

function assertObjectKeys(
  label: string,
  value: unknown,
  allowed: readonly string[],
) {
  if (!isRecord(value)) {
    throw new Error(`Codefly product ${label} must be an object.`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(
      `Codefly product ${label} contains unknown field(s): ${unknown.sort().join(", ")}.`,
    );
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
