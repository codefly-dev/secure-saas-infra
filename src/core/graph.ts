import { PlatformBlueprint, TenantScope } from "./model";

export type SecurityNodeKind =
  | "trust-zone"
  | "network-domain"
  | "workload-plane"
  | "application"
  | "application-component"
  | "tenant"
  | "data-boundary"
  | "identity"
  | "evidence-sink";

export type SecurityEdgeKind =
  | "contains"
  | "placed-in"
  | "can-reach"
  | "can-access"
  | "delegates-to"
  | "audits-to"
  | "runs-on"
  | "uses-identity"
  | "uses-data"
  | "part-of"
  | "calls";

export interface SecurityNode {
  id: string;
  kind: SecurityNodeKind;
  tenantIds: readonly string[];
}

export interface SecurityEdge {
  id: string;
  kind: SecurityEdgeKind;
  from: string;
  to: string;
  brokered?: boolean;
  sourceId?: string;
}

export interface SecurityGraph {
  nodes: ReadonlyMap<string, SecurityNode>;
  edges: readonly SecurityEdge[];
}

export function buildSecurityGraph(
  blueprint: PlatformBlueprint,
): SecurityGraph {
  const nodes = new Map<string, SecurityNode>();
  const edges: SecurityEdge[] = [];
  const addNode = (node: SecurityNode) => nodes.set(node.id, node);

  for (const zone of blueprint.trustZones) {
    addNode({
      id: zone.id,
      kind: "trust-zone",
      tenantIds: tenantIds(zone.tenantScope),
    });
  }

  for (const domain of blueprint.networkDomains) {
    addNode({ id: domain.id, kind: "network-domain", tenantIds: [] });
    edges.push({
      id: `domain:${domain.id}:zone:${domain.zoneId}`,
      kind: "placed-in",
      from: domain.id,
      to: domain.zoneId,
    });
  }

  for (const workload of blueprint.workloadPlanes) {
    addNode({
      id: workload.id,
      kind: "workload-plane",
      tenantIds: tenantIds(workload.tenantScope),
    });
    edges.push({
      id: `workload:${workload.id}:zone:${workload.zoneId}`,
      kind: "placed-in",
      from: workload.id,
      to: workload.zoneId,
    });
  }

  for (const application of blueprint.applications) {
    addNode({
      id: application.id,
      kind: "application",
      tenantIds: tenantIds(application.tenantScope),
    });
    edges.push(
      {
        id: `application:${application.id}:workload:${application.workloadPlaneId}`,
        kind: "runs-on",
        from: application.id,
        to: application.workloadPlaneId,
      },
      {
        id: `application:${application.id}:identity:${application.serviceIdentityId}`,
        kind: "uses-identity",
        from: application.id,
        to: application.serviceIdentityId,
      },
      ...application.dataBoundaryIds.map((boundaryId) => ({
        id: `application:${application.id}:data:${boundaryId}`,
        kind: "uses-data" as const,
        from: application.id,
        to: boundaryId,
      })),
    );
    for (const component of application.components) {
      const componentId = `${application.id}/${component.id}`;
      addNode({
        id: componentId,
        kind: "application-component",
        tenantIds: tenantIds(application.tenantScope),
      });
      edges.push(
        {
          id: `component:${componentId}:application:${application.id}`,
          kind: "part-of",
          from: componentId,
          to: application.id,
        },
        {
          id: `component:${componentId}:workload:${component.workloadPlaneId}`,
          kind: "runs-on",
          from: componentId,
          to: component.workloadPlaneId,
        },
        {
          id: `component:${componentId}:identity:${component.serviceIdentityId}`,
          kind: "uses-identity",
          from: componentId,
          to: component.serviceIdentityId,
        },
        ...component.dataBoundaryIds.map((boundaryId) => ({
          id: `component:${componentId}:data:${boundaryId}`,
          kind: "uses-data" as const,
          from: componentId,
          to: boundaryId,
        })),
      );
    }
    edges.push(
      ...application.componentDependencies.map((dependency) => ({
        id: `component:${application.id}/${dependency.fromComponentId}:calls:${application.id}/${dependency.toComponentId}`,
        kind: "calls" as const,
        from: `${application.id}/${dependency.fromComponentId}`,
        to: `${application.id}/${dependency.toComponentId}`,
        brokered: true,
      })),
      ...application.dependencies.map((dependency) => ({
        id: `component:${application.id}/${dependency.fromComponentId}:calls:${dependency.deploymentId}/${dependency.toComponentId}`,
        kind: "calls" as const,
        from: `${application.id}/${dependency.fromComponentId}`,
        to: `${dependency.deploymentId}/${dependency.toComponentId}`,
        brokered: true,
      })),
    );
  }

  for (const tenant of blueprint.tenants) {
    addNode({
      id: tenant.tenantId,
      kind: "tenant",
      tenantIds: [tenant.tenantId],
    });
    for (const zoneId of tenant.zoneIds) {
      edges.push({
        id: `tenant:${tenant.tenantId}:zone:${zoneId}`,
        kind: "placed-in",
        from: tenant.tenantId,
        to: zoneId,
      });
    }
  }

  for (const boundary of blueprint.dataBoundaries) {
    addNode({
      id: boundary.id,
      kind: "data-boundary",
      tenantIds: tenantIds(boundary.tenantScope),
    });
    edges.push({
      id: `data:${boundary.id}:zone:${boundary.zoneId}`,
      kind: "placed-in",
      from: boundary.id,
      to: boundary.zoneId,
    });
  }

  for (const identity of blueprint.identities) {
    addNode({
      id: identity.id,
      kind: "identity",
      tenantIds: identity.tenantId ? [identity.tenantId] : [],
    });
  }

  for (const delegation of blueprint.identityDelegations) {
    edges.push({
      id: delegation.id,
      kind: "delegates-to",
      from: delegation.fromIdentityId,
      to: delegation.toIdentityId,
    });
  }

  for (const sink of blueprint.evidenceSinks) {
    addNode({
      id: sink.id,
      kind: "evidence-sink",
      tenantIds: tenantIds(sink.tenantScope),
    });
  }

  for (const flow of blueprint.flows) {
    const hops = [flow.fromZoneId, ...(flow.viaZoneIds ?? []), flow.toZoneId];
    for (let index = 0; index < hops.length - 1; index++) {
      edges.push({
        id: hops.length === 2 ? flow.id : `${flow.id}:hop-${index + 1}`,
        sourceId: flow.id,
        kind: "can-reach",
        from: hops[index],
        to: hops[index + 1],
        brokered: flow.authorization === "brokered",
      });
    }
  }

  for (const grant of blueprint.grants) {
    if (grant.effect !== "allow") continue;
    for (const resourceId of grant.resourceIds) {
      edges.push({
        id: `${grant.id}:${resourceId}`,
        kind: "can-access",
        from: grant.identityId,
        to: resourceId,
        brokered: grant.conditions?.brokered === "true",
      });
    }
  }

  for (const requirement of blueprint.evidenceRequirements) {
    for (const sourceId of requirement.sourceIds) {
      edges.push({
        id: `${requirement.id}:${sourceId}`,
        kind: "audits-to",
        from: sourceId,
        to: requirement.sinkId,
      });
    }
  }

  return { nodes, edges };
}

function tenantIds(scope: TenantScope): readonly string[] {
  if (scope.mode === "dedicated") return [scope.tenantId];
  if (scope.mode === "pooled") return scope.tenantIds;
  return [];
}
