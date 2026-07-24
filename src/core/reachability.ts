import { buildSecurityGraph, SecurityEdge } from "./graph";
import { PlatformBlueprint } from "./model";

export interface NetworkPath {
  fromZoneId: string;
  toZoneId: string;
  zoneIds: readonly string[];
  edgeIds: readonly string[];
  flowIds: readonly string[];
  brokeredAtSource: boolean;
}

export interface NetworkPathOptions {
  toZoneId?: string;
  maxDepth?: number;
  maxPaths?: number;
}

export function findNetworkPaths(
  blueprint: PlatformBlueprint,
  fromZoneId: string,
  options: NetworkPathOptions = {},
): NetworkPath[] {
  const graph = buildSecurityGraph(blueprint);
  const adjacency = new Map<string, SecurityEdge[]>();
  for (const edge of graph.edges) {
    if (edge.kind !== "can-reach") continue;
    adjacency.set(edge.from, [...(adjacency.get(edge.from) ?? []), edge]);
  }

  const maxDepth = options.maxDepth ?? Math.max(blueprint.trustZones.length, 1);
  const maxPaths = options.maxPaths ?? 1_000;
  const paths: NetworkPath[] = [];
  const queue: Array<{
    zoneIds: string[];
    edges: SecurityEdge[];
  }> = [{ zoneIds: [fromZoneId], edges: [] }];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (current.edges.length >= maxDepth) continue;
    const currentZone = current.zoneIds[current.zoneIds.length - 1];

    for (const edge of adjacency.get(currentZone) ?? []) {
      if (current.zoneIds.includes(edge.to)) continue;
      const zoneIds = [...current.zoneIds, edge.to];
      const edges = [...current.edges, edge];
      if (!options.toZoneId || edge.to === options.toZoneId) {
        if (paths.length >= maxPaths) {
          throw new Error(
            `Network reachability analysis exceeded ${maxPaths} paths from '${fromZoneId}'; raise the reviewed limit or reduce graph complexity.`,
          );
        }
        paths.push({
          fromZoneId,
          toZoneId: edge.to,
          zoneIds,
          edgeIds: edges.map((entry) => entry.id),
          flowIds: [
            ...new Set(edges.map((entry) => entry.sourceId ?? entry.id)),
          ],
          brokeredAtSource: edges[0]?.brokered === true,
        });
      }
      if (!options.toZoneId || edge.to !== options.toZoneId) {
        queue.push({ zoneIds, edges });
      }
    }
  }

  return paths;
}
