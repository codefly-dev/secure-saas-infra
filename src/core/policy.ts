import { buildSecurityGraph, SecurityGraph } from "./graph";
import {
  DataBoundary,
  NetworkDomain,
  PlatformBlueprint,
  TenantScope,
} from "./model";
import { cidrsOverlap, parseCidr } from "../cidr";
import { analyzeEntitlements } from "./entitlements";
import { findNetworkPaths } from "./reachability";

export type ViolationSeverity = "critical" | "high" | "medium";

export interface BlueprintViolation {
  code: string;
  severity: ViolationSeverity;
  message: string;
  path?: string;
}

export interface BlueprintPolicyContext {
  blueprint: PlatformBlueprint;
  graph: SecurityGraph;
}

export interface BlueprintPolicy {
  id: string;
  evaluate(context: BlueprintPolicyContext): readonly BlueprintViolation[];
}

export const defaultBlueprintPolicies: readonly BlueprintPolicy[] = [
  structuralIntegrityPolicy(),
  networkBoundaryPolicy(),
  transitiveNetworkPolicy(),
  workloadPlanePolicy(),
  applicationDeploymentPolicy(),
  tenantIsolationPolicy(),
  dataProtectionPolicy(),
  identityPolicy(),
  evidencePolicy(),
];

export function evaluateBlueprint(
  blueprint: PlatformBlueprint,
  policies: readonly BlueprintPolicy[] = defaultBlueprintPolicies,
): BlueprintViolation[] {
  const graph = buildSecurityGraph(blueprint);
  return policies.flatMap((policy) => policy.evaluate({ blueprint, graph }));
}

function transitiveNetworkPolicy(): BlueprintPolicy {
  return {
    id: "transitive-network-boundaries",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const zones = new Map(
        blueprint.trustZones.map((zone) => [zone.id, zone]),
      );
      const inspectedZones = new Set(
        blueprint.networkDomains
          .filter((domain) => domain.inspectedEgress)
          .map((domain) => domain.zoneId),
      );

      for (const source of blueprint.trustZones) {
        const paths = findNetworkPaths(blueprint, source.id);
        for (const path of paths) {
          const destination = zones.get(path.toZoneId);
          if (!destination) continue;

          if (
            source.kind === "execution" &&
            (destination.kind === "control-plane" ||
              destination.kind === "data") &&
            !path.brokeredAtSource &&
            path.zoneIds.length > 2
          ) {
            violations.push({
              code: "NET_TRANSITIVE_EXECUTION_BYPASS",
              severity: "critical",
              message: `Execution zone '${source.id}' reaches trusted zone '${destination.id}' through an unbrokered transitive path.`,
              path: path.zoneIds.join(" -> "),
            });
          }

          if (
            blueprint.posture.requireInspectedEgress &&
            destination.kind === "external" &&
            !path.zoneIds.some((zoneId) => inspectedZones.has(zoneId))
          ) {
            violations.push({
              code: "NET_TRANSITIVE_UNINSPECTED_EGRESS",
              severity: "critical",
              message: `Zone '${source.id}' reaches external zone '${destination.id}' without traversing inspected egress.`,
              path: path.zoneIds.join(" -> "),
            });
          }

          const sourceTenants = tenantIdsFromScope(source.tenantScope);
          const destinationTenants = tenantIdsFromScope(
            destination.tenantScope,
          );
          if (
            sourceTenants.length > 0 &&
            destinationTenants.length > 0 &&
            !sourceTenants.some((tenantId) =>
              destinationTenants.includes(tenantId),
            )
          ) {
            violations.push({
              code: "NET_CROSS_TENANT_PATH",
              severity: "critical",
              message: `Network path crosses from tenant-scoped zone '${source.id}' to '${destination.id}'.`,
              path: path.zoneIds.join(" -> "),
            });
          }
        }
      }

      return deduplicateViolations(violations);
    },
  };
}

export function assertBlueprint(
  blueprint: PlatformBlueprint,
  policies: readonly BlueprintPolicy[] = defaultBlueprintPolicies,
): void {
  const violations = evaluateBlueprint(blueprint, policies);
  if (violations.length === 0) return;

  throw new Error(
    `Cloud-neutral platform blueprint '${blueprint.name}' violates security invariants:\n${violations
      .map(
        (violation) =>
          `- [${violation.severity}] ${violation.code}: ${violation.message}`,
      )
      .join("\n")}`,
  );
}

function structuralIntegrityPolicy(): BlueprintPolicy {
  return {
    id: "structural-integrity",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const resourceIdsList = [
        ...blueprint.trustZones.map((entry) => entry.id),
        ...blueprint.networkDomains.map((entry) => entry.id),
        ...blueprint.workloadPlanes.map((entry) => entry.id),
        ...blueprint.applications.map((entry) => entry.id),
        ...blueprint.tenants.map((entry) => entry.tenantId),
        ...blueprint.dataBoundaries.map((entry) => entry.id),
        ...blueprint.identities.map((entry) => entry.id),
        ...blueprint.evidenceSinks.map((entry) => entry.id),
      ];
      const allIds = [
        ...resourceIdsList,
        ...blueprint.flows.map((entry) => entry.id),
        ...blueprint.grants.map((entry) => entry.id),
        ...blueprint.identityDelegations.map((entry) => entry.id),
        ...blueprint.evidenceRequirements.map((entry) => entry.id),
      ];
      const duplicates = duplicateValues(allIds);
      for (const duplicate of duplicates) {
        violations.push(
          violation(
            "CORE_DUPLICATE_ID",
            "critical",
            `Identifier '${duplicate}' is not globally unique.`,
          ),
        );
      }

      const zoneIds = new Set(blueprint.trustZones.map((zone) => zone.id));
      const resourceIds = new Set(resourceIdsList);
      const identityIds = new Set(
        blueprint.identities.map((identity) => identity.id),
      );
      for (const domain of blueprint.networkDomains) {
        if (!zoneIds.has(domain.zoneId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_ZONE",
              "critical",
              `Network domain '${domain.id}' references unknown zone '${domain.zoneId}'.`,
            ),
          );
        }
        if (
          !Number.isInteger(domain.availabilityZoneCount) ||
          domain.availabilityZoneCount < 1
        ) {
          violations.push(
            violation(
              "CORE_INVALID_RESILIENCE",
              "high",
              `Network domain '${domain.id}' must use at least one availability zone.`,
            ),
          );
        }
        for (const cidr of domain.cidrs) {
          try {
            parseCidr(cidr);
          } catch (error) {
            violations.push(
              violation(
                "CORE_INVALID_CIDR",
                "critical",
                error instanceof Error
                  ? error.message
                  : `Invalid CIDR '${cidr}'.`,
              ),
            );
          }
        }
      }

      const allocations = blueprint.networkDomains.flatMap((domain) =>
        domain.cidrs.map((cidr) => ({ domainId: domain.id, cidr })),
      );
      for (let left = 0; left < allocations.length; left++) {
        for (let right = left + 1; right < allocations.length; right++) {
          try {
            if (cidrsOverlap(allocations[left].cidr, allocations[right].cidr)) {
              violations.push(
                violation(
                  "CORE_OVERLAPPING_CIDR",
                  "critical",
                  `Network domains '${allocations[left].domainId}' (${allocations[left].cidr}) and '${allocations[right].domainId}' (${allocations[right].cidr}) overlap.`,
                ),
              );
            }
          } catch {
            // The invalid CIDR is already reported above.
          }
        }
      }

      for (const flow of blueprint.flows) {
        if (!zoneIds.has(flow.fromZoneId) || !zoneIds.has(flow.toZoneId)) {
          violations.push(
            violation(
              "CORE_INVALID_FLOW",
              "critical",
              `Flow '${flow.id}' references an unknown source or destination zone.`,
            ),
          );
        }
        for (const via of flow.viaZoneIds ?? []) {
          if (!zoneIds.has(via)) {
            violations.push(
              violation(
                "CORE_INVALID_FLOW_HOP",
                "critical",
                `Flow '${flow.id}' references unknown transit zone '${via}'.`,
              ),
            );
          }
        }
      }

      for (const workload of blueprint.workloadPlanes) {
        if (!zoneIds.has(workload.zoneId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_WORKLOAD_ZONE",
              "critical",
              `Workload plane '${workload.id}' references unknown zone '${workload.zoneId}'.`,
            ),
          );
        }
      }

      for (const grant of blueprint.grants) {
        if (!identityIds.has(grant.identityId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_IDENTITY",
              "critical",
              `Grant '${grant.id}' references unknown identity '${grant.identityId}'.`,
            ),
          );
        }
        for (const resourceId of grant.resourceIds) {
          if (!resourceIds.has(resourceId)) {
            violations.push(
              violation(
                "CORE_UNKNOWN_RESOURCE",
                "critical",
                `Grant '${grant.id}' references unknown resource '${resourceId}'.`,
              ),
            );
          }
        }
      }

      for (const delegation of blueprint.identityDelegations) {
        if (!identityIds.has(delegation.fromIdentityId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_DELEGATION_SOURCE",
              "critical",
              `Identity delegation '${delegation.id}' references unknown source identity '${delegation.fromIdentityId}'.`,
            ),
          );
        }
        if (!identityIds.has(delegation.toIdentityId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_DELEGATION_TARGET",
              "critical",
              `Identity delegation '${delegation.id}' references unknown target identity '${delegation.toIdentityId}'.`,
            ),
          );
        }
      }

      for (const requirement of blueprint.evidenceRequirements) {
        if (!resourceIds.has(requirement.sinkId)) {
          violations.push(
            violation(
              "CORE_UNKNOWN_EVIDENCE_SINK",
              "critical",
              `Evidence requirement '${requirement.id}' references unknown sink '${requirement.sinkId}'.`,
            ),
          );
        }
        for (const sourceId of requirement.sourceIds) {
          if (!resourceIds.has(sourceId)) {
            violations.push(
              violation(
                "CORE_UNKNOWN_EVIDENCE_SOURCE",
                "critical",
                `Evidence requirement '${requirement.id}' references unknown source '${sourceId}'.`,
              ),
            );
          }
        }
      }

      return violations;
    },
  };
}

function applicationDeploymentPolicy(): BlueprintPolicy {
  return {
    id: "application-deployments",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const workloads = new Map(
        blueprint.workloadPlanes.map((workload) => [workload.id, workload]),
      );
      const identities = new Map(
        blueprint.identities.map((identity) => [identity.id, identity]),
      );
      const boundaries = new Map(
        blueprint.dataBoundaries.map((boundary) => [boundary.id, boundary]),
      );
      const applications = new Map(
        blueprint.applications.map((application) => [
          application.id,
          application,
        ]),
      );
      for (const identityId of duplicateValues(
        blueprint.applications.map(
          (application) => application.serviceIdentityId,
        ),
      )) {
        violations.push(
          violation(
            "APP_SHARED_SERVICE_IDENTITY",
            "critical",
            `Service identity '${identityId}' cannot be shared by multiple application deployments.`,
          ),
        );
      }
      for (const boundaryId of duplicateValues(
        blueprint.applications.flatMap(
          (application) => application.dataBoundaryIds,
        ),
      )) {
        violations.push(
          violation(
            "APP_SHARED_DATA_BOUNDARY",
            "critical",
            `Data boundary '${boundaryId}' cannot be implicitly shared by multiple application deployments.`,
          ),
        );
      }
      for (const identityId of duplicateValues(
        blueprint.applications.flatMap((application) =>
          application.components.map(
            (component) => component.serviceIdentityId,
          ),
        ),
      )) {
        violations.push(
          violation(
            "APP_SHARED_COMPONENT_IDENTITY",
            "critical",
            `Component service identity '${identityId}' cannot be shared by multiple application components.`,
          ),
        );
      }
      for (const boundaryId of duplicateValues(
        blueprint.applications.flatMap((application) =>
          application.components.flatMap(
            (component) => component.dataBoundaryIds,
          ),
        ),
      )) {
        violations.push(
          violation(
            "APP_SHARED_COMPONENT_DATA",
            "critical",
            `Data boundary '${boundaryId}' cannot be implicitly shared by multiple application components.`,
          ),
        );
      }
      for (const application of blueprint.applications) {
        const workload = workloads.get(application.workloadPlaneId);
        if (!workload) {
          violations.push(
            violation(
              "APP_UNKNOWN_WORKLOAD_PLANE",
              "critical",
              `Application '${application.id}' references unknown workload plane '${application.workloadPlaneId}'.`,
            ),
          );
        } else if (
          JSON.stringify(workload.tenantScope) !==
          JSON.stringify(application.tenantScope)
        ) {
          violations.push(
            violation(
              "APP_SCOPE_MISMATCH",
              "critical",
              `Application '${application.id}' and its workload plane have different tenant scopes.`,
            ),
          );
        }
        const identity = identities.get(application.serviceIdentityId);
        if (!identity || identity.kind !== "workload" || !identity.shortLived) {
          violations.push(
            violation(
              "APP_IDENTITY_POSTURE",
              "critical",
              `Application '${application.id}' requires a short-lived workload service identity.`,
            ),
          );
        }
        const componentIds = application.components.map(
          (component) => component.id,
        );
        for (const duplicate of duplicateValues(componentIds)) {
          violations.push(
            violation(
              "APP_DUPLICATE_COMPONENT",
              "critical",
              `Application '${application.id}' has duplicate component '${duplicate}'.`,
            ),
          );
        }
        const componentData = [
          ...new Set(
            application.components.flatMap(
              (component) => component.dataBoundaryIds,
            ),
          ),
        ].sort();
        if (
          JSON.stringify(componentData) !==
          JSON.stringify([...application.dataBoundaryIds].sort())
        ) {
          violations.push(
            violation(
              "APP_COMPONENT_DATA_COVERAGE",
              "critical",
              `Application '${application.id}' data boundaries must exactly equal component-owned data boundaries.`,
            ),
          );
        }
        for (const component of application.components) {
          const componentWorkload = workloads.get(component.workloadPlaneId);
          if (
            !componentWorkload ||
            JSON.stringify(componentWorkload.tenantScope) !==
              JSON.stringify(application.tenantScope)
          ) {
            violations.push(
              violation(
                "APP_COMPONENT_WORKLOAD_POSTURE",
                "critical",
                `Application '${application.id}' component '${component.id}' requires a matching workload plane.`,
              ),
            );
          }
          const componentIdentity = identities.get(component.serviceIdentityId);
          if (
            !componentIdentity ||
            componentIdentity.kind !== "workload" ||
            !componentIdentity.shortLived
          ) {
            violations.push(
              violation(
                "APP_COMPONENT_IDENTITY_POSTURE",
                "critical",
                `Application '${application.id}' component '${component.id}' requires a short-lived workload identity.`,
              ),
            );
          }
          if (
            component.availability.minimumReplicas < 1 ||
            component.availability.maximumUnavailable >=
              component.availability.minimumReplicas
          ) {
            violations.push(
              violation(
                "APP_COMPONENT_AVAILABILITY_POSTURE",
                "high",
                `Application '${application.id}' component '${component.id}' must retain at least one available replica during disruption.`,
              ),
            );
          }
          for (const boundaryId of component.dataBoundaryIds) {
            const boundary = boundaries.get(boundaryId);
            if (
              !boundary ||
              JSON.stringify(boundary.tenantScope) !==
                JSON.stringify(application.tenantScope)
            ) {
              violations.push(
                violation(
                  "APP_COMPONENT_DATA_POSTURE",
                  "critical",
                  `Application '${application.id}' component '${component.id}' has invalid data boundary '${boundaryId}'.`,
                ),
              );
            }
          }
        }
        for (const boundaryId of application.dataBoundaryIds) {
          const boundary = boundaries.get(boundaryId);
          if (!boundary) {
            violations.push(
              violation(
                "APP_UNKNOWN_DATA_BOUNDARY",
                "critical",
                `Application '${application.id}' references unknown data boundary '${boundaryId}'.`,
              ),
            );
          } else if (
            JSON.stringify(boundary.tenantScope) !==
            JSON.stringify(application.tenantScope)
          ) {
            violations.push(
              violation(
                "APP_DATA_SCOPE_MISMATCH",
                "critical",
                `Application '${application.id}' cannot attach data boundary '${boundaryId}' with a different tenant scope.`,
              ),
            );
          }
        }
        const componentDependencyKeys = new Set<string>();
        for (const dependency of application.componentDependencies) {
          const key = `${dependency.fromComponentId}:${dependency.toComponentId}:${dependency.audience}`;
          if (
            dependency.fromComponentId === dependency.toComponentId ||
            !componentIds.includes(dependency.fromComponentId) ||
            !componentIds.includes(dependency.toComponentId) ||
            dependency.actions.length === 0 ||
            !dependency.audience ||
            componentDependencyKeys.has(key)
          ) {
            violations.push(
              violation(
                "APP_COMPONENT_DEPENDENCY_INVALID",
                "critical",
                `Application '${application.id}' has an invalid component dependency '${dependency.fromComponentId}' -> '${dependency.toComponentId}'.`,
              ),
            );
          }
          componentDependencyKeys.add(key);
        }
        if (
          application.availability.minimumReplicas < 2 ||
          application.availability.maximumUnavailable >=
            application.availability.minimumReplicas
        ) {
          violations.push(
            violation(
              "APP_AVAILABILITY_POSTURE",
              "high",
              `Application '${application.id}' must retain at least one available replica during disruption.`,
            ),
          );
        }
        if (
          !application.release.digestPinnedImages ||
          !application.release.signatureVerification ||
          !application.release.provenanceVerification ||
          !application.release.rollbackRequired
        ) {
          violations.push(
            violation(
              "APP_RELEASE_POSTURE",
              "critical",
              `Application '${application.id}' requires digest pinning, signature and provenance verification, and rollback.`,
            ),
          );
        }
        for (const dependency of application.dependencies) {
          const target = applications.get(dependency.deploymentId);
          if (
            dependency.deploymentId === application.id ||
            !target ||
            !componentIds.includes(dependency.fromComponentId) ||
            !target.components.some(
              (component) => component.id === dependency.toComponentId,
            ) ||
            dependency.actions.length === 0 ||
            !dependency.audience
          ) {
            violations.push(
              violation(
                "APP_DEPENDENCY_INVALID",
                "critical",
                `Application '${application.id}' has an invalid dependency on '${dependency.deploymentId}'.`,
              ),
            );
          }
        }
        const evidence = blueprint.evidenceRequirements.find(
          (requirement) =>
            requirement.sourceIds.includes(application.id) &&
            requirement.eventTypes.includes("deployment") &&
            requirement.eventTypes.includes("authorization"),
        );
        if (!evidence) {
          violations.push(
            violation(
              "APP_EVIDENCE_MISSING",
              "high",
              `Application '${application.id}' requires deployment and authorization evidence.`,
            ),
          );
        }
      }
      return violations;
    },
  };
}

function workloadPlanePolicy(): BlueprintPolicy {
  return {
    id: "workload-planes",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const zones = new Map(
        blueprint.trustZones.map((zone) => [zone.id, zone]),
      );
      const capabilities = new Set(blueprint.requiredCapabilities);

      for (const workload of blueprint.workloadPlanes) {
        const zone = zones.get(workload.zoneId);
        if (
          blueprint.posture.forbidPublicControlPlanes &&
          workload.controlPlanePublic
        ) {
          violations.push(
            violation(
              "WORKLOAD_PUBLIC_CONTROL_PLANE",
              "critical",
              `Workload plane '${workload.id}' must not expose its control plane publicly.`,
            ),
          );
        }

        if (!workload.workloadIdentity) {
          violations.push(
            violation(
              "WORKLOAD_IDENTITY_MISSING",
              "critical",
              `Workload plane '${workload.id}' must use workload identity.`,
            ),
          );
        }

        if (workload.executionTrust === "untrusted") {
          if (zone?.kind !== "execution") {
            violations.push(
              violation(
                "WORKLOAD_UNTRUSTED_ZONE",
                "critical",
                `Untrusted workload plane '${workload.id}' must be placed in an execution trust zone.`,
              ),
            );
          }
          if (workload.credentialMode !== "brokered") {
            violations.push(
              violation(
                "WORKLOAD_UNBROKERED_CREDENTIALS",
                "critical",
                `Untrusted workload plane '${workload.id}' must use brokered credentials.`,
              ),
            );
          }
          if (
            workload.runtimeIsolation !== "microvm" &&
            workload.runtimeIsolation !== "dedicated-vm"
          ) {
            violations.push(
              violation(
                "WORKLOAD_WEAK_RUNTIME_ISOLATION",
                "critical",
                `Untrusted workload plane '${workload.id}' requires microVM or dedicated-VM isolation.`,
              ),
            );
          }
          if (!workload.maxExecutionMinutes) {
            violations.push(
              violation(
                "WORKLOAD_UNBOUNDED_EXECUTION",
                "high",
                `Untrusted workload plane '${workload.id}' must declare a maximum execution duration.`,
              ),
            );
          }
        } else if (workload.credentialMode === "ambient") {
          violations.push(
            violation(
              "WORKLOAD_AMBIENT_CREDENTIALS",
              "critical",
              `Workload plane '${workload.id}' must not use ambient credentials.`,
            ),
          );
        }

        const required = workloadCapabilities(workload);
        for (const capability of required) {
          if (!capabilities.has(capability)) {
            violations.push(
              violation(
                "WORKLOAD_CAPABILITY_UNDECLARED",
                "critical",
                `Workload plane '${workload.id}' requires capability '${capability}', but the blueprint does not declare it.`,
              ),
            );
          }
        }
      }

      return violations;
    },
  };
}

function workloadCapabilities(
  workload: PlatformBlueprint["workloadPlanes"][number],
): PlatformBlueprint["requiredCapabilities"] {
  const required: PlatformBlueprint["requiredCapabilities"][number][] = [];
  if (workload.workloadIdentity) required.push("workload-identity");
  if (
    workload.orchestrator === "managed-kubernetes" &&
    !workload.controlPlanePublic
  ) {
    required.push("private-control-plane");
  }
  if (
    workload.orchestrator === "microvm" ||
    workload.runtimeIsolation === "microvm"
  ) {
    required.push("microvm-runtime");
  }
  if (workload.orchestrator === "external-sandbox") {
    required.push("external-sandbox");
  }
  if (workload.orchestrator === "serverless") {
    required.push("serverless-runtime");
  }
  return required;
}

function networkBoundaryPolicy(): BlueprintPolicy {
  return {
    id: "network-boundaries",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const zones = new Map(
        blueprint.trustZones.map((zone) => [zone.id, zone]),
      );
      const domainsByZone = groupBy(
        blueprint.networkDomains,
        (domain) => domain.zoneId,
      );

      if (blueprint.posture.forbidPublicControlPlanes) {
        for (const zone of blueprint.trustZones) {
          if (
            (zone.kind === "control-plane" || zone.kind === "data") &&
            zone.publicAccess
          ) {
            violations.push(
              violation(
                "NET_PUBLIC_TRUSTED_ZONE",
                "critical",
                `Trusted zone '${zone.id}' must not be public.`,
              ),
            );
          }
        }
      }

      for (const domain of blueprint.networkDomains) {
        const zone = zones.get(domain.zoneId);
        if (
          domain.directInternetAccess &&
          zone?.kind !== "egress" &&
          zone?.kind !== "edge"
        ) {
          violations.push(
            violation(
              "NET_DIRECT_INTERNET",
              "critical",
              `Network domain '${domain.id}' has direct internet access outside an edge or egress zone.`,
            ),
          );
        }
      }

      if (blueprint.posture.requireInspectedEgress) {
        if (
          !blueprint.networkDomains.some((domain) => domain.inspectedEgress)
        ) {
          violations.push(
            violation(
              "NET_INSPECTION_MISSING",
              "critical",
              "The blueprint requires inspected egress but declares no inspected network domain.",
            ),
          );
        }
        for (const flow of blueprint.flows) {
          const destination = zones.get(flow.toZoneId);
          if (destination?.kind !== "external") continue;
          if ((flow.externalDestinations ?? []).length === 0) {
            violations.push(
              violation(
                "NET_EMPTY_EGRESS_ALLOWLIST",
                "critical",
                `External flow '${flow.id}' must declare approved destinations.`,
              ),
            );
          }
          const inspected = (flow.viaZoneIds ?? []).some((zoneId) =>
            (domainsByZone.get(zoneId) ?? []).some(
              (domain) => domain.inspectedEgress,
            ),
          );
          if (!inspected) {
            violations.push(
              violation(
                "NET_UNINSPECTED_EGRESS",
                "critical",
                `External flow '${flow.id}' does not traverse an inspected egress zone.`,
              ),
            );
          }
        }
      }

      for (const flow of blueprint.flows) {
        const source = zones.get(flow.fromZoneId);
        const destination = zones.get(flow.toZoneId);
        if (
          source?.kind === "execution" &&
          (destination?.kind === "control-plane" ||
            destination?.kind === "data") &&
          flow.authorization !== "brokered"
        ) {
          violations.push(
            violation(
              "NET_EXECUTION_BYPASS",
              "critical",
              `Execution flow '${flow.id}' into '${destination.kind}' must be brokered.`,
            ),
          );
        }
      }

      return violations;
    },
  };
}

function tenantIsolationPolicy(): BlueprintPolicy {
  return {
    id: "tenant-isolation",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const zoneById = new Map(
        blueprint.trustZones.map((zone) => [zone.id, zone]),
      );
      const dataById = new Map(
        blueprint.dataBoundaries.map((data) => [data.id, data]),
      );
      const identityById = new Map(
        blueprint.identities.map((identity) => [identity.id, identity]),
      );

      for (const tenant of blueprint.tenants) {
        if (
          tenant.zoneIds.length === 0 ||
          tenant.dataBoundaryIds.length === 0
        ) {
          violations.push(
            violation(
              "TENANT_INCOMPLETE_PLACEMENT",
              "critical",
              `Tenant '${tenant.tenantId}' must have compute/network and data placement.`,
            ),
          );
        }

        for (const zoneId of tenant.zoneIds) {
          if (
            !scopeContainsTenant(
              zoneById.get(zoneId)?.tenantScope,
              tenant.tenantId,
            )
          ) {
            violations.push(
              violation(
                "TENANT_ZONE_SCOPE_MISMATCH",
                "critical",
                `Zone '${zoneId}' does not include tenant '${tenant.tenantId}'.`,
              ),
            );
          }
        }
        for (const dataId of tenant.dataBoundaryIds) {
          if (
            !scopeContainsTenant(
              dataById.get(dataId)?.tenantScope,
              tenant.tenantId,
            )
          ) {
            violations.push(
              violation(
                "TENANT_DATA_SCOPE_MISMATCH",
                "critical",
                `Data boundary '${dataId}' does not include tenant '${tenant.tenantId}'.`,
              ),
            );
          }
        }
        for (const identityId of tenant.identityIds) {
          if (identityById.get(identityId)?.tenantId !== tenant.tenantId) {
            violations.push(
              violation(
                "TENANT_IDENTITY_SCOPE_MISMATCH",
                "critical",
                `Identity '${identityId}' is not scoped to tenant '${tenant.tenantId}'.`,
              ),
            );
          }
        }

        if (tenant.isolationTier === "dedicated-account") {
          const zones = tenant.zoneIds.map((zoneId) => zoneById.get(zoneId));
          if (
            zones.some(
              (zone) =>
                !zone?.isolationBoundary ||
                zone.tenantScope.mode !== "dedicated",
            )
          ) {
            violations.push(
              violation(
                "TENANT_ACCOUNT_BOUNDARY_MISSING",
                "critical",
                `Dedicated-account tenant '${tenant.tenantId}' must use dedicated zones with explicit isolation boundaries.`,
              ),
            );
          }
          const boundaries = tenant.dataBoundaryIds.map((id) =>
            dataById.get(id),
          );
          if (
            boundaries.some(
              (boundary) => !boundary?.encryption.dedicatedPerTenant,
            )
          ) {
            violations.push(
              violation(
                "TENANT_DEDICATED_KEY_MISSING",
                "critical",
                `Dedicated-account tenant '${tenant.tenantId}' must use tenant-dedicated encryption.`,
              ),
            );
          }
        }
      }

      return violations;
    },
  };
}

function dataProtectionPolicy(): BlueprintPolicy {
  return {
    id: "data-protection",
    evaluate: ({ blueprint }) =>
      blueprint.dataBoundaries.flatMap((boundary) => dataViolations(boundary)),
  };
}

function dataViolations(boundary: DataBoundary): BlueprintViolation[] {
  const violations: BlueprintViolation[] = [];
  if (boundary.services.length === 0) {
    violations.push(
      violation(
        "DATA_SERVICE_MISSING",
        "high",
        `Data boundary '${boundary.id}' must declare at least one data service.`,
      ),
    );
  }
  if (
    boundary.recovery.backupRequired &&
    boundary.recovery.restoreTestIntervalDays < 1
  ) {
    violations.push(
      violation(
        "DATA_RESTORE_TEST_MISSING",
        "critical",
        `Data boundary '${boundary.id}' cannot require backups without a restore-test cadence.`,
      ),
    );
  }
  if (
    boundary.classification === "public" ||
    boundary.classification === "internal"
  )
    return violations;
  if (
    !boundary.encryption.customerManagedKey ||
    !boundary.encryption.rotationRequired
  ) {
    violations.push(
      violation(
        "DATA_ENCRYPTION_POSTURE",
        "critical",
        `Data boundary '${boundary.id}' requires a rotating customer-managed key.`,
      ),
    );
  }
  if (
    boundary.classification === "regulated" &&
    !boundary.encryption.dedicatedPerTenant
  ) {
    violations.push(
      violation(
        "DATA_REGULATED_SHARED_KEY",
        "critical",
        `Regulated data boundary '${boundary.id}' requires tenant-dedicated encryption.`,
      ),
    );
  }
  if (!boundary.deletionEvidenceRequired) {
    violations.push(
      violation(
        "DATA_DELETION_EVIDENCE",
        "high",
        `Data boundary '${boundary.id}' must emit deletion evidence.`,
      ),
    );
  }
  if (
    (boundary.services.includes("object") && !boundary.versioningRequired) ||
    boundary.retentionDays < 1
  ) {
    violations.push(
      violation(
        "DATA_RETENTION_POSTURE",
        "high",
        `Data boundary '${boundary.id}' requires versioning and a positive retention period.`,
      ),
    );
  }
  if (boundary.services.includes("object") && !boundary.objectAuditRequired) {
    violations.push(
      violation(
        "DATA_OBJECT_AUDIT_MISSING",
        "critical",
        `Data boundary '${boundary.id}' must require object-level access evidence.`,
      ),
    );
  }
  if (!boundary.exportEvidenceRequired) {
    violations.push(
      violation(
        "DATA_EXPORT_EVIDENCE",
        "high",
        `Data boundary '${boundary.id}' must emit export evidence.`,
      ),
    );
  }
  if (
    !boundary.recovery.backupRequired ||
    !boundary.recovery.deletionProtectionRequired ||
    !boundary.recovery.finalSnapshotRequired ||
    !boundary.recovery.multiAzRequired
  ) {
    violations.push(
      violation(
        "DATA_RECOVERY_POSTURE",
        "critical",
        `Confidential data boundary '${boundary.id}' requires protected backups, multi-AZ availability, deletion protection, and a final recovery point.`,
      ),
    );
  }
  return violations;
}

function identityPolicy(): BlueprintPolicy {
  return {
    id: "identity",
    evaluate: ({ blueprint }) => {
      const violations: BlueprintViolation[] = [];
      const dataById = new Map(
        blueprint.dataBoundaries.map((data) => [data.id, data]),
      );
      for (const identity of blueprint.identities) {
        if (!identity.shortLived) {
          violations.push(
            violation(
              "IDENTITY_LONG_LIVED",
              "critical",
              `Identity '${identity.id}' must use short-lived credentials.`,
            ),
          );
        }
      }
      for (const grant of blueprint.grants) {
        if (grant.effect !== "allow" || !grant.tenantId) continue;
        const identity = blueprint.identities.find(
          (entry) => entry.id === grant.identityId,
        );
        if (identity?.tenantId !== grant.tenantId) {
          violations.push(
            violation(
              "IDENTITY_GRANT_SCOPE_MISMATCH",
              "critical",
              `Grant '${grant.id}' tenant scope does not match identity '${grant.identityId}'.`,
            ),
          );
        }
        for (const resourceId of grant.resourceIds) {
          const boundary = dataById.get(resourceId);
          if (
            boundary &&
            !scopeContainsTenant(boundary.tenantScope, grant.tenantId)
          ) {
            violations.push(
              violation(
                "IDENTITY_CROSS_TENANT_GRANT",
                "critical",
                `Grant '${grant.id}' crosses the tenant boundary for '${grant.tenantId}'.`,
              ),
            );
          }
        }
      }
      const identities = new Map(
        blueprint.identities.map((identity) => [identity.id, identity]),
      );
      const grants = new Map(
        blueprint.grants.map((grant) => [grant.id, grant]),
      );
      const resourceTenants = tenantScopesByResource(blueprint);
      for (const entitlement of analyzeEntitlements(blueprint).entitlements) {
        if (entitlement.decision !== "allow") continue;
        const principalTenant = identities.get(
          entitlement.principalId,
        )?.tenantId;
        const targetTenants = resourceTenants.get(entitlement.resourceId) ?? [];
        if (
          !principalTenant ||
          targetTenants.length === 0 ||
          targetTenants.includes(principalTenant)
        ) {
          continue;
        }
        const grant = grants.get(entitlement.grantId);
        if (
          grant?.exception &&
          validAccessException(
            grant.exception,
            entitlement.resourceId,
            blueprint,
          )
        ) {
          continue;
        }
        violations.push(
          violation(
            "IDENTITY_CROSS_TENANT_PATH",
            "critical",
            `Identity '${entitlement.principalId}' reaches tenant-scoped resource '${entitlement.resourceId}' through ${entitlement.viaIdentityIds.join(" -> ")}.`,
          ),
        );
      }
      for (const delegation of blueprint.identityDelegations) {
        const source = identities.get(delegation.fromIdentityId);
        if (
          source?.kind === "vendor" &&
          (!delegation.conditions?.audience ||
            !delegation.conditions?.externalSubject)
        ) {
          violations.push(
            violation(
              "IDENTITY_VENDOR_CONFUSED_DEPUTY",
              "critical",
              `Vendor delegation '${delegation.id}' must bind both audience and externalSubject.`,
            ),
          );
        }
      }
      for (const grant of blueprint.grants) {
        if (
          grant.effect === "allow" &&
          grant.actions.some(
            (action) =>
              action === "*" || action === "*:*" || action.endsWith(":*"),
          )
        ) {
          violations.push(
            violation(
              "IDENTITY_WILDCARD_GRANT",
              "critical",
              `Allow grant '${grant.id}' must not use wildcard actions.`,
            ),
          );
        }
      }
      return violations;
    },
  };
}

function tenantScopesByResource(
  blueprint: PlatformBlueprint,
): Map<string, readonly string[]> {
  const scopes = new Map<string, readonly string[]>();
  for (const boundary of blueprint.dataBoundaries) {
    scopes.set(boundary.id, tenantIdsFromScope(boundary.tenantScope));
  }
  for (const workload of blueprint.workloadPlanes) {
    scopes.set(workload.id, tenantIdsFromScope(workload.tenantScope));
  }
  for (const zone of blueprint.trustZones) {
    scopes.set(zone.id, tenantIdsFromScope(zone.tenantScope));
  }
  return scopes;
}

function tenantIdsFromScope(scope: TenantScope): readonly string[] {
  if (scope.mode === "dedicated") return [scope.tenantId];
  if (scope.mode === "pooled") return scope.tenantIds;
  return [];
}

function validAccessException(
  exception: NonNullable<PlatformBlueprint["grants"][number]["exception"]>,
  resourceId: string,
  blueprint: PlatformBlueprint,
): boolean {
  if (Date.parse(exception.expiresAt) <= Date.now()) return false;
  return blueprint.evidenceRequirements.some(
    (requirement) =>
      requirement.id === exception.auditRequirementId &&
      requirement.sourceIds.includes(resourceId),
  );
}

function evidencePolicy(): BlueprintPolicy {
  return {
    id: "evidence",
    evaluate: ({ blueprint }) => {
      if (!blueprint.posture.requireImmutableAudit) return [];
      const violations: BlueprintViolation[] = [];
      if (blueprint.evidenceSinks.length === 0) {
        violations.push(
          violation(
            "EVIDENCE_SINK_MISSING",
            "critical",
            "The blueprint requires immutable audit evidence but declares no evidence sink.",
          ),
        );
      }
      const sinks = new Map(
        blueprint.evidenceSinks.map((sink) => [sink.id, sink]),
      );
      const coveredSources = new Set(
        blueprint.evidenceRequirements.flatMap(
          (requirement) => requirement.sourceIds,
        ),
      );
      for (const requirement of blueprint.evidenceRequirements) {
        const sink = sinks.get(requirement.sinkId);
        if (!sink) {
          violations.push(
            violation(
              "EVIDENCE_UNKNOWN_SINK",
              "critical",
              `Evidence requirement '${requirement.id}' references unknown sink '${requirement.sinkId}'.`,
            ),
          );
        } else if (
          !sink.immutable ||
          sink.retentionDays < blueprint.posture.minimumAuditRetentionDays
        ) {
          violations.push(
            violation(
              "EVIDENCE_WEAK_SINK",
              "critical",
              `Evidence sink '${sink.id}' must be immutable and retain evidence for at least ${blueprint.posture.minimumAuditRetentionDays} days.`,
            ),
          );
        }
      }
      for (const boundary of blueprint.dataBoundaries) {
        if (
          boundary.classification !== "public" &&
          !coveredSources.has(boundary.id)
        ) {
          violations.push(
            violation(
              "EVIDENCE_DATA_NOT_COVERED",
              "critical",
              `Data boundary '${boundary.id}' is not connected to an evidence requirement.`,
            ),
          );
        }
      }
      return violations;
    },
  };
}

function scopeContainsTenant(
  scope: TenantScope | undefined,
  tenantId: string,
): boolean {
  if (!scope || scope.mode === "platform") return false;
  if (scope.mode === "dedicated") return scope.tenantId === tenantId;
  return scope.tenantIds.includes(tenantId);
}

function duplicateValues(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) duplicates.add(value);
    seen.add(value);
  }
  return [...duplicates];
}

function groupBy<T>(
  values: readonly T[],
  key: (value: T) => string,
): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const value of values) {
    const groupKey = key(value);
    groups.set(groupKey, [...(groups.get(groupKey) ?? []), value]);
  }
  return groups;
}

function violation(
  code: string,
  severity: ViolationSeverity,
  message: string,
): BlueprintViolation {
  return { code, severity, message };
}

function deduplicateViolations(
  violations: readonly BlueprintViolation[],
): BlueprintViolation[] {
  const seen = new Set<string>();
  return violations.filter((entry) => {
    const key = `${entry.code}:${entry.path ?? entry.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function internetFacingDomains(
  blueprint: PlatformBlueprint,
): readonly NetworkDomain[] {
  return blueprint.networkDomains.filter(
    (domain) => domain.directInternetAccess,
  );
}
