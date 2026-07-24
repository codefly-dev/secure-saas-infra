import { IdentityGrant, PlatformBlueprint } from "./model";

export interface EffectiveEntitlement {
  principalId: string;
  effectiveIdentityId: string;
  viaIdentityIds: readonly string[];
  delegationIds: readonly string[];
  delegationConditions: readonly Readonly<Record<string, string>>[];
  grantId: string;
  resourceId: string;
  action: string;
  tenantId?: string;
  decision: "allow" | "deny";
  deniedByGrantIds: readonly string[];
  grantConditions?: Readonly<Record<string, string>>;
}

export interface EntitlementAnalysis {
  entitlements: readonly EffectiveEntitlement[];
}

interface ReachableIdentity {
  identityId: string;
  viaIdentityIds: readonly string[];
  delegationIds: readonly string[];
  delegationConditions: readonly Readonly<Record<string, string>>[];
}

export function analyzeEntitlements(
  blueprint: PlatformBlueprint,
): EntitlementAnalysis {
  const delegations = new Map<
    string,
    Array<{
      id: string;
      toIdentityId: string;
      conditions?: Readonly<Record<string, string>>;
    }>
  >();
  for (const delegation of blueprint.identityDelegations) {
    delegations.set(delegation.fromIdentityId, [
      ...(delegations.get(delegation.fromIdentityId) ?? []),
      {
        id: delegation.id,
        toIdentityId: delegation.toIdentityId,
        conditions: delegation.conditions,
      },
    ]);
  }

  const grantsByIdentity = new Map<string, IdentityGrant[]>();
  for (const grant of blueprint.grants) {
    grantsByIdentity.set(grant.identityId, [
      ...(grantsByIdentity.get(grant.identityId) ?? []),
      grant,
    ]);
  }

  const entitlements: EffectiveEntitlement[] = [];
  for (const principal of blueprint.identities) {
    const reachable = reachableIdentities(principal.id, delegations);
    const allDenies = reachable.flatMap((entry) =>
      (grantsByIdentity.get(entry.identityId) ?? []).filter(
        (grant) => grant.effect === "deny",
      ),
    );
    for (const reachableIdentity of reachable) {
      const grants = grantsByIdentity.get(reachableIdentity.identityId) ?? [];
      const allows = grants.filter((grant) => grant.effect === "allow");

      for (const allow of allows) {
        for (const resourceId of allow.resourceIds) {
          for (const action of allow.actions) {
            const deniedBy = [
              ...new Set(
                allDenies
                  .filter(
                    (deny) =>
                      resourceMatches(deny.resourceIds, resourceId) &&
                      actionMatches(deny.actions, action),
                  )
                  .map((deny) => deny.id),
              ),
            ];
            entitlements.push({
              principalId: principal.id,
              effectiveIdentityId: reachableIdentity.identityId,
              viaIdentityIds: reachableIdentity.viaIdentityIds,
              delegationIds: reachableIdentity.delegationIds,
              delegationConditions: reachableIdentity.delegationConditions,
              grantId: allow.id,
              resourceId,
              action,
              tenantId: allow.tenantId,
              decision: deniedBy.length > 0 ? "deny" : "allow",
              deniedByGrantIds: deniedBy,
              grantConditions: allow.conditions,
            });
          }
        }
      }
    }
  }

  return { entitlements };
}

function reachableIdentities(
  principalId: string,
  delegations: ReadonlyMap<
    string,
    readonly {
      id: string;
      toIdentityId: string;
      conditions?: Readonly<Record<string, string>>;
    }[]
  >,
): ReachableIdentity[] {
  const reachable: ReachableIdentity[] = [];
  const queue: ReachableIdentity[] = [
    {
      identityId: principalId,
      viaIdentityIds: [principalId],
      delegationIds: [],
      delegationConditions: [],
    },
  ];
  const maxPaths = 1_000;

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reachable.length >= maxPaths) {
      throw new Error(
        `Entitlement analysis exceeded ${maxPaths} delegation paths from '${principalId}'; reduce graph complexity before deployment.`,
      );
    }
    reachable.push(current);

    for (const delegation of delegations.get(current.identityId) ?? []) {
      if (current.viaIdentityIds.includes(delegation.toIdentityId)) continue;
      queue.push({
        identityId: delegation.toIdentityId,
        viaIdentityIds: [...current.viaIdentityIds, delegation.toIdentityId],
        delegationIds: [...current.delegationIds, delegation.id],
        delegationConditions: [
          ...current.delegationConditions,
          delegation.conditions ?? {},
        ],
      });
    }
  }

  return reachable;
}

function resourceMatches(
  resources: readonly string[],
  requested: string,
): boolean {
  return resources.includes("*") || resources.includes(requested);
}

function actionMatches(actions: readonly string[], requested: string): boolean {
  return actions.some((action) => {
    if (action === "*" || action === "*:*" || action === requested) return true;
    if (!action.endsWith(":*")) return false;
    return requested.startsWith(action.slice(0, -1));
  });
}
