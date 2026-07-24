export type AwsEksAccessPolicy = "cluster-admin" | "admin" | "edit" | "view";

export type AwsEksAccessPrincipal =
  | {
      kind: "identity-center-permission-set";
      category: "workforce" | "break-glass";
      permissionSetName: string;
    }
  | {
      kind: "iam-role";
      category: "workforce" | "automation" | "break-glass";
      roleArn: string;
    };

export interface AwsEksAccessGrantConfig {
  id: string;
  principal: AwsEksAccessPrincipal;
  accessPolicy: AwsEksAccessPolicy;
  scope:
    | { type: "cluster" }
    | { type: "namespace"; namespaces: readonly string[] };
}

export interface AwsEksAccessGrantPlan {
  id: string;
  principal:
    | {
        kind: "identity-center-permission-set";
        category: "workforce" | "break-glass";
        permissionSetName: string;
        roleNameRegex: string;
        rolePathPrefix: "/aws-reserved/sso.amazonaws.com/";
      }
    | {
        kind: "iam-role";
        category: "workforce" | "automation" | "break-glass";
        roleArn: string;
      };
  accessPolicy: AwsEksAccessPolicy;
  policyArn: string;
  scope:
    | { type: "cluster" }
    | { type: "namespace"; namespaces: readonly string[] };
}

const policyNames: Readonly<Record<AwsEksAccessPolicy, string>> = {
  "cluster-admin": "AmazonEKSClusterAdminPolicy",
  admin: "AmazonEKSAdminPolicy",
  edit: "AmazonEKSEditPolicy",
  view: "AmazonEKSViewPolicy",
};

const reservedNamespaces = new Set([
  "argocd",
  "kube-node-lease",
  "kube-public",
  "kube-system",
  "kyverno",
]);

export function compileAwsEksAccessGrants(
  input: readonly AwsEksAccessGrantConfig[],
): readonly AwsEksAccessGrantPlan[] {
  if (!Array.isArray(input)) {
    throw new Error("EKS_ACCESS_INVALID accessGrants must be an array.");
  }
  const ids = new Set<string>();
  const principals = new Set<string>();
  const plans = input.map((grant, index) => {
    exactKeys(
      grant,
      ["id", "principal", "accessPolicy", "scope"],
      `accessGrants[${index}]`,
    );
    const id = dnsLabel(grant.id, `accessGrants[${index}].id`);
    if (ids.has(id)) {
      throw new Error(
        `EKS_ACCESS_DUPLICATE duplicate access grant id '${id}'.`,
      );
    }
    ids.add(id);
    const accessPolicy = oneOf(
      grant.accessPolicy,
      ["cluster-admin", "admin", "edit", "view"] as const,
      `accessGrants[${index}].accessPolicy`,
    );
    const principal = normalizePrincipal(grant.principal, index);
    const principalKey =
      principal.kind === "identity-center-permission-set"
        ? `${principal.kind}/${principal.permissionSetName}`
        : `${principal.kind}/${principal.roleArn}`;
    if (principals.has(principalKey)) {
      throw new Error(
        `EKS_ACCESS_DUPLICATE principal '${principalKey}' has more than one EKS access entry.`,
      );
    }
    principals.add(principalKey);
    const scope = normalizeScope(grant.scope, accessPolicy, index);
    if (
      accessPolicy === "cluster-admin" &&
      principal.category === "automation"
    ) {
      throw new Error(
        "EKS_ACCESS_AUTOMATION_ADMIN_DENIED automation cannot receive EKS cluster-admin.",
      );
    }
    return {
      id,
      principal,
      accessPolicy,
      policyArn: `arn:aws:eks::aws:cluster-access-policy/${policyNames[accessPolicy]}`,
      scope,
    } satisfies AwsEksAccessGrantPlan;
  });
  return plans.sort((left, right) => left.id.localeCompare(right.id));
}

export function hasAwsEksClusterAdministrator(
  input: readonly AwsEksAccessGrantConfig[],
): boolean {
  return compileAwsEksAccessGrants(input).some(
    (grant) =>
      grant.accessPolicy === "cluster-admin" && grant.scope.type === "cluster",
  );
}

function normalizePrincipal(
  input: AwsEksAccessPrincipal,
  index: number,
): AwsEksAccessGrantPlan["principal"] {
  if (input?.kind === "identity-center-permission-set") {
    exactKeys(
      input,
      ["kind", "category", "permissionSetName"],
      `accessGrants[${index}].principal`,
    );
    const category = oneOf(
      input.category,
      ["workforce", "break-glass"] as const,
      `accessGrants[${index}].principal.category`,
    );
    const permissionSetName = permissionSet(
      input.permissionSetName,
      `accessGrants[${index}].principal.permissionSetName`,
    );
    return {
      kind: "identity-center-permission-set",
      category,
      permissionSetName,
      roleNameRegex: `^AWSReservedSSO_${escapeRegex(permissionSetName)}_[A-Fa-f0-9]{16}$`,
      rolePathPrefix: "/aws-reserved/sso.amazonaws.com/",
    };
  }
  if (input?.kind === "iam-role") {
    exactKeys(
      input,
      ["kind", "category", "roleArn"],
      `accessGrants[${index}].principal`,
    );
    return {
      kind: "iam-role",
      category: oneOf(
        input.category,
        ["workforce", "automation", "break-glass"] as const,
        `accessGrants[${index}].principal.category`,
      ),
      roleArn: roleArn(
        input.roleArn,
        `accessGrants[${index}].principal.roleArn`,
      ),
    };
  }
  throw new Error(
    `EKS_ACCESS_PRINCIPAL_DENIED accessGrants[${index}].principal.kind is unsupported.`,
  );
}

function normalizeScope(
  input: AwsEksAccessGrantConfig["scope"],
  policy: AwsEksAccessPolicy,
  index: number,
): AwsEksAccessGrantPlan["scope"] {
  if (input?.type === "cluster") {
    exactKeys(input, ["type"], `accessGrants[${index}].scope`);
    if (policy === "admin" || policy === "edit") {
      throw new Error(
        `EKS_ACCESS_SCOPE_DENIED '${policy}' must be namespace-scoped; use an explicit cluster-admin grant for whole-cluster authority.`,
      );
    }
    return { type: "cluster" };
  }
  if (input?.type === "namespace") {
    exactKeys(input, ["type", "namespaces"], `accessGrants[${index}].scope`);
    if (policy === "cluster-admin") {
      throw new Error(
        "EKS_ACCESS_SCOPE_DENIED cluster-admin must use cluster scope.",
      );
    }
    if (!Array.isArray(input.namespaces) || input.namespaces.length === 0) {
      throw new Error(
        `EKS_ACCESS_SCOPE_DENIED accessGrants[${index}] needs at least one exact namespace.`,
      );
    }
    const namespaces = input.namespaces
      .map((namespace, namespaceIndex) =>
        dnsLabel(
          namespace,
          `accessGrants[${index}].scope.namespaces[${namespaceIndex}]`,
        ),
      )
      .sort();
    if (new Set(namespaces).size !== namespaces.length) {
      throw new Error(
        `EKS_ACCESS_SCOPE_DENIED accessGrants[${index}] has duplicate namespaces.`,
      );
    }
    if (namespaces.some((namespace) => reservedNamespaces.has(namespace))) {
      throw new Error(
        `EKS_ACCESS_SYSTEM_NAMESPACE_DENIED accessGrants[${index}] cannot target a reserved control-plane namespace.`,
      );
    }
    return { type: "namespace", namespaces };
  }
  throw new Error(
    `EKS_ACCESS_SCOPE_DENIED accessGrants[${index}].scope.type is unsupported.`,
  );
}

function exactKeys(value: unknown, keys: readonly string[], path: string) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`EKS_ACCESS_INVALID ${path} must be an exact object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `EKS_ACCESS_INVALID ${path} must contain exactly: ${expected.join(", ")}.`,
    );
  }
}

function oneOf<T extends string>(
  value: string,
  values: readonly T[],
  path: string,
): T {
  if (!values.includes(value as T)) {
    throw new Error(
      `EKS_ACCESS_INVALID ${path} must be one of: ${values.join(", ")}.`,
    );
  }
  return value as T;
}

function dnsLabel(value: string, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value)
  ) {
    throw new Error(`EKS_ACCESS_INVALID ${path} must be one exact DNS label.`);
  }
  return value;
}

function permissionSet(value: string, path: string): string {
  if (
    typeof value !== "string" ||
    value.length > 64 ||
    !/^[A-Za-z0-9+=,.@_-]+$/.test(value) ||
    /placeholder/i.test(value)
  ) {
    throw new Error(
      `EKS_ACCESS_INVALID ${path} must be an exact IAM Identity Center permission-set name.`,
    );
  }
  return value;
}

function roleArn(value: string, path: string): string {
  if (
    typeof value !== "string" ||
    !/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.includes("..") ||
    /placeholder/i.test(value)
  ) {
    throw new Error(
      `EKS_ACCESS_INVALID ${path} must be one exact IAM role ARN.`,
    );
  }
  return value;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
