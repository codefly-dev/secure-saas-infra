import { createHash } from "node:crypto";
import {
  assertPaasSecurityIntent,
  PAAS_CONTROL_STATE_API_VERSION,
  type PaasIdentityRole,
  type PaasOperation,
  type PaasSecurityIntent,
} from "../../core";

export interface CodeflyPaasTenantBoundaryPlan {
  tenantId: string;
  namespaces: {
    builder: string;
    runtime: string;
    egress: string;
  };
  serviceAccounts: {
    builder: string;
    deployer: string;
    runtime: string;
    egress: string;
  };
  quota: {
    maxConcurrentBuilds: number;
    maxConcurrentDeployments: number;
    maxCpu: string;
    maxMemory: string;
    maxStorage: string;
    maxExecutionMinutes: number;
  };
  builderRuntimeClass: "deus-microvm" | "deus-dedicated-vm";
  runtimeClass?: "deus-microvm" | "deus-dedicated-vm";
}

export interface CodeflyPaasControlPlanePlan {
  apiVersion: "paas.codefly.dev/control-plane/v1alpha1";
  intentDigest: string;
  name: string;
  environment: string;
  controlStateApiVersion: typeof PAAS_CONTROL_STATE_API_VERSION;
  systemNamespace: string;
  globalServiceAccounts: Readonly<
    Record<"control-plane" | "registry" | "audit", string>
  >;
  endpoints: readonly {
    id: string;
    exposure: "private" | "public";
    authentication: "oidc" | "mtls" | "oidc+mtls";
    authorization: "rbac" | "capability";
    operations: readonly PaasOperation[];
    tenantBindingRequired: true;
    directHostExecution: false;
    executionTarget: "control-plane" | "tenant-sandbox";
  }[];
  accessControl: PaasSecurityIntent["accessControl"];
  tenants: readonly CodeflyPaasTenantBoundaryPlan[];
  scheduling: PaasSecurityIntent["scheduling"];
  supplyChain: PaasSecurityIntent["supplyChain"];
  deploymentState: PaasSecurityIntent["deploymentState"];
  audit: PaasSecurityIntent["audit"];
}

export type CodeflyPaasControlPlaneArtifacts = Readonly<Record<string, string>>;

export function compileCodeflyPaasControlPlane(
  intent: PaasSecurityIntent,
): CodeflyPaasControlPlanePlan {
  assertPaasSecurityIntent(intent);
  const intentDigest = digest(intent);
  const identities = new Map(
    intent.identities.map((identity) => [identity.role, identity]),
  );
  const globalIdentity = (role: "control-plane" | "registry" | "audit") =>
    dnsLabel(identities.get(role)!.id);
  const tenants = [...intent.tenants]
    .sort((left, right) => left.tenantId.localeCompare(right.tenantId))
    .map((tenant): CodeflyPaasTenantBoundaryPlan => {
      const tenantLabel = dnsLabel(tenant.tenantId);
      const serviceAccount = (
        role: Extract<
          PaasIdentityRole,
          "builder" | "deployer" | "runtime" | "egress"
        >,
      ) => dnsLabel(`${identities.get(role)!.id}-${tenantLabel}`);
      return {
        tenantId: tenant.tenantId,
        namespaces: {
          builder: dnsLabel(
            `codefly-build-${tenantLabel}-${intent.environment}`,
          ),
          runtime: dnsLabel(
            `codefly-runtime-${tenantLabel}-${intent.environment}`,
          ),
          egress: dnsLabel(
            `codefly-egress-${tenantLabel}-${intent.environment}`,
          ),
        },
        serviceAccounts: {
          builder: serviceAccount("builder"),
          deployer: serviceAccount("deployer"),
          runtime: serviceAccount("runtime"),
          egress: serviceAccount("egress"),
        },
        quota: {
          maxConcurrentBuilds: tenant.maxConcurrentBuilds,
          maxConcurrentDeployments: tenant.maxConcurrentDeployments,
          maxCpu: tenant.maxCpu,
          maxMemory: tenant.maxMemory,
          maxStorage: tenant.maxStorage,
          maxExecutionMinutes: tenant.maxExecutionMinutes,
        },
        builderRuntimeClass:
          intent.builder.isolation === "microvm"
            ? "deus-microvm"
            : "deus-dedicated-vm",
        ...(intent.runtime.trust === "untrusted"
          ? {
              runtimeClass:
                intent.runtime.isolation === "microvm"
                  ? ("deus-microvm" as const)
                  : ("deus-dedicated-vm" as const),
            }
          : {}),
      };
    });
  const namespaceValues = tenants.flatMap((tenant) =>
    Object.values(tenant.namespaces),
  );
  if (new Set(namespaceValues).size !== namespaceValues.length) {
    throw new Error("Codefly PaaS tenant namespaces must be globally unique.");
  }
  return {
    apiVersion: "paas.codefly.dev/control-plane/v1alpha1",
    intentDigest,
    name: intent.name,
    environment: intent.environment,
    controlStateApiVersion: PAAS_CONTROL_STATE_API_VERSION,
    systemNamespace: dnsLabel(`codefly-system-${intent.environment}`),
    globalServiceAccounts: {
      "control-plane": globalIdentity("control-plane"),
      registry: globalIdentity("registry"),
      audit: globalIdentity("audit"),
    },
    endpoints: [...intent.endpoints]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((endpoint) => ({
        id: endpoint.id,
        exposure: endpoint.exposure,
        authentication: endpoint.authentication as Exclude<
          typeof endpoint.authentication,
          "none"
        >,
        authorization: endpoint.authorization as Exclude<
          typeof endpoint.authorization,
          "none"
        >,
        operations: [...endpoint.operations].sort(),
        tenantBindingRequired: true,
        directHostExecution: false,
        executionTarget: endpoint.executionTarget,
      })),
    accessControl: {
      ...intent.accessControl,
      trustedCapabilityIssuers: [
        ...intent.accessControl.trustedCapabilityIssuers,
      ].sort(),
    },
    tenants,
    scheduling: { ...intent.scheduling },
    supplyChain: { ...intent.supplyChain },
    deploymentState: { ...intent.deploymentState },
    audit: {
      ...intent.audit,
      requiredFields: [...intent.audit.requiredFields].sort(),
    },
  };
}

export function renderCodeflyPaasControlPlaneArtifacts(
  plan: CodeflyPaasControlPlanePlan,
): CodeflyPaasControlPlaneArtifacts {
  const artifacts: Record<string, string> = {};
  artifacts["paas/control-plane/namespace.yaml"] = namespace(
    plan.systemNamespace,
    "platform",
    "control-plane",
    plan.intentDigest,
  );
  artifacts["paas/control-plane/service-accounts.yaml"] = multiDocument(
    Object.entries(plan.globalServiceAccounts).map(([role, name]) =>
      serviceAccount(plan.systemNamespace, name, role),
    ),
  );
  artifacts["paas/control-plane/network-policy.yaml"] = multiDocument([
    defaultDenyNetworkPolicy(plan.systemNamespace),
    allowDnsNetworkPolicy(plan.systemNamespace),
  ]);
  artifacts["paas/control-plane/contract.yaml"] = controlPlaneContract(plan);
  artifacts["paas/policies/builder-sandbox.yaml"] = builderPolicy(plan);
  artifacts["paas/runtime-classes.yaml"] = multiDocument([
    runtimeClass("deus-microvm", "deus-microvm"),
    runtimeClass("deus-dedicated-vm", "deus-dedicated-vm"),
  ]);

  for (const tenant of plan.tenants) {
    const root = `paas/tenants/${dnsLabel(tenant.tenantId)}`;
    artifacts[`${root}/namespaces.yaml`] = multiDocument([
      namespace(
        tenant.namespaces.builder,
        tenant.tenantId,
        "builder",
        plan.intentDigest,
      ),
      namespace(
        tenant.namespaces.runtime,
        tenant.tenantId,
        "runtime",
        plan.intentDigest,
      ),
      namespace(
        tenant.namespaces.egress,
        tenant.tenantId,
        "egress",
        plan.intentDigest,
      ),
    ]);
    artifacts[`${root}/service-accounts.yaml`] = multiDocument([
      serviceAccount(
        tenant.namespaces.builder,
        tenant.serviceAccounts.builder,
        "builder",
        tenant.tenantId,
      ),
      serviceAccount(
        tenant.namespaces.runtime,
        tenant.serviceAccounts.deployer,
        "deployer",
        tenant.tenantId,
      ),
      serviceAccount(
        tenant.namespaces.runtime,
        tenant.serviceAccounts.runtime,
        "runtime",
        tenant.tenantId,
      ),
      serviceAccount(
        tenant.namespaces.egress,
        tenant.serviceAccounts.egress,
        "egress",
        tenant.tenantId,
      ),
    ]);
    artifacts[`${root}/resource-quotas.yaml`] = resourceQuotas(tenant);
    artifacts[`${root}/network-policies.yaml`] = tenantNetworkPolicies(tenant);
    artifacts[`${root}/contract.yaml`] = tenantContract(plan, tenant);
  }
  artifacts["paas/paas-security-plan.json"] =
    `${JSON.stringify(plan, null, 2)}\n`;
  artifacts["paas/kustomization.yaml"] = rootKustomization(plan);
  return Object.fromEntries(
    Object.entries(artifacts).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}

function rootKustomization(plan: CodeflyPaasControlPlanePlan) {
  const resources = [
    "control-plane/namespace.yaml",
    "control-plane/service-accounts.yaml",
    "control-plane/network-policy.yaml",
    "control-plane/contract.yaml",
    "policies/builder-sandbox.yaml",
    "runtime-classes.yaml",
    ...plan.tenants.flatMap((tenant) => {
      const root = `tenants/${dnsLabel(tenant.tenantId)}`;
      return [
        `${root}/namespaces.yaml`,
        `${root}/service-accounts.yaml`,
        `${root}/resource-quotas.yaml`,
        `${root}/network-policies.yaml`,
        `${root}/contract.yaml`,
      ];
    }),
  ];
  return yaml([
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    "resources:",
    ...resources.map((resource) => `  - ${scalar(resource)}`),
  ]);
}

function runtimeClass(name: string, handler: string) {
  return yaml([
    "apiVersion: node.k8s.io/v1",
    "kind: RuntimeClass",
    "metadata:",
    `  name: ${scalar(name)}`,
    `handler: ${scalar(handler)}`,
  ]);
}

function namespace(
  name: string,
  tenantId: string,
  plane: string,
  intentDigest: string,
) {
  const tenantLabel = dnsLabel(tenantId);
  return yaml([
    "apiVersion: v1",
    "kind: Namespace",
    "metadata:",
    `  name: ${scalar(name)}`,
    "  annotations:",
    `    security.deus.dev/paas-intent-digest: ${scalar(intentDigest)}`,
    "  labels:",
    `    security.deus.dev/tenant-id: ${scalar(tenantLabel)}`,
    `    security.deus.dev/paas-plane: ${scalar(plane)}`,
    `    security.deus.dev/paas-intent-digest: ${scalar(intentDigest.slice(0, 63))}`,
    "    pod-security.kubernetes.io/enforce: restricted",
    "    pod-security.kubernetes.io/enforce-version: latest",
    "    pod-security.kubernetes.io/audit: restricted",
    "    pod-security.kubernetes.io/warn: restricted",
  ]);
}

function serviceAccount(
  namespaceName: string,
  name: string,
  role: string,
  tenantId?: string,
) {
  const tenantLabel = tenantId ? dnsLabel(tenantId) : undefined;
  return yaml([
    "apiVersion: v1",
    "kind: ServiceAccount",
    "metadata:",
    `  name: ${scalar(name)}`,
    `  namespace: ${scalar(namespaceName)}`,
    "  labels:",
    `    security.deus.dev/paas-role: ${scalar(role)}`,
    ...(tenantLabel
      ? [`    security.deus.dev/tenant-id: ${scalar(tenantLabel)}`]
      : []),
    "automountServiceAccountToken: false",
  ]);
}

function resourceQuotas(tenant: CodeflyPaasTenantBoundaryPlan) {
  return multiDocument([
    quota(
      tenant.namespaces.builder,
      "builder-quota",
      tenant.quota.maxConcurrentBuilds,
      tenant.quota,
    ),
    quota(
      tenant.namespaces.runtime,
      "runtime-quota",
      tenant.quota.maxConcurrentDeployments * 20,
      tenant.quota,
    ),
    quota(
      tenant.namespaces.egress,
      "egress-quota",
      tenant.quota.maxConcurrentDeployments * 2,
      tenant.quota,
    ),
  ]);
}

function quota(
  namespaceName: string,
  name: string,
  pods: number,
  resources: CodeflyPaasTenantBoundaryPlan["quota"],
) {
  return yaml([
    "apiVersion: v1",
    "kind: ResourceQuota",
    "metadata:",
    `  name: ${scalar(name)}`,
    `  namespace: ${scalar(namespaceName)}`,
    "spec:",
    "  hard:",
    `    pods: ${scalar(String(pods))}`,
    `    requests.cpu: ${scalar(resources.maxCpu)}`,
    `    limits.cpu: ${scalar(resources.maxCpu)}`,
    `    requests.memory: ${scalar(resources.maxMemory)}`,
    `    limits.memory: ${scalar(resources.maxMemory)}`,
    `    requests.storage: ${scalar(resources.maxStorage)}`,
    '    persistentvolumeclaims: "20"',
    '    services.loadbalancers: "0"',
    '    services.nodeports: "0"',
  ]);
}

function tenantNetworkPolicies(tenant: CodeflyPaasTenantBoundaryPlan) {
  return multiDocument(
    Object.values(tenant.namespaces).flatMap((namespaceName) => [
      defaultDenyNetworkPolicy(namespaceName),
      allowDnsNetworkPolicy(namespaceName),
      ...(namespaceName === tenant.namespaces.builder ||
      namespaceName === tenant.namespaces.runtime
        ? [allowBrokeredEgress(namespaceName, tenant)]
        : []),
    ]),
  );
}

function defaultDenyNetworkPolicy(namespaceName: string) {
  return yaml([
    "apiVersion: networking.k8s.io/v1",
    "kind: NetworkPolicy",
    "metadata:",
    "  name: default-deny",
    `  namespace: ${scalar(namespaceName)}`,
    "spec:",
    "  podSelector: {}",
    "  policyTypes:",
    "    - Ingress",
    "    - Egress",
  ]);
}

function allowDnsNetworkPolicy(namespaceName: string) {
  return yaml([
    "apiVersion: networking.k8s.io/v1",
    "kind: NetworkPolicy",
    "metadata:",
    "  name: allow-dns",
    `  namespace: ${scalar(namespaceName)}`,
    "spec:",
    "  podSelector: {}",
    "  policyTypes:",
    "    - Egress",
    "  egress:",
    "    - to:",
    "        - namespaceSelector:",
    "            matchLabels:",
    "              kubernetes.io/metadata.name: kube-system",
    "      ports:",
    "        - protocol: UDP",
    "          port: 53",
    "        - protocol: TCP",
    "          port: 53",
  ]);
}

function allowBrokeredEgress(
  namespaceName: string,
  tenant: CodeflyPaasTenantBoundaryPlan,
) {
  const tenantLabel = dnsLabel(tenant.tenantId);
  return yaml([
    "apiVersion: networking.k8s.io/v1",
    "kind: NetworkPolicy",
    "metadata:",
    "  name: allow-tenant-egress-broker",
    `  namespace: ${scalar(namespaceName)}`,
    "spec:",
    "  podSelector: {}",
    "  policyTypes:",
    "    - Egress",
    "  egress:",
    "    - to:",
    "        - namespaceSelector:",
    "            matchLabels:",
    `              kubernetes.io/metadata.name: ${scalar(tenant.namespaces.egress)}`,
    "          podSelector:",
    "            matchLabels:",
    `              security.deus.dev/tenant-id: ${scalar(tenantLabel)}`,
    `              security.deus.dev/paas-role: ${scalar("egress")}`,
  ]);
}

function builderPolicy(plan: CodeflyPaasControlPlanePlan) {
  return yaml([
    "apiVersion: kyverno.io/v1",
    "kind: ClusterPolicy",
    "metadata:",
    "  name: codefly-tenant-builder-sandbox",
    "spec:",
    "  validationFailureAction: Enforce",
    "  background: true",
    "  webhookConfiguration:",
    "    failurePolicy: Fail",
    "  rules:",
    ...plan.tenants.flatMap((tenant) => [
      `    - name: ${scalar(`builder-${dnsLabel(tenant.tenantId)}`)}`,
      "      match:",
      "        any:",
      "          - resources:",
      "              kinds:",
      "                - Pod",
      "              namespaces:",
      `                - ${scalar(tenant.namespaces.builder)}`,
      "      validate:",
      `        message: ${scalar("Codefly builders require tenant/job identity, microVM isolation, no service-account token, and a deadline.")}`,
      "        pattern:",
      "          metadata:",
      "            labels:",
      `              security.deus.dev/tenant-id: ${scalar(dnsLabel(tenant.tenantId))}`,
      '              security.deus.dev/build-id: "?*"',
      "          spec:",
      `            serviceAccountName: ${scalar(tenant.serviceAccounts.builder)}`,
      `            runtimeClassName: ${scalar(tenant.builderRuntimeClass)}`,
      "            automountServiceAccountToken: false",
      '            activeDeadlineSeconds: "?*"',
      "            securityContext:",
      "              seccompProfile:",
      "                type: RuntimeDefault",
    ]),
  ]);
}

function controlPlaneContract(plan: CodeflyPaasControlPlanePlan) {
  return yaml([
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: codefly-control-plane-security-contract",
    `  namespace: ${scalar(plan.systemNamespace)}`,
    "data:",
    `  intent-digest: ${scalar(plan.intentDigest)}`,
    `  control-state-api-version: ${scalar(plan.controlStateApiVersion)}`,
    `  endpoints.json: ${blockJson(plan.endpoints)}`,
    `  access-control.json: ${blockJson(plan.accessControl)}`,
    `  scheduling.json: ${blockJson(plan.scheduling)}`,
    `  supply-chain.json: ${blockJson(plan.supplyChain)}`,
    `  deployment-state.json: ${blockJson(plan.deploymentState)}`,
    `  audit.json: ${blockJson(plan.audit)}`,
  ]);
}

function tenantContract(
  plan: CodeflyPaasControlPlanePlan,
  tenant: CodeflyPaasTenantBoundaryPlan,
) {
  return yaml([
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: codefly-tenant-security-contract",
    `  namespace: ${scalar(tenant.namespaces.runtime)}`,
    "data:",
    `  tenant-id: ${scalar(tenant.tenantId)}`,
    `  intent-digest: ${scalar(plan.intentDigest)}`,
    `  namespaces.json: ${blockJson(tenant.namespaces)}`,
    `  service-accounts.json: ${blockJson(tenant.serviceAccounts)}`,
    `  quota.json: ${blockJson(tenant.quota)}`,
    `  builder-runtime-class: ${scalar(tenant.builderRuntimeClass)}`,
  ]);
}

function blockJson(value: unknown) {
  return scalar(JSON.stringify(value));
}

function multiDocument(documents: readonly string[]) {
  return `${documents.map((document) => document.trimEnd()).join("\n---\n")}\n`;
}

function yaml(lines: readonly string[]) {
  return `${lines.join("\n")}\n`;
}

function scalar(value: string) {
  return JSON.stringify(value);
}

function digest(value: unknown) {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonical(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function dnsLabel(value: string) {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");
  if (!normalized) throw new Error(`Codefly DNS label '${value}' is invalid.`);
  if (normalized.length <= 63) return normalized;
  return `${normalized.slice(0, 54).replace(/-+$/g, "")}-${digest(value).slice(0, 8)}`;
}
