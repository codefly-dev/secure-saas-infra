import { createHash } from "node:crypto";
import path from "node:path";
import type {
  CodeflyProductComponentPlan,
  CodeflyProductTopologyPlan,
  CodeflyProductWorkspacePlan,
} from "./productTopology";

export type CodeflyProductSecurityArtifacts = Readonly<Record<string, string>>;

export interface CodeflyProductSecurityRenderOptions {
  environmentName: string;
  images: Readonly<Record<string, string>>;
  serviceOverlayPaths?: Readonly<Record<string, string>>;
  ingress?: {
    namespace: string;
    serviceAccount: string;
  };
  workloadIdentityAnnotations?: Readonly<
    Record<string, Readonly<Record<string, string>>>
  >;
  imageVerification: {
    issuer: string;
    subject: string;
    rekorUrl?: string;
  };
  trustDomain?: string;
}

export function productServiceKey(
  deploymentId: string,
  componentId: string,
  service: string,
) {
  return `${deploymentId}/${componentId}/${service}`;
}

export function productComponentKey(deploymentId: string, componentId: string) {
  return `${deploymentId}/${componentId}`;
}

export function renderCodeflyProductSecurityArtifacts(
  plan: CodeflyProductTopologyPlan,
  options: CodeflyProductSecurityRenderOptions,
): CodeflyProductSecurityArtifacts {
  validateOptions(plan, options);
  const artifacts: Record<string, string> = {};
  const planDigest = digest(plan);
  for (const workspace of plan.workspaces) {
    for (const component of workspace.components) {
      const namespace = dnsLabel(
        `${workspace.workspaceName}-${component.moduleName}-${options.environmentName}`,
      );
      const serviceAccount = dnsLabel(
        `${workspace.deploymentId}-${component.componentId}-workload`,
      );
      const root = `workspaces/${workspace.workspaceName}/modules/${component.moduleName}/security/${options.environmentName}`;
      artifacts[`${root}/namespace.yaml`] = renderNamespace(
        workspace,
        component,
        namespace,
        planDigest,
      );
      artifacts[`${root}/service-account.yaml`] = renderServiceAccount(
        workspace,
        component,
        namespace,
        serviceAccount,
        options,
      );
      artifacts[`${root}/network-policy.yaml`] = renderNetworkPolicies(
        plan,
        workspace,
        component,
        namespace,
        options,
      );
      artifacts[`${root}/authorization-policy.yaml`] =
        renderAuthorizationPolicy(
          plan,
          workspace,
          component,
          namespace,
          serviceAccount,
          options,
        );
      artifacts[`${root}/pod-disruption-budget.yaml`] = renderPdbs(
        component,
        namespace,
      );
      artifacts[`${root}/verify-images.yaml`] = renderImagePolicy(
        workspace,
        component,
        namespace,
        options,
      );
      artifacts[`${root}/security-contract.yaml`] = renderSecurityContract(
        plan,
        workspace,
        component,
        namespace,
        planDigest,
        options,
      );
      for (const service of component.services) {
        const workloadPatch = renderWorkloadPatch(
          workspace,
          component,
          namespace,
          serviceAccount,
          service.name,
          service.agent.agent,
          options.images[
            productServiceKey(
              workspace.deploymentId,
              component.componentId,
              service.name,
            )
          ],
        );
        artifacts[`${root}/patches/${service.name}.yaml`] = workloadPatch;
        if (options.serviceOverlayPaths) {
          artifacts[`${root}/services/${service.name}/workload-patch.yaml`] =
            workloadPatch;
          artifacts[`${root}/services/${service.name}/kustomization.yaml`] =
            renderServiceIntegrationKustomization(
              workspace,
              component,
              service.name,
              options.serviceOverlayPaths[
                productServiceKey(
                  workspace.deploymentId,
                  component.componentId,
                  service.name,
                )
              ],
              options.environmentName,
            );
        }
      }
      artifacts[`${root}/kustomization.yaml`] = renderKustomization(
        workspace,
        component,
        namespace,
      );
    }
  }
  artifacts["product-security-plan.yaml"] = renderPlanEvidence(
    plan,
    planDigest,
    options,
  );
  return Object.fromEntries(
    Object.entries(artifacts).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}

function validateOptions(
  plan: CodeflyProductTopologyPlan,
  options: CodeflyProductSecurityRenderOptions,
) {
  assertDnsLabel(options.environmentName, "environment name");
  if (!options.imageVerification.issuer.trim()) {
    throw new Error("Codefly product image verification requires an issuer.");
  }
  if (!options.imageVerification.subject.trim()) {
    throw new Error("Codefly product image verification requires a subject.");
  }
  if (options.ingress) {
    assertDnsLabel(options.ingress.namespace, "ingress namespace");
    assertDnsLabel(options.ingress.serviceAccount, "ingress service account");
  }
  const expectedServices = plan.workspaces.flatMap((workspace) =>
    workspace.components.flatMap((component) =>
      component.services.map((service) =>
        productServiceKey(
          workspace.deploymentId,
          component.componentId,
          service.name,
        ),
      ),
    ),
  );
  assertExactKeys("image", expectedServices, Object.keys(options.images));
  for (const key of expectedServices) {
    if (!/@sha256:[a-f0-9]{64}$/.test(options.images[key])) {
      throw new Error(
        `Codefly product service '${key}' requires a digest-pinned image.`,
      );
    }
  }
  if (options.serviceOverlayPaths) {
    assertExactKeys(
      "service overlay",
      expectedServices,
      Object.keys(options.serviceOverlayPaths),
    );
    for (const [key, value] of Object.entries(options.serviceOverlayPaths)) {
      if (!isSafeRelativePath(value)) {
        throw new Error(
          `Codefly product service overlay '${key}' must be a safe relative path.`,
        );
      }
    }
  }
  const expectedComponents = plan.workspaces.flatMap((workspace) =>
    workspace.components.map((component) =>
      productComponentKey(workspace.deploymentId, component.componentId),
    ),
  );
  for (const key of Object.keys(options.workloadIdentityAnnotations ?? {})) {
    if (!expectedComponents.includes(key)) {
      throw new Error(
        `Codefly product workload identity annotations contain unknown component '${key}'.`,
      );
    }
  }
  const cloudIdentities = new Map<string, string>();
  const identityKeys = new Set([
    "eks.amazonaws.com/role-arn",
    "iam.gke.io/gcp-service-account",
    "azure.workload.identity/client-id",
  ]);
  for (const [componentKey, annotations] of Object.entries(
    options.workloadIdentityAnnotations ?? {},
  )) {
    for (const [key, value] of Object.entries(annotations)) {
      if (!key.trim() || !value.trim()) {
        throw new Error(
          `Codefly product workload identity annotation '${componentKey}' must not be empty.`,
        );
      }
      if (!identityKeys.has(key)) continue;
      const owner = cloudIdentities.get(value);
      if (owner && owner !== componentKey) {
        throw new Error(
          `Codefly product cloud identity '${value}' cannot be shared by '${owner}' and '${componentKey}'.`,
        );
      }
      cloudIdentities.set(value, componentKey);
    }
  }
  if (
    plan.workspaces.some((workspace) =>
      workspace.components.some((component) => component.ingress === "public"),
    ) &&
    !options.ingress
  ) {
    throw new Error(
      "Codefly public product components require an ingress identity.",
    );
  }
}

function renderNamespace(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  planDigest: string,
) {
  return document([
    "apiVersion: v1",
    "kind: Namespace",
    "metadata:",
    `  name: ${scalar(namespace)}`,
    "  annotations:",
    `    security.deus.dev/blueprint-digest: ${scalar(planDigest)}`,
    "  labels:",
    `    security.deus.dev/application: ${scalar(workspace.deploymentId)}`,
    `    security.deus.dev/component: ${scalar(component.componentId)}`,
    `    security.deus.dev/identity: ${scalar(component.serviceIdentityId)}`,
    `    security.deus.dev/blueprint-digest: ${scalar(planDigest.slice(0, 63))}`,
    "    istio.io/dataplane-mode: ambient",
    "    pod-security.kubernetes.io/enforce: restricted",
    "    pod-security.kubernetes.io/enforce-version: latest",
    "    pod-security.kubernetes.io/audit: restricted",
    "    pod-security.kubernetes.io/warn: restricted",
  ]);
}

function renderServiceAccount(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  serviceAccount: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  const annotations =
    options.workloadIdentityAnnotations?.[
      productComponentKey(workspace.deploymentId, component.componentId)
    ] ?? {};
  return document([
    "apiVersion: v1",
    "kind: ServiceAccount",
    "metadata:",
    `  name: ${scalar(serviceAccount)}`,
    `  namespace: ${scalar(namespace)}`,
    ...(Object.keys(annotations).length > 0
      ? [
          "  annotations:",
          ...Object.entries(annotations)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([key, value]) => `    ${scalar(key)}: ${scalar(value)}`),
        ]
      : []),
    "automountServiceAccountToken: false",
  ]);
}

function renderNetworkPolicies(
  plan: CodeflyProductTopologyPlan,
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  const documents = [
    networkPolicy(namespace, "default-deny", [
      "spec:",
      "  podSelector: {}",
      "  policyTypes:",
      "    - Ingress",
      "    - Egress",
    ]),
    networkPolicy(namespace, "allow-dns", [
      "spec:",
      "  podSelector: {}",
      "  policyTypes:",
      "    - Egress",
      "  egress:",
      "    - to:",
      "        - namespaceSelector:",
      "            matchLabels:",
      "              kubernetes.io/metadata.name: kube-system",
      "          podSelector:",
      "            matchLabels:",
      "              k8s-app: kube-dns",
      "      ports:",
      "        - protocol: UDP",
      "          port: 53",
      "        - protocol: TCP",
      "          port: 53",
    ]),
    networkPolicy(namespace, "allow-component-internal", [
      "spec:",
      "  podSelector: {}",
      "  policyTypes:",
      "    - Ingress",
      "    - Egress",
      "  ingress:",
      "    - from:",
      "        - podSelector: {}",
      "  egress:",
      "    - to:",
      "        - podSelector: {}",
    ]),
  ];
  for (const target of outgoingTargets(
    plan,
    workspace,
    component,
    options.environmentName,
  )) {
    documents.push(
      networkPolicy(namespace, `allow-egress-${target.name}`, [
        "spec:",
        "  podSelector: {}",
        "  policyTypes:",
        "    - Egress",
        "  egress:",
        "    - to:",
        "        - namespaceSelector:",
        "            matchLabels:",
        `              security.deus.dev/application: ${scalar(target.deploymentId)}`,
        `              security.deus.dev/component: ${scalar(target.componentId)}`,
      ]),
    );
  }
  for (const caller of incomingCallers(
    plan,
    workspace,
    component,
    options.environmentName,
  )) {
    documents.push(
      networkPolicy(namespace, `allow-ingress-${caller.name}`, [
        "spec:",
        "  podSelector: {}",
        "  policyTypes:",
        "    - Ingress",
        "  ingress:",
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        `              security.deus.dev/application: ${scalar(caller.deploymentId)}`,
        `              security.deus.dev/component: ${scalar(caller.componentId)}`,
      ]),
    );
  }
  if (component.ingress === "public") {
    documents.push(
      networkPolicy(namespace, "allow-platform-ingress", [
        "spec:",
        "  podSelector: {}",
        "  policyTypes:",
        "    - Ingress",
        "  ingress:",
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        `              kubernetes.io/metadata.name: ${scalar(options.ingress!.namespace)}`,
      ]),
    );
  }
  return `${documents.join("\n---\n")}\n`;
}

function renderAuthorizationPolicy(
  plan: CodeflyProductTopologyPlan,
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  serviceAccount: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  const principals = [
    principal(options, namespace, serviceAccount),
    ...incomingCallers(plan, workspace, component, options.environmentName).map(
      (caller) =>
        principal(
          options,
          caller.namespace,
          dnsLabel(`${caller.deploymentId}-${caller.componentId}-workload`),
        ),
    ),
    ...(component.ingress === "public"
      ? [
          principal(
            options,
            options.ingress!.namespace,
            options.ingress!.serviceAccount,
          ),
        ]
      : []),
  ];
  return document([
    "apiVersion: security.istio.io/v1",
    "kind: AuthorizationPolicy",
    "metadata:",
    "  name: allow-declared-identities",
    `  namespace: ${scalar(namespace)}`,
    "spec:",
    "  action: ALLOW",
    "  rules:",
    "    - from:",
    "        - source:",
    "            principals:",
    ...[...new Set(principals)]
      .sort()
      .map((value) => `              - ${scalar(value)}`),
  ]);
}

function renderPdbs(component: CodeflyProductComponentPlan, namespace: string) {
  return `${component.services
    .map((service) =>
      document([
        "apiVersion: policy/v1",
        "kind: PodDisruptionBudget",
        "metadata:",
        `  name: ${scalar(`${service.name}-availability`)}`,
        `  namespace: ${scalar(namespace)}`,
        "spec:",
        `  maxUnavailable: ${component.maximumUnavailable}`,
        "  selector:",
        "    matchLabels:",
        `      app: ${scalar(service.name)}`,
      ]).trimEnd(),
    )
    .join("\n---\n")}\n`;
}

function renderImagePolicy(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  return document([
    "apiVersion: kyverno.io/v1",
    "kind: Policy",
    "metadata:",
    "  name: verify-product-images",
    `  namespace: ${scalar(namespace)}`,
    "spec:",
    "  admission: true",
    "  background: false",
    "  validationFailureAction: Enforce",
    "  webhookConfiguration:",
    "    failurePolicy: Fail",
    "    timeoutSeconds: 30",
    "  rules:",
    ...component.services.flatMap((service) => {
      const image =
        options.images[
          productServiceKey(
            workspace.deploymentId,
            component.componentId,
            service.name,
          )
        ];
      return [
        `    - name: ${scalar(`verify-${service.name}`)}`,
        "      match:",
        "        any:",
        "          - resources:",
        "              kinds:",
        "                - Pod",
        "              selector:",
        "                matchLabels:",
        `                  app: ${scalar(service.name)}`,
        "      verifyImages:",
        "        - imageReferences:",
        `            - ${scalar(image)}`,
        "          failureAction: Enforce",
        "          required: true",
        "          mutateDigest: false",
        "          verifyDigest: true",
        "          attestors:",
        "            - count: 1",
        "              entries:",
        "                - keyless:",
        `                    issuer: ${scalar(options.imageVerification.issuer)}`,
        `                    subject: ${scalar(options.imageVerification.subject)}`,
        "                    rekor:",
        `                      url: ${scalar(options.imageVerification.rekorUrl ?? "https://rekor.sigstore.dev")}`,
        "          attestations:",
        "            - type: https://slsa.dev/provenance/v1",
        "              attestors:",
        "                - count: 1",
        "                  entries:",
        "                    - keyless:",
        `                        issuer: ${scalar(options.imageVerification.issuer)}`,
        `                        subject: ${scalar(options.imageVerification.subject)}`,
        "                        rekor:",
        `                          url: ${scalar(options.imageVerification.rekorUrl ?? "https://rekor.sigstore.dev")}`,
        "            - type: https://spdx.dev/Document",
        "              attestors:",
        "                - count: 1",
        "                  entries:",
        "                    - keyless:",
        `                        issuer: ${scalar(options.imageVerification.issuer)}`,
        `                        subject: ${scalar(options.imageVerification.subject)}`,
        "                        rekor:",
        `                          url: ${scalar(options.imageVerification.rekorUrl ?? "https://rekor.sigstore.dev")}`,
      ];
    }),
  ]);
}

function renderSecurityContract(
  plan: CodeflyProductTopologyPlan,
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  planDigest: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  const images = component.services.map(
    (service) =>
      options.images[
        productServiceKey(
          workspace.deploymentId,
          component.componentId,
          service.name,
        )
      ],
  );
  const internalContracts = workspace.componentDependencies
    .filter(
      (dependency) => dependency.fromComponentId === component.componentId,
    )
    .map((dependency) => ({
      scope: "internal",
      target: `${workspace.deploymentId}/${dependency.toComponentId}`,
      protocol: dependency.protocol,
      authorization: dependency.authorization,
      audience: dependency.audience,
      actions: dependency.actions,
    }));
  const externalContracts = workspace.dependencies
    .filter(
      (dependency) => dependency.fromComponentId === component.componentId,
    )
    .map((dependency) => ({
      scope: "external",
      target: `${dependency.toDeploymentId}/${dependency.toComponentId}`,
      protocol: dependency.protocol,
      authorization: dependency.authorization,
      audience: dependency.audience,
      actions: dependency.actions,
    }));
  const callers = incomingCallers(
    plan,
    workspace,
    component,
    options.environmentName,
  ).map((caller) => `${caller.deploymentId}/${caller.componentId}`);
  return document([
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: deus-product-security-contract",
    `  namespace: ${scalar(namespace)}`,
    "data:",
    `  plan-digest: ${scalar(planDigest)}`,
    `  deployment: ${scalar(workspace.deploymentId)}`,
    `  component: ${scalar(component.componentId)}`,
    `  workload-plane: ${scalar(component.workloadPlaneId)}`,
    `  workload-identity: ${scalar(component.serviceIdentityId)}`,
    `  data-boundaries: ${scalar(component.dataBoundaryIds.join(","))}`,
    `  minimum-replicas: ${scalar(String(component.minimumReplicas))}`,
    `  maximum-unavailable: ${scalar(String(component.maximumUnavailable))}`,
    `  digest-pinned-images: ${scalar(images.join(","))}`,
    `  declared-callers: ${scalar(callers.sort().join(","))}`,
    `  outgoing-contracts: ${scalar(canonical([...internalContracts, ...externalContracts]))}`,
    `  signature-verification-required: ${scalar(String(component.release.signatureVerification))}`,
    `  provenance-verification-required: ${scalar(String(component.release.provenanceVerification))}`,
    `  rollback-required: ${scalar(String(component.release.rollbackRequired))}`,
  ]);
}

function renderWorkloadPatch(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
  serviceAccount: string,
  service: string,
  agent: string,
  image: string,
) {
  return document([
    "apiVersion: apps/v1",
    `kind: ${statefulAgent(agent) ? "StatefulSet" : "Deployment"}`,
    "metadata:",
    `  name: ${scalar(service)}`,
    `  namespace: ${scalar(namespace)}`,
    "spec:",
    "  template:",
    "    metadata:",
    "      labels:",
    `        security.deus.dev/application: ${scalar(workspace.deploymentId)}`,
    `        security.deus.dev/component: ${scalar(component.componentId)}`,
    `        security.deus.dev/identity: ${scalar(component.serviceIdentityId)}`,
    "    spec:",
    `      serviceAccountName: ${scalar(serviceAccount)}`,
    "      automountServiceAccountToken: false",
    "      containers:",
    `        - name: ${scalar(containerName(agent, service))}`,
    `          image: ${scalar(image)}`,
  ]);
}

function renderKustomization(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  namespace: string,
) {
  return document([
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    `namespace: ${scalar(namespace)}`,
    "resources:",
    "  - namespace.yaml",
    "  - service-account.yaml",
    "  - network-policy.yaml",
    "  - authorization-policy.yaml",
    "  - pod-disruption-budget.yaml",
    "  - verify-images.yaml",
    "  - security-contract.yaml",
    "commonLabels:",
    `  security.deus.dev/application: ${scalar(workspace.deploymentId)}`,
    `  security.deus.dev/component: ${scalar(component.componentId)}`,
  ]);
}

function renderServiceIntegrationKustomization(
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  service: string,
  serviceOverlayPath: string,
  environmentName: string,
) {
  const integrationDirectory = `workspaces/${workspace.workspaceName}/modules/${component.moduleName}/security/${environmentName}/services/${service}`;
  const normalizedResource = path.posix.normalize(serviceOverlayPath);
  if (!normalizedResource.startsWith(`${integrationDirectory}/`)) {
    throw new Error(
      `Codefly product service overlay '${workspace.deploymentId}/${component.componentId}/${service}' must be contained by its generated integration directory.`,
    );
  }
  const resource = path.posix.relative(
    integrationDirectory,
    normalizedResource,
  );
  return document([
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    "resources:",
    `  - ${scalar(resource)}`,
    "patchesStrategicMerge:",
    '  - "workload-patch.yaml"',
  ]);
}

function renderPlanEvidence(
  plan: CodeflyProductTopologyPlan,
  planDigest: string,
  options: CodeflyProductSecurityRenderOptions,
) {
  return document([
    `apiVersion: ${scalar(plan.apiVersion)}`,
    "kind: ProductSecurityEvidence",
    "metadata:",
    `  environment: ${scalar(options.environmentName)}`,
    `  planDigest: ${scalar(planDigest)}`,
    `  composedWithServiceOutputs: ${String(Boolean(options.serviceOverlayPaths))}`,
    "workspaces:",
    ...plan.workspaces.flatMap((workspace) => [
      `  - deployment: ${scalar(workspace.deploymentId)}`,
      `    workspace: ${scalar(workspace.workspaceName)}`,
      "    components:",
      ...workspace.components.flatMap((component) => [
        `      - name: ${scalar(component.componentId)}`,
        `        namespace: ${scalar(dnsLabel(`${workspace.workspaceName}-${component.moduleName}-${options.environmentName}`))}`,
        `        identity: ${scalar(component.serviceIdentityId)}`,
        "        services:",
        ...component.services.map(
          (service) => `          - ${scalar(service.name)}`,
        ),
      ]),
    ]),
  ]);
}

interface EndpointRef {
  deploymentId: string;
  componentId: string;
  namespace: string;
  name: string;
}

function outgoingTargets(
  plan: CodeflyProductTopologyPlan,
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  environmentName: string,
): EndpointRef[] {
  const internal = workspace.componentDependencies
    .filter(
      (dependency) => dependency.fromComponentId === component.componentId,
    )
    .map((dependency) =>
      endpointRef(
        plan,
        workspace.deploymentId,
        dependency.toComponentId,
        "internal",
        environmentName,
      ),
    );
  const external = workspace.dependencies
    .filter(
      (dependency) => dependency.fromComponentId === component.componentId,
    )
    .map((dependency) =>
      endpointRef(
        plan,
        dependency.toDeploymentId,
        dependency.toComponentId,
        "external",
        environmentName,
      ),
    );
  return uniqueEndpoints([...internal, ...external]);
}

function incomingCallers(
  plan: CodeflyProductTopologyPlan,
  workspace: CodeflyProductWorkspacePlan,
  component: CodeflyProductComponentPlan,
  environmentName: string,
): EndpointRef[] {
  const callers: EndpointRef[] = [];
  for (const candidate of plan.workspaces) {
    for (const dependency of candidate.componentDependencies) {
      if (
        candidate.deploymentId === workspace.deploymentId &&
        dependency.toComponentId === component.componentId
      ) {
        callers.push(
          endpointRef(
            plan,
            candidate.deploymentId,
            dependency.fromComponentId,
            "internal",
            environmentName,
          ),
        );
      }
    }
    for (const dependency of candidate.dependencies) {
      if (
        dependency.toDeploymentId === workspace.deploymentId &&
        dependency.toComponentId === component.componentId
      ) {
        callers.push(
          endpointRef(
            plan,
            candidate.deploymentId,
            dependency.fromComponentId,
            "external",
            environmentName,
          ),
        );
      }
    }
  }
  return uniqueEndpoints(callers);
}

function endpointRef(
  plan: CodeflyProductTopologyPlan,
  deploymentId: string,
  componentId: string,
  scope: "internal" | "external",
  environmentName: string,
): EndpointRef {
  const workspace = plan.workspaces.find(
    (candidate) => candidate.deploymentId === deploymentId,
  );
  const component = workspace?.components.find(
    (candidate) => candidate.componentId === componentId,
  );
  if (!workspace || !component) {
    throw new Error(
      `Codefly product dependency references missing component '${deploymentId}/${componentId}'.`,
    );
  }
  return {
    deploymentId,
    componentId,
    namespace: dnsLabel(
      `${workspace.workspaceName}-${component.moduleName}-${environmentName}`,
    ),
    name: dnsLabel(`${scope}-${deploymentId}-${componentId}`),
  };
}

function uniqueEndpoints(values: readonly EndpointRef[]) {
  return [
    ...new Map(
      values.map((value) => [
        `${value.deploymentId}/${value.componentId}`,
        value,
      ]),
    ).values(),
  ];
}

function principal(
  options: CodeflyProductSecurityRenderOptions,
  namespace: string,
  serviceAccount: string,
) {
  return `${options.trustDomain ?? "cluster.local"}/ns/${namespace}/sa/${serviceAccount}`;
}

function networkPolicy(
  namespace: string,
  name: string,
  body: readonly string[],
) {
  return document([
    "apiVersion: networking.k8s.io/v1",
    "kind: NetworkPolicy",
    "metadata:",
    `  name: ${scalar(name)}`,
    `  namespace: ${scalar(namespace)}`,
    ...body,
  ]).trimEnd();
}

function statefulAgent(agent: string) {
  return new Set(["postgres", "redis", "vault", "s3"]).has(agent);
}

function containerName(agent: string, service: string) {
  return (
    {
      nextjs: "nextjs",
      postgres: "postgres",
      redis: "redis",
      vault: "vault",
      s3: "minio",
    }[agent] ?? service
  );
}

function assertExactKeys(
  label: string,
  expected: readonly string[],
  observed: readonly string[],
) {
  const left = [...new Set(expected)].sort();
  const right = [...new Set(observed)].sort();
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error(
      `Codefly product ${label} keys mismatch; expected [${left.join(", ")}], observed [${right.join(", ")}].`,
    );
  }
}

function assertDnsLabel(value: string, label: string) {
  if (value.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value)) {
    throw new Error(`Codefly product ${label} must be a DNS label.`);
  }
}

function dnsLabel(value: string) {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (normalized.length <= 63) return normalized;
  return `${normalized.slice(0, 54).replace(/-$/g, "")}-${digest(value).slice(0, 8)}`;
}

function isSafeRelativePath(value: string) {
  return (
    Boolean(value) &&
    !value.startsWith("/") &&
    !value.split("/").includes("..") &&
    !value.includes("\\")
  );
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

function scalar(value: string) {
  return JSON.stringify(value);
}

function document(lines: readonly string[]) {
  return `${lines.join("\n")}\n`;
}
