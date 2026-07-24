import type {
  CodeflyDeploymentPlan,
  CodeflyPaasPlan,
  CodeflyServicePlan,
} from "./codeflyAdapter";
import { CODEFLY_PAAS_COMPATIBILITY } from "./compatibility";

export type CodeflyRenderedArtifacts = Readonly<Record<string, string>>;

export function renderCodeflyArtifacts(
  plan: CodeflyPaasPlan,
): CodeflyRenderedArtifacts {
  const artifacts: Record<string, string> = {
    "workspace.codefly.yaml": renderWorkspace(plan),
    "codefly-plan.yaml": renderPlanEvidence(plan),
  };
  const moduleNames = new Set<string>();
  for (const deployment of plan.deployments) {
    if (moduleNames.has(deployment.moduleName)) {
      throw new Error(
        `Codefly module '${deployment.moduleName}' is bound to multiple deployments.`,
      );
    }
    moduleNames.add(deployment.moduleName);
    const root = `modules/${deployment.moduleName}`;
    artifacts[`${root}/module.codefly.yaml`] = renderModule(deployment);
    for (const service of deployment.servicePlans) {
      artifacts[`${root}/services/${service.name}/service.codefly.yaml`] =
        renderService(deployment, service);
    }
    artifacts[`${root}/deployment/kustomize/base/namespace.yaml`] =
      renderNamespace(deployment);
    artifacts[`${root}/deployment/kustomize/base/service-account.yaml`] =
      renderServiceAccount(deployment);
    artifacts[`${root}/deployment/kustomize/base/network-policy.yaml`] =
      renderNetworkPolicies(deployment, plan);
    artifacts[`${root}/deployment/kustomize/base/pod-disruption-budget.yaml`] =
      renderPodDisruptionBudgets(deployment);
    artifacts[`${root}/deployment/kustomize/base/security-contract.yaml`] =
      renderSecurityContract(deployment, plan.blueprintDigest);
    artifacts[`${root}/deployment/kustomize/base/kustomization.yaml`] =
      renderBaseKustomization();
    artifacts[
      `${root}/deployment/kustomize/overlays/${plan.environment.name}/kustomization.yaml`
    ] = renderEnvironmentOverlay(deployment, plan.environment.name);
  }
  return Object.fromEntries(
    Object.entries(artifacts).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}

function renderWorkspace(plan: CodeflyPaasPlan) {
  const environment = plan.environment;
  const lines = [
    `name: ${scalar(environment.namespacePrefix)}`,
    `description: ${scalar("Warden and Mind secure PaaS workspace")}`,
    "layout: modules",
    "modules:",
    ...plan.deployments.map(
      (deployment) => `  - name: ${scalar(deployment.moduleName)}`,
    ),
    "environments:",
    `  - name: ${scalar(environment.name)}`,
    `    description: ${scalar(`Generated ${environment.clusterKind} deployment target`)}`,
    "    cluster:",
    `      kind: ${scalar(environment.clusterKind)}`,
    ...(environment.kubeconfig
      ? [`      kubeconfig: ${scalar(environment.kubeconfig)}`]
      : []),
    ...(environment.kubeContext
      ? [`      context: ${scalar(environment.kubeContext)}`]
      : []),
    "    registry:",
    `      url: ${scalar(environment.registry)}`,
    ...(environment.registryAuth
      ? [`      auth: ${scalar(environment.registryAuth)}`]
      : []),
  ];
  if (environment.gitopsRepository) {
    lines.push(
      "gitops:",
      `  repo-url: ${scalar(environment.gitopsRepository)}`,
      ...(environment.gitopsPath
        ? [`  path: ${scalar(environment.gitopsPath)}`]
        : []),
      `  branch: ${scalar(environment.gitopsBranch ?? "main")}`,
    );
  }
  return document(lines);
}

function renderModule(deployment: CodeflyDeploymentPlan) {
  const lines = [
    "kind: module",
    `name: ${scalar(deployment.moduleName)}`,
    `description: ${scalar(`${deployment.deploymentId} independent product deployment`)}`,
    "interface:",
    "  endpoints:",
    ...deployment.interfaceEndpoints.flatMap((endpoint) => [
      `    - service: ${scalar(endpoint.service)}`,
      `      endpoint: ${scalar(endpoint.endpoint)}`,
      `      visibility: ${scalar(endpoint.visibility)}`,
    ]),
    "services:",
    ...deployment.services.map((service) => `  - name: ${scalar(service)}`),
  ];
  return document(lines);
}

function renderService(
  deployment: CodeflyDeploymentPlan,
  service: CodeflyServicePlan,
) {
  const dependencies = [
    ...service.internalDependencies.map((name) => ({
      name,
      moduleName: undefined,
      endpointName: undefined,
    })),
    ...service.externalDependencies.map((dependency) => ({
      name: dependency.serviceName,
      moduleName: dependency.moduleName,
      endpointName: dependency.endpointName,
    })),
  ];
  const lines = [
    `name: ${scalar(service.name)}`,
    "version: 0.0.0",
    "agent:",
    "  kind: codefly:service",
    `  name: ${scalar(service.agent.name)}`,
    `  version: ${scalar(service.agent.version)}`,
    `  publisher: ${scalar(service.agent.publisher)}`,
    ...(dependencies.length === 0
      ? []
      : [
          "service-dependencies:",
          ...dependencies.flatMap((dependency) => [
            `  - name: ${scalar(dependency.name)}`,
            ...(dependency.moduleName
              ? [`    module: ${scalar(dependency.moduleName)}`]
              : []),
            ...(dependency.endpointName
              ? [
                  "    endpoints:",
                  `      - name: ${scalar(dependency.endpointName)}`,
                ]
              : []),
          ]),
        ]),
    "endpoints:",
    ...service.endpoints.flatMap((endpoint) => [
      `  - name: ${scalar(endpoint.name)}`,
      `    api: ${scalar(endpoint.api)}`,
      `    visibility: ${scalar(endpoint.visibility)}`,
    ]),
    "spec:",
    "  hot-reload: false",
    `  image: ${scalar(service.image)}`,
    `  service-account: ${scalar(deployment.serviceAccountName)}`,
  ];
  return document(lines);
}

function renderNamespace(deployment: CodeflyDeploymentPlan) {
  return document([
    "apiVersion: v1",
    "kind: Namespace",
    "metadata:",
    `  name: ${scalar(deployment.namespace)}`,
    "  labels:",
    `    security.deus.dev/application: ${scalar(deployment.deploymentId)}`,
    "    istio.io/dataplane-mode: ambient",
    "    pod-security.kubernetes.io/enforce: restricted",
    "    pod-security.kubernetes.io/enforce-version: latest",
    "    pod-security.kubernetes.io/audit: restricted",
    "    pod-security.kubernetes.io/warn: restricted",
  ]);
}

function renderServiceAccount(deployment: CodeflyDeploymentPlan) {
  return document([
    "apiVersion: v1",
    "kind: ServiceAccount",
    "metadata:",
    `  name: ${scalar(deployment.serviceAccountName)}`,
    `  namespace: ${scalar(deployment.namespace)}`,
    ...(Object.keys(deployment.serviceAccountAnnotations).length === 0
      ? []
      : [
          "  annotations:",
          ...Object.entries(deployment.serviceAccountAnnotations).map(
            ([key, value]) => `    ${key}: ${scalar(value)}`,
          ),
        ]),
    "automountServiceAccountToken: false",
  ]);
}

function renderNetworkPolicies(
  deployment: CodeflyDeploymentPlan,
  plan: CodeflyPaasPlan,
) {
  const documents = [
    document([
      "apiVersion: networking.k8s.io/v1",
      "kind: NetworkPolicy",
      "metadata:",
      "  name: default-deny",
      `  namespace: ${scalar(deployment.namespace)}`,
      "spec:",
      "  podSelector: {}",
      "  policyTypes:",
      "    - Ingress",
      "    - Egress",
    ]).trimEnd(),
    document([
      "apiVersion: networking.k8s.io/v1",
      "kind: NetworkPolicy",
      "metadata:",
      "  name: allow-dns",
      `  namespace: ${scalar(deployment.namespace)}`,
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
    ]).trimEnd(),
  ];
  for (const dependency of deployment.dependencies) {
    const target = plan.deployments.find(
      (candidate) => candidate.deploymentId === dependency.deploymentId,
    );
    if (!target) continue;
    documents.push(
      document([
        "apiVersion: networking.k8s.io/v1",
        "kind: NetworkPolicy",
        "metadata:",
        `  name: ${scalar(`allow-egress-to-${target.deploymentId}`)}`,
        `  namespace: ${scalar(deployment.namespace)}`,
        "spec:",
        "  podSelector: {}",
        "  policyTypes:",
        "    - Egress",
        "  egress:",
        "    - to:",
        "        - namespaceSelector:",
        "            matchLabels:",
        `              security.deus.dev/application: ${scalar(target.deploymentId)}`,
        "          podSelector:",
        "            matchLabels:",
        `              app: ${scalar(dependency.serviceName)}`,
        "      ports:",
        `        - port: ${scalar(dependency.endpointName)}`,
        "          protocol: TCP",
      ]).trimEnd(),
    );
  }
  const callers = plan.deployments.filter((candidate) =>
    candidate.dependencies.some(
      (dependency) => dependency.deploymentId === deployment.deploymentId,
    ),
  );
  for (const caller of callers) {
    documents.push(
      document([
        "apiVersion: networking.k8s.io/v1",
        "kind: NetworkPolicy",
        "metadata:",
        `  name: ${scalar(`allow-ingress-from-${caller.deploymentId}`)}`,
        `  namespace: ${scalar(deployment.namespace)}`,
        "spec:",
        "  podSelector:",
        "    matchLabels:",
        `      app: ${scalar(dependencyService(caller, deployment.deploymentId))}`,
        "  policyTypes:",
        "    - Ingress",
        "  ingress:",
        "    - from:",
        "        - namespaceSelector:",
        "            matchLabels:",
        `              security.deus.dev/application: ${scalar(caller.deploymentId)}`,
        "      ports:",
        `        - port: ${scalar(
          caller.dependencies.find(
            (dependency) => dependency.deploymentId === deployment.deploymentId,
          )!.endpointName,
        )}`,
        "          protocol: TCP",
      ]).trimEnd(),
    );
  }
  if (deployment.ingress === "public") {
    const ingressNamespace = plan.environment.ingressNamespace;
    if (!ingressNamespace) {
      throw new Error(
        `Codefly deployment '${deployment.deploymentId}' has public ingress without an ingress namespace.`,
      );
    }
    for (const endpoint of deployment.interfaceEndpoints.filter(
      (candidate) => candidate.visibility === "public",
    )) {
      documents.push(
        document([
          "apiVersion: networking.k8s.io/v1",
          "kind: NetworkPolicy",
          "metadata:",
          `  name: ${scalar(`allow-public-${endpoint.service}-${endpoint.endpoint}`)}`,
          `  namespace: ${scalar(deployment.namespace)}`,
          "spec:",
          "  podSelector:",
          "    matchLabels:",
          `      app: ${scalar(endpoint.service)}`,
          "  policyTypes:",
          "    - Ingress",
          "  ingress:",
          "    - from:",
          "        - namespaceSelector:",
          "            matchLabels:",
          `              kubernetes.io/metadata.name: ${scalar(ingressNamespace)}`,
          "      ports:",
          `        - port: ${scalar(endpoint.endpoint)}`,
          "          protocol: TCP",
        ]).trimEnd(),
      );
    }
  }
  return `${documents.join("\n---\n")}\n`;
}

function renderPodDisruptionBudgets(deployment: CodeflyDeploymentPlan) {
  return `${deployment.services
    .map((service) =>
      document([
        "apiVersion: policy/v1",
        "kind: PodDisruptionBudget",
        "metadata:",
        `  name: ${scalar(`${service}-availability`)}`,
        `  namespace: ${scalar(deployment.namespace)}`,
        "spec:",
        `  maxUnavailable: ${deployment.maximumUnavailable}`,
        "  selector:",
        "    matchLabels:",
        `      app: ${scalar(service)}`,
      ]).trimEnd(),
    )
    .join("\n---\n")}\n`;
}

function renderSecurityContract(
  deployment: CodeflyDeploymentPlan,
  blueprintDigest: string,
) {
  return document([
    "apiVersion: v1",
    "kind: ConfigMap",
    "metadata:",
    "  name: deus-security-contract",
    `  namespace: ${scalar(deployment.namespace)}`,
    "  labels:",
    `    security.deus.dev/application: ${scalar(deployment.deploymentId)}`,
    `    security.deus.dev/blueprint-digest: ${scalar(blueprintDigest)}`,
    "data:",
    `  workload-plane: ${scalar(deployment.workloadPlaneId)}`,
    `  data-boundaries: ${scalar(deployment.dataBoundaryIds.join(","))}`,
    `  workload-identity-required: ${scalar(String(deployment.workloadIdentityRequired))}`,
    `  signature-verification-required: ${scalar(String(deployment.signatureVerificationRequired))}`,
    `  provenance-verification-required: ${scalar(String(deployment.provenanceVerificationRequired))}`,
    `  rollback-required: ${scalar(String(deployment.rollbackRequired))}`,
  ]);
}

function renderBaseKustomization() {
  return document([
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    "resources:",
    "  - namespace.yaml",
    "  - service-account.yaml",
    "  - network-policy.yaml",
    "  - pod-disruption-budget.yaml",
    "  - security-contract.yaml",
  ]);
}

function renderEnvironmentOverlay(
  deployment: CodeflyDeploymentPlan,
  environmentName: string,
) {
  return document([
    "apiVersion: kustomize.config.k8s.io/v1beta1",
    "kind: Kustomization",
    `namespace: ${scalar(deployment.namespace)}`,
    "resources:",
    "  - ../../base",
    ...deployment.services.map(
      (service) =>
        `  - ../../../../services/${service}/deployment/kustomize/overlays/${environmentName}`,
    ),
    "patches:",
    ...deployment.servicePlans.flatMap((service) => [
      "  - target:",
      "      group: apps",
      "      version: v1",
      "      kind: Deployment",
      `      name: ${scalar(service.name)}`,
      "    patch: |-",
      "      - op: add",
      "        path: /spec/template/spec/serviceAccountName",
      `        value: ${scalar(deployment.serviceAccountName)}`,
      "      - op: replace",
      "        path: /spec/template/spec/automountServiceAccountToken",
      "        value: false",
      "      - op: replace",
      "        path: /spec/replicas",
      `        value: ${deployment.minimumReplicas}`,
      "      - op: replace",
      "        path: /spec/template/spec/containers/0/image",
      `        value: ${scalar(service.image)}`,
    ]),
    "commonLabels:",
    `  security.deus.dev/application: ${scalar(deployment.deploymentId)}`,
    `  security.deus.dev/workload-plane: ${scalar(deployment.workloadPlaneId)}`,
  ]);
}

function renderPlanEvidence(plan: CodeflyPaasPlan) {
  return document([
    `apiVersion: ${scalar(plan.apiVersion)}`,
    "kind: DeploymentEvidence",
    "metadata:",
    `  blueprintDigest: ${scalar(plan.blueprintDigest)}`,
    `  environment: ${scalar(plan.environment.name)}`,
    "  compatibility:",
    `    minimumCliVersion: ${scalar(CODEFLY_PAAS_COMPATIBILITY.minimumCliVersion)}`,
    `    maximumCliVersionExclusive: ${scalar(CODEFLY_PAAS_COMPATIBILITY.maximumCliVersionExclusive)}`,
    `    agentProtocolVersion: ${CODEFLY_PAAS_COMPATIBILITY.agentProtocolVersion}`,
    "    requiredAgents:",
    ...Object.entries(CODEFLY_PAAS_COMPATIBILITY.requiredAgents).map(
      ([agent, version]) => `      ${scalar(agent)}: ${scalar(version)}`,
    ),
    "deployments:",
    ...plan.deployments.flatMap((deployment) => [
      `  - id: ${scalar(deployment.deploymentId)}`,
      `    module: ${scalar(deployment.moduleName)}`,
      `    namespace: ${scalar(deployment.namespace)}`,
      `    serviceAccount: ${scalar(deployment.serviceAccountName)}`,
      "    dataBoundaries:",
      ...deployment.dataBoundaryIds.map(
        (boundary) => `      - ${scalar(boundary)}`,
      ),
      "    images:",
      ...Object.entries(deployment.images).map(
        ([service, image]) => `      ${service}: ${scalar(image)}`,
      ),
    ]),
  ]);
}

function dependencyService(
  caller: CodeflyDeploymentPlan,
  targetDeploymentId: string,
) {
  const dependency = caller.dependencies.find(
    (candidate) => candidate.deploymentId === targetDeploymentId,
  );
  if (!dependency) {
    throw new Error(
      `Codefly caller '${caller.deploymentId}' has no dependency on '${targetDeploymentId}'.`,
    );
  }
  return dependency.serviceName;
}

function scalar(value: string) {
  return JSON.stringify(value);
}

function document(lines: readonly string[]) {
  return `${lines.join("\n")}\n`;
}
