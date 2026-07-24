import type { CodeflyPaasPlan } from "./codeflyAdapter";

export const CODEFLY_PAAS_COMPATIBILITY = {
  contractVersion: "paas.codefly.dev/v1alpha1",
  minimumCliVersion: "0.1.3",
  maximumCliVersionExclusive: "0.2.0",
  agentProtocolVersion: 2,
  requiredAgents: {
    "codefly.dev/go-grpc": "0.1.6",
    "codefly.dev/nextjs": "0.0.110",
  },
  requiredFeatures: [
    "declared-environments",
    "local-agent-resolution",
    "module-interfaces",
    "cross-module-service-dependencies",
    "module-kustomize-overlays",
    "render-only-deployment",
  ],
} as const;

export interface ObservedCodeflyCompatibility {
  cliVersion: string;
  agentProtocolVersion: number;
  installedAgents: Readonly<Record<string, string>>;
  features: readonly string[];
}

export function assertCodeflyCompatibility(
  observed: ObservedCodeflyCompatibility,
) {
  if (
    compareVersions(
      observed.cliVersion,
      CODEFLY_PAAS_COMPATIBILITY.minimumCliVersion,
    ) < 0 ||
    compareVersions(
      observed.cliVersion,
      CODEFLY_PAAS_COMPATIBILITY.maximumCliVersionExclusive,
    ) >= 0
  ) {
    throw new Error(
      `Codefly CLI ${observed.cliVersion} is outside supported range >=${CODEFLY_PAAS_COMPATIBILITY.minimumCliVersion} <${CODEFLY_PAAS_COMPATIBILITY.maximumCliVersionExclusive}.`,
    );
  }
  if (
    observed.agentProtocolVersion !==
    CODEFLY_PAAS_COMPATIBILITY.agentProtocolVersion
  ) {
    throw new Error(
      `Codefly agent protocol ${observed.agentProtocolVersion} is incompatible with required protocol ${CODEFLY_PAAS_COMPATIBILITY.agentProtocolVersion}.`,
    );
  }
  for (const [agent, requiredVersion] of Object.entries(
    CODEFLY_PAAS_COMPATIBILITY.requiredAgents,
  )) {
    const installed = observed.installedAgents[agent];
    if (installed !== requiredVersion) {
      throw new Error(
        `Codefly agent '${agent}' must be exactly ${requiredVersion}; observed ${installed ?? "missing"}.`,
      );
    }
  }
  const features = new Set(observed.features);
  const missing = CODEFLY_PAAS_COMPATIBILITY.requiredFeatures.filter(
    (feature) => !features.has(feature),
  );
  if (missing.length > 0) {
    throw new Error(
      `Codefly is missing required PaaS features: ${missing.join(", ")}.`,
    );
  }
}

export function codeflyCompatibilityEvidence(
  plan: CodeflyPaasPlan,
): Readonly<Record<string, unknown>> {
  return {
    contractVersion: CODEFLY_PAAS_COMPATIBILITY.contractVersion,
    blueprintDigest: plan.blueprintDigest,
    cliRange: {
      minimum: CODEFLY_PAAS_COMPATIBILITY.minimumCliVersion,
      maximumExclusive: CODEFLY_PAAS_COMPATIBILITY.maximumCliVersionExclusive,
    },
    agentProtocolVersion: CODEFLY_PAAS_COMPATIBILITY.agentProtocolVersion,
    requiredAgents: CODEFLY_PAAS_COMPATIBILITY.requiredAgents,
    requiredFeatures: CODEFLY_PAAS_COMPATIBILITY.requiredFeatures,
  };
}

function compareVersions(left: string, right: string) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

function parseVersion(value: string) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(value.trim());
  if (!match)
    throw new Error(`Codefly version '${value}' is not strict semver.`);
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}
