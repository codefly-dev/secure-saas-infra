import {
  AwsIamProviderExtensions,
  compileAwsBackups,
  compileAwsDataBoundaries,
  compileAwsIam,
  compileAwsNetworkBlueprint,
  compileAwsWorkloads,
} from "../src/adapters/aws";
import type { PlatformBlueprint } from "../src/core";
import {
  PROVIDER_CONTRACT_VERSION,
  ProviderContractAdapter,
  registerProviderContract,
} from "./contracts/providerContract";

const aws: ProviderContractAdapter = {
  name: "aws",
  compile(blueprint) {
    const network = compileAwsNetworkBlueprint(blueprint, {
      shareTransitGatewayWithOrganization: true,
      createEksByZoneId: {},
      spokeKindByZoneId: {},
    });
    const workloads = compileAwsWorkloads(blueprint, {
      eks: {
        version: "1.33",
        endpointPublicAccess: false,
        autoModeNodePools: ["system", "general-purpose"],
        networkPolicyMode: "strict",
        secretsEncryption: true,
        controlPlaneLogTypes: [
          "api",
          "audit",
          "authenticator",
          "controllerManager",
          "scheduler",
        ],
      },
      e2b: { vendorRoleConfigured: true, externalIdConfigured: true },
      microvm: {
        enabled: true,
        runtimeClassName: "deus-microvm",
        nodeIsolationLabel: "deus.dev/sandbox-runtime=microvm",
      },
    });
    const data = compileAwsDataBoundaries(blueprint, {
      noncurrentVersionExpirationDays: 30,
    });
    const backups = compileAwsBackups(blueprint, {
      vaultLockEnabled: true,
      backupIntervalMinutes: 60,
      coldStorageAfterDays: 90,
      deleteAfterDays: 365,
    });
    const iam = compileAwsIam(blueprint, iamExtensions(blueprint));
    return {
      contractVersion: PROVIDER_CONTRACT_VERSION,
      provider: "aws",
      networkDomainIds: [
        network.egress.networkDomainId,
        ...network.spokes.map((spoke) => spoke.networkDomainId),
      ].sort(),
      privateWorkloadPlaneIds: workloads.planes
        .map((plane) => plane.planeId)
        .sort(),
      dataBoundaryIds: data.artifactStores
        .map((store) => store.boundaryId)
        .sort(),
      backupBoundaryIds: backups.backups
        .map((backup) => backup.boundaryId)
        .sort(),
      identityIds: iam.workloadIdentityAssociations
        .map((identity) => identity.identityId)
        .sort(),
      evidenceSinkIds: [
        ...new Set(backups.backups.map((backup) => backup.evidenceSinkId)),
      ].sort(),
    };
  },
};

registerProviderContract(aws);

function iamExtensions(blueprint: PlatformBlueprint): AwsIamProviderExtensions {
  return {
    accountId: "123456789012",
    organizationId: "o-example123456",
    identities: Object.fromEntries(
      blueprint.identities.map((identity) => [
        identity.id,
        {
          roleArn: `arn:aws:iam::123456789012:role/${identity.id}`,
          podIdentity: {
            namespace: "contract",
            serviceAccount: identity.id,
          },
        },
      ]),
    ),
    resources: Object.fromEntries(
      blueprint.dataBoundaries.map((boundary) => {
        const tenantIds =
          boundary.tenantScope.mode === "dedicated"
            ? [boundary.tenantScope.tenantId]
            : boundary.tenantScope.mode === "pooled"
              ? [...boundary.tenantScope.tenantIds]
              : [];
        return [
          boundary.id,
          {
            kind: "data" as const,
            bucketArn: `arn:aws:s3:::${boundary.id}`,
            prefixByTenant: Object.fromEntries(
              tenantIds.map((tenantId) => [tenantId, `tenants/${tenantId}/`]),
            ),
            keyArnByTenant: Object.fromEntries(
              tenantIds.map((tenantId) => [
                tenantId,
                `arn:aws:kms:us-east-1:123456789012:key/${
                  boundary.encryption.dedicatedPerTenant
                    ? tenantId
                    : boundary.id
                }`,
              ]),
            ),
          },
        ];
      }),
    ),
  };
}
