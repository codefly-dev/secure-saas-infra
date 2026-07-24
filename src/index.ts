import * as pulumi from "@pulumi/pulumi";
import {
  argocdConfig,
  awsAllowedAccountIds,
  awsOrganizationId,
  awsRegion,
  awsBootstrapAccessAccountName,
  awsBootstrapAccessPlan,
  backupConfig,
  complianceConfig,
  codeflyRegistryConfig,
  costControlsConfig,
  customerDataConfig,
  detectionConfig,
  databaseConfig,
  dnsConfig,
  e2bByocAccessConfig,
  eksConfig,
  githubGovernanceConfig,
  githubOidcConfig,
  identityCenterConfig,
  ingressConfig,
  logArchiveConfig,
  macieConfig,
  managedPostgresContractPath,
  managedPostgresEnvironment,
  networkConfig,
  networkRoutingConfig,
  organizationAuditConfig,
  organizationConfig,
  platformBlueprintMigrationReport,
  platformBlueprint,
  securityConfig,
  securityToolingConfig,
  sharedServicesConfig,
  spokeStackConfig,
  stackKind,
  validateConfig,
  wafConfig,
} from "./config";
import { createCodeflyRegistry } from "./codeflyRegistry";
import {
  createCustomerDataStore,
  createCustomerDataStoresFromBlueprint,
} from "./customerData";
import { createBackupAccountStack } from "./stacks/backupStack";
import { createAwsBootstrapAccessStack } from "./stacks/awsBootstrapAccessStack";
import { createComplianceStack } from "./stacks/complianceStack";
import { createCostControlsStack } from "./stacks/costControlsStack";
import { createDetectionStack } from "./stacks/detectionStack";
import { createE2bByocStack } from "./stacks/e2bByocStack";
import { createGithubGovernanceStack } from "./stacks/githubGovernanceStack";
import { createGithubOidcStack } from "./stacks/githubOidcStack";
import { createArgocdStack } from "./stacks/argocdStack";
import { createDnsStack } from "./stacks/dnsStack";
import { createIdentityStack } from "./stacks/identityStack";
import { createIngressStack } from "./stacks/ingressStack";
import { createLogArchiveStack } from "./stacks/logArchiveStack";
import { createMacieStack } from "./stacks/macieStack";
import { createNetworkHubStack } from "./stacks/networkHubStack";
import { createNetworkRoutingStack } from "./stacks/networkRoutingStack";
import { createOrganizationAuditStack } from "./stacks/organizationAuditStack";
import { createOrganizationStack } from "./stacks/organizationStack";
import { createSecurityToolingStack } from "./stacks/securityToolingStack";
import { createSharedServicesStack } from "./stacks/sharedServicesStack";
import { createSpokeClusterStack } from "./stacks/spokeClusterStack";
import { createWafStack } from "./stacks/wafStack";
import { createWorkloadStack } from "./stacks/workloadStack";
import { firewallEndpointForAz } from "./network";
import { loadManagedPostgresContract } from "./managedPostgresContract";
import { materializeAwsDatabaseInfrastructureHandoff } from "./databaseAccess";
import { materializeAwsPostgresAccessProfile } from "./postgresAccessProfile";
import { compileAwsApplyLaneIamConstraint } from "./adapters/aws";

validateConfig();

const managedPostgresIntent =
  platformBlueprint && managedPostgresContractPath
    ? loadManagedPostgresContract(
        managedPostgresContractPath,
        managedPostgresEnvironment!,
        platformBlueprint,
      )
    : undefined;

const organization =
  stackKind === "management"
    ? createOrganizationStack(organizationConfig)
    : undefined;

const awsBootstrapAccess =
  stackKind === "account-access"
    ? createAwsBootstrapAccessStack(
        awsBootstrapAccessPlan,
        awsBootstrapAccessAccountName!,
      )
    : undefined;

const awsDataIamRoleConstraint =
  awsBootstrapAccessPlan && awsBootstrapAccessAccountName
    ? compileAwsApplyLaneIamConstraint(
        awsBootstrapAccessPlan,
        awsBootstrapAccessAccountName,
        "database",
      )
    : undefined;

const networkHub =
  stackKind === "network-hub"
    ? createNetworkHubStack({
        networkConfig,
        securityConfig,
        platformBlueprint,
      })
    : undefined;

const networkRouting =
  stackKind === "network-routing"
    ? createNetworkRoutingStack(networkRoutingConfig, platformBlueprint)
    : undefined;

const organizationAudit =
  stackKind === "organization-audit"
    ? createOrganizationAuditStack(organizationAuditConfig)
    : undefined;

const identity =
  stackKind === "identity"
    ? createIdentityStack(identityCenterConfig)
    : undefined;
const githubOidc =
  stackKind === "github-oidc"
    ? createGithubOidcStack(githubOidcConfig)
    : undefined;
const githubGovernance =
  stackKind === "github-governance"
    ? createGithubGovernanceStack(githubGovernanceConfig)
    : undefined;
const e2bByoc =
  stackKind === "execution" && !platformBlueprint
    ? createE2bByocStack(e2bByocAccessConfig)
    : undefined;
const customerData =
  stackKind === "execution" ||
  (stackKind === "single-account" && platformBlueprint)
    ? stackKind === "single-account" && platformBlueprint
      ? createCustomerDataStoresFromBlueprint(
          platformBlueprint,
          customerDataConfig,
        )
      : createCustomerDataStore(customerDataConfig)
    : undefined;

const spokeCluster =
  stackKind === "platform" || stackKind === "execution"
    ? createSpokeClusterStack({
        spokeConfig: spokeStackConfig,
        eksConfig,
        securityConfig,
        platformBlueprint,
        e2bByocAccessConfig,
        databaseConfig,
        managedPostgresIntent,
        awsOrganizationId,
        awsAccountId: awsAllowedAccountIds[0],
        awsRegion,
        iamRoleConstraint: awsDataIamRoleConstraint,
      })
    : undefined;

const workload =
  stackKind === "single-account"
    ? createWorkloadStack({
        networkConfig,
        eksConfig,
        securityConfig,
        platformBlueprint,
        e2bByocAccessConfig,
        databaseConfig,
        managedPostgresIntent,
        awsOrganizationId,
        awsAccountId: awsAllowedAccountIds[0],
        awsRegion,
        iamRoleConstraint: awsDataIamRoleConstraint,
      })
    : undefined;

const codeflyRegistry =
  (stackKind === "platform" || stackKind === "single-account") &&
  codeflyRegistryConfig.enabled
    ? createCodeflyRegistry(codeflyRegistryConfig)
    : undefined;

const logArchive =
  stackKind === "log-archive"
    ? createLogArchiveStack(logArchiveConfig)
    : undefined;
const securityTooling =
  stackKind === "security-tooling"
    ? createSecurityToolingStack(securityToolingConfig)
    : undefined;
const sharedServices =
  stackKind === "shared-services"
    ? createSharedServicesStack(sharedServicesConfig)
    : undefined;

const backup =
  stackKind === "backup"
    ? createBackupAccountStack(backupConfig, platformBlueprint)
    : undefined;
const detection =
  stackKind === "detection" ? createDetectionStack(detectionConfig) : undefined;
const compliance =
  stackKind === "compliance"
    ? createComplianceStack(complianceConfig)
    : undefined;
const costControls =
  stackKind === "cost-controls"
    ? createCostControlsStack(costControlsConfig)
    : undefined;
const macie = stackKind === "macie" ? createMacieStack(macieConfig) : undefined;
const waf = stackKind === "waf" ? createWafStack(wafConfig) : undefined;
const ingress =
  stackKind === "ingress" && ingressConfig
    ? createIngressStack(ingressConfig)
    : undefined;
const dns =
  stackKind === "dns" && dnsConfig ? createDnsStack(dnsConfig) : undefined;
const argocd =
  stackKind === "argocd" && argocdConfig
    ? createArgocdStack(argocdConfig)
    : undefined;

const network = networkHub?.network ?? workload?.network;

export const organizationArn = organization?.organizationArn;
export const organizationRootId = organization?.rootId;
export const organizationalUnitIds = organization?.organizationalUnitIds;
export const organizationAccountIds = organization?.accountIds;
export const awsBootstrapAccessAccountId = awsBootstrapAccess?.accountId;
export const awsBootstrapAccessSourceDigest = awsBootstrapAccess?.sourceDigest;
export const awsBootstrapAccessRoles = awsBootstrapAccess
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(awsBootstrapAccess.roles).map(([lane, resource]) => [
          lane,
          {
            roleArn: resource.role.arn,
            permissionsBoundaryArn: resource.boundary.arn,
            delegatedRolePermissionsBoundaryArn:
              resource.delegatedBoundary?.arn,
            mode: resource.plan.mode,
            actionSet: resource.plan.actionSet,
            externalId: resource.plan.externalId,
            sourceIdentityPattern: resource.plan.sourceIdentityPattern,
            productionApprovalRequired:
              resource.plan.productionApprovalRequired,
            destructiveMutation: resource.plan.destructiveMutation,
          },
        ]),
      ),
    )
  : undefined;
export const transitGatewayId = network?.transitGateway.id;
export const spokeTransitGatewayRouteTableId =
  network?.spokeTransitGatewayRouteTable.id;
export const egressTransitGatewayRouteTableId =
  network?.egressTransitGatewayRouteTable.id;
export const egressVpcId = network?.egressVpc.id;
export const egressZoneId = networkHub?.semanticIds.zoneId;
export const egressNetworkDomainId = networkHub?.semanticIds.networkDomainId;
export const egressPublicRouteTableIds = network?.egressPublicRouteTables.map(
  (routeTable) => routeTable.id,
);
export const egressFirewallRouteTableIds =
  network?.egressFirewallRouteTables.map((routeTable) => routeTable.id);
export const egressFirewallEndpointIdsForPublicRoutes = network?.networkFirewall
  ? pulumi.all(
      network.egressPublicSubnets.map((subnet) =>
        firewallEndpointForAz(
          network.networkFirewall!,
          subnet.availabilityZone,
        ),
      ),
    )
  : undefined;
export const spokeVpcIds = workload
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(workload.network.spokes).map(([name, spoke]) => [
          name,
          spoke.vpc.id,
        ]),
      ),
    )
  : undefined;
export const spokeName = spokeCluster?.spoke.name;
export const spokeCidr = spokeCluster?.spoke.cidr;
export const spokeVpcId = spokeCluster?.spoke.vpc.id;
export const spokeTransitGatewayAttachmentId =
  spokeCluster?.spoke.attachment.id;
export const spokeZoneId = spokeCluster?.semanticIds.zoneId;
export const spokeNetworkDomainId = spokeCluster?.semanticIds.networkDomainId;
export const databaseClusterIds = spokeCluster
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(spokeCluster.databases).map(([boundaryId, database]) => [
          boundaryId,
          database.cluster.id,
        ]),
      ),
    )
  : workload
    ? pulumi.output(
        Object.fromEntries(
          Object.entries(workload.databases).map(([boundaryId, database]) => [
            boundaryId,
            database.cluster.id,
          ]),
        ),
      )
    : undefined;
export const databaseBindings =
  spokeCluster?.databaseBindings ?? workload?.databaseBindings;
export const databaseMigrationBindings =
  spokeCluster?.databaseMigrationBindings ??
  workload?.databaseMigrationBindings;
export const databaseBootstrapBindings =
  spokeCluster?.databaseBootstrapBindings ??
  workload?.databaseBootstrapBindings;
const managedDatabaseAccess =
  spokeCluster?.databaseAccess ?? workload?.databaseAccess;
function requiredDatabaseAssociationId(
  bindingId: string,
  accessClass: "runtime" | "migration",
  association: { associationId: pulumi.Input<string> } | undefined,
) {
  if (!association) {
    throw new Error(
      `Managed PostgreSQL binding '${bindingId}' is missing its persistent ${accessClass} Pod Identity association.`,
    );
  }
  return association.associationId;
}
export const databaseAccessBindings = managedDatabaseAccess
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(managedDatabaseAccess).map(([bindingId, access]) => [
          bindingId,
          {
            runtime: {
              namespace: access.runtime.namespace,
              serviceAccount: access.runtime.serviceAccount,
              databaseUser: access.runtime.databaseUser,
              roleArn: access.runtime.role.arn,
              associationId: requiredDatabaseAssociationId(
                bindingId,
                "runtime",
                access.runtime.association,
              ),
              securityGroupId: access.runtime.securityGroup.id,
              bindingDigest: access.runtime.bindingDigest,
              workloadBundleDigest: access.runtime.workloadBundleDigest,
              status: {
                state: "pending-infrastructure",
                reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
              },
            },
          },
        ]),
      ),
    )
  : undefined;
export const databaseMigrationAccessBindings = managedDatabaseAccess
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(managedDatabaseAccess).map(([bindingId, access]) => [
          bindingId,
          {
            migration: {
              namespace: access.migration.namespace,
              serviceAccount: access.migration.serviceAccount,
              databaseUser: access.migration.databaseUser,
              roleArn: access.migration.role.arn,
              associationId: requiredDatabaseAssociationId(
                bindingId,
                "migration",
                access.migration.association,
              ),
              securityGroupId: access.migration.securityGroup.id,
              bindingDigest: access.migration.bindingDigest,
              workloadBundleDigest: access.migration.workloadBundleDigest,
              status: {
                state: "pending-infrastructure",
                reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
              },
            },
          },
        ]),
      ),
    )
  : undefined;
export const databaseBootstrapAccessBindings = managedDatabaseAccess
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(managedDatabaseAccess).map(([bindingId, access]) => {
          const identity = access.bootstrap;
          return [
            bindingId,
            {
              namespace: identity.namespace,
              serviceAccount: identity.serviceAccount,
              roleArn: identity.role.arn,
              associationId: null,
              securityGroupId: identity.securityGroup.id,
              bindingDigest: identity.bindingDigest,
              workloadBundleDigest: identity.workloadBundleDigest,
              status: {
                state: "pending-jit-authorization",
                reason: "POSTGRES_BOOTSTRAP_JIT_AUTHORIZATION_REQUIRED",
              },
            },
          ];
        }),
      ),
    )
  : undefined;
export const databaseInfrastructureHandoffs = managedDatabaseAccess
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(managedDatabaseAccess).map(([bindingId, access]) => [
          bindingId,
          materializeAwsDatabaseInfrastructureHandoff(bindingId, access),
        ]),
      ),
    )
  : undefined;
export const postgresAccessProfiles =
  managedDatabaseAccess && databaseBindings && managedPostgresIntent
    ? pulumi.output(
        Object.fromEntries(
          managedPostgresIntent.bindings.map((binding) => {
            const projection = databaseBindings[binding.id];
            const access = managedDatabaseAccess[binding.id];
            if (!projection || !access) {
              throw new Error(
                `Managed PostgreSQL binding '${binding.id}' is missing its AWS database or access materialization.`,
              );
            }
            return [
              binding.id,
              materializeAwsPostgresAccessProfile({
                binding,
                accessClass: "runtime",
                endpoint: projection.endpoint,
                port: projection.port,
                databaseName: projection.databaseName,
                caCertIdentifier: projection.tls.caCertIdentifier,
                caBundleRef: projection.tls.caBundleRef,
                region: projection.authentication.region,
                proxyResourceId: projection.proxyResourceId,
                databaseUser: projection.runtimeDatabaseUser,
                semanticIdentityId: binding.access.runtimeIdentityId,
                roleArn: access.runtime.role.arn,
                namespace: access.runtime.namespace,
                serviceAccount: access.runtime.serviceAccount,
                podIdentityAssociationId: requiredDatabaseAssociationId(
                  binding.id,
                  "runtime",
                  access.runtime.association,
                ),
                securityGroupId: access.runtime.securityGroup.id,
                bindingDigest: access.runtime.bindingDigest,
                workloadBundleDigest: access.runtime.workloadBundleDigest,
                workloadManifest: access.runtime.workloadManifest,
              }),
            ];
          }),
        ),
      )
    : undefined;
export const postgresMigrationAccessProfiles =
  managedDatabaseAccess && databaseMigrationBindings && managedPostgresIntent
    ? pulumi.output(
        Object.fromEntries(
          managedPostgresIntent.bindings.map((binding) => {
            const projection = databaseMigrationBindings[binding.id];
            const access = managedDatabaseAccess[binding.id];
            if (!projection || !access) {
              throw new Error(
                `Managed PostgreSQL binding '${binding.id}' is missing its AWS migration database or access materialization.`,
              );
            }
            return [
              binding.id,
              materializeAwsPostgresAccessProfile({
                binding,
                accessClass: "migration",
                endpoint: projection.endpoint,
                port: projection.port,
                databaseName: projection.databaseName,
                caCertIdentifier: projection.tls.caCertIdentifier,
                caBundleRef: projection.tls.caBundleRef,
                region: projection.authentication.region,
                proxyResourceId: projection.proxyResourceId,
                databaseUser: projection.migrationDatabaseUser,
                semanticIdentityId: binding.access.migrationIdentityId,
                roleArn: access.migration.role.arn,
                namespace: access.migration.namespace,
                serviceAccount: access.migration.serviceAccount,
                podIdentityAssociationId: requiredDatabaseAssociationId(
                  binding.id,
                  "migration",
                  access.migration.association,
                ),
                securityGroupId: access.migration.securityGroup.id,
                bindingDigest: access.migration.bindingDigest,
                workloadBundleDigest: access.migration.workloadBundleDigest,
                workloadManifest: access.migration.workloadManifest,
              }),
            ];
          }),
        ),
      )
    : undefined;
export const routedSpokes = networkRouting?.routedSpokes;
export const eksClusters = workload?.clusters ?? spokeCluster?.clusters;
export const codeflyRegistryRepositoryUrls = codeflyRegistry
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(codeflyRegistry.repositories).map(
          ([logicalName, repository]) => [
            logicalName,
            repository.repositoryUrl,
          ],
        ),
      ),
    )
  : undefined;
export const codeflyRegistryRepositoryArns = codeflyRegistry
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(codeflyRegistry.repositories).map(
          ([logicalName, repository]) => [logicalName, repository.arn],
        ),
      ),
    )
  : undefined;
export const codeflyRegistryKmsKeyArn = codeflyRegistry?.kmsKey.arn;
export const logArchiveBucketName = logArchive?.bucket.bucket;
export const logArchiveBucketArn = logArchive?.bucket.arn;
export const logArchiveKmsKeyArn = logArchive?.kmsKey.arn;
export const logArchiveOrganizationTrailName =
  logArchive?.organizationTrailName;
export const logArchiveCloudTrailSourceAccountId =
  logArchive?.cloudTrailSourceAccountId;
export const organizationTrailArn = logArchive?.trail?.arn;
export const managementOrganizationTrailArn = organizationAudit?.trail.arn;
export const guardDutyDetectorId = securityTooling?.guardDutyDetector?.id;
export const vaultAutoUnsealKeyArn = sharedServices?.vaultKey?.arn;
export const vaultBackupBucketName = sharedServices?.backupBucket?.bucket;
export const identityGroupIds = identity?.groupIds;
export const identityPermissionSetArns = identity?.permissionSetArns;
export const githubOidcRoleArns = githubOidc
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(githubOidc.roles).map(([name, role]) => [
          name,
          role.arn,
        ]),
      ),
    )
  : undefined;
export const githubMainRulesetId = githubGovernance?.mainRuleset?.rulesetId;
export const githubPushRulesetId = githubGovernance?.pushRuleset?.rulesetId;
export const githubProtectedEnvironments = githubGovernance
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(githubGovernance.environments).map(([name, env]) => [
          name,
          env.id,
        ]),
      ),
    )
  : undefined;
export const e2bByocVendorRoleArn =
  e2bByoc?.vendorRole?.arn ??
  spokeCluster?.e2bByoc?.vendorRole?.arn ??
  workload?.e2bByoc?.vendorRole?.arn;
export const customerArtifactBucketName = customerData?.artifactBucket?.bucket;
export const customerArtifactKmsKeyArn = customerData?.artifactKmsKey?.arn;
export const backupPrimaryVaultArn = backup?.primaryVault.arn;
export const backupReplicaVaultArn = backup?.replicaVault?.arn;
export const backupPrimaryKeyArn = backup?.primaryKmsKey.arn;
export const backupReplicaKeyArn = backup?.replicaKmsKey?.arn;
export const detectionTopicArn = detection?.topic.arn;
export const conformancePackName = compliance?.conformancePack?.name;
export const auditManagerAssessmentArn =
  compliance?.auditManagerAssessment?.arn;
export const tenantBudgetNames = costControls
  ? costControls.budgets.map((budget) => budget.name)
  : undefined;
export const macieAccountId = macie?.account.id;
export const wafWebAclArn = waf?.webAcl.arn;
export const ingressDistributionId = ingress?.distribution.id;
export const ingressDistributionDomainName = ingress?.distribution.domainName;
export const ingressCertificateArn = ingress?.certificate.arn;
export const ingressVpcOriginId = ingress?.vpcOrigin.id;
export const ingressLogBucketName = ingress?.logBucket.bucket;
export const dnsRootZoneId = dns?.rootZone?.zoneId;
export const dnsRootZoneNameServers = dns?.rootZone?.nameServers;
export const dnsEnvironmentZoneIds = dns
  ? pulumi.output(
      Object.fromEntries(
        Object.entries(dns.environmentZones).map(([env, zone]) => [
          env,
          zone.zoneId,
        ]),
      ),
    )
  : undefined;
export const argocdNamespace = argocd?.namespace.metadata.name;
export const argocdReleaseName = argocd?.release.name;
export const blueprintMigrationReport = platformBlueprintMigrationReport;
