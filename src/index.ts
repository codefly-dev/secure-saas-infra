import * as pulumi from "@pulumi/pulumi";
import {
  argocdConfig,
  backupConfig,
  complianceConfig,
  costControlsConfig,
  customerDataConfig,
  detectionConfig,
  dnsConfig,
  e2bByocAccessConfig,
  eksConfig,
  githubGovernanceConfig,
  githubOidcConfig,
  identityCenterConfig,
  ingressConfig,
  logArchiveConfig,
  macieConfig,
  networkConfig,
  networkRoutingConfig,
  organizationAuditConfig,
  organizationConfig,
  securityConfig,
  securityToolingConfig,
  sharedServicesConfig,
  spokeStackConfig,
  stackKind,
  validateConfig,
  wafConfig,
} from "./config";
import { createCustomerDataStore } from "./customerData";
import { createBackupAccountStack } from "./stacks/backupStack";
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

validateConfig();

const organization =
  stackKind === "management"
    ? createOrganizationStack(organizationConfig)
    : undefined;

const networkHub =
  stackKind === "network-hub"
    ? createNetworkHubStack({ networkConfig, securityConfig })
    : undefined;

const networkRouting =
  stackKind === "network-routing"
    ? createNetworkRoutingStack(networkRoutingConfig)
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
  stackKind === "execution"
    ? createE2bByocStack(e2bByocAccessConfig)
    : undefined;
const customerData =
  stackKind === "execution"
    ? createCustomerDataStore(customerDataConfig)
    : undefined;

const spokeCluster =
  stackKind === "platform" || stackKind === "execution"
    ? createSpokeClusterStack({
        spokeConfig: spokeStackConfig,
        eksConfig,
        securityConfig,
      })
    : undefined;

const workload =
  stackKind === "single-account"
    ? createWorkloadStack({ networkConfig, eksConfig, securityConfig })
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
  stackKind === "backup" ? createBackupAccountStack(backupConfig) : undefined;
const detection =
  stackKind === "detection"
    ? createDetectionStack(detectionConfig)
    : undefined;
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
const dns = stackKind === "dns" && dnsConfig ? createDnsStack(dnsConfig) : undefined;
const argocd =
  stackKind === "argocd" && argocdConfig
    ? createArgocdStack(argocdConfig)
    : undefined;

const network = networkHub?.network ?? workload?.network;

export const organizationArn = organization?.organizationArn;
export const organizationRootId = organization?.rootId;
export const organizationalUnitIds = organization?.organizationalUnitIds;
export const organizationAccountIds = organization?.accountIds;
export const transitGatewayId = network?.transitGateway.id;
export const spokeTransitGatewayRouteTableId =
  network?.spokeTransitGatewayRouteTable.id;
export const egressTransitGatewayRouteTableId =
  network?.egressTransitGatewayRouteTable.id;
export const egressVpcId = network?.egressVpc.id;
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
export const routedSpokes = networkRouting?.routedSpokes;
export const eksClusters = workload?.clusters ?? spokeCluster?.clusters;
export const logArchiveBucketName = logArchive?.bucket.bucket;
export const logArchiveBucketArn = logArchive?.bucket.arn;
export const logArchiveKmsKeyArn = logArchive?.kmsKey.arn;
export const logArchiveOrganizationTrailName = logArchive?.organizationTrailName;
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
export const e2bByocVendorRoleArn = e2bByoc?.vendorRole?.arn;
export const customerArtifactBucketName = customerData?.artifactBucket?.bucket;
export const customerArtifactKmsKeyArn = customerData?.artifactKmsKey?.arn;
export const backupPrimaryVaultArn = backup?.primaryVault.arn;
export const backupReplicaVaultArn = backup?.replicaVault?.arn;
export const backupPrimaryKeyArn = backup?.primaryKmsKey.arn;
export const backupReplicaKeyArn = backup?.replicaKmsKey?.arn;
export const detectionTopicArn = detection?.topic.arn;
export const conformancePackName = compliance?.conformancePack?.name;
export const auditManagerAssessmentArn = compliance?.auditManagerAssessment?.arn;
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
