export type CloudProvider = "aws" | "gcp" | "azure";

export type IsolationTier =
  | "pooled"
  | "dedicated-data"
  | "dedicated-network"
  | "dedicated-account";

export type TrustZoneKind =
  | "edge"
  | "control-plane"
  | "workload"
  | "execution"
  | "data"
  | "security"
  | "egress"
  | "external";

export type DataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "regulated";

export type TenantScope =
  | { mode: "platform" }
  | { mode: "pooled"; tenantIds: readonly string[] }
  | { mode: "dedicated"; tenantId: string };

export interface SecurityPosture {
  forbidPublicControlPlanes: boolean;
  requireInspectedEgress: boolean;
  requireImmutableAudit: boolean;
  minimumAuditRetentionDays: number;
}

export interface TrustZone {
  id: string;
  kind: TrustZoneKind;
  publicAccess: boolean;
  tenantScope: TenantScope;
  isolationBoundary?: string;
}

export interface NetworkDomain {
  id: string;
  zoneId: string;
  cidrs: readonly string[];
  availabilityZoneCount: number;
  directInternetAccess: boolean;
  inspectedEgress: boolean;
}

export interface NetworkFlow {
  id: string;
  fromZoneId: string;
  toZoneId: string;
  protocol: "tcp" | "udp" | "icmp" | "https" | "any";
  ports?: readonly number[];
  purpose: string;
  authorization: "direct" | "brokered";
  viaZoneIds?: readonly string[];
  externalDestinations?: readonly string[];
}

export type WorkloadOrchestrator =
  | "managed-kubernetes"
  | "serverless"
  | "microvm"
  | "external-sandbox";

export type RuntimeIsolation =
  | "process"
  | "container"
  | "microvm"
  | "dedicated-vm";

export interface WorkloadPlane {
  id: string;
  zoneId: string;
  tenantScope: TenantScope;
  executionTrust: "trusted" | "semi-trusted" | "untrusted";
  orchestrator: WorkloadOrchestrator;
  runtimeIsolation: RuntimeIsolation;
  controlPlanePublic: boolean;
  workloadIdentity: boolean;
  credentialMode: "ambient" | "workload-identity" | "brokered";
  maxExecutionMinutes?: number;
}

export interface EncryptionRequirement {
  customerManagedKey: boolean;
  dedicatedPerTenant: boolean;
  rotationRequired: boolean;
}

export type DataService = "object" | "relational";

export interface RecoveryRequirement {
  backupRequired: boolean;
  rpoMinutes: number;
  rtoMinutes: number;
  multiAzRequired: boolean;
  deletionProtectionRequired: boolean;
  finalSnapshotRequired: boolean;
  restoreTestIntervalDays: number;
}

export interface DataBoundary {
  id: string;
  zoneId: string;
  classification: DataClassification;
  tenantScope: TenantScope;
  services: readonly DataService[];
  encryption: EncryptionRequirement;
  recovery: RecoveryRequirement;
  retentionDays: number;
  versioningRequired: boolean;
  replicationRequired: boolean;
  objectAuditRequired: boolean;
  deletionEvidenceRequired: boolean;
  exportEvidenceRequired: boolean;
}

export interface Identity {
  id: string;
  kind: "workforce" | "workload" | "automation" | "vendor";
  tenantId?: string;
  shortLived: boolean;
}

export interface IdentityDelegation {
  id: string;
  fromIdentityId: string;
  toIdentityId: string;
  conditions?: Readonly<Record<string, string>>;
}

export interface AccessException {
  owner: string;
  reason: string;
  expiresAt: string;
  auditRequirementId: string;
}

export interface IdentityGrant {
  id: string;
  identityId: string;
  resourceIds: readonly string[];
  actions: readonly string[];
  effect: "allow" | "deny";
  tenantId?: string;
  conditions?: Readonly<Record<string, string>>;
  exception?: AccessException;
}

export interface EvidenceSink {
  id: string;
  immutable: boolean;
  retentionDays: number;
  tenantScope: TenantScope;
}

export interface EvidenceRequirement {
  id: string;
  sourceIds: readonly string[];
  sinkId: string;
  eventTypes: readonly string[];
}

export interface TenantPlacement {
  tenantId: string;
  isolationTier: IsolationTier;
  zoneIds: readonly string[];
  dataBoundaryIds: readonly string[];
  identityIds: readonly string[];
}

export interface ApplicationDependency {
  deploymentId: string;
  fromComponentId: string;
  toComponentId: string;
  protocol: "https" | "grpc";
  authorization: "workload-identity" | "capability";
  audience: string;
  actions: readonly string[];
}

export interface ApplicationComponentDependency {
  fromComponentId: string;
  toComponentId: string;
  protocol: "https" | "grpc";
  authorization: "workload-identity" | "capability";
  audience: string;
  actions: readonly string[];
}

export interface ApplicationComponent {
  id: string;
  workloadPlaneId: string;
  serviceIdentityId: string;
  dataBoundaryIds: readonly string[];
  ingress: "none" | "private" | "public";
  availability: {
    minimumReplicas: number;
    maximumUnavailable: number;
  };
}

export interface ApplicationDeployment {
  id: string;
  workloadPlaneId: string;
  serviceIdentityId: string;
  tenantScope: TenantScope;
  dataBoundaryIds: readonly string[];
  ingress: "none" | "private" | "public";
  components: readonly ApplicationComponent[];
  componentDependencies: readonly ApplicationComponentDependency[];
  dependencies: readonly ApplicationDependency[];
  availability: {
    minimumReplicas: number;
    maximumUnavailable: number;
  };
  release: {
    digestPinnedImages: boolean;
    signatureVerification: boolean;
    provenanceVerification: boolean;
    rollbackRequired: boolean;
  };
}

export type PlatformCapability =
  | "private-network"
  | "centralized-egress"
  | "managed-firewall"
  | "private-control-plane"
  | "workload-identity"
  | "customer-managed-encryption"
  | "immutable-audit-log"
  | "dedicated-account-boundary"
  | "microvm-runtime"
  | "external-sandbox"
  | "serverless-runtime";

export interface PlatformBlueprint {
  apiVersion: "security.deus.dev/v1alpha1";
  name: string;
  environment: string;
  posture: SecurityPosture;
  requiredCapabilities: readonly PlatformCapability[];
  trustZones: readonly TrustZone[];
  networkDomains: readonly NetworkDomain[];
  flows: readonly NetworkFlow[];
  workloadPlanes: readonly WorkloadPlane[];
  applications: readonly ApplicationDeployment[];
  tenants: readonly TenantPlacement[];
  dataBoundaries: readonly DataBoundary[];
  identities: readonly Identity[];
  identityDelegations: readonly IdentityDelegation[];
  grants: readonly IdentityGrant[];
  evidenceSinks: readonly EvidenceSink[];
  evidenceRequirements: readonly EvidenceRequirement[];
}

export function platformTenantScope(): TenantScope {
  return { mode: "platform" };
}
