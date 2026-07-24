import * as pulumi from "@pulumi/pulumi";
import {
  parsePostgresAccessProfile,
  postgresAccessProfileSpecDigest,
  type ManagedPostgresBinding,
  type PostgresAccessClass,
  type PostgresAccessProfile,
  type PostgresAccessProfileDigestSubject,
} from "./core";
import {
  awsDatabaseAccessBindingDigest,
  type AwsDatabaseWorkloadManifest,
} from "./databaseAccess";
import { awsManagedPostgresDatabaseUser } from "./adapters/aws";

export interface ResolvedAwsPostgresAccessProfileInput {
  binding: ManagedPostgresBinding;
  accessClass: PostgresAccessClass;
  endpoint: string;
  port: number;
  databaseName: string;
  caCertIdentifier: string;
  caBundleRef: string;
  region: string;
  proxyResourceId: string;
  databaseUser: string;
  semanticIdentityId: string;
  roleArn: string;
  namespace: string;
  serviceAccount: string;
  podIdentityAssociationId: string;
  securityGroupId: string;
  bindingDigest: string;
  workloadBundleDigest: string;
  workloadManifest: AwsDatabaseWorkloadManifest;
}

export function compileAwsPostgresAccessProfile(
  args: ResolvedAwsPostgresAccessProfileInput,
): PostgresAccessProfile {
  if (args.port !== args.binding.database.port) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' port does not match its ManagedPostgres binding.`,
    );
  }
  if (args.databaseName !== args.binding.database.name) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' database name does not match its ManagedPostgres binding.`,
    );
  }
  const expectedIdentityId =
    args.accessClass === "runtime"
      ? args.binding.access.runtimeIdentityId
      : args.binding.access.migrationIdentityId;
  if (args.semanticIdentityId !== expectedIdentityId) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' does not bind the exact ${args.accessClass} identity.`,
    );
  }
  if (
    args.databaseUser !== awsManagedPostgresDatabaseUser(expectedIdentityId)
  ) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' database user does not match its exact semantic identity.`,
    );
  }
  if (
    args.workloadManifest.serviceAccount.metadata.namespace !==
      args.namespace ||
    args.workloadManifest.serviceAccount.metadata.name !== args.serviceAccount
  ) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' workload bundle does not bind the exact namespace and ServiceAccount.`,
    );
  }
  if (
    awsDatabaseAccessBindingDigest(args.workloadManifest) !==
    args.workloadBundleDigest
  ) {
    throw new Error(
      `PostgreSQL access profile '${args.binding.id}' workload bundle digest does not match its exact manifest.`,
    );
  }
  const subject: PostgresAccessProfileDigestSubject = {
    apiVersion: "security.deus.dev/postgres-access-profile/v1alpha1",
    kind: "PostgresAccessProfile",
    id: `${args.binding.id}-${args.accessClass}`,
    bindingId: args.binding.id,
    application: {
      applicationId: args.binding.tenantId,
      componentId: args.binding.codefly.module,
      serviceRef: `${args.binding.codefly.workspace}/${args.binding.codefly.module}/${args.binding.codefly.service}`,
      dataBoundaryId: args.binding.dataBoundaryId,
    },
    accessClass: args.accessClass,
    connection: {
      endpoint: args.endpoint,
      port: args.port,
      databaseName: args.databaseName,
      tls: {
        mode: "verify-full",
        caCertIdentifier: args.caCertIdentifier,
        caBundleRef: args.caBundleRef,
      },
    },
    authentication: {
      kind: "aws-rds-iam",
      region: args.region,
      target: "rds-proxy",
      resourceId: args.proxyResourceId,
      databaseUser: args.databaseUser,
      tokenDelivery: "per-physical-connection",
    },
    identity: {
      semanticIdentityId: args.semanticIdentityId,
      roleArn: args.roleArn,
      namespace: args.namespace,
      serviceAccount: args.serviceAccount,
      podIdentityAssociationId: args.podIdentityAssociationId,
    },
    network: {
      securityGroupId: args.securityGroupId,
      exposure: "private",
      sourceBoundaryMode: "exact-pod-security-group",
    },
    enforcement: {
      bindingDigest: args.bindingDigest,
      workloadBundleDigest: args.workloadBundleDigest,
      requiredPodLabels: args.workloadManifest.requiredPodLabels,
      requiredPodAnnotations: args.workloadManifest.requiredPodAnnotations,
      requiredPodScheduling: args.workloadManifest.requiredPodScheduling,
    },
  };
  return parsePostgresAccessProfile({
    ...subject,
    profileSpecDigest: postgresAccessProfileSpecDigest(subject),
    readiness: {
      state: "pending-infrastructure",
      ready: false,
      blockers: [
        "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
        "DATABASE_DEPLOYMENT_AUTHORITY_NOT_OBSERVED",
        "POSTGRES_SQL_BOOTSTRAP_EVIDENCE_REQUIRED",
      ],
      evidenceRefs: [],
    },
    credentials: null,
  });
}

export function materializeAwsPostgresAccessProfile(args: {
  binding: ManagedPostgresBinding;
  accessClass: PostgresAccessClass;
  endpoint: pulumi.Input<string>;
  port: pulumi.Input<number>;
  databaseName: pulumi.Input<string>;
  caCertIdentifier: pulumi.Input<string>;
  caBundleRef: pulumi.Input<string>;
  region: pulumi.Input<string>;
  proxyResourceId: pulumi.Input<string>;
  databaseUser: pulumi.Input<string>;
  semanticIdentityId: string;
  roleArn: pulumi.Input<string>;
  namespace: string;
  serviceAccount: string;
  podIdentityAssociationId: pulumi.Input<string>;
  securityGroupId: pulumi.Input<string>;
  bindingDigest: pulumi.Input<string>;
  workloadBundleDigest: pulumi.Input<string>;
  workloadManifest: pulumi.Input<AwsDatabaseWorkloadManifest>;
}): pulumi.Output<PostgresAccessProfile> {
  return pulumi
    .output({
      endpoint: args.endpoint,
      port: args.port,
      databaseName: args.databaseName,
      caCertIdentifier: args.caCertIdentifier,
      caBundleRef: args.caBundleRef,
      region: args.region,
      proxyResourceId: args.proxyResourceId,
      databaseUser: args.databaseUser,
      roleArn: args.roleArn,
      podIdentityAssociationId: args.podIdentityAssociationId,
      securityGroupId: args.securityGroupId,
      bindingDigest: args.bindingDigest,
      workloadBundleDigest: args.workloadBundleDigest,
      workloadManifest: args.workloadManifest,
    })
    .apply((resolved) =>
      compileAwsPostgresAccessProfile({
        ...resolved,
        binding: args.binding,
        accessClass: args.accessClass,
        semanticIdentityId: args.semanticIdentityId,
        namespace: args.namespace,
        serviceAccount: args.serviceAccount,
      }),
    );
}
