import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  parseAwsDatabaseInfrastructureHandoff,
  parseCloudContextCatalog,
  parseCloudContextObservationEvidence,
  parseInfrastructureControllerProtocolContract,
  parseInfrastructureControllerRequest,
  parseManagedPostgresIntent,
  parsePostgresAccessProfile,
  parsePostgresAccessObservationEvidence,
  parseWorkloadIdentityBinding,
  createWardenMindBlueprint,
} from "../../src/core";
import { parseAwsBootstrapAccessPlan } from "../../src/adapters/aws";

export interface IacContractRegistryEntry {
  id: string;
  owner: string;
  contractPath: string;
  schemaPath: string;
  schemaId: string;
  parse(value: unknown): unknown;
  canonicalDigest(value: unknown): string;
  parserOnlySemanticRules: readonly string[];
}

export const IAC_CONTRACT_REGISTRY: readonly IacContractRegistryEntry[] =
  Object.freeze([
    entry({
      id: "aws-database-infrastructure-handoff-v1alpha1",
      owner: "secure-saas-infra/aws-database-infrastructure-handoff",
      contractPath:
        "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
      schemaPath:
        "schemas/aws-database-infrastructure-handoff-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/aws-database-infrastructure-handoff-v1alpha1.schema.json",
      parse: parseAwsDatabaseInfrastructureHandoff,
      parserOnlySemanticRules: [
        "top-level handoff specification is content-addressed",
        "each manifest bundle is content-addressed",
        "namespace, ServiceAccount, and binding digest substitutions are denied",
        "bootstrap association is absent while runtime and migration are persistent",
        "recursive rejection of credential material",
      ],
    }),
    entry({
      id: "aws-bootstrap-access-v1alpha1",
      owner: "secure-saas-infra/aws-bootstrap",
      contractPath: "contracts/aws-bootstrap-access-v1alpha1.json",
      schemaPath: "schemas/aws-bootstrap-access-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/aws-bootstrap-access-v1alpha1.schema.json",
      parse: parseAwsBootstrapAccessPlan,
      parserOnlySemanticRules: [
        "cross-field AWS account/ARN ownership",
        "controller/management account separation",
        "production and foundational-account authority",
        "account-kind action-set ceilings",
        "role and permissions-boundary separation",
      ],
    }),
    entry({
      id: "cloud-context-observation-v1alpha1",
      owner: "secure-saas-infra/cloud-context-observation",
      contractPath: "contracts/cloud-context-observation-v1alpha1.json",
      schemaPath: "schemas/cloud-context-observation-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/cloud-context-observation-v1alpha1.schema.json",
      parse: parseCloudContextObservationEvidence,
      parserOnlySemanticRules: [
        "dependency and resolution identities are exact and unique",
        "observation timestamps are canonical UTC calendar values",
        "Ed25519 signature encoding is canonical base64url",
        "credential-shaped provider authority values are rejected",
      ],
    }),
    entry({
      id: "cloud-context-v1alpha1",
      owner: "secure-saas-infra/cloud-context",
      contractPath: "contracts/cloud-context-v1alpha1.json",
      schemaPath: "schemas/cloud-context-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/cloud-context-v1alpha1.schema.json",
      parse: (value) =>
        parseCloudContextCatalog(
          value,
          createWardenMindBlueprint(),
          parseManagedPostgresIntent(
            JSON.parse(
              readFileSync("contracts/managed-postgres-v1alpha1.json", "utf8"),
            ),
            "development",
            createWardenMindBlueprint(),
          ),
        ),
      parserOnlySemanticRules: [
        "context and placement identifiers are unique and referentially closed",
        "platform and delegated untrusted runtimes retain separate trust boundaries",
        "resource bindings exactly match Managed PostgreSQL ownership",
        "planned status cannot claim observation or readiness evidence",
        "credential material and wildcard references are recursively rejected",
      ],
    }),
    entry({
      id: "infrastructure-controller-protocol-v1alpha1",
      owner: "secure-saas-infra/infrastructure-controller-protocol",
      contractPath:
        "contracts/infrastructure-controller-protocol-v1alpha1.json",
      schemaPath:
        "schemas/infrastructure-controller-protocol-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/infrastructure-controller-protocol-v1alpha1.schema.json",
      parse: parseInfrastructureControllerProtocolContract,
      parserOnlySemanticRules: [
        "complete reason-code catalog",
        "cross-message request/operation subject binding",
        "event hash-chain integrity",
        "deprecation replacement membership",
        "retryability catalog semantics",
      ],
    }),
    entry({
      id: "infrastructure-controller-request-v1alpha1",
      owner: "secure-saas-infra/infrastructure-controller",
      contractPath: "contracts/infrastructure-controller-request-v1alpha1.json",
      schemaPath:
        "schemas/infrastructure-controller-request-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/infrastructure-controller-request-v1alpha1.schema.json",
      parse: parseInfrastructureControllerRequest,
      parserOnlySemanticRules: [
        "authorization identity and tenant binding",
        "capability lifetime and replay state",
        "operation-specific plan and approval policy",
        "idempotency and deadline policy",
      ],
    }),
    entry({
      id: "managed-postgres-v1alpha1",
      owner: "secure-saas-infra/managed-postgres",
      contractPath: "contracts/managed-postgres-v1alpha1.json",
      schemaPath: "schemas/managed-postgres-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/managed-postgres-v1alpha1.schema.json",
      parse: (value) =>
        parseManagedPostgresIntent(
          value,
          "development",
          createWardenMindBlueprint(),
        ),
      parserOnlySemanticRules: [
        "one binding per application service and relational data boundary",
        "exact application component and runtime identity ownership",
        "short-lived automation identity for the infrastructure migration lane",
        "distinct runtime and migration identities and network boundaries",
        "data-boundary encryption, recovery, and retention compatibility",
      ],
    }),
    entry({
      id: "managed-postgres-v1alpha2",
      owner: "secure-saas-infra/managed-postgres",
      contractPath: "contracts/managed-postgres-v1alpha2.json",
      schemaPath: "schemas/managed-postgres-v1alpha2.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/managed-postgres-v1alpha2.schema.json",
      parse: (value) =>
        parseManagedPostgresIntent(
          value,
          "development",
          createWardenMindBlueprint(),
        ),
      parserOnlySemanticRules: [
        "organization, platform tenant, application, and resource owner are explicit",
        "one platform tenant cannot be shared across applications",
        "resource owner exactly matches the runtime workload identity",
        "all v1alpha1 data, access, and recovery boundaries remain enforced",
        "downgrade to an ambiguous tenant identifier is forbidden",
      ],
    }),
    entry({
      id: "postgres-access-observation-v1alpha1",
      owner: "secure-saas-infra/postgres-access-observation",
      contractPath: "contracts/postgres-access-observation-v1alpha1.json",
      schemaPath: "schemas/postgres-access-observation-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/postgres-access-observation-v1alpha1.schema.json",
      parse: parsePostgresAccessObservationEvidence,
      parserOnlySemanticRules: [
        "access class and allowed deployment kind are exact",
        "all required resource observations precede evidence issuance",
        "PostgreSQL bootstrap completion precedes evidence issuance",
        "evidence issuance and expiry are monotonically ordered",
        "recursive rejection of credential material",
      ],
    }),
    entry({
      id: "postgres-access-profile-v1alpha1",
      owner: "secure-saas-infra/postgres-access-profile",
      contractPath: "contracts/postgres-access-profile-v1alpha1.json",
      schemaPath: "schemas/postgres-access-profile-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/postgres-access-profile-v1alpha1.schema.json",
      parse: parsePostgresAccessProfile,
      parserOnlySemanticRules: [
        "profile identity binds the exact resource binding and access class",
        "service reference binds the exact application component",
        "profile specification is content-addressed and mutation-evident",
        "binding digest is carried by required workload annotations",
        "v1alpha1 is fail-closed pending infrastructure observation only",
        "recursive rejection of credential material",
      ],
    }),
    entry({
      id: "workload-identity-binding-v1alpha1",
      owner: "secure-saas-infra/workload-identity-binding",
      contractPath: "contracts/workload-identity-binding-v1alpha1.json",
      schemaPath: "schemas/workload-identity-binding-v1alpha1.schema.json",
      schemaId:
        "https://security.deus.dev/schemas/workload-identity-binding-v1alpha1.schema.json",
      parse: parseWorkloadIdentityBinding,
      parserOnlySemanticRules: [
        "exact namespace and ServiceAccount OIDC subject binding",
        "exact SPIFFE identity binding",
        "content-addressed binding evidence",
        "verification evidence lifetime ordering",
        "credential-free and wildcard-free provider references",
      ],
    }),
  ]);

function entry(
  value: Omit<IacContractRegistryEntry, "canonicalDigest">,
): IacContractRegistryEntry {
  return Object.freeze({
    ...value,
    canonicalDigest(input: unknown): string {
      return createHash("sha256")
        .update(canonicalJson(value.parse(input)))
        .digest("hex");
    },
  });
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([key, entryValue]) =>
          `${JSON.stringify(key)}:${canonicalJson(entryValue)}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
