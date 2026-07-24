import { createHash } from "node:crypto";
import type { PlatformBlueprint } from "./model";
import { assertBlueprint } from "./policy";

export const MANAGED_POSTGRES_API_VERSION =
  "security.deus.dev/managed-postgres/v1alpha1" as const;
export const MANAGED_POSTGRES_V1ALPHA2_API_VERSION =
  "security.deus.dev/managed-postgres/v1alpha2" as const;
export const MANAGED_POSTGRES_BROKER_API_VERSION =
  "security.deus.dev/resource-broker/v1alpha1" as const;

export type ManagedPostgresEnvironment =
  | "development"
  | "staging"
  | "production";

export interface ManagedPostgresIntent {
  apiVersion:
    | typeof MANAGED_POSTGRES_API_VERSION
    | typeof MANAGED_POSTGRES_V1ALPHA2_API_VERSION;
  name: string;
  environment: ManagedPostgresEnvironment;
  broker: {
    apiVersion: typeof MANAGED_POSTGRES_BROKER_API_VERSION;
    resourceKind: "ManagedPostgres";
    authorization: "capability";
    tenantBindingRequired: true;
    idempotencyRequired: true;
    directProviderCredentials: false;
  };
  plugin: {
    publisher: string;
    name: "postgres";
    version: string;
  };
  bindings: readonly ManagedPostgresBinding[];
}

export interface ManagedPostgresBinding {
  id: string;
  tenantId: string;
  tenancy?: ManagedPostgresTenancy;
  dataBoundaryId: string;
  codefly: {
    workspace: string;
    module: string;
    service: string;
  };
  database: {
    name: string;
    engine: "postgresql";
    majorVersion: string;
    port: 5432;
    extensions: readonly string[];
  };
  provisioning: {
    requestedBy: "codefly-postgres-plugin";
    owner: "provider-adapter";
    serviceClass: "managed-postgresql";
    networkExposure: "private";
    multiZone: true;
    customerManagedEncryption: true;
    deletionProtection: true;
    pointInTimeRecovery: true;
    backupRetentionDays: number;
    restoreTestIntervalDays: number;
  };
  access: {
    runtimeIdentityId: string;
    migrationIdentityId: string;
    networkAccess: {
      mode: "explicit-source-boundaries";
      runtimeBoundaryId: string;
      migrationBoundaryId: string;
      separateBoundaries: true;
      allowNetworkCidr: false;
    };
    authentication: "workload-identity";
    tlsMode: "verify-full";
    credentialDelivery: "reference-only";
    adminCredentialsExposed: false;
    separateMigrationIdentity: true;
  };
  outputs: {
    endpoint: "reference";
    port: "value";
    databaseName: "value";
    caBundle: "reference";
    runtimeIdentity: "reference";
    migrationIdentity: "reference";
    credentials: "never";
  };
  audit: {
    immutable: true;
    denialEvents: true;
    accessEvidence: true;
    provisioningEvidence: true;
  };
}

export interface ManagedPostgresTenancy {
  organizationId: string;
  platformTenantId: string;
  applicationId: string;
  resourceOwnerId: string;
}

export interface ManagedPostgresV1alpha1MigrationOptions {
  environment: ManagedPostgresEnvironment;
  blueprint?: PlatformBlueprint;
  organizationId: string;
  platformTenantIds: Readonly<Record<string, string>>;
}

export function parseManagedPostgresIntent(
  value: unknown,
  environment: ManagedPostgresEnvironment,
  blueprint?: PlatformBlueprint,
): ManagedPostgresIntent {
  const root = objectValue(value, "managedPostgres", [
    "apiVersion",
    "name",
    "broker",
    "plugin",
    "bindings",
  ]);
  const apiVersion = stringValue(root.apiVersion, "apiVersion");
  if (
    apiVersion !== MANAGED_POSTGRES_API_VERSION &&
    apiVersion !== MANAGED_POSTGRES_V1ALPHA2_API_VERSION
  ) {
    throw new Error(
      `managedPostgres.apiVersion must be '${MANAGED_POSTGRES_API_VERSION}' or '${MANAGED_POSTGRES_V1ALPHA2_API_VERSION}'.`,
    );
  }
  const brokerInput = objectValue(root.broker, "broker", [
    "apiVersion",
    "resourceKind",
    "authorization",
    "tenantBindingRequired",
    "idempotencyRequired",
    "directProviderCredentials",
  ]);
  const pluginInput = objectValue(root.plugin, "plugin", [
    "publisher",
    "name",
    "version",
  ]);
  const intent: ManagedPostgresIntent = {
    apiVersion,
    name: nameValue(root.name, "name"),
    environment: enumValue(environment, "managedPostgresEnvironment", [
      "development",
      "staging",
      "production",
    ]),
    broker: {
      apiVersion: literalValue(
        brokerInput.apiVersion,
        "broker.apiVersion",
        MANAGED_POSTGRES_BROKER_API_VERSION,
      ),
      resourceKind: literalValue(
        brokerInput.resourceKind,
        "broker.resourceKind",
        "ManagedPostgres",
      ),
      authorization: literalValue(
        brokerInput.authorization,
        "broker.authorization",
        "capability",
      ),
      tenantBindingRequired: trueValue(
        brokerInput.tenantBindingRequired,
        "broker.tenantBindingRequired",
      ),
      idempotencyRequired: trueValue(
        brokerInput.idempotencyRequired,
        "broker.idempotencyRequired",
      ),
      directProviderCredentials: falseValue(
        brokerInput.directProviderCredentials,
        "broker.directProviderCredentials",
      ),
    },
    plugin: {
      publisher: nameValue(pluginInput.publisher, "plugin.publisher"),
      name: literalValue(pluginInput.name, "plugin.name", "postgres"),
      version: semverValue(pluginInput.version, "plugin.version"),
    },
    bindings: arrayValue(root.bindings, "bindings", (binding, path) =>
      parseBinding(binding, path, apiVersion),
    ),
  };
  assertManagedPostgresIntent(intent, blueprint);
  return intent;
}

export function assertManagedPostgresIntent(
  intent: ManagedPostgresIntent,
  blueprint?: PlatformBlueprint,
): void {
  if (!intent.bindings.length) {
    throw new Error("Managed Postgres requires at least one binding.");
  }
  const ids = new Set<string>();
  const serviceRefs = new Set<string>();
  const dataBoundaries = new Set<string>();
  const applicationTenants = new Map<string, string>();
  const tenantApplications = new Map<string, string>();
  for (const binding of intent.bindings) {
    if (ids.has(binding.id)) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' is duplicated.`,
      );
    }
    ids.add(binding.id);
    const serviceRef = codeflyServiceRef(binding);
    if (serviceRefs.has(serviceRef)) {
      throw new Error(
        `Managed Postgres Codefly service '${serviceRef}' is bound more than once.`,
      );
    }
    serviceRefs.add(serviceRef);
    if (dataBoundaries.has(binding.dataBoundaryId)) {
      throw new Error(
        `Managed Postgres data boundary '${binding.dataBoundaryId}' is bound more than once.`,
      );
    }
    dataBoundaries.add(binding.dataBoundaryId);
    if (intent.apiVersion === MANAGED_POSTGRES_V1ALPHA2_API_VERSION) {
      const tenancy = binding.tenancy;
      if (
        !tenancy ||
        tenancy.applicationId !== binding.tenantId ||
        tenancy.resourceOwnerId !== binding.access.runtimeIdentityId
      ) {
        throw new Error(
          `Managed Postgres binding '${binding.id}' has an invalid explicit tenancy owner chain.`,
        );
      }
      const priorTenant = applicationTenants.get(tenancy.applicationId);
      const priorApplication = tenantApplications.get(tenancy.platformTenantId);
      if (
        (priorTenant && priorTenant !== tenancy.platformTenantId) ||
        (priorApplication && priorApplication !== tenancy.applicationId)
      ) {
        throw new Error(
          `Managed Postgres binding '${binding.id}' crosses an explicit platform tenant boundary.`,
        );
      }
      applicationTenants.set(tenancy.applicationId, tenancy.platformTenantId);
      tenantApplications.set(tenancy.platformTenantId, tenancy.applicationId);
    } else if (binding.tenancy) {
      throw new Error(
        `Managed Postgres v1alpha1 binding '${binding.id}' cannot claim v1alpha2 tenancy fields.`,
      );
    }
    if (
      binding.access.runtimeIdentityId === binding.access.migrationIdentityId
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' must separate runtime and migration identities.`,
      );
    }
    if (
      binding.access.networkAccess.runtimeBoundaryId ===
      binding.access.networkAccess.migrationBoundaryId
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' must separate runtime and migration network boundaries.`,
      );
    }
    if (intent.environment === "production") {
      if (binding.provisioning.backupRetentionDays < 14) {
        throw new Error(
          `Managed Postgres binding '${binding.id}' requires at least 14 backup days in production.`,
        );
      }
    }
  }
  if (!blueprint) return;
  assertBlueprint(blueprint);
  const boundaries = new Map(
    blueprint.dataBoundaries.map((boundary) => [boundary.id, boundary]),
  );
  const applications = new Map(
    blueprint.applications.map((application) => [application.id, application]),
  );
  const identities = new Map(
    blueprint.identities.map((identity) => [identity.id, identity]),
  );
  for (const binding of intent.bindings) {
    const boundary = boundaries.get(binding.dataBoundaryId);
    if (!boundary || !boundary.services.includes("relational")) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' requires relational data boundary '${binding.dataBoundaryId}'.`,
      );
    }
    if (
      !boundary.encryption.customerManagedKey ||
      !boundary.encryption.rotationRequired ||
      !boundary.recovery.multiAzRequired ||
      !boundary.recovery.deletionProtectionRequired ||
      !boundary.recovery.backupRequired
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' weakens data-boundary security or recovery.`,
      );
    }
    if (
      binding.provisioning.backupRetentionDays <
        Math.min(boundary.retentionDays, 35) ||
      binding.provisioning.restoreTestIntervalDays >
        boundary.recovery.restoreTestIntervalDays
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' does not satisfy data-boundary recovery.`,
      );
    }
    const application = applications.get(binding.tenantId);
    const component = application?.components.find(
      (candidate) => candidate.id === binding.codefly.module,
    );
    if (
      !application ||
      application.id !== binding.tenantId ||
      !component ||
      !component.dataBoundaryIds.includes(binding.dataBoundaryId) ||
      component.serviceIdentityId !== binding.access.runtimeIdentityId
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' crosses its Codefly tenant or component data boundary.`,
      );
    }
    const migrationIdentity = identities.get(
      binding.access.migrationIdentityId,
    );
    if (
      !migrationIdentity ||
      migrationIdentity.kind !== "automation" ||
      !migrationIdentity.shortLived
    ) {
      throw new Error(
        `Managed Postgres binding '${binding.id}' requires a short-lived automation migration identity.`,
      );
    }
  }
}

export function managedPostgresIntentDigest(
  intent: ManagedPostgresIntent,
): string {
  assertManagedPostgresIntent(intent);
  return createHash("sha256").update(canonicalJson(intent)).digest("hex");
}

export function managedPostgresBindingDigest(
  intent: ManagedPostgresIntent,
  binding: ManagedPostgresBinding,
): string {
  assertManagedPostgresIntent(intent);
  return createHash("sha256")
    .update(
      canonicalJson({
        apiVersion: intent.apiVersion,
        environment: intent.environment,
        broker: intent.broker,
        plugin: intent.plugin,
        binding,
      }),
    )
    .digest("hex");
}

export function codeflyServiceRef(binding: ManagedPostgresBinding): string {
  return `${binding.codefly.workspace}/${binding.codefly.module}/${binding.codefly.service}`;
}

export function migrateManagedPostgresV1alpha1ToV1alpha2(
  value: unknown,
  options: ManagedPostgresV1alpha1MigrationOptions,
): Record<string, unknown> {
  const source = parseManagedPostgresIntent(
    value,
    options.environment,
    options.blueprint,
  );
  if (source.apiVersion !== MANAGED_POSTGRES_API_VERSION) {
    throw new Error(
      "MANAGED_POSTGRES_MIGRATION_SOURCE_DENIED: source must be v1alpha1.",
    );
  }
  const organizationId = nameValue(
    options.organizationId,
    "migration.organizationId",
  );
  const raw = structuredClone(value) as Record<string, unknown>;
  const rawBindings = raw.bindings as Record<string, unknown>[];
  const migratedBindings = source.bindings.map((binding, index) => {
    const platformTenantId = nameValue(
      options.platformTenantIds[binding.tenantId],
      `migration.platformTenantIds.${binding.tenantId}`,
    );
    const { tenantId: _tenantId, ...rest } = rawBindings[index];
    return {
      ...rest,
      tenancy: {
        organizationId,
        platformTenantId,
        applicationId: binding.tenantId,
        resourceOwnerId: binding.access.runtimeIdentityId,
      },
    };
  });
  const migrated = {
    ...raw,
    apiVersion: MANAGED_POSTGRES_V1ALPHA2_API_VERSION,
    bindings: migratedBindings,
  };
  parseManagedPostgresIntent(migrated, options.environment, options.blueprint);
  return migrated;
}

export function downgradeManagedPostgresV1alpha2ToV1alpha1(): never {
  throw new Error(
    "MANAGED_POSTGRES_DOWNGRADE_DENIED: v1alpha2 explicit organization, platform tenant, application, and resource owner identity cannot be discarded.",
  );
}

function parseBinding(
  value: unknown,
  path: string,
  apiVersion: ManagedPostgresIntent["apiVersion"],
): ManagedPostgresBinding {
  const v1alpha2 = apiVersion === MANAGED_POSTGRES_V1ALPHA2_API_VERSION;
  const input = objectValue(value, path, [
    "id",
    v1alpha2 ? "tenancy" : "tenantId",
    "dataBoundaryId",
    "codefly",
    "database",
    "provisioning",
    "access",
    "outputs",
    "audit",
  ]);
  const codefly = objectValue(input.codefly, `${path}.codefly`, [
    "workspace",
    "module",
    "service",
  ]);
  const database = objectValue(input.database, `${path}.database`, [
    "name",
    "engine",
    "majorVersion",
    "port",
    "extensions",
  ]);
  const provisioning = objectValue(input.provisioning, `${path}.provisioning`, [
    "requestedBy",
    "owner",
    "serviceClass",
    "networkExposure",
    "multiZone",
    "customerManagedEncryption",
    "deletionProtection",
    "pointInTimeRecovery",
    "backupRetentionDays",
    "restoreTestIntervalDays",
  ]);
  const access = objectValue(input.access, `${path}.access`, [
    "runtimeIdentityId",
    "migrationIdentityId",
    "networkAccess",
    "authentication",
    "tlsMode",
    "credentialDelivery",
    "adminCredentialsExposed",
    "separateMigrationIdentity",
  ]);
  const networkAccess = objectValue(
    access.networkAccess,
    `${path}.access.networkAccess`,
    [
      "mode",
      "runtimeBoundaryId",
      "migrationBoundaryId",
      "separateBoundaries",
      "allowNetworkCidr",
    ],
  );
  const outputs = objectValue(input.outputs, `${path}.outputs`, [
    "endpoint",
    "port",
    "databaseName",
    "caBundle",
    "runtimeIdentity",
    "migrationIdentity",
    "credentials",
  ]);
  const audit = objectValue(input.audit, `${path}.audit`, [
    "immutable",
    "denialEvents",
    "accessEvidence",
    "provisioningEvidence",
  ]);
  const tenancy = v1alpha2
    ? objectValue(input.tenancy, `${path}.tenancy`, [
        "organizationId",
        "platformTenantId",
        "applicationId",
        "resourceOwnerId",
      ])
    : undefined;
  const tenantId = v1alpha2
    ? nameValue(tenancy!.applicationId, `${path}.tenancy.applicationId`)
    : nameValue(input.tenantId, `${path}.tenantId`);
  return {
    id: nameValue(input.id, `${path}.id`),
    tenantId,
    ...(tenancy
      ? {
          tenancy: {
            organizationId: nameValue(
              tenancy.organizationId,
              `${path}.tenancy.organizationId`,
            ),
            platformTenantId: nameValue(
              tenancy.platformTenantId,
              `${path}.tenancy.platformTenantId`,
            ),
            applicationId: tenantId,
            resourceOwnerId: nameValue(
              tenancy.resourceOwnerId,
              `${path}.tenancy.resourceOwnerId`,
            ),
          },
        }
      : {}),
    dataBoundaryId: nameValue(input.dataBoundaryId, `${path}.dataBoundaryId`),
    codefly: {
      workspace: nameValue(codefly.workspace, `${path}.codefly.workspace`),
      module: nameValue(codefly.module, `${path}.codefly.module`),
      service: nameValue(codefly.service, `${path}.codefly.service`),
    },
    database: {
      name: sqlNameValue(database.name, `${path}.database.name`),
      engine: literalValue(
        database.engine,
        `${path}.database.engine`,
        "postgresql",
      ),
      majorVersion: integerStringValue(
        database.majorVersion,
        `${path}.database.majorVersion`,
      ),
      port: literalValue(database.port, `${path}.database.port`, 5432),
      extensions: uniqueArray(
        database.extensions,
        `${path}.database.extensions`,
        extensionNameValue,
      ),
    },
    provisioning: {
      requestedBy: literalValue(
        provisioning.requestedBy,
        `${path}.provisioning.requestedBy`,
        "codefly-postgres-plugin",
      ),
      owner: literalValue(
        provisioning.owner,
        `${path}.provisioning.owner`,
        "provider-adapter",
      ),
      serviceClass: literalValue(
        provisioning.serviceClass,
        `${path}.provisioning.serviceClass`,
        "managed-postgresql",
      ),
      networkExposure: literalValue(
        provisioning.networkExposure,
        `${path}.provisioning.networkExposure`,
        "private",
      ),
      multiZone: trueValue(
        provisioning.multiZone,
        `${path}.provisioning.multiZone`,
      ),
      customerManagedEncryption: trueValue(
        provisioning.customerManagedEncryption,
        `${path}.provisioning.customerManagedEncryption`,
      ),
      deletionProtection: trueValue(
        provisioning.deletionProtection,
        `${path}.provisioning.deletionProtection`,
      ),
      pointInTimeRecovery: trueValue(
        provisioning.pointInTimeRecovery,
        `${path}.provisioning.pointInTimeRecovery`,
      ),
      backupRetentionDays: integerValue(
        provisioning.backupRetentionDays,
        `${path}.provisioning.backupRetentionDays`,
        1,
        35,
      ),
      restoreTestIntervalDays: integerValue(
        provisioning.restoreTestIntervalDays,
        `${path}.provisioning.restoreTestIntervalDays`,
        1,
        365,
      ),
    },
    access: {
      runtimeIdentityId: nameValue(
        access.runtimeIdentityId,
        `${path}.access.runtimeIdentityId`,
      ),
      migrationIdentityId: nameValue(
        access.migrationIdentityId,
        `${path}.access.migrationIdentityId`,
      ),
      networkAccess: {
        mode: literalValue(
          networkAccess.mode,
          `${path}.access.networkAccess.mode`,
          "explicit-source-boundaries",
        ),
        runtimeBoundaryId: nameValue(
          networkAccess.runtimeBoundaryId,
          `${path}.access.networkAccess.runtimeBoundaryId`,
        ),
        migrationBoundaryId: nameValue(
          networkAccess.migrationBoundaryId,
          `${path}.access.networkAccess.migrationBoundaryId`,
        ),
        separateBoundaries: trueValue(
          networkAccess.separateBoundaries,
          `${path}.access.networkAccess.separateBoundaries`,
        ),
        allowNetworkCidr: falseValue(
          networkAccess.allowNetworkCidr,
          `${path}.access.networkAccess.allowNetworkCidr`,
        ),
      },
      authentication: literalValue(
        access.authentication,
        `${path}.access.authentication`,
        "workload-identity",
      ),
      tlsMode: literalValue(
        access.tlsMode,
        `${path}.access.tlsMode`,
        "verify-full",
      ),
      credentialDelivery: literalValue(
        access.credentialDelivery,
        `${path}.access.credentialDelivery`,
        "reference-only",
      ),
      adminCredentialsExposed: falseValue(
        access.adminCredentialsExposed,
        `${path}.access.adminCredentialsExposed`,
      ),
      separateMigrationIdentity: trueValue(
        access.separateMigrationIdentity,
        `${path}.access.separateMigrationIdentity`,
      ),
    },
    outputs: {
      endpoint: literalValue(
        outputs.endpoint,
        `${path}.outputs.endpoint`,
        "reference",
      ),
      port: literalValue(outputs.port, `${path}.outputs.port`, "value"),
      databaseName: literalValue(
        outputs.databaseName,
        `${path}.outputs.databaseName`,
        "value",
      ),
      caBundle: literalValue(
        outputs.caBundle,
        `${path}.outputs.caBundle`,
        "reference",
      ),
      runtimeIdentity: literalValue(
        outputs.runtimeIdentity,
        `${path}.outputs.runtimeIdentity`,
        "reference",
      ),
      migrationIdentity: literalValue(
        outputs.migrationIdentity,
        `${path}.outputs.migrationIdentity`,
        "reference",
      ),
      credentials: literalValue(
        outputs.credentials,
        `${path}.outputs.credentials`,
        "never",
      ),
    },
    audit: {
      immutable: trueValue(audit.immutable, `${path}.audit.immutable`),
      denialEvents: trueValue(audit.denialEvents, `${path}.audit.denialEvents`),
      accessEvidence: trueValue(
        audit.accessEvidence,
        `${path}.audit.accessEvidence`,
      ),
      provisioningEvidence: trueValue(
        audit.provisioningEvidence,
        `${path}.audit.provisioningEvidence`,
      ),
    },
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function objectValue(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  const missing = allowed.filter((field) => !(field in input));
  const unknown = Object.keys(input).filter(
    (field) => !allowed.includes(field),
  );
  if (missing.length) {
    throw new Error(`${path} is missing field(s): ${missing.join(", ")}.`);
  }
  if (unknown.length) {
    throw new Error(`${path} contains unknown field '${unknown.sort()[0]}'.`);
  }
  return input;
}

function arrayValue<T>(
  value: unknown,
  path: string,
  parser: (entry: unknown, entryPath: string) => T,
): T[] {
  if (!Array.isArray(value) || !value.length) {
    throw new Error(`${path} must be a non-empty array.`);
  }
  return value.map((entry, index) => parser(entry, `${path}[${index}]`));
}

function uniqueArray<T>(
  value: unknown,
  path: string,
  parser: (entry: unknown, entryPath: string) => T,
): T[] {
  const parsed = arrayValue(value, path, parser);
  if (new Set(parsed).size !== parsed.length) {
    throw new Error(`${path} must contain unique values.`);
  }
  return parsed;
}

function stringValue(value: unknown, path: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${path} must be a non-empty string.`);
  }
  return value;
}

function nameValue(value: unknown, path: string): string {
  const parsed = stringValue(value, path);
  if (
    parsed.length > 128 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(parsed)
  ) {
    throw new Error(`${path} must be a lowercase bounded name.`);
  }
  return parsed;
}

function sqlNameValue(value: unknown, path: string): string {
  const parsed = stringValue(value, path);
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(parsed)) {
    throw new Error(`${path} must be a safe PostgreSQL identifier.`);
  }
  return parsed;
}

function extensionNameValue(value: unknown, path: string): string {
  const parsed = stringValue(value, path);
  if (!/^[a-z][a-z0-9_-]{0,62}$/.test(parsed)) {
    throw new Error(`${path} must be a safe PostgreSQL extension name.`);
  }
  return parsed;
}

function integerStringValue(value: unknown, path: string): string {
  const parsed = stringValue(value, path);
  if (!/^[1-9][0-9]*$/.test(parsed)) {
    throw new Error(`${path} must be a positive integer string.`);
  }
  return parsed;
}

function semverValue(value: unknown, path: string): string {
  const parsed = stringValue(value, path);
  if (!/^\d+\.\d+\.\d+$/.test(parsed)) {
    throw new Error(`${path} must be an exact semantic version.`);
  }
  return parsed;
}

function integerValue(
  value: unknown,
  path: string,
  minimum: number,
  maximum: number,
): number {
  if (
    !Number.isInteger(value) ||
    (value as number) < minimum ||
    (value as number) > maximum
  ) {
    throw new Error(
      `${path} must be an integer from ${minimum} to ${maximum}.`,
    );
  }
  return value as number;
}

function enumValue<T extends string>(
  value: unknown,
  path: string,
  allowed: readonly T[],
): T {
  if (typeof value !== "string" || !allowed.includes(value as T)) {
    throw new Error(`${path} must be one of ${allowed.join(", ")}.`);
  }
  return value as T;
}

function literalValue<T extends string | number | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) {
    throw new Error(`${path} must be '${String(expected)}'.`);
  }
  return expected;
}

function trueValue(value: unknown, path: string): true {
  return literalValue(value, path, true);
}

function falseValue(value: unknown, path: string): false {
  return literalValue(value, path, false);
}
