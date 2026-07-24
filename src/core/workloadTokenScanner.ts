import { createHash } from "node:crypto";
import { parseAllDocuments } from "yaml";

export const WORKLOAD_TOKEN_SCAN_API_VERSION =
  "evidence.security.deus.dev/workload-token-scan/v1" as const;
export const WORKLOAD_TOKEN_SCANNER_VERSION = "1.0.0" as const;

export type WorkloadTokenExceptionIssue =
  | "workload-automount"
  | "service-account-automount"
  | "projected-service-account-token";

export interface RenderedManifestSource {
  path: string;
  yaml: string;
}

export interface WorkloadTokenException {
  id: string;
  apiVersion: string;
  kind: string;
  namespace: string;
  name: string;
  issue: WorkloadTokenExceptionIssue;
  reason: string;
  approvedBy: string;
  expiresAt: string;
}

export interface WorkloadTokenScanFinding {
  code:
    | "TOKEN_SCAN_YAML_INVALID"
    | "TOKEN_SCAN_DOCUMENT_INVALID"
    | "TOKEN_SCAN_RESOURCE_IDENTITY_INVALID"
    | "TOKEN_SCAN_RESOURCE_DUPLICATE"
    | "TOKEN_SCAN_WORKLOAD_KIND_UNKNOWN"
    | "TOKEN_SCAN_POD_SPEC_MISSING"
    | "TOKEN_SCAN_WORKLOAD_AUTOMOUNT_NOT_FALSE"
    | "TOKEN_SCAN_SERVICE_ACCOUNT_AUTOMOUNT_NOT_FALSE"
    | "TOKEN_SCAN_PROJECTED_TOKEN_FORBIDDEN"
    | "TOKEN_SCAN_EXCEPTION_INVALID"
    | "TOKEN_SCAN_EXCEPTION_DUPLICATE"
    | "TOKEN_SCAN_EXCEPTION_UNUSED";
  sourcePath: string;
  documentIndex: number;
  resource: string | null;
  fieldPath: string;
  message: string;
}

export interface WorkloadTokenScanReport {
  apiVersion: typeof WORKLOAD_TOKEN_SCAN_API_VERSION;
  scannerVersion: typeof WORKLOAD_TOKEN_SCANNER_VERSION;
  scannedAt: string;
  sourceDigest: string;
  sources: readonly { path: string; sha256: string }[];
  documentCount: number;
  resourceCount: number;
  workloadCount: number;
  serviceAccountCount: number;
  exceptionsUsed: readonly string[];
  findings: readonly WorkloadTokenScanFinding[];
  pass: boolean;
}

interface ResourceIdentity {
  apiVersion: string;
  kind: string;
  namespace: string;
  name: string;
  key: string;
}

interface ScanState {
  nowMs: number;
  findings: WorkloadTokenScanFinding[];
  resourceKeys: Set<string>;
  workloadCount: number;
  serviceAccountCount: number;
  resourceCount: number;
  exceptions: Map<string, WorkloadTokenException>;
  exceptionsUsed: Set<string>;
}

const podSpecPaths = new Map<string, readonly string[]>([
  ["v1/Pod", ["spec"]],
  ["v1/ReplicationController", ["spec", "template", "spec"]],
  ["apps/v1/Deployment", ["spec", "template", "spec"]],
  ["apps/v1/StatefulSet", ["spec", "template", "spec"]],
  ["apps/v1/DaemonSet", ["spec", "template", "spec"]],
  ["apps/v1/ReplicaSet", ["spec", "template", "spec"]],
  ["batch/v1/Job", ["spec", "template", "spec"]],
  ["batch/v1/CronJob", ["spec", "jobTemplate", "spec", "template", "spec"]],
  ["argoproj.io/v1alpha1/Rollout", ["spec", "template", "spec"]],
]);

export function scanRenderedWorkloadTokens(args: {
  sources: readonly RenderedManifestSource[];
  scannedAt: string;
  exceptions?: readonly WorkloadTokenException[];
}): WorkloadTokenScanReport {
  const scannedAt = exactTimestamp(args.scannedAt, "scannedAt");
  if (args.sources.length === 0) {
    throw new Error(
      "TOKEN_SCAN_SOURCE_EMPTY: at least one rendered source is required",
    );
  }
  const sources = normalizeSources(args.sources);
  const state: ScanState = {
    nowMs: Date.parse(scannedAt),
    findings: [],
    resourceKeys: new Set(),
    workloadCount: 0,
    serviceAccountCount: 0,
    resourceCount: 0,
    exceptions: new Map(),
    exceptionsUsed: new Set(),
  };
  validateExceptions(args.exceptions ?? [], state);
  let documentCount = 0;
  for (const source of sources) {
    const documents = parseAllDocuments(source.yaml, {
      prettyErrors: false,
      strict: true,
      uniqueKeys: true,
    });
    for (const [documentIndex, document] of documents.entries()) {
      documentCount += 1;
      if (document.errors.length > 0) {
        addFinding(state, {
          code: "TOKEN_SCAN_YAML_INVALID",
          sourcePath: source.path,
          documentIndex,
          resource: null,
          fieldPath: "$",
          message: document.errors.map((error) => error.message).join("; "),
        });
        continue;
      }
      let value: unknown;
      try {
        value = document.toJS({ maxAliasCount: 0 });
      } catch (error) {
        addFinding(state, {
          code: "TOKEN_SCAN_YAML_INVALID",
          sourcePath: source.path,
          documentIndex,
          resource: null,
          fieldPath: "$",
          message: errorMessage(error),
        });
        continue;
      }
      if (value === null || value === undefined) continue;
      scanResource(value, source.path, documentIndex, "$", state);
    }
  }
  for (const exception of state.exceptions.values()) {
    if (!state.exceptionsUsed.has(exception.id)) {
      addFinding(state, {
        code: "TOKEN_SCAN_EXCEPTION_UNUSED",
        sourcePath: "<exceptions>",
        documentIndex: 0,
        resource: resourceKey(exception),
        fieldPath: exception.id,
        message: `exception '${exception.id}' does not match a denied token use`,
      });
    }
  }
  const findings = [...state.findings].sort(compareFindings);
  const sourceEvidence = sources.map((source) => ({
    path: source.path,
    sha256: sha256(source.yaml),
  }));
  return {
    apiVersion: WORKLOAD_TOKEN_SCAN_API_VERSION,
    scannerVersion: WORKLOAD_TOKEN_SCANNER_VERSION,
    scannedAt,
    sourceDigest: sha256(stableJson(sourceEvidence)),
    sources: sourceEvidence,
    documentCount,
    resourceCount: state.resourceCount,
    workloadCount: state.workloadCount,
    serviceAccountCount: state.serviceAccountCount,
    exceptionsUsed: [...state.exceptionsUsed].sort(),
    findings,
    pass: findings.length === 0,
  };
}

export function assertRenderedWorkloadTokens(
  args: Parameters<typeof scanRenderedWorkloadTokens>[0],
): WorkloadTokenScanReport {
  const report = scanRenderedWorkloadTokens(args);
  if (!report.pass) {
    throw new Error(
      `WORKLOAD_TOKEN_SCAN_FAILED: ${report.findings
        .map(
          (finding) =>
            `${finding.code} ${finding.resource ?? finding.sourcePath} ${finding.fieldPath}`,
        )
        .join("; ")}`,
    );
  }
  return report;
}

function scanResource(
  value: unknown,
  sourcePath: string,
  documentIndex: number,
  fieldPath: string,
  state: ScanState,
) {
  if (!isObject(value)) {
    addFinding(state, {
      code: "TOKEN_SCAN_DOCUMENT_INVALID",
      sourcePath,
      documentIndex,
      resource: null,
      fieldPath,
      message: "rendered Kubernetes document must be an object",
    });
    return;
  }
  const apiVersion = value.apiVersion;
  const kind = value.kind;
  if (typeof apiVersion !== "string" || typeof kind !== "string") {
    addFinding(state, {
      code: "TOKEN_SCAN_DOCUMENT_INVALID",
      sourcePath,
      documentIndex,
      resource: null,
      fieldPath,
      message:
        "rendered Kubernetes resource requires string apiVersion and kind",
    });
    return;
  }
  if (kind === "List" || kind.endsWith("List")) {
    if (!Array.isArray(value.items)) {
      addFinding(state, {
        code: "TOKEN_SCAN_DOCUMENT_INVALID",
        sourcePath,
        documentIndex,
        resource: null,
        fieldPath: `${fieldPath}.items`,
        message: "Kubernetes List items must be an array",
      });
      return;
    }
    value.items.forEach((item, index) =>
      scanResource(
        item,
        sourcePath,
        documentIndex,
        `${fieldPath}.items[${index}]`,
        state,
      ),
    );
    return;
  }

  state.resourceCount += 1;
  const identity = resourceIdentity(value, apiVersion, kind);
  if (!identity) {
    addFinding(state, {
      code: "TOKEN_SCAN_RESOURCE_IDENTITY_INVALID",
      sourcePath,
      documentIndex,
      resource: null,
      fieldPath: `${fieldPath}.metadata`,
      message:
        "resource requires exact metadata.name and optional exact metadata.namespace",
    });
    return;
  }
  if (state.resourceKeys.has(identity.key)) {
    addFinding(state, {
      code: "TOKEN_SCAN_RESOURCE_DUPLICATE",
      sourcePath,
      documentIndex,
      resource: identity.key,
      fieldPath,
      message: "resource identity occurs more than once in rendered input",
    });
  }
  state.resourceKeys.add(identity.key);

  if (apiVersion === "v1" && kind === "ServiceAccount") {
    state.serviceAccountCount += 1;
    if (value.automountServiceAccountToken !== false) {
      denyOrExcept(state, identity, "service-account-automount", {
        code: "TOKEN_SCAN_SERVICE_ACCOUNT_AUTOMOUNT_NOT_FALSE",
        sourcePath,
        documentIndex,
        resource: identity.key,
        fieldPath: `${fieldPath}.automountServiceAccountToken`,
        message:
          "ServiceAccount automountServiceAccountToken must be boolean false",
      });
    }
    return;
  }

  const podSpecPath = podSpecPaths.get(`${apiVersion}/${kind}`);
  const structuralPodSpecPath = findStructuralPodSpecPath(value);
  if (!podSpecPath) {
    if (structuralPodSpecPath) {
      addFinding(state, {
        code: "TOKEN_SCAN_WORKLOAD_KIND_UNKNOWN",
        sourcePath,
        documentIndex,
        resource: identity.key,
        fieldPath: `${fieldPath}.${structuralPodSpecPath.join(".")}`,
        message: `unrecognized workload kind '${apiVersion}/${kind}' contains a PodSpec-shaped object`,
      });
    }
    return;
  }

  state.workloadCount += 1;
  const podSpec = atPath(value, podSpecPath);
  const podSpecField = `${fieldPath}.${podSpecPath.join(".")}`;
  if (!isObject(podSpec)) {
    addFinding(state, {
      code: "TOKEN_SCAN_POD_SPEC_MISSING",
      sourcePath,
      documentIndex,
      resource: identity.key,
      fieldPath: podSpecField,
      message: "recognized workload does not contain its required PodSpec",
    });
    return;
  }
  if (podSpec.automountServiceAccountToken !== false) {
    denyOrExcept(state, identity, "workload-automount", {
      code: "TOKEN_SCAN_WORKLOAD_AUTOMOUNT_NOT_FALSE",
      sourcePath,
      documentIndex,
      resource: identity.key,
      fieldPath: `${podSpecField}.automountServiceAccountToken`,
      message: "PodSpec automountServiceAccountToken must be boolean false",
    });
  }
  if (Array.isArray(podSpec.volumes)) {
    for (const [volumeIndex, volume] of podSpec.volumes.entries()) {
      if (!isObject(volume) || !isObject(volume.projected)) continue;
      const sources = volume.projected.sources;
      if (!Array.isArray(sources)) continue;
      for (const [sourceIndex, projected] of sources.entries()) {
        if (isObject(projected) && hasOwn(projected, "serviceAccountToken")) {
          denyOrExcept(state, identity, "projected-service-account-token", {
            code: "TOKEN_SCAN_PROJECTED_TOKEN_FORBIDDEN",
            sourcePath,
            documentIndex,
            resource: identity.key,
            fieldPath: `${podSpecField}.volumes[${volumeIndex}].projected.sources[${sourceIndex}].serviceAccountToken`,
            message: "projected serviceAccountToken volume source is forbidden",
          });
        }
      }
    }
  }
}

function validateExceptions(
  exceptions: readonly WorkloadTokenException[],
  state: ScanState,
) {
  for (const exception of exceptions) {
    let valid = true;
    try {
      exactIdentifier(exception.id, "exception.id");
      exactApiVersion(exception.apiVersion, "exception.apiVersion");
      exactIdentifier(exception.kind, "exception.kind");
      exactResourceSegment(exception.namespace, "exception.namespace");
      exactResourceSegment(exception.name, "exception.name");
      exactIdentifier(exception.approvedBy, "exception.approvedBy");
      if (
        typeof exception.reason !== "string" ||
        exception.reason.length < 12
      ) {
        throw new Error(
          "exception.reason must explain the exceptional token use",
        );
      }
      exactTimestamp(exception.expiresAt, "exception.expiresAt");
      if (Date.parse(exception.expiresAt) <= state.nowMs) {
        throw new Error("exception.expiresAt must be in the future");
      }
      if (
        ![
          "workload-automount",
          "service-account-automount",
          "projected-service-account-token",
        ].includes(exception.issue)
      ) {
        throw new Error("exception.issue is unknown");
      }
    } catch (error) {
      valid = false;
      addFinding(state, {
        code: "TOKEN_SCAN_EXCEPTION_INVALID",
        sourcePath: "<exceptions>",
        documentIndex: 0,
        resource: null,
        fieldPath: exception?.id ?? "<unknown>",
        message: errorMessage(error),
      });
    }
    if (!valid) continue;
    const key = exceptionKey(exception, exception.issue);
    if (state.exceptions.has(key)) {
      addFinding(state, {
        code: "TOKEN_SCAN_EXCEPTION_DUPLICATE",
        sourcePath: "<exceptions>",
        documentIndex: 0,
        resource: resourceKey(exception),
        fieldPath: exception.id,
        message: "more than one exception matches the same resource and issue",
      });
      continue;
    }
    state.exceptions.set(key, exception);
  }
}

function denyOrExcept(
  state: ScanState,
  identity: ResourceIdentity,
  issue: WorkloadTokenExceptionIssue,
  finding: WorkloadTokenScanFinding,
) {
  const exception = state.exceptions.get(exceptionKey(identity, issue));
  if (exception) {
    state.exceptionsUsed.add(exception.id);
    return;
  }
  addFinding(state, finding);
}

function findStructuralPodSpecPath(
  resource: Record<string, unknown>,
): readonly string[] | null {
  for (const path of [
    ["spec", "template", "spec"],
    ["spec", "jobTemplate", "spec", "template", "spec"],
  ] as const) {
    const candidate = atPath(resource, path);
    if (
      isObject(candidate) &&
      (Array.isArray(candidate.containers) ||
        Array.isArray(candidate.initContainers) ||
        Array.isArray(candidate.ephemeralContainers))
    ) {
      return path;
    }
  }
  return null;
}

function resourceIdentity(
  resource: Record<string, unknown>,
  apiVersion: string,
  kind: string,
): ResourceIdentity | null {
  if (!isObject(resource.metadata)) return null;
  const name = resource.metadata.name;
  const namespace = resource.metadata.namespace ?? "default";
  try {
    exactApiVersion(apiVersion, "apiVersion");
    exactIdentifier(kind, "kind");
    exactResourceSegment(name, "metadata.name");
    exactResourceSegment(namespace, "metadata.namespace");
  } catch {
    return null;
  }
  return {
    apiVersion,
    kind,
    namespace: namespace as string,
    name: name as string,
    key: `${apiVersion}/${kind}/${namespace}/${name}`,
  };
}

function normalizeSources(sources: readonly RenderedManifestSource[]) {
  const result = sources.map((source) => {
    if (
      typeof source.path !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(source.path) ||
      source.path.startsWith("/") ||
      source.path.split("/").some((segment) => segment === "..")
    ) {
      throw new Error(
        `TOKEN_SCAN_SOURCE_PATH: '${source.path}' is not a safe relative path`,
      );
    }
    if (typeof source.yaml !== "string") {
      throw new Error(
        `TOKEN_SCAN_SOURCE_BODY: '${source.path}' must contain text`,
      );
    }
    return { path: source.path, yaml: source.yaml };
  });
  result.sort((left, right) => left.path.localeCompare(right.path));
  for (let index = 1; index < result.length; index += 1) {
    if (result[index - 1].path === result[index].path) {
      throw new Error(
        `TOKEN_SCAN_SOURCE_DUPLICATE: '${result[index].path}' occurs more than once`,
      );
    }
  }
  return result;
}

function exceptionKey(
  resource: Pick<
    ResourceIdentity,
    "apiVersion" | "kind" | "namespace" | "name"
  >,
  issue: WorkloadTokenExceptionIssue,
) {
  return `${resourceKey(resource)}#${issue}`;
}

function resourceKey(
  resource: Pick<
    ResourceIdentity,
    "apiVersion" | "kind" | "namespace" | "name"
  >,
) {
  return `${resource.apiVersion}/${resource.kind}/${resource.namespace}/${resource.name}`;
}

function atPath(value: unknown, path: readonly string[]): unknown {
  let current = value;
  for (const segment of path) {
    if (!isObject(current)) return undefined;
    current = current[segment];
  }
  return current;
}

function addFinding(state: ScanState, finding: WorkloadTokenScanFinding) {
  state.findings.push(finding);
}

function compareFindings(
  left: WorkloadTokenScanFinding,
  right: WorkloadTokenScanFinding,
) {
  return stableJson(left).localeCompare(stableJson(right));
}

function exactIdentifier(
  value: unknown,
  path: string,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length > 128 ||
    !/^[A-Za-z][A-Za-z0-9]*(?:[._:-][A-Za-z0-9]+)*$/.test(value)
  ) {
    throw new Error(`${path} is not an exact identifier`);
  }
}

function exactResourceSegment(
  value: unknown,
  path: string,
): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length > 253 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)
  ) {
    throw new Error(`${path} is not an exact Kubernetes resource segment`);
  }
}

function exactApiVersion(
  value: unknown,
  path: string,
): asserts value is string {
  if (
    typeof value !== "string" ||
    !/^(?:v[0-9]+|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\/v[0-9]+(?:alpha[0-9]+|beta[0-9]+)?)$/.test(
      value,
    )
  ) {
    throw new Error(`${path} is not an exact Kubernetes apiVersion`);
  }
}

function exactTimestamp(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) ||
    Number.isNaN(Date.parse(value))
  ) {
    throw new Error(`${path} must be an ISO-8601 UTC timestamp`);
  }
  return value;
}

function hasOwn(value: object, key: string) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
