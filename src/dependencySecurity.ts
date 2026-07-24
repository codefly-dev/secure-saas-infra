export interface DependencyException {
  advisoryId: string;
  severity: "low" | "moderate";
  owner: string;
  reason: string;
  expiresAt: string;
  compensatingControls: readonly string[];
}

export interface DependencyExceptionFile {
  schemaVersion: 1;
  exceptions: readonly DependencyException[];
}

export interface DependencyAdvisory {
  advisoryId: string;
  packageName: string;
  severity: string;
  title: string;
  url?: string;
}

export interface DependencyAuditEvaluation {
  advisories: readonly DependencyAdvisory[];
  accepted: readonly DependencyAdvisory[];
  failures: readonly string[];
  warnings: readonly string[];
}

export function evaluateDependencyAudit(
  report: unknown,
  exceptionFile: unknown,
  now = new Date(),
): DependencyAuditEvaluation {
  const auditReport = asRecord(report, "audit report");
  if (auditReport.error !== undefined) {
    throw new Error(
      "npm audit returned an error instead of an advisory report.",
    );
  }
  const exceptions = parseExceptionFile(exceptionFile);
  const advisories = extractAdvisories(auditReport);
  const exceptionById = new Map(
    exceptions.exceptions.map((entry) => [entry.advisoryId, entry]),
  );
  const failures: string[] = [];
  const warnings: string[] = [];
  const accepted: DependencyAdvisory[] = [];

  for (const exception of exceptions.exceptions) {
    if (Date.parse(exception.expiresAt) <= now.getTime()) {
      failures.push(
        `Dependency exception '${exception.advisoryId}' expired at ${exception.expiresAt}.`,
      );
    }
    if (
      exception.owner.trim().length === 0 ||
      exception.reason.trim().length === 0 ||
      exception.compensatingControls.length === 0
    ) {
      failures.push(
        `Dependency exception '${exception.advisoryId}' requires an owner, reason, and compensating controls.`,
      );
    }
  }

  for (const advisory of advisories) {
    if (advisory.severity === "critical" || advisory.severity === "high") {
      failures.push(
        `${advisory.severity.toUpperCase()} dependency advisory ${advisory.advisoryId} affects ${advisory.packageName}: ${advisory.title}`,
      );
      continue;
    }
    if (advisory.severity === "moderate") {
      const exception = exceptionById.get(advisory.advisoryId);
      if (!exception) {
        failures.push(
          `Moderate dependency advisory ${advisory.advisoryId} is not covered by a reviewed exception.`,
        );
      } else if (exception.severity !== "moderate") {
        failures.push(
          `Dependency exception '${exception.advisoryId}' declares severity '${exception.severity}' but the audit reports 'moderate'.`,
        );
      } else if (Date.parse(exception.expiresAt) > now.getTime()) {
        accepted.push(advisory);
      }
    }
  }

  const advisoryIds = new Set(advisories.map((entry) => entry.advisoryId));
  for (const exception of exceptions.exceptions) {
    if (!advisoryIds.has(exception.advisoryId)) {
      warnings.push(
        `Dependency exception '${exception.advisoryId}' is stale because the advisory is no longer present.`,
      );
    }
  }

  return { advisories, accepted, failures: [...new Set(failures)], warnings };
}

export function extractAdvisories(report: unknown): DependencyAdvisory[] {
  const root = asRecord(report, "audit report");
  const vulnerabilities = asRecord(
    root.vulnerabilities ?? {},
    "audit report vulnerabilities",
  );
  const advisories = new Map<string, DependencyAdvisory>();
  const packageCounts = new Map<string, number>([
    ["info", 0],
    ["low", 0],
    ["moderate", 0],
    ["high", 0],
    ["critical", 0],
  ]);

  for (const [packageName, rawVulnerability] of Object.entries(
    vulnerabilities,
  )) {
    const vulnerability = asRecord(
      rawVulnerability,
      `vulnerability '${packageName}'`,
    );
    const severity = normalizeSeverity(
      vulnerability.severity,
      `vulnerability '${packageName}'`,
    );
    packageCounts.set(severity, (packageCounts.get(severity) ?? 0) + 1);
    if (!Array.isArray(vulnerability.via)) {
      throw new Error(`vulnerability '${packageName}' via must be an array.`);
    }
    const via = vulnerability.via;
    let foundConcreteAdvisory = false;
    let foundStringAdvisory = false;
    const concreteSeverities: string[] = [];

    for (const rawAdvisory of via) {
      if (typeof rawAdvisory === "string") {
        foundStringAdvisory = true;
        continue;
      }
      if (
        rawAdvisory === null ||
        typeof rawAdvisory !== "object" ||
        Array.isArray(rawAdvisory)
      ) {
        continue;
      }
      foundConcreteAdvisory = true;
      const advisory = rawAdvisory as Record<string, unknown>;
      const url = typeof advisory.url === "string" ? advisory.url : undefined;
      const advisoryId =
        url?.split("/").filter(Boolean).at(-1) ??
        `npm-${String(advisory.source ?? packageName)}`;
      const entry: DependencyAdvisory = {
        advisoryId,
        packageName,
        severity: normalizeSeverity(
          advisory.severity ?? severity,
          `advisory '${advisoryId}'`,
        ),
        title: String(advisory.title ?? "Unnamed npm advisory"),
        url,
      };
      concreteSeverities.push(entry.severity);
      advisories.set(`${entry.advisoryId}:${entry.packageName}`, entry);
    }

    if (
      foundConcreteAdvisory &&
      !foundStringAdvisory &&
      severity !== "high" &&
      severity !== "critical" &&
      maximumSeverity(concreteSeverities) !== severity
    ) {
      throw new Error(
        `vulnerability '${packageName}' severity '${severity}' does not equal its maximum concrete advisory severity`,
      );
    }

    if (
      !foundConcreteAdvisory ||
      foundStringAdvisory ||
      severity === "high" ||
      severity === "critical"
    ) {
      const entry: DependencyAdvisory = {
        advisoryId: `npm-package-${packageName}`,
        packageName,
        severity,
        title: `Transitive ${severity} vulnerability reported for ${packageName}`,
      };
      advisories.set(`${entry.advisoryId}:${entry.packageName}`, entry);
    }
  }

  assertAggregateMetadata(root.metadata, packageCounts);

  return [...advisories.values()];
}

function maximumSeverity(values: readonly string[]): string | undefined {
  const order = ["info", "low", "moderate", "high", "critical"];
  return [...values].sort(
    (left, right) => order.indexOf(right) - order.indexOf(left),
  )[0];
}

function normalizeSeverity(value: unknown, label: string): string {
  const severity = String(value ?? "").toLowerCase();
  if (!["info", "low", "moderate", "high", "critical"].includes(severity)) {
    throw new Error(
      `${label} has unsupported severity '${severity || "missing"}'.`,
    );
  }
  return severity;
}

function assertAggregateMetadata(
  metadataValue: unknown,
  packageCounts: ReadonlyMap<string, number>,
) {
  const metadata = asRecord(metadataValue, "audit report metadata");
  const counts = asRecord(
    metadata.vulnerabilities,
    "audit report metadata vulnerabilities",
  );
  const severities = ["info", "low", "moderate", "high", "critical"];
  let total = 0;
  for (const severity of severities) {
    const actual = counts[severity];
    if (!Number.isSafeInteger(actual) || Number(actual) < 0) {
      throw new Error(
        `audit report metadata severity '${severity}' must be a non-negative integer.`,
      );
    }
    const expected = packageCounts.get(severity) ?? 0;
    if (actual !== expected) {
      throw new Error(
        `audit report metadata severity '${severity}' reports ${actual} but ${expected} package vulnerabilities were parsed.`,
      );
    }
    total += expected;
  }
  if (!Number.isSafeInteger(counts.total) || counts.total !== total) {
    throw new Error(
      `audit report metadata total reports ${String(counts.total)} but ${total} package vulnerabilities were parsed.`,
    );
  }
}

function parseExceptionFile(value: unknown): DependencyExceptionFile {
  const input = asRecord(value, "dependency exception file");
  if (input.schemaVersion !== 1 || !Array.isArray(input.exceptions)) {
    throw new Error(
      "Dependency exception file must use schemaVersion 1 and contain an exceptions array.",
    );
  }
  const parsed: DependencyExceptionFile = {
    schemaVersion: 1,
    exceptions: input.exceptions.map((raw, index) => {
      const entry = asRecord(raw, `dependency exception ${index}`);
      const severity = entry.severity;
      if (severity !== "low" && severity !== "moderate") {
        throw new Error(
          `Dependency exception ${index} cannot accept severity '${String(severity)}'.`,
        );
      }
      if (!Array.isArray(entry.compensatingControls)) {
        throw new Error(
          `Dependency exception ${index} requires compensatingControls.`,
        );
      }
      const advisoryId = String(entry.advisoryId ?? "");
      const expiresAt = String(entry.expiresAt ?? "");
      if (advisoryId.trim().length === 0) {
        throw new Error(`Dependency exception ${index} requires advisoryId.`);
      }
      if (!Number.isFinite(Date.parse(expiresAt))) {
        throw new Error(
          `Dependency exception '${advisoryId}' has an invalid expiresAt value.`,
        );
      }
      const compensatingControls = entry.compensatingControls.map(String);
      if (compensatingControls.some((control) => control.trim().length === 0)) {
        throw new Error(
          `Dependency exception '${advisoryId}' contains an empty compensating control.`,
        );
      }
      return {
        advisoryId,
        severity,
        owner: String(entry.owner ?? ""),
        reason: String(entry.reason ?? ""),
        expiresAt,
        compensatingControls,
      };
    }),
  };
  const advisoryIds = parsed.exceptions.map((entry) => entry.advisoryId);
  if (new Set(advisoryIds).size !== advisoryIds.length) {
    throw new Error("Dependency exception advisory IDs must be unique.");
  }
  return parsed;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}
