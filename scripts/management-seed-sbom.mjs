import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv from "ajv";
import parseSpdxExpression from "spdx-expression-parse";

const DOCUMENT_ID = "SPDXRef-DOCUMENT";
const OFFICIAL_SPDX_SCHEMA = JSON.parse(
  readFileSync(
    new URL("../schemas/vendor/spdx-2.3.schema.json", import.meta.url),
    "utf8",
  ),
);
const officialSpdxValidator = new Ajv({
  allErrors: true,
  strict: false,
}).compile(OFFICIAL_SPDX_SCHEMA);

export function normalizeManagementSeedSbom(lock, generated) {
  assertRecord(lock, "package-lock");
  assertRecord(lock.packages, "package-lock packages");
  assertRecord(generated, "generated SBOM");
  if (
    generated.spdxVersion !== "SPDX-2.3" ||
    !Array.isArray(generated.packages)
  ) {
    throw new Error("SBOM is not a populated SPDX 2.3 document");
  }

  const lockEntries = Object.entries(lock.packages).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  const packages = [];
  const idsByPath = new Map();
  for (const [packagePath, entry] of lockEntries) {
    assertRecord(entry, `package-lock entry '${packagePath || "."}'`);
    const expected = lockPackage(packagePath, entry);
    const SPDXID = packageId(packagePath);
    if ([...idsByPath.values()].includes(SPDXID)) {
      throw new Error("SPDX package path identity collided");
    }
    idsByPath.set(packagePath, SPDXID);
    const normalized = {
      name: expected.name,
      SPDXID,
      versionInfo: expected.version,
      packageFileName: packagePath,
      downloadLocation: lockDownloadLocation(entry.resolved),
      filesAnalyzed: false,
      licenseDeclared: lockLicense(entry.license),
    };
    if (expected.checksum === null) {
      delete normalized.checksums;
    } else {
      normalized.checksums = [
        { algorithm: "SHA512", checksumValue: expected.checksum },
      ];
    }
    packages.push(normalized);
  }

  const relationships = lockRelationships(lock.packages, idsByPath);
  const graphDigest = sha256(
    canonicalJson({
      packages: lockEntries.map(([packagePath, entry]) => ({
        path: packagePath,
        name: lockPackage(packagePath, entry).name,
        version: entry.version,
        integrity: entry.integrity ?? null,
        resolved: entry.resolved ?? null,
        dependencies: entry.dependencies ?? {},
        devDependencies: entry.devDependencies ?? {},
        optionalDependencies: entry.optionalDependencies ?? {},
        peerDependencies: entry.peerDependencies ?? {},
      })),
      relationships,
    }),
  );
  const root = idsByPath.get("");
  if (!root) throw new Error("package-lock root package is missing");
  const normalized = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: DOCUMENT_ID,
    name: `${lock.name ?? lock.packages[""].name}@${lock.version ?? lock.packages[""].version}`,
    documentNamespace: `https://security.deus.dev/spdx/management-seed/${graphDigest}`,
    creationInfo: {
      created: "1970-01-01T00:00:00.000Z",
      creators: ["Tool: secure-saas-infra/management-seed-sbom-v1"],
    },
    documentDescribes: [root],
    packages,
    relationships,
  };
  assertOfficialSpdx(normalized);
  assertSpdxLicenseSemantics(normalized);
  return normalized;
}

export function assertManagementSeedSbom(lock, sbom) {
  assertOfficialSpdx(sbom);
  assertSpdxLicenseSemantics(sbom);
  const normalized = normalizeManagementSeedSbom(lock, sbom);
  if (canonicalJson(sbom) !== canonicalJson(normalized)) {
    throw new Error(
      "SPDX package path, multiplicity, document, or relationship graph differs from package-lock",
    );
  }
  return normalized;
}

function assertOfficialSpdx(value) {
  if (!officialSpdxValidator(value)) {
    const errors = (officialSpdxValidator.errors ?? [])
      .map((entry) => `${entry.instancePath || "/"} ${entry.message}`)
      .join("; ");
    throw new Error(`SBOM fails the official SPDX 2.3 JSON schema: ${errors}`);
  }
}

function assertSpdxLicenseSemantics(value) {
  for (const entry of value.packages ?? []) {
    const license = entry?.licenseDeclared;
    if (
      license === undefined ||
      license === "NOASSERTION" ||
      license === "NONE"
    ) {
      continue;
    }
    try {
      parseSpdxExpression(license);
    } catch {
      throw new Error(
        `SPDX package '${entry?.name ?? "unknown"}' has an invalid license expression`,
      );
    }
  }
}

function lockDownloadLocation(value) {
  if (value === undefined) return "NOASSERTION";
  if (typeof value !== "string") {
    throw new Error("package-lock resolved location is not a string");
  }
  try {
    return new URL(value).href;
  } catch {
    return "NOASSERTION";
  }
}

function lockLicense(value) {
  if (value === undefined) return "NOASSERTION";
  if (typeof value !== "string") {
    throw new Error("package-lock license is not a string");
  }
  try {
    parseSpdxExpression(value);
    return value;
  } catch {
    return "NOASSERTION";
  }
}

function lockRelationships(lockPackages, idsByPath) {
  const relationships = [
    {
      spdxElementId: DOCUMENT_ID,
      relatedSpdxElement: idsByPath.get(""),
      relationshipType: "DESCRIBES",
    },
  ];
  const edges = new Map();
  for (const [packagePath, entry] of Object.entries(lockPackages)) {
    const parentId = idsByPath.get(packagePath);
    addDependencyGroup(
      edges,
      lockPackages,
      idsByPath,
      packagePath,
      parentId,
      entry.dependencies,
      "DEPENDENCY_OF",
      true,
    );
    addDependencyGroup(
      edges,
      lockPackages,
      idsByPath,
      packagePath,
      parentId,
      entry.devDependencies,
      "DEV_DEPENDENCY_OF",
      packagePath === "",
    );
    addDependencyGroup(
      edges,
      lockPackages,
      idsByPath,
      packagePath,
      parentId,
      entry.optionalDependencies,
      "OPTIONAL_DEPENDENCY_OF",
      false,
    );
    addDependencyGroup(
      edges,
      lockPackages,
      idsByPath,
      packagePath,
      parentId,
      entry.peerDependencies,
      "PREREQUISITE_FOR",
      false,
    );
  }
  relationships.push(...edges.values());
  return relationships.sort((left, right) =>
    canonicalJson(left).localeCompare(canonicalJson(right)),
  );
}

function addDependencyGroup(
  edges,
  lockPackages,
  idsByPath,
  parentPath,
  parentId,
  dependencies,
  relationshipType,
  required,
) {
  if (dependencies === undefined) return;
  assertRecord(dependencies, `${relationshipType} dependencies`);
  for (const dependency of Object.keys(dependencies).sort()) {
    const dependencyPath = resolveDependencyPath(
      lockPackages,
      parentPath,
      dependency,
    );
    if (dependencyPath === undefined) {
      if (required) {
        throw new Error(
          `package-lock dependency '${dependency}' from '${parentPath || "."}' is unresolved`,
        );
      }
      continue;
    }
    const edge = {
      spdxElementId: idsByPath.get(dependencyPath),
      relatedSpdxElement: parentId,
      relationshipType,
    };
    const key = `${edge.spdxElementId}\u0000${edge.relatedSpdxElement}\u0000${relationshipType}`;
    edges.set(key, edge);
  }
}

function resolveDependencyPath(packages, parentPath, dependency) {
  let current = parentPath;
  while (true) {
    const candidate = current
      ? `${current}/node_modules/${dependency}`
      : `node_modules/${dependency}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (!current) return undefined;
    const marker = current.lastIndexOf("/node_modules/");
    current = marker < 0 ? "" : current.slice(0, marker);
  }
}

function lockPackage(packagePath, entry) {
  const name = packagePath
    ? packagePath.split("node_modules/").at(-1)
    : entry.name;
  if (typeof name !== "string" || typeof entry.version !== "string") {
    throw new Error(`package-lock entry '${packagePath || "."}' is incomplete`);
  }
  const checksum = integrityChecksum(entry.integrity);
  return {
    name,
    version: entry.version,
    checksum,
    tuple: canonicalJson([name, entry.version, checksum]),
  };
}

function integrityChecksum(value) {
  if (value === undefined) return null;
  if (typeof value !== "string" || !value.startsWith("sha512-")) {
    throw new Error("package-lock integrity must use SHA512");
  }
  return Buffer.from(value.slice("sha512-".length), "base64").toString("hex");
}

function packageId(packagePath) {
  return `SPDXRef-Package-lock-${sha256(packagePath || ".").slice(0, 32)}`;
}

function assertRecord(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
