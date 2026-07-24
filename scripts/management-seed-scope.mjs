import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { runReadOnlyGit } from "./safe-git.mjs";

export function loadManagementSeedScope(root) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const file = safeFile(
    repositoryRoot,
    "security/management-seed-qualification-scope.json",
  );
  const scope = JSON.parse(readFileSync(file, "utf8"));
  if (
    scope?.apiVersion !==
      "security.deus.dev/management-seed-qualification-scope/v1" ||
    !Array.isArray(scope.sourceFiles) ||
    !Array.isArray(scope.tests?.compilationSourceFiles) ||
    !Array.isArray(scope.tests?.compiledOutputs) ||
    !Array.isArray(scope.tests?.included) ||
    !Array.isArray(scope.tests?.quarantined)
  ) {
    throw new Error("Management-seed qualification scope is malformed.");
  }
  assertUniqueSorted(scope.sourceFiles, "sourceFiles");
  assertUniqueSorted(
    scope.tests.compilationSourceFiles,
    "tests.compilationSourceFiles",
  );
  assertUniqueSorted(scope.tests.compiledOutputs, "tests.compiledOutputs");
  assertUniqueSorted(scope.tests.included, "tests.included");
  assertUniqueSorted(scope.tests.quarantined, "tests.quarantined");
  assertExactTestClassification(repositoryRoot, scope.tests);
  assertExactContractClassification(repositoryRoot, scope.contracts);
  for (const entry of scope.sourceFiles) safeFile(repositoryRoot, entry);
  assertQualificationClosure(scope);
  return Object.freeze(scope);
}

function assertQualificationClosure(scope) {
  for (const entry of [
    scope.build.programEntrypoint,
    scope.build.policyEntrypoint,
    scope.build.supportEntrypoint,
    ...scope.tests.included,
    ...scope.tests.compilationSourceFiles,
    ...scope.contracts.includedChecked.flatMap((item) => [
      `contracts/${item.contract}`,
      `schemas/${item.schema}`,
    ]),
    ...scope.contracts.includedSchemaOnly.map(
      (item) => `schemas/${item.schema}`,
    ),
  ]) {
    if (!scope.sourceFiles.includes(entry)) {
      throw new Error(`Governed input '${entry}' is missing from sourceFiles.`);
    }
  }
  for (const entry of scope.tests.included) {
    if (!scope.tests.compilationSourceFiles.includes(entry)) {
      throw new Error(
        `Governed test '${entry}' is missing from the compilation closure.`,
      );
    }
  }
  const quarantined = new Set([
    ...scope.tests.quarantined,
    ...scope.contracts.quarantinedChecked.flatMap((item) => [
      `contracts/${item.contract}`,
      `schemas/${item.schema}`,
    ]),
    ...scope.contracts.quarantinedSchemaOnly.map((item) => `schemas/${item}`),
  ]);
  const leaked = scope.sourceFiles.filter(
    (entry) =>
      quarantined.has(entry) ||
      entry.startsWith("gitops/") ||
      /(?:argocd|gitops|disposable-cluster|infrastructure-controller|managed-postgres|cloud-context)/i.test(
        entry,
      ),
  );
  if (leaked.length > 0) {
    throw new Error(
      `Quarantined platform inputs entered management-seed sourceFiles: ${leaked.join(", ")}.`,
    );
  }
}

export function managementSeedSourceState(root, { requireClean = false } = {}) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const scope = loadManagementSeedScope(repositoryRoot);
  const revision = runReadOnlyGit(repositoryRoot, ["rev-parse", "HEAD"]).trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) {
    throw new Error("Git did not return a full source revision.");
  }
  const dirty =
    runReadOnlyGit(repositoryRoot, [
      "status",
      "--porcelain",
      "--untracked-files=all",
    ]).trim().length > 0;
  if (requireClean && dirty) {
    throw new Error("Management-seed qualification requires a clean worktree.");
  }
  const entries = scope.sourceFiles.map((entry) => ({
    path: entry,
    sha256: hashFile(safeFile(repositoryRoot, entry)),
  }));
  return {
    revision,
    dirty,
    treeDigest: sha256(canonicalJson(entries)),
    entries,
  };
}

export function managementSeedTreeDigest(root) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const scope = loadManagementSeedScope(repositoryRoot);
  const entries = scope.sourceFiles.map((entry) => ({
    path: entry,
    sha256: hashFile(safeFile(repositoryRoot, entry)),
  }));
  return sha256(canonicalJson(entries));
}

export function managementSeedQualifiedSourceState(root, revision) {
  if (!/^[a-f0-9]{40}$/.test(revision ?? "")) {
    throw new Error("Qualified management-seed revision is invalid.");
  }
  const repositoryRoot = realpathSync(path.resolve(root));
  const scope = loadManagementSeedScope(repositoryRoot);
  const entries = scope.sourceFiles.map((entry) => ({
    path: entry,
    sha256: hashFile(safeFile(repositoryRoot, entry)),
  }));
  return {
    revision,
    dirty: false,
    treeDigest: sha256(canonicalJson(entries)),
    entries,
  };
}

export function assertExactBuildOutputs(root, directory, expected) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const base = path.resolve(repositoryRoot, directory);
  if (!existsSync(base) || !lstatSync(base).isDirectory()) {
    throw new Error(`Expected build directory '${directory}' is missing.`);
  }
  const actual = [];
  walkFiles(base, base, actual);
  assertExact(actual.sort(), [...expected].sort(), `${directory} outputs`);
}

export function safeFile(root, value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    path.isAbsolute(value) ||
    value.split(/[\\/]/).includes("..")
  ) {
    throw new Error(`Unsafe management-seed path '${value}'.`);
  }
  const candidate = path.resolve(root, value);
  if (!isWithin(root, candidate)) {
    throw new Error(`Management-seed path escapes the repository: ${value}.`);
  }
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    throw new Error(
      `Management-seed input must be a direct regular file: ${value}.`,
    );
  }
  return candidate;
}

export function safeArtifactOutput(root, value) {
  const repositoryRoot = realpathSync(path.resolve(root));
  if (
    typeof value !== "string" ||
    !value.startsWith("artifacts/") ||
    path.isAbsolute(value) ||
    value.split(/[\\/]/).includes("..")
  ) {
    throw new Error(`Unsafe management-seed artifact output '${value}'.`);
  }
  const candidate = path.resolve(repositoryRoot, value);
  if (!isWithin(path.join(repositoryRoot, "artifacts"), candidate)) {
    throw new Error(
      `Management-seed artifact output escapes artifacts: ${value}.`,
    );
  }
  let current = repositoryRoot;
  for (const segment of path
    .relative(repositoryRoot, path.dirname(candidate))
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, segment);
    if (
      !existsSync(current) ||
      !lstatSync(current).isDirectory() ||
      lstatSync(current).isSymbolicLink() ||
      realpathSync(current) !== current
    ) {
      throw new Error(
        "Management-seed artifact output parent must be an existing real directory.",
      );
    }
  }
  if (
    existsSync(candidate) &&
    (!lstatSync(candidate).isFile() ||
      lstatSync(candidate).isSymbolicLink() ||
      realpathSync(candidate) !== candidate)
  ) {
    throw new Error(
      "Management-seed artifact output must be a regular non-symlink file.",
    );
  }
  return candidate;
}

export function writeAtomicArtifact(root, value, body) {
  const output = safeArtifactOutput(root, value);
  const temporary = `${output}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, body, { flag: "wx", mode: 0o600 });
    safeArtifactOutput(root, value);
    renameSync(temporary, output);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertExactTestClassification(root, tests) {
  const actual = readdirSync(path.join(root, "tests"))
    .filter((name) => name.endsWith(".test.ts"))
    .map((name) => `tests/${name}`)
    .sort();
  const included = [...tests.included];
  const quarantined = [...tests.quarantined];
  const overlap = included.filter((entry) => quarantined.includes(entry));
  if (overlap.length > 0) {
    throw new Error(
      `Tests cannot be both included and quarantined: ${overlap.join(", ")}.`,
    );
  }
  assertExact(
    [...included, ...quarantined].sort(),
    actual,
    "test classification",
  );
}

function assertExactContractClassification(root, contracts) {
  for (const name of [
    "includedChecked",
    "includedSchemaOnly",
    "quarantinedChecked",
    "quarantinedSchemaOnly",
  ]) {
    if (!Array.isArray(contracts?.[name])) {
      throw new Error(`Management-seed contracts.${name} must be an array.`);
    }
  }
  const checked = [
    ...contracts.includedChecked,
    ...contracts.quarantinedChecked,
  ];
  const schemas = [
    ...checked.map((entry) => entry.schema),
    ...contracts.includedSchemaOnly.map((entry) => entry.schema),
    ...contracts.quarantinedSchemaOnly,
  ].sort();
  const contractNames = checked.map((entry) => entry.contract).sort();
  const actualSchemas = readdirSync(path.join(root, "schemas"))
    .filter((name) => name.endsWith(".schema.json"))
    .sort();
  const actualContracts = readdirSync(path.join(root, "contracts"))
    .filter((name) => name.endsWith(".json"))
    .sort();
  assertExact(schemas, actualSchemas, "contract schema classification");
  assertExact(
    contractNames,
    actualContracts,
    "contract example classification",
  );
}

function assertUniqueSorted(values, label) {
  if (
    values.some((entry) => typeof entry !== "string") ||
    new Set(values).size !== values.length ||
    JSON.stringify(values) !== JSON.stringify([...values].sort())
  ) {
    throw new Error(
      `Management-seed ${label} must be a unique sorted string list.`,
    );
  }
}

function assertExact(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const unexpected = actual.filter((entry) => !expected.includes(entry));
    const missing = expected.filter((entry) => !actual.includes(entry));
    throw new Error(
      `${label} mismatch (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"}).`,
    );
  }
}

function walkFiles(base, current, output) {
  for (const name of readdirSync(current).sort()) {
    const candidate = path.join(current, name);
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink()) {
      throw new Error(`Build output contains symlink '${candidate}'.`);
    }
    if (stat.isDirectory()) walkFiles(base, candidate, output);
    else if (stat.isFile())
      output.push(path.relative(base, candidate).split(path.sep).join("/"));
    else
      throw new Error(
        `Build output contains unsupported entry '${candidate}'.`,
      );
  }
}

function hashFile(file) {
  return sha256(readFileSync(file));
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}
