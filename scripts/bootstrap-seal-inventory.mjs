import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { canonicalJson } from "./management-seed-scope.mjs";

export const BOOTSTRAP_SEAL_INVENTORY_PATH =
  "artifacts/bootstrap-seal-inventory.json";
export const BOOTSTRAP_SEAL_INVENTORY_API_VERSION =
  "security.deus.dev/bootstrap-seal-inventory/v1";

const generatedRoots = Object.freeze([
  "artifacts/bootstrap-pulumi-home/plugins/resource-aws-v7.27.0",
  "dist-management-seed",
  "dist-management-seed-policy",
  "node_modules",
]);
const generatedFiles = Object.freeze([
  "Pulumi.management.yaml",
  "artifacts/contract-schema-validation.json",
  "artifacts/deus-aws-bootstrap",
  "artifacts/local-gate-evidence.json",
  "artifacts/management-seed-access-bundle.json",
  "artifacts/management-seed-access.template.json",
  "artifacts/secure-saas-infra.spdx.json",
  "artifacts/security-contract-evidence.json",
  "onboarding.local.json",
]);
const executableGeneratedFiles = new Set(["artifacts/deus-aws-bootstrap"]);
const requiredEmptyDirectories = Object.freeze([
  "artifacts/pulumi-plans",
  "artifacts/runtime-output",
]);

export function writeBootstrapSealInventory(root) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const inventory = collectBootstrapSealInventory(repositoryRoot);
  const output = directPath(repositoryRoot, BOOTSTRAP_SEAL_INVENTORY_PATH);
  const temporary = `${output}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(inventory, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    renameSync(temporary, output);
  } finally {
    rmSync(temporary, { force: true });
  }
  return inventoryBinding(repositoryRoot, inventory);
}

export function assertBootstrapSealInventory(root, binding) {
  const repositoryRoot = realpathSync(path.resolve(root));
  if (
    binding?.path !== BOOTSTRAP_SEAL_INVENTORY_PATH ||
    !/^[a-f0-9]{64}$/.test(binding.sha256 ?? "") ||
    !Number.isSafeInteger(binding.entryCount) ||
    !Number.isSafeInteger(binding.totalFileBytes) ||
    !Number.isSafeInteger(binding.maximumFileSize)
  ) {
    throw new Error("bootstrap seal inventory binding is malformed");
  }
  const file = directPath(repositoryRoot, binding.path);
  const source = readFileSync(file);
  if (sha256(source) !== binding.sha256) {
    throw new Error("bootstrap seal inventory file changed");
  }
  let documented;
  try {
    documented = JSON.parse(source.toString("utf8"));
  } catch {
    throw new Error("bootstrap seal inventory is not valid JSON");
  }
  const actual = collectBootstrapSealInventory(repositoryRoot);
  if (
    canonicalJson(documented) !== canonicalJson(actual) ||
    canonicalJson(inventoryBinding(repositoryRoot, actual)) !==
      canonicalJson(binding)
  ) {
    throw new Error(
      "bootstrap seal inventory no longer matches the execution tree",
    );
  }
  return actual;
}

export function assertEmbeddedBootstrapSealInventory(
  root,
  binding,
  inventoryBytes,
  embeddedGeneratedFiles,
) {
  const repositoryRoot = realpathSync(path.resolve(root));
  assertInventoryBinding(binding);
  if (
    !Buffer.isBuffer(inventoryBytes) ||
    sha256(inventoryBytes) !== binding.sha256
  ) {
    throw new Error("embedded bootstrap seal inventory bytes changed");
  }
  if (!(embeddedGeneratedFiles instanceof Map)) {
    throw new Error("embedded bootstrap generated-file inventory is malformed");
  }
  let documented;
  try {
    documented = JSON.parse(inventoryBytes.toString("utf8"));
  } catch {
    throw new Error("embedded bootstrap seal inventory is not valid JSON");
  }
  const entries = [];
  for (const relative of generatedRoots) {
    walkGenerated(repositoryRoot, relative, entries);
  }
  if (
    embeddedGeneratedFiles.size !== generatedFiles.length ||
    generatedFiles.some((relative) => !embeddedGeneratedFiles.has(relative))
  ) {
    throw new Error("embedded bootstrap generated-file inventory is not exact");
  }
  for (const relative of generatedFiles) {
    const bytes = embeddedGeneratedFiles.get(relative);
    if (!Buffer.isBuffer(bytes)) {
      throw new Error(`embedded seal file '${relative}' is not binary data`);
    }
    entries.push(bufferEntry(relative, bytes));
  }
  const actual = finalizeInventory(entries);
  if (
    canonicalJson(documented) !== canonicalJson(actual) ||
    canonicalJson(
      inventoryBindingFromBytes(binding.path, inventoryBytes, actual),
    ) !== canonicalJson(binding)
  ) {
    throw new Error(
      "embedded bootstrap seal inventory does not match the reproduced execution tree",
    );
  }
  return actual;
}

export function collectBootstrapSealInventory(root) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const entries = [];
  for (const relative of generatedRoots) {
    walkGenerated(repositoryRoot, relative, entries);
  }
  for (const relative of generatedFiles) {
    entries.push(fileEntry(repositoryRoot, relative));
  }
  for (const relative of requiredEmptyDirectories) {
    const directory = directPath(repositoryRoot, relative);
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`seal output directory '${relative}' is unsafe`);
    }
    if (readdirSync(directory).length !== 0) {
      throw new Error(`seal output directory '${relative}' must be empty`);
    }
  }
  return finalizeInventory(entries);
}

function finalizeInventory(entries) {
  entries.sort((left, right) =>
    Buffer.compare(
      Buffer.from(left.path, "utf8"),
      Buffer.from(right.path, "utf8"),
    ),
  );
  if (
    entries.length === 0 ||
    entries.length > 300_000 ||
    new Set(entries.map((entry) => entry.path)).size !== entries.length
  ) {
    throw new Error(
      "bootstrap seal entry inventory is empty, duplicate, or excessive",
    );
  }
  const files = entries.filter((entry) => entry.type === "file");
  const totalFileBytes = files.reduce((total, entry) => total + entry.size, 0);
  const maximumFileSize = Math.max(...files.map((entry) => entry.size));
  if (
    !Number.isSafeInteger(totalFileBytes) ||
    totalFileBytes > 8 * 1024 * 1024 * 1024 ||
    maximumFileSize > 2 * 1024 * 1024 * 1024
  ) {
    throw new Error("bootstrap seal file inventory exceeds its byte budget");
  }
  return {
    apiVersion: BOOTSTRAP_SEAL_INVENTORY_API_VERSION,
    entryCount: entries.length,
    totalFileBytes,
    maximumFileSize,
    entries,
  };
}

function walkGenerated(root, relative, entries) {
  const value = directPath(root, relative);
  const stat = lstatSync(value);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(
      `generated seal root '${relative}' is not a direct directory`,
    );
  }
  entries.push({ path: relative, type: "directory" });
  for (const name of readdirSync(value).sort()) {
    const child = `${relative}/${name}`;
    const childValue = path.join(root, ...child.split("/"));
    const childStat = lstatSync(childValue);
    if (childStat.isSymbolicLink()) {
      if (
        relative !== "node_modules" &&
        !relative.startsWith("node_modules/")
      ) {
        throw new Error(`generated seal symlink is forbidden at '${child}'`);
      }
      const target = readlinkSync(childValue);
      const resolved = realpathSync(childValue);
      if (!isWithin(path.join(root, "node_modules"), resolved)) {
        throw new Error(
          `dependency symlink escapes node_modules at '${child}'`,
        );
      }
      entries.push({ path: child, type: "symlink", target });
    } else if (childStat.isDirectory()) {
      walkGenerated(root, child, entries);
    } else if (childStat.isFile()) {
      entries.push(fileEntry(root, child));
    } else {
      throw new Error(`generated seal path '${child}' has an unsupported type`);
    }
  }
}

function fileEntry(root, relative) {
  const value = directPath(root, relative);
  const stat = lstatSync(value);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(
      `exact seal file '${relative}' is not a direct regular file`,
    );
  }
  const entry = {
    path: relative,
    type: "file",
    size: stat.size,
    executable: (stat.mode & 0o111) !== 0,
    sha256: sha256File(value),
  };
  if (
    generatedFiles.includes(relative) &&
    entry.executable !== executableGeneratedFiles.has(relative)
  ) {
    throw new Error(`exact seal file '${relative}' has an unsafe mode`);
  }
  return entry;
}

function bufferEntry(relative, bytes) {
  return {
    path: relative,
    type: "file",
    size: bytes.length,
    executable: executableGeneratedFiles.has(relative),
    sha256: sha256(bytes),
  };
}

function inventoryBinding(root, inventory) {
  const inventoryPath = directPath(root, BOOTSTRAP_SEAL_INVENTORY_PATH);
  return {
    path: BOOTSTRAP_SEAL_INVENTORY_PATH,
    sha256: sha256File(inventoryPath),
    entryCount: inventory.entryCount,
    totalFileBytes: inventory.totalFileBytes,
    maximumFileSize: inventory.maximumFileSize,
  };
}

function inventoryBindingFromBytes(inventoryPath, bytes, inventory) {
  return {
    path: inventoryPath,
    sha256: sha256(bytes),
    entryCount: inventory.entryCount,
    totalFileBytes: inventory.totalFileBytes,
    maximumFileSize: inventory.maximumFileSize,
  };
}

function assertInventoryBinding(binding) {
  if (
    binding?.path !== BOOTSTRAP_SEAL_INVENTORY_PATH ||
    !/^[a-f0-9]{64}$/.test(binding.sha256 ?? "") ||
    !Number.isSafeInteger(binding.entryCount) ||
    !Number.isSafeInteger(binding.totalFileBytes) ||
    !Number.isSafeInteger(binding.maximumFileSize)
  ) {
    throw new Error("bootstrap seal inventory binding is malformed");
  }
}

function directPath(root, relative) {
  if (
    typeof relative !== "string" ||
    relative === "" ||
    path.isAbsolute(relative) ||
    relative.split(/[\\/]/).includes("..")
  ) {
    throw new Error(`unsafe seal path '${relative}'`);
  }
  const value = path.join(root, ...relative.split("/"));
  const parent = path.dirname(value);
  if (!existsSync(parent) || !isWithin(root, realpathSync(parent))) {
    throw new Error(`seal path '${relative}' escapes the execution root`);
  }
  return value;
}

function isWithin(root, value) {
  const relative = path.relative(root, value);
  return !(
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  );
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256File(value) {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const descriptor = openSync(value, "r");
  try {
    for (;;) {
      const count = readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally {
    closeSync(descriptor);
  }
  return digest.digest("hex");
}
