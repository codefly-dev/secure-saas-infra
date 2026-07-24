"use strict";

const { registerHooks } = require("node:module");
const { realpathSync } = require("node:fs");
const path = require("node:path");
const { fileURLToPath } = require("node:url");

const root = realpathSync(
  path.resolve(process.env.MANAGEMENT_SEED_TEST_ROOT || process.cwd()),
);
const buildRoot = realpathSync(path.join(root, "dist-management-seed-test"));
const dependencyRoot = realpathSync(path.join(root, "node_modules"));
let allowed;
let allowedSource;
try {
  allowed = new Set(
    JSON.parse(process.env.MANAGEMENT_SEED_TEST_ALLOWED_FILES || "[]"),
  );
  allowedSource = new Set(
    JSON.parse(process.env.MANAGEMENT_SEED_TEST_ALLOWED_SOURCE_FILES || "[]"),
  );
} catch {
  deny("runtime allowlist is not valid JSON");
}
if (allowed.size === 0) deny("compiled allowlist is empty");
if (allowedSource.size === 0) deny("source allowlist is empty");

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    assertAllowedUrl(resolved.url);
    return resolved;
  },
});

process.on("exit", () => {
  for (const loaded of Object.keys(require.cache)) {
    assertAllowedFile(loaded);
  }
});

function assertAllowedUrl(url) {
  if (typeof url !== "string" || url.startsWith("node:")) return;
  if (!url.startsWith("file:")) {
    deny(`module URL '${url}' is not a built-in or file module`);
  }
  assertAllowedFile(fileURLToPath(url));
}

function assertAllowedFile(resolved) {
  if (typeof resolved !== "string" || !path.isAbsolute(resolved)) return;
  let canonical;
  try {
    canonical = realpathSync(resolved);
  } catch {
    deny(`module path '${resolved}' is not a real file`);
  }
  if (isWithin(dependencyRoot, canonical)) return;
  const relativeToRoot = normalized(path.relative(root, canonical));
  if (relativeToRoot === "scripts/management-seed-test-runtime-guard.cjs") {
    return;
  }
  if (allowedSource.has(relativeToRoot)) return;
  const relativeToBuild = normalized(path.relative(buildRoot, canonical));
  if (
    relativeToBuild.startsWith("../") ||
    path.isAbsolute(relativeToBuild) ||
    !allowed.has(relativeToBuild)
  ) {
    deny(`local module '${relativeToRoot}' is outside the compiled allowlist`);
  }
}

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function normalized(value) {
  return value.split(path.sep).join("/");
}

function deny(message) {
  process.stderr.write(`MANAGEMENT_SEED_TEST_RUNTIME_DENIED: ${message}\n`);
  process.exit(86);
}
