#!/usr/bin/env node

// Builtins-only helper run by the authenticated Node archive during the
// credential-free, root-owned runtime installation.
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

if (process.geteuid?.() !== 0 || process.platform !== "linux") {
  throw new Error("runtime provenance writer requires root on Linux");
}
const args = parseArgs(process.argv.slice(2));
const root = realpathSync(args.root);
const architecture = args.architecture;
const nodePath = path.join(root, "bin", "node");
const goPath = path.join(root, "toolchains", "go", "bin", "go");
const pulumiPath = path.join(root, "toolchains", "pulumi");
const awsPath = path.join(root, "toolchains", "aws-cli");
const systemRuntime = JSON.parse(
  readFileSync(path.join(root, "system-runtime-closure.json"), "utf8"),
);
assertSystemRuntimeClosure(systemRuntime, architecture);
const provenance = {
  apiVersion: "security.deus.dev/bootstrap-runtime-provenance/v1",
  platform: "linux",
  architecture,
  artifacts: {
    go: artifact(args, "go", "authenticated-host-kit-pinned-sha256"),
    node: artifact(args, "node", "authenticated-host-kit-pinned-sha256"),
    pulumi: artifact(args, "pulumi", "authenticated-host-kit-pinned-sha256"),
    awsCli: {
      ...artifact(args, "aws", "aws-cli-team-pgp"),
      signingKeyFingerprint: args["aws-signing-key-fingerprint"],
    },
  },
  installed: {
    goSha256: hashFile(goPath),
    nodeSha256: hashFile(nodePath),
    pulumiTreeDigest: directoryDigest(pulumiPath),
    awsCliTreeDigest: directoryDigest(awsPath),
  },
  systemRuntime,
};
writeFileSync(
  path.join(root, "runtime-provenance.json"),
  `${JSON.stringify(provenance, null, 2)}\n`,
  { flag: "wx", mode: 0o400 },
);

function assertSystemRuntimeClosure(value, expectedArchitecture) {
  if (
    value?.apiVersion !== "security.deus.dev/system-runtime-closure/v1" ||
    value.architecture !== expectedArchitecture ||
    !Array.isArray(value.loaders) ||
    value.loaders.length === 0 ||
    value.loaders.length > 8 ||
    !Array.isArray(value.libraries) ||
    value.libraries.length > 512
  ) {
    throw new Error("system runtime closure is malformed");
  }
  for (const [label, entries] of [
    ["loader", value.loaders],
    ["library", value.libraries],
  ]) {
    const paths = entries.map((entry) => entry.path);
    if (JSON.stringify(paths) !== JSON.stringify([...paths].sort())) {
      throw new Error(`system runtime ${label} inventory is not sorted`);
    }
    for (const entry of entries) {
      if (
        typeof entry.path !== "string" ||
        (!entry.path.startsWith("/usr/lib/") &&
          !entry.path.startsWith("/lib/")) ||
        !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "") ||
        realpathSync(entry.path) !== entry.path ||
        hashFile(entry.path) !== entry.sha256
      ) {
        throw new Error(`system runtime ${label} binding is invalid`);
      }
    }
  }
}

function artifact(values, prefix, verification) {
  const file = values[`${prefix}-file`];
  const sha256 = values[`${prefix}-sha256`];
  if (!file || !/^[a-f0-9]{64}$/.test(sha256 ?? "")) {
    throw new Error(`invalid ${prefix} provenance`);
  }
  return { file, sha256, verification };
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index]?.startsWith("--") ? values[index].slice(2) : "";
    const value = values[index + 1];
    if (!key || !value || Object.hasOwn(result, key)) {
      throw new Error("invalid provenance writer arguments");
    }
    result[key] = value;
  }
  return result;
}

function directoryDigest(value) {
  const base = realpathSync(value);
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      const relative = path.relative(base, candidate).split(path.sep).join("/");
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(candidate);
        const resolved = realpathSync(candidate);
        const resolvedStat = lstatSync(resolved);
        if (resolvedStat.isDirectory() && isWithin(base, resolved)) {
          entries.push({ path: relative, type: "symlink", target });
        } else if (resolvedStat.isDirectory()) {
          entries.push({
            path: relative,
            type: "symlink",
            target,
            resolvedTreeDigest: directoryDigest(resolved),
          });
        } else if (resolvedStat.isFile()) {
          entries.push({
            path: relative,
            type: "symlink",
            target,
            resolvedSha256: hashFile(resolved),
          });
        } else {
          throw new Error(`unsupported runtime symlink ${candidate}`);
        }
      } else if (stat.isDirectory()) {
        walk(candidate);
      } else if (stat.isFile()) {
        entries.push({
          path: relative,
          type: "file",
          sha256: hashFile(candidate),
        });
      } else {
        throw new Error(`unsupported runtime artifact ${candidate}`);
      }
    }
  };
  walk(base);
  if (entries.length === 0) throw new Error(`empty runtime directory ${value}`);
  return sha256(canonicalJson(entries));
}

function isWithin(root, value) {
  const relative = path.relative(root, value);
  return !(
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  );
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

function hashFile(value) {
  return sha256(readFileSync(value));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
