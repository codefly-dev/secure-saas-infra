#!/usr/bin/env node

// Release-builder-only, builtins-only manifest writer. The authenticated host
// kit carries this output so the independent signer can authenticate the full
// checkout before npm or any checkout program runs.
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const args = parseArgs(process.argv.slice(2));
const root = realpathSync(process.cwd());
if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:[+-][A-Za-z0-9.-]+)?$/.test(args.tag)) {
  throw new Error("source manifest requires an exact release tag");
}
if (!/^[a-f0-9]{40}$/.test(args.revision)) {
  throw new Error("source manifest requires a full Git revision");
}
const actualRevision = git(root, ["rev-parse", "HEAD"]).trim();
const actualTag = git(root, [
  "describe",
  "--tags",
  "--exact-match",
  "HEAD",
]).trim();
const status = git(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
if (
  actualRevision !== args.revision ||
  actualTag !== args.tag ||
  status.length !== 0
) {
  throw new Error("source manifest requires the exact clean tagged checkout");
}

const files = git(root, ["ls-files", "-z"])
  .split("\0")
  .filter(Boolean)
  .sort()
  .map((relative) => {
    assertRelativePath(relative);
    const absolute = path.join(root, relative);
    const stat = lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`source manifest rejects non-regular path '${relative}'`);
    }
    return {
      path: relative,
      executable: (stat.mode & 0o111) !== 0,
      sha256: sha256(readFileSync(absolute)),
    };
  });
if (files.length === 0 || files.length > 10_000) {
  throw new Error("source manifest file inventory is empty or excessive");
}
const subject = {
  apiVersion: "security.deus.dev/bootstrap-host-source-manifest/v1",
  releaseTag: args.tag,
  sourceRevision: args.revision,
  files,
};
const manifest = {
  ...subject,
  manifestDigest: sha256(canonicalJson(subject)),
};
const output = path.resolve(root, args.output);
writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, {
  flag: "wx",
  mode: 0o444,
});

function git(cwd, command) {
  const result = spawnSync(
    "/usr/bin/git",
    [
      "-c",
      "core.fileMode=true",
      "-c",
      "core.fsmonitor=false",
      "-c",
      "core.hooksPath=/dev/null",
      "-c",
      "credential.helper=",
      ...command,
    ],
    {
      cwd,
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
      env: {
        HOME: "/nonexistent",
        LANG: "C",
        PATH: "/usr/bin:/bin",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
      },
    },
  );
  if (result.status !== 0 || result.error) {
    throw new Error(
      `trusted Git inspection failed: ${result.stderr || result.error?.message}`,
    );
  }
  return result.stdout;
}

function assertRelativePath(value) {
  if (
    !value ||
    value !== value.normalize("NFC") ||
    path.isAbsolute(value) ||
    path.normalize(value) !== value ||
    value === ".." ||
    value.startsWith(`..${path.sep}`) ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`unsafe source-manifest path '${value}'`);
  }
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index]?.startsWith("--") ? values[index].slice(2) : "";
    const value = values[index + 1];
    if (!key || !value || Object.hasOwn(result, key)) {
      throw new Error("invalid source-manifest arguments");
    }
    result[key] = value;
  }
  if (Object.keys(result).sort().join(",") !== "output,revision,tag") {
    throw new Error("source manifest requires --tag, --revision, and --output");
  }
  return result;
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
