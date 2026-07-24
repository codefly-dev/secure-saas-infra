#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { loadManagementSeedScope } from "./management-seed-scope.mjs";

export function validateManagementSeedSyntax(root, sourceFiles) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const javascript = sourceFiles.filter((entry) =>
    /\.(?:cjs|mjs)$/.test(entry),
  );
  const shell = sourceFiles.filter(
    (entry) => entry.startsWith("scripts/") && path.extname(entry) === "",
  );
  if (javascript.length === 0 || shell.length === 0) {
    throw new Error("management-seed syntax inventory is unexpectedly empty");
  }
  for (const relative of javascript) {
    const file = safeSource(repositoryRoot, relative);
    runSyntaxCheck(
      process.execPath,
      ["--check", file],
      repositoryRoot,
      relative,
    );
  }
  for (const relative of shell) {
    const file = safeSource(repositoryRoot, relative);
    const stat = lstatSync(file);
    if (
      (stat.mode & 0o111) === 0 ||
      !readFileSync(file, "utf8").startsWith("#!/bin/sh\n")
    ) {
      throw new Error(
        `governed shell program '${relative}' is not executable POSIX sh`,
      );
    }
    runSyntaxCheck("/bin/sh", ["-n", file], repositoryRoot, relative);
  }
  return { javascript: javascript.sort(), shell: shell.sort() };
}

function safeSource(root, relative) {
  const candidate = path.resolve(root, relative);
  const fromRoot = path.relative(root, candidate);
  if (
    !relative ||
    fromRoot.startsWith(`..${path.sep}`) ||
    path.isAbsolute(fromRoot) ||
    !existsSync(candidate)
  ) {
    throw new Error(
      `governed syntax input '${relative}' escapes the repository`,
    );
  }
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    throw new Error(
      `governed syntax input '${relative}' is not a direct regular file`,
    );
  }
  return candidate;
}

function runSyntaxCheck(executable, args, root, relative) {
  const result = spawnSync(executable, args, {
    cwd: root,
    encoding: "utf8",
    env: {
      HOME: process.env.HOME ?? "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin",
    },
  });
  if (result.status !== 0) {
    throw new Error(
      `syntax validation failed for '${relative}': ${result.stderr || result.stdout || "unknown parser error"}`,
    );
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
) {
  try {
    const root = process.cwd();
    const inventory = validateManagementSeedSyntax(
      root,
      loadManagementSeedScope(root).sourceFiles,
    );
    process.stdout.write(
      `Syntax verified for ${inventory.javascript.length} JavaScript modules and ${inventory.shell.length} shell programs.\n`,
    );
  } catch (error) {
    process.stderr.write(`MANAGEMENT_SEED_SYNTAX_DENIED: ${error.message}\n`);
    process.exit(1);
  }
}
