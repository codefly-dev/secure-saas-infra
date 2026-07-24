#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import { loadManagementSeedScope } from "./management-seed-scope.mjs";

const root = process.cwd();
const scope = loadManagementSeedScope(root);
const files = scope.sourceFiles.filter((entry) =>
  /\.(?:cjs|json|md|mjs|ts|yaml|yml)$/.test(entry),
);
const result = spawnSync(
  path.resolve(root, "node_modules", ".bin", "prettier"),
  [process.argv.includes("--write") ? "--write" : "--check", ...files],
  { cwd: root, stdio: "inherit", env: process.env },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
