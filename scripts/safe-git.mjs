import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";

export function runReadOnlyGit(root, args, environment = process.env) {
  return runReadOnlyGitCommand(root, args, environment, "utf8");
}

export function runReadOnlyGitBytes(root, args, environment = process.env) {
  return runReadOnlyGitCommand(root, args, environment, null);
}

function runReadOnlyGitCommand(root, args, environment, encoding) {
  const executable = resolveGit(environment.PATH ?? "");
  const result = spawnSync(
    executable,
    [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "core.hooksPath=/dev/null",
      "-c",
      "credential.helper=",
      ...args,
    ],
    {
      cwd: root,
      encoding,
      env: safeGitEnvironment(environment, executable),
    },
  );
  if (result.status !== 0) {
    throw new Error(
      result.stderr?.toString("utf8") || `git ${args.join(" ")} failed.`,
    );
  }
  return result.stdout;
}

function resolveGit(pathValue) {
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.resolve(directory, "git");
    if (
      existsSync(candidate) &&
      (lstatSync(candidate).isFile() || lstatSync(candidate).isSymbolicLink())
    ) {
      const real = realpathSync(candidate);
      if (lstatSync(real).isFile()) return real;
    }
  }
  throw new Error("Git is unavailable on the qualification PATH.");
}

function safeGitEnvironment(environment, executable) {
  const allowed = [
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "TERM",
  ];
  return {
    ...Object.fromEntries(
      allowed
        .filter((name) => environment[name] !== undefined)
        .map((name) => [name, environment[name]]),
    ),
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    PATH: `${path.dirname(executable)}:/usr/bin:/bin`,
  };
}
