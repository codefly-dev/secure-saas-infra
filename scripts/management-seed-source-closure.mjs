import { readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

const sourceExtensions = [".ts", ".mjs", ".cjs", ".js", ".json"];
const fixedExecutionImportPrefix =
  "file:///usr/local/lib/deus-bootstrap/execution/";

export function assertManagementSeedSourceImportClosure(root, scope) {
  const repositoryRoot = path.resolve(root);
  const governed = new Set(scope.sourceFiles);
  const generated = new Set([
    ...scope.build.programOutputs.map(
      (entry) => `${scope.build.programDirectory}/${entry}`,
    ),
    ...scope.build.policyOutputs.map(
      (entry) => `${scope.build.policyDirectory}/${entry}`,
    ),
    ...scope.build.supportOutputs.map(
      (entry) => `${scope.build.supportDirectory}/${entry}`,
    ),
  ]);

  for (const sourcePath of [...governed].sort()) {
    if (!/\.(?:[cm]?js|ts)$/.test(sourcePath)) continue;
    const source = ts.createSourceFile(
      sourcePath,
      readFileSync(path.resolve(repositoryRoot, sourcePath), "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    visit(source, (specifier) => {
      if (specifier.startsWith(".")) {
        assertGovernedRelativeImport(
          sourcePath,
          specifier,
          governed,
          generated,
        );
      } else if (specifier.startsWith(fixedExecutionImportPrefix)) {
        const target = specifier.slice(fixedExecutionImportPrefix.length);
        if (
          !target ||
          target.includes("%") ||
          target.includes("\\") ||
          target.includes("?") ||
          target.includes("#") ||
          path.posix.normalize(target) !== target ||
          !governed.has(target)
        ) {
          throw new Error(
            `${sourcePath} contains an ungoverned fixed execution import '${specifier}'`,
          );
        }
      } else if (specifier.startsWith("file:")) {
        throw new Error(
          `${sourcePath} contains an unsupported file import '${specifier}'`,
        );
      }
    });
  }
}

function visit(source, inspect) {
  const walk = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier
    ) {
      if (!ts.isStringLiteral(node.moduleSpecifier)) {
        throw new Error(
          `${source.fileName} contains a non-literal module specifier`,
        );
      }
      inspect(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && isModuleLoader(node.expression)) {
      if (
        node.arguments.length !== 1 ||
        !ts.isStringLiteral(node.arguments[0])
      ) {
        throw new Error(
          `${source.fileName} contains a non-literal dynamic module load`,
        );
      }
      inspect(node.arguments[0].text);
    }
    ts.forEachChild(node, walk);
  };
  walk(source);
}

function isModuleLoader(expression) {
  return (
    expression.kind === ts.SyntaxKind.ImportKeyword ||
    (ts.isIdentifier(expression) && expression.text === "require")
  );
}

function assertGovernedRelativeImport(
  importer,
  specifier,
  governed,
  generated,
) {
  if (
    specifier.includes("\\") ||
    specifier.includes("?") ||
    specifier.includes("#")
  ) {
    throw new Error(
      `${importer} contains an unsafe relative import '${specifier}'`,
    );
  }
  const base = path.posix.normalize(
    path.posix.join(path.posix.dirname(importer), specifier),
  );
  if (base === ".." || base.startsWith("../") || path.posix.isAbsolute(base)) {
    throw new Error(`${importer} imports outside the repository: ${specifier}`);
  }
  const candidates = path.posix.extname(base)
    ? [base]
    : [
        base,
        ...sourceExtensions.map((extension) => `${base}${extension}`),
        ...sourceExtensions.map((extension) => `${base}/index${extension}`),
      ];
  const matches = candidates.filter(
    (candidate) => governed.has(candidate) || generated.has(candidate),
  );
  if (matches.length !== 1) {
    throw new Error(
      `${importer} relative import '${specifier}' must resolve to exactly one governed source or declared build output (matches: ${matches.join(", ") || "none"})`,
    );
  }
}
