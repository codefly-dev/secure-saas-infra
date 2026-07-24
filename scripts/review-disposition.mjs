import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { runReadOnlyGit, runReadOnlyGitBytes } from "./safe-git.mjs";

export const REVIEW_DISPOSITION_PATH =
  "security/adversarial-review-disposition.json";
export const REVIEW_DISPOSITION_SCHEMA =
  "schemas/adversarial-review-disposition-v1.schema.json";
export const REVIEW_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1_000;

const expectedReviewers = new Map([
  ["architecture", "seam_architecture_critic"],
  ["security", "seam_security_critic"],
  ["validation", "seam_validation_critic"],
]);

export function validateAdversarialReviewDisposition(
  root,
  {
    requireApproval = true,
    requireFresh = true,
    now = Date.now(),
    trustImmutableQualifiedSource = false,
    expectedParentRevision,
  } = {},
) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const reviewPath = safeSourceFile(repositoryRoot, REVIEW_DISPOSITION_PATH);
  const schemaPath = safeSourceFile(repositoryRoot, REVIEW_DISPOSITION_SCHEMA);
  const disposition = parseJson(readFileSync(reviewPath, "utf8"), reviewPath);
  const schema = parseJson(readFileSync(schemaPath, "utf8"), schemaPath);
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(disposition)) {
    throw new Error(
      `Adversarial review disposition is invalid: ${ajv.errorsText(validate.errors, { separator: "; " })}`,
    );
  }

  const actual = new Map(
    disposition.reviews.map((review) => [review.discipline, review.reviewer]),
  );
  if (
    actual.size !== expectedReviewers.size ||
    [...expectedReviewers].some(
      ([discipline, reviewer]) => actual.get(discipline) !== reviewer,
    )
  ) {
    throw new Error(
      "Adversarial review disposition must contain exactly the architecture, security, and validation reviewers.",
    );
  }

  let treeDigest = disposition.source.treeDigest;
  let revision = disposition.source.revision;
  if (!trustImmutableQualifiedSource) {
    const evidenceRevision = currentRevision(repositoryRoot);
    revision = reviewEvidenceParent(repositoryRoot, evidenceRevision);
    if (
      expectedParentRevision !== undefined &&
      (!/^[a-f0-9]{40}$/.test(expectedParentRevision) ||
        revision !== expectedParentRevision)
    ) {
      throw new Error(
        "Adversarial review evidence is not a direct child of the protected base revision.",
      );
    }
    assertCleanEvidenceCommit(repositoryRoot, revision, evidenceRevision);
    treeDigest = adversarialReviewSourceTreeDigest(repositoryRoot, revision);
  }
  if (
    !/^[a-f0-9]{64}$/.test(treeDigest ?? "") ||
    disposition.source.treeDigest !== treeDigest ||
    !/^[a-f0-9]{40}$/.test(revision ?? "") ||
    disposition.source.revision !== revision
  ) {
    throw new Error(
      "Adversarial review disposition does not bind the exact reviewed parent source tree.",
    );
  }

  const reviewedAt = Date.parse(disposition.reviewedAt);
  if (
    requireFresh &&
    (!Number.isFinite(reviewedAt) ||
      reviewedAt > now + 60_000 ||
      now - reviewedAt > REVIEW_MAX_AGE_MS)
  ) {
    throw new Error(
      "Adversarial review disposition is stale or has a future timestamp.",
    );
  }

  if (
    requireApproval &&
    (disposition.approvedForLocalQualification !== true ||
      disposition.approvedForAwsMutation !== false ||
      disposition.reviews.some((review) => review.localFindings !== "resolved"))
  ) {
    throw new Error(
      "Adversarial review disposition has unresolved local findings.",
    );
  }
  return { disposition, reviewPath, treeDigest };
}

export function adversarialReviewSourceTreeDigest(
  root,
  revision = currentRevision(realpathSync(path.resolve(root))),
) {
  const repositoryRoot = realpathSync(path.resolve(root));
  if (!/^[a-f0-9]{40}$/.test(revision ?? "")) {
    throw new Error(
      "Adversarial review digest requires an exact Git revision.",
    );
  }
  const listed = runReadOnlyGit(repositoryRoot, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    revision,
  ])
    .split("\0")
    .filter(Boolean)
    .map((entry) => parseReviewedTreeEntry(entry))
    .filter((entry) => entry.path !== REVIEW_DISPOSITION_PATH)
    .sort((left, right) => left.path.localeCompare(right.path));
  const paths = new Set();
  const files = listed.map((entry) => {
    if (paths.has(entry.path)) {
      throw new Error(
        "Adversarial review source tree contains duplicate paths.",
      );
    }
    paths.add(entry.path);
    const source = runReadOnlyGitBytes(repositoryRoot, [
      "cat-file",
      "blob",
      entry.object,
    ]);
    return {
      path: entry.path,
      mode: Number.parseInt(entry.mode, 8) & 0o777,
      sha256: sha256(source),
    };
  });
  return sha256(canonicalJson({ revision, files }));
}

function parseReviewedTreeEntry(value) {
  const separator = value.indexOf("\t");
  const metadata = value.slice(0, separator).split(" ");
  const file = value.slice(separator + 1);
  if (
    separator <= 0 ||
    metadata.length !== 3 ||
    metadata[1] !== "blob" ||
    !["100644", "100755"].includes(metadata[0]) ||
    !/^[a-f0-9]{40,64}$/.test(metadata[2]) ||
    file === "" ||
    file.includes("\0")
  ) {
    throw new Error(
      "Adversarial review source tree contains an unsupported Git object or mode.",
    );
  }
  return { mode: metadata[0], object: metadata[2], path: file };
}

function reviewEvidenceParent(root, evidenceRevision) {
  const fields = runReadOnlyGit(root, [
    "rev-list",
    "--parents",
    "-n",
    "1",
    evidenceRevision,
  ])
    .trim()
    .split(/\s+/);
  if (fields.length !== 2 || fields[0] !== evidenceRevision) {
    throw new Error(
      "Adversarial review evidence must be a non-merge child commit.",
    );
  }
  return fields[1];
}

function assertCleanEvidenceCommit(root, parentRevision, evidenceRevision) {
  if (
    runReadOnlyGit(root, [
      "status",
      "--porcelain",
      "--untracked-files=all",
    ]).trim()
  ) {
    throw new Error("Adversarial review evidence requires a clean worktree.");
  }
  const changed = runReadOnlyGit(root, [
    "diff-tree",
    "--no-commit-id",
    "--name-only",
    "-r",
    "-z",
    parentRevision,
    evidenceRevision,
  ])
    .split("\0")
    .filter(Boolean);
  if (changed.length !== 1 || changed[0] !== REVIEW_DISPOSITION_PATH) {
    throw new Error(
      "Adversarial review evidence commit may change only its disposition.",
    );
  }
}

function currentRevision(root) {
  const revision = runReadOnlyGit(root, [
    "rev-parse",
    "--verify",
    "HEAD",
  ]).trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) {
    throw new Error("Adversarial review requires an exact Git revision.");
  }
  return revision;
}

function safeSourceFile(root, value) {
  const candidate = path.resolve(root, value);
  const relative = path.relative(root, candidate);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(`Review source '${value}' escapes the repository.`);
  }
  const stat = lstatSync(candidate);
  const real = realpathSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink() || real !== candidate) {
    throw new Error(`Review source '${value}' is not a safe regular file.`);
  }
  return real;
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`${file} is not valid JSON: ${error.message}`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
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
