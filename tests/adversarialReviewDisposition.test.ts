import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

test("adversarial review is a clean evidence-only child of the reviewed commit", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { execFileSync } from "node:child_process";
    import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
    import { tmpdir } from "node:os";
    import path from "node:path";
    import {
      adversarialReviewSourceTreeDigest,
      validateAdversarialReviewDisposition,
    } from "./scripts/review-disposition.mjs";
    const root = mkdtempSync(path.join(tmpdir(), "review-digest-"));
    process.env.HOME = root;
    process.env.GIT_CONFIG_GLOBAL = "/dev/null";
    process.env.GIT_CONFIG_SYSTEM = "/dev/null";
    process.env.GIT_CONFIG_NOSYSTEM = "1";
    mkdirSync(path.join(root, "schemas"));
    mkdirSync(path.join(root, "security"));
    copyFileSync(
      "schemas/adversarial-review-disposition-v1.schema.json",
      path.join(root, "schemas/adversarial-review-disposition-v1.schema.json"),
    );
    writeFileSync(path.join(root, "source.txt"), "reviewed");
    writeFileSync(path.join(root, "security", "adversarial-review-disposition.json"), "pending\n");
    const git = (...args) => execFileSync("git", args, {
      cwd: root,
      env: {
        HOME: root,
        LANG: "C",
        PATH: process.env.PATH,
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
    });
    git("init", "-q");
    git("config", "user.email", "review@example.invalid");
    git("config", "user.name", "Review Test");
    git("add", ".");
    git("-c", "commit.gpgsign=false", "commit", "-qm", "reviewed source");
    const reviewedRevision = git("rev-parse", "HEAD").toString().trim();
    const reviewedDigest = adversarialReviewSourceTreeDigest(root);
    const review = {
      apiVersion: "security.deus.dev/adversarial-review-disposition/v1alpha1",
      reviewedAt: new Date().toISOString(),
      source: { revision: reviewedRevision, treeDigest: reviewedDigest },
      approvedForLocalQualification: true,
      approvedForAwsMutation: false,
      reviews: [
        { discipline: "architecture", reviewer: "seam_architecture_critic", reviewMode: "read-only", identityAssurance: "process-label-only", localFindings: "resolved", findingSummary: "fixture", awsBoundary: "No AWS authorization." },
        { discipline: "security", reviewer: "seam_security_critic", reviewMode: "read-only", identityAssurance: "process-label-only", localFindings: "resolved", findingSummary: "fixture", awsBoundary: "No AWS authorization." },
        { discipline: "validation", reviewer: "seam_validation_critic", reviewMode: "read-only", identityAssurance: "process-label-only", localFindings: "resolved", findingSummary: "fixture", awsBoundary: "No AWS authorization." },
      ],
    };
    writeFileSync(
      path.join(root, "security", "adversarial-review-disposition.json"),
      JSON.stringify(review, null, 2) + "\n",
    );
    git("add", "security/adversarial-review-disposition.json");
    git("-c", "commit.gpgsign=false", "commit", "-qm", "review evidence only");
    const validated = validateAdversarialReviewDisposition(root, { requireFresh: false });
    assert.equal(validated.treeDigest, reviewedDigest);
    assert.equal(validated.disposition.source.revision, reviewedRevision);
    assert.doesNotThrow(() =>
      validateAdversarialReviewDisposition(root, {
        requireFresh: false,
        expectedParentRevision: reviewedRevision,
      }),
    );
    assert.throws(
      () =>
        validateAdversarialReviewDisposition(root, {
          requireFresh: false,
          expectedParentRevision: "0".repeat(40),
        }),
      /protected base revision/,
    );
    const evidenceRevision = git("rev-parse", "HEAD").toString().trim();
    const evidenceBranch = git("symbolic-ref", "--short", "HEAD").toString().trim();
    writeFileSync(path.join(root, "extra.txt"), "not review evidence");
    git("add", "extra.txt");
    git("-c", "commit.gpgsign=false", "commit", "-qm", "extra evidence file");
    assert.throws(
      () => validateAdversarialReviewDisposition(root, { requireFresh: false }),
      /only its disposition/,
    );
    git("reset", "--hard", evidenceRevision);
    git("checkout", "-qb", "hostile-merge");
    writeFileSync(path.join(root, "side.txt"), "merge input");
    git("add", "side.txt");
    git("-c", "commit.gpgsign=false", "commit", "-qm", "side input");
    git("checkout", "-q", evidenceBranch);
    git("-c", "commit.gpgsign=false", "merge", "--no-gpg-sign", "--no-ff", "hostile-merge", "-qm", "merge evidence");
    assert.throws(
      () => validateAdversarialReviewDisposition(root, { requireFresh: false }),
      /non-merge child commit/,
    );
    git("reset", "--hard", evidenceRevision);
    writeFileSync(path.join(root, "source.txt"), "changed");
    assert.throws(
      () => validateAdversarialReviewDisposition(root, { requireFresh: false }),
      /clean worktree/,
    );
    writeFileSync(path.join(root, "source.txt"), "reviewed");
    chmodSync(path.join(root, "source.txt"), 0o755);
    assert.throws(
      () => validateAdversarialReviewDisposition(root, { requireFresh: false }),
      /clean worktree/,
    );
    rmSync(root, { recursive: true, force: true });
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        HOME: process.cwd(),
        LANG: "C",
        PATH: process.env.PATH ?? "",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
      },
    },
  );
  assert.equal(result.status, 0, result.stderr);
});
