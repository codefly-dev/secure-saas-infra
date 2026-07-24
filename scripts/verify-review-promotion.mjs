#!/usr/bin/env node

import process from "node:process";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";

try {
  const releaseMode =
    process.argv.length === 3 && process.argv[2] === "--release";
  if (!releaseMode && process.argv.length !== 2) {
    throw new Error("Usage: verify-review-promotion.mjs [--release]");
  }
  const expectedParentRevision = process.env.DEUS_REVIEW_BASE_REVISION;
  if (!releaseMode && !/^[a-f0-9]{40}$/.test(expectedParentRevision ?? "")) {
    throw new Error(
      "DEUS_REVIEW_BASE_REVISION must be the exact protected base revision.",
    );
  }
  const result = validateAdversarialReviewDisposition(process.cwd(), {
    ...(releaseMode ? {} : { expectedParentRevision }),
  });
  process.stdout.write(
    `${releaseMode ? "Release" : "Review promotion"} directly follows reviewed revision ${result.disposition.source.revision}.\n`,
  );
} catch (error) {
  process.stderr.write(`REVIEW_PROMOTION_DENIED: ${error.message}\n`);
  process.exit(1);
}
