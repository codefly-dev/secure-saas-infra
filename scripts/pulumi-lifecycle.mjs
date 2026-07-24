export function runAttestedPulumiLifecycle({
  afterLabel,
  attest,
  beforeLabel,
  closePlan,
  invoke,
  reviewedPlan,
}) {
  let invoked = false;
  try {
    attest(beforeLabel);
    invoked = true;
    return invoke();
  } finally {
    try {
      if (invoked) attest(afterLabel);
    } finally {
      if (reviewedPlan) closePlan(reviewedPlan);
    }
  }
}

export function retryExactAttestation(
  attest,
  {
    attempts = 12,
    delayMs = 1_000,
    label = "exact attestation",
    sleep = blockingDelay,
  } = {},
) {
  if (
    typeof attest !== "function" ||
    typeof sleep !== "function" ||
    !Number.isSafeInteger(attempts) ||
    attempts < 1 ||
    attempts > 60 ||
    !Number.isSafeInteger(delayMs) ||
    delayMs < 0 ||
    delayMs > 60_000 ||
    typeof label !== "string" ||
    label.length === 0
  ) {
    throw new Error("exact attestation retry configuration is invalid");
  }
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return attest();
    } catch (error) {
      lastError = error;
      if (attempt < attempts && delayMs > 0) sleep(delayMs);
    }
  }
  throw new Error(
    `${label} did not converge after ${attempts} attempts: ${lastError?.message ?? "unknown attestation failure"}`,
  );
}

function blockingDelay(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}
