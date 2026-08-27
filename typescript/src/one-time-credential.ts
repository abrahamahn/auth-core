export interface OneTimeCredentialFacts {
  readonly exists: boolean;
  readonly nowMs: number;
  readonly expiresAtMs?: number | null;
  readonly consumedAtMs?: number | null;
  readonly failedAttempts: number;
  readonly presentedMatches: boolean;
}

export interface OneTimeCredentialPolicy {
  readonly maxFailedAttempts: number;
}

export type OneTimeCredentialRejectionReason =
  | "not-found"
  | "already-consumed"
  | "expired"
  | "mismatch"
  | "attempts-exhausted";

export type OneTimeCredentialDecision =
  | {
      readonly kind: "accept";
      readonly consume: true;
      readonly failedAttempts: number;
    }
  | {
      readonly kind: "reject";
      readonly reason: OneTimeCredentialRejectionReason;
      readonly consume: boolean;
      readonly failedAttempts: number;
    };

function requireTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value)) {
    throw new RangeError(`${label} must be a safe integer timestamp`);
  }
}

function requireAttemptCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer`);
  }
}

/**
 * Evaluates a single-use credential without performing persistence or comparison itself.
 *
 * Callers are responsible for constant-time verification where applicable and for applying the
 * returned attempt/consumption mutation atomically.
 */
export function evaluateOneTimeCredential(
  facts: OneTimeCredentialFacts,
  policy: OneTimeCredentialPolicy,
): OneTimeCredentialDecision {
  requireTimestamp(facts.nowMs, "nowMs");
  requireAttemptCount(facts.failedAttempts, "failedAttempts");
  if (
    !Number.isSafeInteger(policy.maxFailedAttempts) ||
    policy.maxFailedAttempts <= 0
  ) {
    throw new RangeError("maxFailedAttempts must be a positive safe integer");
  }

  if (!facts.exists) {
    return {
      kind: "reject",
      reason: "not-found",
      consume: false,
      failedAttempts: facts.failedAttempts,
    };
  }

  if (facts.expiresAtMs == null) {
    throw new RangeError("expiresAtMs is required for an existing credential");
  }
  requireTimestamp(facts.expiresAtMs, "expiresAtMs");
  if (facts.consumedAtMs != null)
    requireTimestamp(facts.consumedAtMs, "consumedAtMs");

  if (facts.consumedAtMs != null) {
    return {
      kind: "reject",
      reason: "already-consumed",
      consume: false,
      failedAttempts: facts.failedAttempts,
    };
  }
  if (facts.nowMs >= facts.expiresAtMs) {
    return {
      kind: "reject",
      reason: "expired",
      consume: false,
      failedAttempts: facts.failedAttempts,
    };
  }
  if (facts.failedAttempts >= policy.maxFailedAttempts) {
    return {
      kind: "reject",
      reason: "attempts-exhausted",
      consume: true,
      failedAttempts: facts.failedAttempts,
    };
  }
  if (facts.presentedMatches) {
    return {
      kind: "accept",
      consume: true,
      failedAttempts: facts.failedAttempts,
    };
  }

  const failedAttempts = facts.failedAttempts + 1;
  return {
    kind: "reject",
    reason:
      failedAttempts >= policy.maxFailedAttempts
        ? "attempts-exhausted"
        : "mismatch",
    consume: failedAttempts >= policy.maxFailedAttempts,
    failedAttempts,
  };
}
