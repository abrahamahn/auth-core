export interface AccountLockoutFacts {
  readonly nowMs: number;
  readonly failedAttempts: number;
  readonly mostRecentFailureAtMs?: number | null;
}

export interface AccountLockoutPolicy {
  readonly maxAttempts: number;
  readonly lockoutDurationMs: number;
}

export type AccountLockoutDecision =
  | {
      readonly isLocked: false;
      readonly failedAttempts: number;
    }
  | {
      readonly isLocked: true;
      readonly failedAttempts: number;
      readonly remainingMs?: number;
      readonly lockedUntilMs?: number;
    };

function requireFinite(value: number, label: string): void {
  if (!Number.isFinite(value)) throw new RangeError(`${label} must be finite`);
}

function requireNonNegative(value: number, label: string): void {
  requireFinite(value, label);
  if (value < 0) throw new RangeError(`${label} must not be negative`);
}

function requireAttemptCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer`);
  }
}

export function isLockoutThresholdReached(failedAttempts: number, maxAttempts: number): boolean {
  requireAttemptCount(failedAttempts, 'failedAttempts');
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts <= 0) {
    throw new RangeError('maxAttempts must be a positive safe integer');
  }
  return failedAttempts >= maxAttempts;
}

export function progressiveDelayMs(
  failedAttempts: number,
  mostRecentFailureAtMs: number | null,
  nowMs: number,
  baseDelayMs: number,
  maxDelayMs: number,
): number {
  requireAttemptCount(failedAttempts, 'failedAttempts');
  requireFinite(nowMs, 'nowMs');
  requireNonNegative(baseDelayMs, 'baseDelayMs');
  requireNonNegative(maxDelayMs, 'maxDelayMs');
  if (maxDelayMs < baseDelayMs) {
    throw new RangeError('maxDelayMs must be at least baseDelayMs');
  }
  if (failedAttempts === 0 || mostRecentFailureAtMs === null || baseDelayMs === 0) return 0;
  requireFinite(mostRecentFailureAtMs, 'mostRecentFailureAtMs');
  const fullDelay = Math.min(baseDelayMs * 2 ** (failedAttempts - 1), maxDelayMs);
  const elapsedMs = Math.max(0, nowMs - mostRecentFailureAtMs);
  return Math.max(0, fullDelay - elapsedMs);
}

export function evaluateAccountLockout(
  facts: AccountLockoutFacts,
  policy: AccountLockoutPolicy,
): AccountLockoutDecision {
  requireFinite(facts.nowMs, 'nowMs');
  requireNonNegative(policy.lockoutDurationMs, 'lockoutDurationMs');
  const isLocked = isLockoutThresholdReached(facts.failedAttempts, policy.maxAttempts);
  if (!isLocked) return { isLocked: false, failedAttempts: facts.failedAttempts };
  if (facts.mostRecentFailureAtMs == null) {
    return { isLocked: true, failedAttempts: facts.failedAttempts };
  }
  requireFinite(facts.mostRecentFailureAtMs, 'mostRecentFailureAtMs');
  const lockedUntilMs = facts.mostRecentFailureAtMs + policy.lockoutDurationMs;
  if (lockedUntilMs <= facts.nowMs) {
    return { isLocked: false, failedAttempts: facts.failedAttempts };
  }
  return {
    isLocked: true,
    failedAttempts: facts.failedAttempts,
    remainingMs: lockedUntilMs - facts.nowMs,
    lockedUntilMs,
  };
}
