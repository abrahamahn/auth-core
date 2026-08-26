import { describe, expect, it } from 'vitest';

import {
  evaluateAccountLockout,
  isLockoutThresholdReached,
  progressiveDelayMs,
} from '../src/index.js';

describe('account lockout decisions', () => {
  it('evaluates thresholds and deterministic unlock timing', () => {
    expect(isLockoutThresholdReached(4, 5)).toBe(false);
    expect(
      evaluateAccountLockout(
        { nowMs: 10_000, failedAttempts: 5, mostRecentFailureAtMs: 9_000 },
        { maxAttempts: 5, lockoutDurationMs: 5_000 },
      ),
    ).toEqual({
      isLocked: true,
      failedAttempts: 5,
      remainingMs: 4_000,
      lockedUntilMs: 14_000,
    });
  });

  it('caps progressive delay and subtracts time already served', () => {
    expect(progressiveDelayMs(4, 9_500, 10_000, 1_000, 5_000)).toBe(4_500);
    expect(progressiveDelayMs(1, 8_000, 10_000, 1_000, 5_000)).toBe(0);
    expect(progressiveDelayMs(0, null, 10_000, 1_000, 5_000)).toBe(0);
    expect(progressiveDelayMs(4, 10_500, 10_000, 1_000, 5_000)).toBe(5_000);
  });

  it('unlocks at the deadline and rejects invalid policy values', () => {
    expect(
      evaluateAccountLockout(
        { nowMs: 14_000, failedAttempts: 5, mostRecentFailureAtMs: 9_000 },
        { maxAttempts: 5, lockoutDurationMs: 5_000 },
      ),
    ).toEqual({ isLocked: false, failedAttempts: 5 });
    expect(() => isLockoutThresholdReached(1, 0)).toThrow(RangeError);
    expect(() => progressiveDelayMs(1, 10_000, 10_000, 2_000, 1_000)).toThrow(RangeError);
  });
});
