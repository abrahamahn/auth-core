import { describe, expect, it } from 'vitest';

import { evaluateOneTimeCredential } from '../src/index.js';

const activeCredential = {
  exists: true,
  nowMs: 10_000,
  expiresAtMs: 20_000,
  consumedAtMs: null,
  failedAttempts: 0,
};

describe('one-time credential decisions', () => {
  it('accepts a matching active credential and requires atomic consumption', () => {
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, presentedMatches: true },
        { maxFailedAttempts: 3 },
      ),
    ).toEqual({ kind: 'accept', consume: true, failedAttempts: 0 });
  });

  it('increments mismatches and consumes the credential at the attempt threshold', () => {
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, failedAttempts: 1, presentedMatches: false },
        { maxFailedAttempts: 3 },
      ),
    ).toEqual({ kind: 'reject', reason: 'mismatch', consume: false, failedAttempts: 2 });
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, failedAttempts: 2, presentedMatches: false },
        { maxFailedAttempts: 3 },
      ),
    ).toEqual({
      kind: 'reject',
      reason: 'attempts-exhausted',
      consume: true,
      failedAttempts: 3,
    });
  });

  it('classifies missing, consumed, and expired credentials without exposing details', () => {
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, exists: false, expiresAtMs: null, presentedMatches: false },
        { maxFailedAttempts: 3 },
      ),
    ).toMatchObject({ kind: 'reject', reason: 'not-found', consume: false });
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, consumedAtMs: 9_000, presentedMatches: true },
        { maxFailedAttempts: 3 },
      ),
    ).toMatchObject({ kind: 'reject', reason: 'already-consumed', consume: false });
    expect(
      evaluateOneTimeCredential(
        { ...activeCredential, nowMs: 20_000, presentedMatches: true },
        { maxFailedAttempts: 3 },
      ),
    ).toMatchObject({ kind: 'reject', reason: 'expired', consume: false });
  });

  it('rejects invalid policy and persisted facts', () => {
    expect(() =>
      evaluateOneTimeCredential(
        { ...activeCredential, presentedMatches: true },
        { maxFailedAttempts: 0 },
      ),
    ).toThrow(RangeError);
    expect(() =>
      evaluateOneTimeCredential(
        { ...activeCredential, expiresAtMs: null, presentedMatches: true },
        { maxFailedAttempts: 3 },
      ),
    ).toThrow(RangeError);
  });
});
