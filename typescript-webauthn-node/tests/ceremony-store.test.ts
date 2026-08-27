import { describe, expect, it } from 'vitest';

import { AuthWebAuthnError, InMemoryWebAuthnCeremonyStore } from '../src/index.js';

describe('InMemoryWebAuthnCeremonyStore', () => {
  it('consumes a ceremony exactly once', () => {
    let nowMs = 1_000;
    const store = new InMemoryWebAuthnCeremonyStore({ ttlMs: 500, now: () => nowMs });
    store.put('reg:user-1', {
      kind: 'registration',
      challenge: 'challenge-a',
      subjectId: 'user-1',
    });

    expect(store.consume('reg:user-1', 'registration')).toEqual({
      kind: 'registration',
      challenge: 'challenge-a',
      subjectId: 'user-1',
      expiresAtMs: 1_500,
    });
    expect(() => store.consume('reg:user-1', 'registration')).toThrow(AuthWebAuthnError);
    nowMs = 2_000;
  });

  it('deletes expired and mismatched ceremonies before returning an error', () => {
    let nowMs = 1_000;
    const store = new InMemoryWebAuthnCeremonyStore({ ttlMs: 500, now: () => nowMs });
    store.put('auth:one', { kind: 'authentication', challenge: 'challenge-a' });
    expect(() => store.consume('auth:one', 'registration')).toThrow(/kind does not match/u);
    expect(store.size).toBe(0);

    store.put('auth:two', { kind: 'authentication', challenge: 'challenge-b' });
    nowMs = 1_500;
    expect(() => store.consume('auth:two', 'authentication')).toThrow(/expired/u);
    expect(store.size).toBe(0);
  });
});
