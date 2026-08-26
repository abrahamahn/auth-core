import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  createBackupCodes,
  createTotpSetup,
  createTotpUri,
  formatBackupCode,
  generateTotpCode,
  verifyTotpCode,
  type TotpAlgorithm,
} from '../src/index.js';

interface TotpVectors {
  readonly totp: readonly {
    readonly secretBase32: string;
    readonly timestampMs: number;
    readonly algorithm: TotpAlgorithm;
    readonly digits: number;
    readonly periodSeconds: number;
    readonly code: string;
  }[];
}

const vectors = JSON.parse(
  readFileSync(new URL('../../rust-totp/fixtures/totp-vectors.json', import.meta.url), 'utf8'),
) as TotpVectors;

describe('TOTP provider', () => {
  it('matches the shared RFC 6238 vectors', () => {
    for (const vector of vectors.totp) {
      const config = {
        algorithm: vector.algorithm,
        digits: vector.digits,
        periodSeconds: vector.periodSeconds,
      };
      expect(generateTotpCode(vector.secretBase32, vector.timestampMs, config)).toBe(vector.code);
      expect(
        verifyTotpCode(vector.secretBase32, vector.code, {
          timestampMs: vector.timestampMs,
          config,
        }),
      ).toBe(true);
    }
  });

  it('supports bounded clock drift and rejects malformed codes', () => {
    const vector = vectors.totp[0];
    if (vector === undefined) throw new Error('missing TOTP vector');
    const config = {
      algorithm: vector.algorithm,
      digits: vector.digits,
      periodSeconds: vector.periodSeconds,
    };
    expect(
      verifyTotpCode(vector.secretBase32, vector.code, {
        timestampMs: vector.timestampMs + 30_000,
        window: 1,
        config,
      }),
    ).toBe(true);
    expect(verifyTotpCode(vector.secretBase32, 'not-a-code', { config })).toBe(false);
  });

  it('creates enrollment secrets and canonical otpauth URIs', () => {
    const setup = createTotpSetup({ issuer: 'Example App', label: 'user@example.com' });
    expect(setup.secretBase32).toMatch(/^[A-Z2-7]+=*$/);
    expect(setup.otpauthUrl).toBe(
      createTotpUri(setup.secretBase32, 'Example App', 'user@example.com'),
    );
    expect(setup.otpauthUrl).toContain('otpauth://totp/');
  });

  it('formats caller-supplied secure entropy as one-time recovery codes', () => {
    expect(formatBackupCode(Uint8Array.from([0xab, 0xcd, 0x12, 0x34]))).toBe('ABCD-1234');
    let next = 0;
    expect(
      createBackupCodes(
        (length) => Uint8Array.from({ length }, () => next++),
        { count: 2, bytesPerCode: 4 },
      ),
    ).toEqual(['0001-0203', '0405-0607']);
  });
});
