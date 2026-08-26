import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { sign, verify } from '../src/index.js';

interface JwtVectors {
  readonly hs256: {
    readonly secret: string;
    readonly token: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
    readonly payload: {
      readonly sub: string;
      readonly scope: readonly string[];
    };
  };
}

const vectors = JSON.parse(
  readFileSync(new URL('../fixtures/jwt-vectors.json', import.meta.url), 'utf8'),
) as JwtVectors;

describe('cross-language HS256 vector', () => {
  it('reproduces and verifies the token consumed by the Rust adapter', () => {
    const vector = vectors.hs256;
    const token = sign(vector.payload, vector.secret, {
      expiresIn: vector.expiresAt - vector.issuedAt,
      issuedAtSeconds: vector.issuedAt,
    });

    expect(token).toBe(vector.token);
    expect(
      verify(token, vector.secret, { currentTimeSeconds: vector.issuedAt }),
    ).toMatchObject(vector.payload);
  });
});
