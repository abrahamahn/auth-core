import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { needsRehash, verifyPassword } from '../src/index.js';

interface PasswordVectors {
  readonly argon2id: {
    readonly password: string;
    readonly phc: string;
    readonly config: {
      readonly type: 2;
      readonly memoryCost: number;
      readonly timeCost: number;
      readonly parallelism: number;
    };
  };
}

const vectors = JSON.parse(
  readFileSync(new URL('../fixtures/password-vectors.json', import.meta.url), 'utf8'),
) as PasswordVectors;

describe('cross-language password vector', () => {
  it('verifies the same Argon2id PHC string as the Rust adapter', async () => {
    await expect(verifyPassword(vectors.argon2id.password, vectors.argon2id.phc)).resolves.toBe(
      true,
    );
    expect(needsRehash(vectors.argon2id.phc, vectors.argon2id.config)).toBe(false);
  });
});
