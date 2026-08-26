import { describe, expect, it } from 'vitest';

import {
  DEFAULT_ARGON2_CONFIG,
  DummyHashPool,
  hashPassword,
  needsRehash,
  verifyPassword,
} from '../src/index.js';

const FAST_TEST_CONFIG = {
  type: 2 as const,
  memoryCost: 1_024,
  timeCost: 2,
  parallelism: 1,
};

describe('Argon2 password adapter', () => {
  it('hashes and verifies passwords using self-describing PHC strings', async () => {
    const hash = await hashPassword('correct horse battery staple', FAST_TEST_CONFIG);

    expect(hash).toMatch(/^\$argon2id\$v=19\$m=1024,t=2,p=1\$/);
    await expect(verifyPassword('correct horse battery staple', hash)).resolves.toBe(true);
    await expect(verifyPassword('wrong password', hash)).resolves.toBe(false);
  });

  it('treats malformed and non-Argon2 hashes as invalid and stale', async () => {
    await expect(verifyPassword('password', 'not-a-phc-string')).resolves.toBe(false);
    expect(needsRehash('not-a-phc-string', FAST_TEST_CONFIG)).toBe(true);
    expect(needsRehash('$argon2id$invalid', FAST_TEST_CONFIG)).toBe(true);
  });

  it('detects parameter upgrades without knowing the password', async () => {
    const hash = await hashPassword('upgrade me', FAST_TEST_CONFIG);

    expect(needsRehash(hash, FAST_TEST_CONFIG)).toBe(false);
    expect(needsRehash(hash, { ...FAST_TEST_CONFIG, memoryCost: 2_048 })).toBe(true);
  });

  it('rejects invalid resource parameters before hashing', async () => {
    await expect(
      hashPassword('password', { ...DEFAULT_ARGON2_CONFIG, memoryCost: 0 }),
    ).rejects.toThrow('memoryCost must be a positive integer');
  });
});

describe('DummyHashPool', () => {
  it('deduplicates concurrent initialization and verifies known and unknown accounts', async () => {
    const pool = new DummyHashPool({ config: FAST_TEST_CONFIG, size: 2 });
    await Promise.all([pool.initialize(), pool.initialize(), pool.initialize()]);
    expect(pool.isInitialized()).toBe(true);

    const knownHash = await hashPassword('known password', FAST_TEST_CONFIG);
    await expect(pool.verify('known password', knownHash)).resolves.toBe(true);
    await expect(pool.verify('wrong password', knownHash)).resolves.toBe(false);
    await expect(pool.verify('any password', null)).resolves.toBe(false);

    pool.reset();
    expect(pool.isInitialized()).toBe(false);
    await expect(pool.verify('any password', undefined)).resolves.toBe(false);
  });
});
