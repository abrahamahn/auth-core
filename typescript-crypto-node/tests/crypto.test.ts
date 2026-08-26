import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  contextualDeviceFingerprint,
  decryptSecret,
  encryptSecret,
  generateBase64UrlToken,
  generateHexToken,
  generateNumericCode,
  generateOpaqueToken,
  sha256TokenDigest,
  stableDeviceFingerprint,
} from '../src/index.js';

interface CryptoVectors {
  readonly tokenDigests: readonly {
    readonly input: string;
    readonly digest: string;
  }[];
  readonly fingerprints: {
    readonly deviceId: string;
    readonly stable: string;
    readonly identity: string;
    readonly userAgent: string;
    readonly contextual: string;
  };
  readonly secretEnvelope: {
    readonly plaintext: string;
    readonly encryptionKey: string;
    readonly envelope: string;
  };
}

const vectors = JSON.parse(
  readFileSync(new URL('../../rust-crypto/fixtures/crypto-vectors.json', import.meta.url), 'utf8'),
) as CryptoVectors;

describe('opaque credentials', () => {
  it('matches cross-language SHA-256 digest vectors', () => {
    for (const vector of vectors.tokenDigests) {
      expect(sha256TokenDigest(vector.input)).toBe(vector.digest);
    }
  });

  it('generates correctly encoded high-entropy tokens and uniform numeric code shapes', () => {
    expect(generateHexToken(32)).toMatch(/^[a-f0-9]{64}$/);
    expect(generateBase64UrlToken(32)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const generated = generateOpaqueToken();
    expect(generated.digest).toBe(sha256TokenDigest(generated.plain));
    for (const digits of [4, 6, 8]) expect(generateNumericCode(digits)).toMatch(/^\d+$/);
  });
});

describe('authenticated secret envelopes', () => {
  it('decrypts the shared cross-language envelope', () => {
    expect(
      decryptSecret(vectors.secretEnvelope.envelope, vectors.secretEnvelope.encryptionKey),
    ).toBe(vectors.secretEnvelope.plaintext);
  });

  it('round-trips with randomized salt and IV and authenticates the ciphertext', () => {
    const first = encryptSecret(
      vectors.secretEnvelope.plaintext,
      vectors.secretEnvelope.encryptionKey,
    );
    const second = encryptSecret(
      vectors.secretEnvelope.plaintext,
      vectors.secretEnvelope.encryptionKey,
    );
    expect(first).not.toBe(second);
    expect(decryptSecret(first, vectors.secretEnvelope.encryptionKey)).toBe(
      vectors.secretEnvelope.plaintext,
    );
    expect(() => decryptSecret(first, 'wrong-key')).toThrow();
    expect(() => decryptSecret(`${first}:extra`, vectors.secretEnvelope.encryptionKey)).toThrow(
      'Invalid encrypted secret format',
    );
  });
});

describe('device fingerprints', () => {
  it('matches domain-separated cross-language vectors', () => {
    expect(stableDeviceFingerprint(vectors.fingerprints.deviceId)).toBe(
      vectors.fingerprints.stable,
    );
    expect(
      contextualDeviceFingerprint(
        vectors.fingerprints.identity,
        vectors.fingerprints.userAgent,
      ),
    ).toBe(vectors.fingerprints.contextual);
  });
});
