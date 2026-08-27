import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  CSRF_TOKEN_BYTES,
  contextualDeviceFingerprint,
  decryptCsrfToken,
  decryptSecret,
  encryptCsrfToken,
  encryptSecret,
  generateBase64UrlToken,
  generateHexToken,
  generateNumericCode,
  generateOpaqueToken,
  generateCsrfToken,
  isSecretEnvelope,
  sha256TokenDigest,
  signCsrfToken,
  stableDeviceFingerprint,
  validateCsrfToken,
  verifySignedCsrfToken,
} from "../src/index.js";

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
  readonly csrf: {
    readonly token: string;
    readonly secret: string;
    readonly signedToken: string;
    readonly encryptedToken: string;
  };
}

const vectors = JSON.parse(
  readFileSync(
    new URL("../../rust-crypto/fixtures/crypto-vectors.json", import.meta.url),
    "utf8",
  ),
) as CryptoVectors;

describe("opaque credentials", () => {
  it("matches cross-language SHA-256 digest vectors", () => {
    for (const vector of vectors.tokenDigests) {
      expect(sha256TokenDigest(vector.input)).toBe(vector.digest);
    }
  });

  it("generates correctly encoded high-entropy tokens and uniform numeric code shapes", () => {
    expect(generateHexToken(32)).toMatch(/^[a-f0-9]{64}$/);
    expect(generateBase64UrlToken(32)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const generated = generateOpaqueToken();
    expect(generated.digest).toBe(sha256TokenDigest(generated.plain));
    for (const digits of [4, 6, 8])
      expect(generateNumericCode(digits)).toMatch(/^\d+$/);
  });
});

describe("authenticated secret envelopes", () => {
  it("decrypts the shared cross-language envelope", () => {
    expect(
      decryptSecret(
        vectors.secretEnvelope.envelope,
        vectors.secretEnvelope.encryptionKey,
      ),
    ).toBe(vectors.secretEnvelope.plaintext);
  });

  it("round-trips with randomized salt and IV and authenticates the ciphertext", () => {
    const first = encryptSecret(
      vectors.secretEnvelope.plaintext,
      vectors.secretEnvelope.encryptionKey,
    );
    const second = encryptSecret(
      vectors.secretEnvelope.plaintext,
      vectors.secretEnvelope.encryptionKey,
    );
    expect(first).not.toBe(second);
    expect(isSecretEnvelope(first)).toBe(true);
    expect(isSecretEnvelope(vectors.secretEnvelope.plaintext)).toBe(false);
    expect(decryptSecret(first, vectors.secretEnvelope.encryptionKey)).toBe(
      vectors.secretEnvelope.plaintext,
    );
    expect(() => decryptSecret(first, "wrong-key")).toThrow();
    expect(() =>
      decryptSecret(`${first}:extra`, vectors.secretEnvelope.encryptionKey),
    ).toThrow("Invalid encrypted secret format");
  });
});

describe("device fingerprints", () => {
  it("matches domain-separated cross-language vectors", () => {
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

describe("CSRF token protection", () => {
  it("matches the shared signing and encrypted-envelope vectors", () => {
    expect(signCsrfToken(vectors.csrf.token, vectors.csrf.secret)).toBe(
      vectors.csrf.signedToken,
    );
    expect(
      verifySignedCsrfToken(vectors.csrf.signedToken, vectors.csrf.secret),
    ).toEqual({
      valid: true,
      token: vectors.csrf.token,
    });
    expect(
      decryptCsrfToken(vectors.csrf.encryptedToken, vectors.csrf.secret),
    ).toBe(vectors.csrf.signedToken);
  });

  it("round-trips encrypted and signed double-submit tokens", () => {
    const token = generateCsrfToken();
    expect(Buffer.from(token, "base64url")).toHaveLength(CSRF_TOKEN_BYTES);
    const cookie = encryptCsrfToken(
      signCsrfToken(token, vectors.csrf.secret),
      vectors.csrf.secret,
    );
    expect(
      validateCsrfToken(cookie, token, {
        secret: vectors.csrf.secret,
        encrypted: true,
        signed: true,
      }),
    ).toBe(true);
    expect(
      validateCsrfToken(cookie, `${token}x`, {
        secret: vectors.csrf.secret,
        encrypted: true,
        signed: true,
      }),
    ).toBe(false);
  });

  it("rejects malformed, tampered, and misconfigured inputs", () => {
    expect(verifySignedCsrfToken("unsigned", vectors.csrf.secret)).toEqual({
      valid: false,
      token: null,
    });
    expect(
      decryptCsrfToken(`${vectors.csrf.encryptedToken}x`, vectors.csrf.secret),
    ).toBeNull();
    expect(
      validateCsrfToken(undefined, vectors.csrf.token, {
        secret: vectors.csrf.secret,
      }),
    ).toBe(false);
    expect(() => signCsrfToken(vectors.csrf.token, "")).toThrow(
      "secret must not be empty",
    );
  });
});
