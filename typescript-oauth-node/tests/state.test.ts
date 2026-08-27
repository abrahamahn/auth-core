import { describe, expect, it } from "vitest";

import {
  createOAuthStateManager,
  createPkcePair,
  OAuthStateError,
} from "../src/index.js";

describe("OAuth state manager", () => {
  it("owns generic protected state without knowing application payload fields", () => {
    let now = 1_700_000_000_000;
    const manager = createOAuthStateManager<{ readonly linking: boolean }>({
      maxAgeMs: 10_000,
      nowMs: () => now,
      nonce: () => "nonce-123",
      protect: (plaintext) => Buffer.from(plaintext).toString("base64url"),
      unprotect: (protectedState) =>
        Buffer.from(protectedState, "base64url").toString("utf8"),
      parsePayload(value) {
        if (value === null || typeof value !== "object" || Array.isArray(value))
          throw new Error();
        const linking = (value as Record<string, unknown>)["linking"];
        if (typeof linking !== "boolean") throw new Error();
        return { linking };
      },
    });

    const state = manager.create("google", "https://app.example/callback", {
      linking: true,
    });
    expect(manager.decode(manager.encode(state))).toEqual(state);

    now += 10_001;
    expectStateError(
      () => manager.decode(manager.encode(state)),
      "EXPIRED_STATE",
    );
  });

  it("rejects malformed and unprotected state with stable failure categories", () => {
    const manager = createOAuthStateManager({
      maxAgeMs: 1_000,
      nowMs: () => 100,
      protect: (value) => value,
      unprotect: (value) => value,
    });

    expectStateError(
      () => manager.decode('{"provider":"google"}'),
      "MALFORMED_STATE",
    );
    expectStateError(() => manager.decode("not-json"), "PROTECTION_FAILED");
  });
});

describe("PKCE", () => {
  it("generates the RFC 7636 S256 challenge from a verifier", () => {
    const pair = createPkcePair(() => Buffer.alloc(32, 7));

    expect(pair.verifier).toHaveLength(43);
    expect(pair.challenge).toBe("3Ev4DHdHPRMPoN6GukAY_pi7IUAF5qWJHRK6kURvnoE");
    expect(pair.method).toBe("S256");
  });
});

function expectStateError(
  operation: () => unknown,
  code: OAuthStateError["code"],
): void {
  try {
    operation();
    throw new Error("Expected operation to throw");
  } catch (error) {
    expect(error).toBeInstanceOf(OAuthStateError);
    expect((error as OAuthStateError).code).toBe(code);
  }
}
