import { describe, expect, it } from "vitest";

import {
  deriveAuthenticationAssurance,
  evaluateMfaChallenge,
  evaluateStepUp,
  selectMfaChallengeFactor,
} from "../src/mfa.js";

describe("MFA assurance", () => {
  it("derives single-factor, multi-factor, and phishing-resistant assurance", () => {
    expect(deriveAuthenticationAssurance([])).toEqual({
      level: "unauthenticated",
      authenticatedAtMs: null,
      factorCount: 0,
    });
    expect(
      deriveAuthenticationAssurance([
        { factor: "password", verifiedAtMs: 1_000 },
      ]),
    ).toEqual({
      level: "single-factor",
      authenticatedAtMs: 1_000,
      factorCount: 1,
    });
    expect(
      deriveAuthenticationAssurance([
        { factor: "password", verifiedAtMs: 1_000 },
        { factor: "totp", verifiedAtMs: 1_100 },
      ]),
    ).toEqual({
      level: "multi-factor",
      authenticatedAtMs: 1_000,
      factorCount: 2,
    });
    expect(
      deriveAuthenticationAssurance([
        { factor: "webauthn", verifiedAtMs: 1_200, userVerified: true },
        { factor: "webauthn", verifiedAtMs: 1_300, userVerified: false },
      ]),
    ).toEqual({
      level: "phishing-resistant",
      authenticatedAtMs: 1_200,
      factorCount: 1,
    });
  });

  it("uses the most recent evidence subset and enforces freshness", () => {
    const evidence = [
      { factor: "password", verifiedAtMs: 100 },
      { factor: "password", verifiedAtMs: 900 },
      { factor: "totp", verifiedAtMs: 950 },
      { factor: "sms-otp", verifiedAtMs: 10 },
    ] as const;
    expect(deriveAuthenticationAssurance(evidence).authenticatedAtMs).toBe(900);
    expect(
      evaluateStepUp(evidence, 1_000, {
        minimumLevel: "multi-factor",
        maxAgeMs: 100,
      }),
    ).toMatchObject({ kind: "allow" });
    expect(
      evaluateStepUp(evidence, 1_001, {
        minimumLevel: "multi-factor",
        maxAgeMs: 100,
      }),
    ).toMatchObject({ kind: "challenge", reason: "stale" });
  });

  it("requires configured factors independently of the aggregate level", () => {
    expect(
      evaluateStepUp(
        [
          { factor: "password", verifiedAtMs: 900 },
          { factor: "sms-otp", verifiedAtMs: 950 },
        ],
        1_000,
        {
          minimumLevel: "multi-factor",
          requiredFactors: ["totp"],
        },
      ),
    ).toMatchObject({ kind: "challenge", reason: "required-factor-missing" });
  });
});

describe("MFA challenges", () => {
  it("selects only enrolled factors using application policy order", () => {
    expect(
      selectMfaChallengeFactor(
        ["sms-otp", "totp"],
        ["webauthn", "totp", "sms-otp"],
      ),
    ).toBe("totp");
    expect(selectMfaChallengeFactor(["sms-otp"], ["totp"])).toBeNull();
  });

  it("accepts matching decoded challenge facts", () => {
    expect(
      evaluateMfaChallenge(
        {
          purpose: "login",
          subject: "user-1",
          factor: "totp",
          credentialVersion: 4,
          expiresAtMs: 2_000,
        },
        {
          allowedPurposes: ["login"],
          allowedFactors: ["totp"],
          expectedSubject: "user-1",
          currentCredentialVersion: 4,
          nowMs: 1_999,
        },
      ),
    ).toEqual({ kind: "accept" });
  });

  it.each([
    [{ purpose: null }, "malformed"],
    [{ purpose: "other" }, "purpose-mismatch"],
    [{ factor: "sms-otp" }, "factor-not-allowed"],
    [{ subject: "user-2" }, "subject-mismatch"],
    [{ credentialVersion: 3 }, "credential-version-mismatch"],
    [{ consumedAtMs: 1_500 }, "already-consumed"],
    [{ expiresAtMs: 1_999 }, "expired"],
  ] as const)("rejects %s as %s", (override, reason) => {
    expect(
      evaluateMfaChallenge(
        {
          purpose: "login",
          subject: "user-1",
          factor: "totp",
          credentialVersion: 4,
          expiresAtMs: 2_000,
          ...override,
        },
        {
          allowedPurposes: ["login"],
          allowedFactors: ["totp"],
          expectedSubject: "user-1",
          currentCredentialVersion: 4,
          nowMs: 1_999,
        },
      ),
    ).toEqual({ kind: "reject", reason });
  });
});
