import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  classifyRefreshCredential,
  credentialEpochMatches,
  deriveAuthenticationAssurance,
  evaluateAccountLockout,
  evaluateMfaChallenge,
  evaluateOneTimeCredential,
  evaluateSessionBinding,
  isCommonPassword,
  isSessionIdle,
  progressiveDelayMs,
  selectSessionsForEviction,
  sessionIdleRemainingMs,
  sessionIdleWindowMs,
  sessionSpanMs,
  validatePassword,
  type AuthenticationFactor,
  type MfaChallengeDecision,
  type MfaChallengeFactor,
  type OneTimeCredentialDecision,
  type RefreshCredentialDecision,
} from "../src/index.js";

interface ParityVectors {
  readonly passwords: readonly {
    readonly password: string;
    readonly userInputs: string[];
    readonly score: number;
    readonly valid: boolean;
    readonly common: boolean;
  }[];
  readonly refresh: readonly {
    readonly nowMs: number;
    readonly expiresAtMs: number;
    readonly rotatedAtMs: number | null;
    readonly familyRevokedAtMs: number | null;
    readonly gracePeriodMs: number;
    readonly decision: string;
  }[];
  readonly progressiveDelay: readonly {
    readonly failedAttempts: number;
    readonly mostRecentFailureAtMs: number;
    readonly nowMs: number;
    readonly baseDelayMs: number;
    readonly maxDelayMs: number;
    readonly expectedMs: number;
  }[];
  readonly sessionIdle: readonly {
    readonly lastActiveAtMs: number;
    readonly idleTimeoutMs: number;
    readonly nowMs: number;
    readonly idle: boolean;
    readonly remainingMs: number;
  }[];
  readonly sessionBindings: readonly {
    readonly expected: string | null;
    readonly presented: string | null;
    readonly decision: string;
  }[];
  readonly credentialEpochs: readonly {
    readonly observed: number;
    readonly current: number;
    readonly matches: boolean;
  }[];
  readonly sessionLifetimes: readonly {
    readonly remembered: boolean;
    readonly defaultSpanMs: number;
    readonly rememberedSpanMs: number;
    readonly maxIdleMs: number;
    readonly expectedSpanMs: number;
    readonly expectedIdleWindowMs: number;
  }[];
  readonly sessionEviction: {
    readonly maxSessions: number;
    readonly sessions: readonly {
      readonly id: string;
      readonly createdAtMs: number;
    }[];
    readonly expectedIds: readonly string[];
  };
  readonly lockouts: readonly {
    readonly nowMs: number;
    readonly failedAttempts: number;
    readonly mostRecentFailureAtMs: number | null;
    readonly maxAttempts: number;
    readonly lockoutDurationMs: number;
    readonly isLocked: boolean;
    readonly remainingMs: number | null;
    readonly lockedUntilMs: number | null;
  }[];
  readonly oneTimeCredentials: readonly {
    readonly exists: boolean;
    readonly nowMs: number;
    readonly expiresAtMs: number | null;
    readonly consumedAtMs: number | null;
    readonly failedAttempts: number;
    readonly presentedMatches: boolean;
    readonly maxFailedAttempts: number;
    readonly decision: string;
    readonly consume: boolean;
    readonly resultFailedAttempts: number;
  }[];
  readonly mfaAssurance: readonly {
    readonly evidence: readonly {
      readonly factor: AuthenticationFactor;
      readonly verifiedAtMs: number;
      readonly userVerified: boolean;
    }[];
    readonly level: string;
    readonly authenticatedAtMs: number | null;
    readonly factorCount: number;
  }[];
  readonly mfaChallenges: readonly {
    readonly purpose: string | null;
    readonly subject: string | null;
    readonly factor: MfaChallengeFactor | null;
    readonly credentialVersion: number | null;
    readonly expiresAtMs: number | null;
    readonly consumedAtMs: number | null;
    readonly allowedPurposes: readonly string[];
    readonly allowedFactors: readonly MfaChallengeFactor[];
    readonly expectedSubject: string;
    readonly currentCredentialVersion: number;
    readonly nowMs: number;
    readonly decision: string;
  }[];
}

const vectors = JSON.parse(
  readFileSync(
    new URL("../../rust/fixtures/core-vectors.json", import.meta.url),
    "utf8",
  ),
) as ParityVectors;

function refreshDecisionLabel(decision: RefreshCredentialDecision): string {
  if (decision.kind === "revoke-family") return `revoke:${decision.reason}`;
  if (decision.kind === "reject") return `reject:${decision.reason}`;
  return decision.kind;
}

function oneTimeDecisionLabel(decision: OneTimeCredentialDecision): string {
  return decision.kind === "accept" ? "accept" : `reject:${decision.reason}`;
}

function mfaChallengeDecisionLabel(decision: MfaChallengeDecision): string {
  return decision.kind === "accept" ? "accept" : `reject:${decision.reason}`;
}

describe("TypeScript/Rust auth-core parity vectors", () => {
  it("pins password outcomes", () => {
    for (const vector of vectors.passwords) {
      const result = validatePassword(vector.password, vector.userInputs);
      expect(result.score).toBe(vector.score);
      expect(result.isValid).toBe(vector.valid);
      expect(isCommonPassword(vector.password)).toBe(vector.common);
    }
  });

  it("pins refresh, delay, and idle decisions", () => {
    for (const vector of vectors.refresh) {
      expect(refreshDecisionLabel(classifyRefreshCredential(vector))).toBe(
        vector.decision,
      );
    }
    for (const vector of vectors.progressiveDelay) {
      expect(
        progressiveDelayMs(
          vector.failedAttempts,
          vector.mostRecentFailureAtMs,
          vector.nowMs,
          vector.baseDelayMs,
          vector.maxDelayMs,
        ),
      ).toBe(vector.expectedMs);
    }
    for (const vector of vectors.sessionIdle) {
      expect(
        isSessionIdle(
          vector.lastActiveAtMs,
          vector.idleTimeoutMs,
          vector.nowMs,
        ),
      ).toBe(vector.idle);
      expect(
        sessionIdleRemainingMs(
          vector.lastActiveAtMs,
          vector.idleTimeoutMs,
          vector.nowMs,
        ),
      ).toBe(vector.remainingMs);
    }
  });

  it("pins binding, credential epoch, lifetime, eviction, and lockout decisions", () => {
    for (const vector of vectors.sessionBindings) {
      expect(evaluateSessionBinding(vector.expected, vector.presented)).toBe(
        vector.decision,
      );
    }
    for (const vector of vectors.credentialEpochs) {
      expect(credentialEpochMatches(vector.observed, vector.current)).toBe(
        vector.matches,
      );
    }
    for (const vector of vectors.sessionLifetimes) {
      const spanMs = sessionSpanMs(vector.remembered, vector);
      expect(spanMs).toBe(vector.expectedSpanMs);
      expect(sessionIdleWindowMs(spanMs, vector.maxIdleMs)).toBe(
        vector.expectedIdleWindowMs,
      );
    }

    const evicted = selectSessionsForEviction(
      vectors.sessionEviction.sessions,
      vectors.sessionEviction.maxSessions,
      (session) => session.createdAtMs,
    );
    expect(evicted.map((session) => session.id)).toEqual(
      vectors.sessionEviction.expectedIds,
    );

    for (const vector of vectors.lockouts) {
      const decision = evaluateAccountLockout(vector, vector);
      expect(decision.isLocked).toBe(vector.isLocked);
      expect(decision.failedAttempts).toBe(vector.failedAttempts);
      expect(decision.isLocked ? (decision.remainingMs ?? null) : null).toBe(
        vector.remainingMs,
      );
      expect(decision.isLocked ? (decision.lockedUntilMs ?? null) : null).toBe(
        vector.lockedUntilMs,
      );
    }
  });

  it("pins one-time credential decisions", () => {
    for (const vector of vectors.oneTimeCredentials) {
      const decision = evaluateOneTimeCredential(vector, vector);
      expect(oneTimeDecisionLabel(decision)).toBe(vector.decision);
      expect(decision.consume).toBe(vector.consume);
      expect(decision.failedAttempts).toBe(vector.resultFailedAttempts);
    }
  });

  it("pins MFA assurance and challenge decisions", () => {
    for (const vector of vectors.mfaAssurance) {
      expect(deriveAuthenticationAssurance(vector.evidence)).toEqual({
        level: vector.level,
        authenticatedAtMs: vector.authenticatedAtMs,
        factorCount: vector.factorCount,
      });
    }
    for (const vector of vectors.mfaChallenges) {
      const decision = evaluateMfaChallenge(vector, vector);
      expect(mfaChallengeDecisionLabel(decision)).toBe(vector.decision);
    }
  });
});
