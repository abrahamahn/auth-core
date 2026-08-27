export const AUTHENTICATION_FACTORS = [
  'password',
  'magic-link',
  'email-otp',
  'sms-otp',
  'totp',
  'recovery-code',
  'oauth',
  'webauthn',
] as const;

export type AuthenticationFactor = (typeof AUTHENTICATION_FACTORS)[number];

export const MFA_CHALLENGE_FACTORS = [
  'email-otp',
  'sms-otp',
  'totp',
  'recovery-code',
  'webauthn',
] as const satisfies readonly AuthenticationFactor[];

export type MfaChallengeFactor = (typeof MFA_CHALLENGE_FACTORS)[number];

export const AUTHENTICATION_ASSURANCE_LEVELS = [
  'unauthenticated',
  'single-factor',
  'multi-factor',
  'phishing-resistant',
] as const;

export type AuthenticationAssuranceLevel = (typeof AUTHENTICATION_ASSURANCE_LEVELS)[number];

export interface AuthenticationEvidence {
  readonly factor: AuthenticationFactor;
  readonly verifiedAtMs: number;
  /** Whether a WebAuthn ceremony performed authenticator user verification. */
  readonly userVerified?: boolean;
}

export interface AuthenticationAssurance {
  readonly level: AuthenticationAssuranceLevel;
  /** Time at which the evidence needed for this level was most recently complete. */
  readonly authenticatedAtMs: number | null;
  readonly factorCount: number;
}

export interface StepUpPolicy {
  readonly minimumLevel: AuthenticationAssuranceLevel;
  readonly maxAgeMs?: number;
  readonly requiredFactors?: readonly AuthenticationFactor[];
}

export type StepUpChallengeReason =
  | 'unauthenticated'
  | 'insufficient-assurance'
  | 'required-factor-missing'
  | 'stale';

export type StepUpDecision =
  | {
      readonly kind: 'allow';
      readonly assurance: AuthenticationAssurance;
    }
  | {
      readonly kind: 'challenge';
      readonly reason: StepUpChallengeReason;
      readonly assurance: AuthenticationAssurance;
    };

export interface MfaChallengeFacts {
  readonly purpose: string | null;
  readonly subject: string | null;
  readonly factor: MfaChallengeFactor | null;
  readonly credentialVersion: number | null;
  readonly expiresAtMs?: number | null;
  readonly consumedAtMs?: number | null;
}

export interface MfaChallengePolicy {
  readonly allowedPurposes: readonly string[];
  readonly allowedFactors: readonly MfaChallengeFactor[];
  readonly expectedSubject?: string;
  readonly currentCredentialVersion?: number;
  readonly nowMs?: number;
}

export type MfaChallengeRejectionReason =
  | 'malformed'
  | 'purpose-mismatch'
  | 'factor-not-allowed'
  | 'subject-mismatch'
  | 'credential-version-mismatch'
  | 'already-consumed'
  | 'expired';

export type MfaChallengeDecision =
  | { readonly kind: 'accept' }
  | {
      readonly kind: 'reject';
      readonly reason: MfaChallengeRejectionReason;
    };

const assuranceRank: Readonly<Record<AuthenticationAssuranceLevel, number>> = {
  unauthenticated: 0,
  'single-factor': 1,
  'multi-factor': 2,
  'phishing-resistant': 3,
};

function isAuthenticationFactor(value: string): value is AuthenticationFactor {
  return (AUTHENTICATION_FACTORS as readonly string[]).includes(value);
}

function requireTimestamp(value: number, label: string): void {
  if (!Number.isSafeInteger(value)) {
    throw new RangeError(`${label} must be a safe integer timestamp`);
  }
}

function latestEvidenceByFactor(
  evidence: readonly AuthenticationEvidence[],
): ReadonlyMap<AuthenticationFactor, { verifiedAtMs: number; userVerifiedAtMs: number | null }> {
  const latest = new Map<
    AuthenticationFactor,
    { verifiedAtMs: number; userVerifiedAtMs: number | null }
  >();
  for (const item of evidence) {
    const factor: string = item.factor;
    if (!isAuthenticationFactor(factor)) {
      throw new RangeError(`unknown authentication factor: ${factor}`);
    }
    requireTimestamp(item.verifiedAtMs, 'verifiedAtMs');
    const current = latest.get(factor);
    const userVerifiedAtMs =
      factor === 'webauthn' && item.userVerified === true
        ? Math.max(current?.userVerifiedAtMs ?? Number.NEGATIVE_INFINITY, item.verifiedAtMs)
        : (current?.userVerifiedAtMs ?? null);
    latest.set(factor, {
      verifiedAtMs: Math.max(current?.verifiedAtMs ?? Number.NEGATIVE_INFINITY, item.verifiedAtMs),
      userVerifiedAtMs,
    });
  }
  return latest;
}

/** Derives the strongest assurance supported by the supplied verified evidence. */
export function deriveAuthenticationAssurance(
  evidence: readonly AuthenticationEvidence[],
): AuthenticationAssurance {
  const latest = latestEvidenceByFactor(evidence);
  if (latest.size === 0) {
    return {
      level: 'unauthenticated',
      authenticatedAtMs: null,
      factorCount: 0,
    };
  }

  const webauthn = latest.get('webauthn');
  if (webauthn?.userVerifiedAtMs != null) {
    return {
      level: 'phishing-resistant',
      authenticatedAtMs: webauthn.userVerifiedAtMs,
      factorCount: latest.size,
    };
  }

  const timestamps = [...latest.values()]
    .map((item) => item.verifiedAtMs)
    .sort((left, right) => right - left);
  if (timestamps.length >= 2) {
    return {
      level: 'multi-factor',
      authenticatedAtMs: timestamps[1] ?? null,
      factorCount: latest.size,
    };
  }

  return {
    level: 'single-factor',
    authenticatedAtMs: timestamps[0] ?? null,
    factorCount: 1,
  };
}

/** Determines whether existing authentication evidence satisfies a step-up policy. */
export function evaluateStepUp(
  evidence: readonly AuthenticationEvidence[],
  nowMs: number,
  policy: StepUpPolicy,
): StepUpDecision {
  requireTimestamp(nowMs, 'nowMs');
  const minimumLevel: string = policy.minimumLevel;
  if (!(minimumLevel in assuranceRank)) {
    throw new RangeError(`unknown assurance level: ${minimumLevel}`);
  }
  if (
    policy.maxAgeMs !== undefined &&
    (!Number.isSafeInteger(policy.maxAgeMs) || policy.maxAgeMs < 0)
  ) {
    throw new RangeError('maxAgeMs must be a non-negative safe integer');
  }

  const latest = latestEvidenceByFactor(evidence);
  const assurance = deriveAuthenticationAssurance(evidence);
  if (assurance.level === 'unauthenticated') {
    return { kind: 'challenge', reason: 'unauthenticated', assurance };
  }

  const requiredFactors = policy.requiredFactors ?? [];
  if (requiredFactors.some((factor) => !latest.has(factor))) {
    return { kind: 'challenge', reason: 'required-factor-missing', assurance };
  }
  if (assuranceRank[assurance.level] < assuranceRank[policy.minimumLevel]) {
    return { kind: 'challenge', reason: 'insufficient-assurance', assurance };
  }

  if (policy.maxAgeMs !== undefined) {
    const cutoffMs = nowMs - policy.maxAgeMs;
    requireTimestamp(cutoffMs, 'step-up cutoff');
    const assuranceIsStale =
      assurance.authenticatedAtMs === null || assurance.authenticatedAtMs < cutoffMs;
    const requiredFactorIsStale = requiredFactors.some(
      (factor) => (latest.get(factor)?.verifiedAtMs ?? Number.NEGATIVE_INFINITY) < cutoffMs,
    );
    if (assuranceIsStale || requiredFactorIsStale) {
      return { kind: 'challenge', reason: 'stale', assurance };
    }
  }

  return { kind: 'allow', assurance };
}

/** Selects the first enrolled challenge factor in application-supplied preference order. */
export function selectMfaChallengeFactor(
  enrolledFactors: readonly MfaChallengeFactor[],
  preferredFactors: readonly MfaChallengeFactor[],
): MfaChallengeFactor | null {
  const enrolled = new Set(enrolledFactors);
  return preferredFactors.find((factor) => enrolled.has(factor)) ?? null;
}

/** Evaluates already-decoded MFA challenge claims without owning token cryptography. */
export function evaluateMfaChallenge(
  facts: MfaChallengeFacts,
  policy: MfaChallengePolicy,
): MfaChallengeDecision {
  if (policy.allowedPurposes.length === 0 || policy.allowedFactors.length === 0) {
    throw new RangeError('MFA challenge policy must allow a purpose and factor');
  }
  if (
    policy.currentCredentialVersion !== undefined &&
    (!Number.isSafeInteger(policy.currentCredentialVersion) ||
      policy.currentCredentialVersion < 0)
  ) {
    throw new RangeError('currentCredentialVersion must be a non-negative safe integer');
  }
  if (
    facts.purpose === null ||
    facts.purpose.length === 0 ||
    facts.subject === null ||
    facts.subject.length === 0 ||
    facts.factor === null ||
    facts.credentialVersion === null ||
    !Number.isSafeInteger(facts.credentialVersion) ||
    facts.credentialVersion < 0
  ) {
    return { kind: 'reject', reason: 'malformed' };
  }
  if (!policy.allowedPurposes.includes(facts.purpose)) {
    return { kind: 'reject', reason: 'purpose-mismatch' };
  }
  if (!policy.allowedFactors.includes(facts.factor)) {
    return { kind: 'reject', reason: 'factor-not-allowed' };
  }
  if (policy.expectedSubject !== undefined && facts.subject !== policy.expectedSubject) {
    return { kind: 'reject', reason: 'subject-mismatch' };
  }
  if (
    policy.currentCredentialVersion !== undefined &&
    facts.credentialVersion !== policy.currentCredentialVersion
  ) {
    return { kind: 'reject', reason: 'credential-version-mismatch' };
  }
  if (facts.consumedAtMs != null) {
    requireTimestamp(facts.consumedAtMs, 'consumedAtMs');
    return { kind: 'reject', reason: 'already-consumed' };
  }
  if (facts.expiresAtMs != null) {
    requireTimestamp(facts.expiresAtMs, 'expiresAtMs');
    if (policy.nowMs === undefined) {
      throw new RangeError('nowMs is required when expiresAtMs is present');
    }
    requireTimestamp(policy.nowMs, 'nowMs');
    if (policy.nowMs >= facts.expiresAtMs) {
      return { kind: 'reject', reason: 'expired' };
    }
  }

  return { kind: 'accept' };
}
