export interface RefreshCredentialFacts {
  readonly nowMs: number;
  readonly expiresAtMs: number;
  readonly rotatedAtMs?: number | null;
  readonly familyRevokedAtMs?: number | null;
  readonly gracePeriodMs: number;
}

export type RefreshCredentialDecision =
  | { readonly kind: 'rotate' }
  | { readonly kind: 'retry-current' }
  | { readonly kind: 'reject'; readonly reason: 'expired' }
  | {
      readonly kind: 'revoke-family';
      readonly reason: 'family-revoked' | 'credential-reuse';
    };

export type SessionBindingDecision = 'unbound' | 'not-checked' | 'match' | 'mismatch';

export interface SessionLifetimePolicy {
  readonly defaultSpanMs: number;
  readonly rememberedSpanMs: number;
  readonly maxIdleMs: number;
}

function requireFinite(value: number, label: string): void {
  if (!Number.isFinite(value)) throw new RangeError(`${label} must be finite`);
}

function requireNonNegative(value: number, label: string): void {
  requireFinite(value, label);
  if (value < 0) throw new RangeError(`${label} must not be negative`);
}

export function classifyRefreshCredential(
  facts: RefreshCredentialFacts,
): RefreshCredentialDecision {
  requireFinite(facts.nowMs, 'nowMs');
  requireFinite(facts.expiresAtMs, 'expiresAtMs');
  requireNonNegative(facts.gracePeriodMs, 'gracePeriodMs');
  if (facts.familyRevokedAtMs != null) {
    requireFinite(facts.familyRevokedAtMs, 'familyRevokedAtMs');
    return { kind: 'revoke-family', reason: 'family-revoked' };
  }
  if (facts.expiresAtMs <= facts.nowMs) return { kind: 'reject', reason: 'expired' };
  if (facts.rotatedAtMs == null) return { kind: 'rotate' };
  requireFinite(facts.rotatedAtMs, 'rotatedAtMs');
  if (facts.nowMs - facts.rotatedAtMs < facts.gracePeriodMs) {
    return { kind: 'retry-current' };
  }
  return { kind: 'revoke-family', reason: 'credential-reuse' };
}

export function credentialEpochMatches(observedEpoch: number, currentEpoch: number): boolean {
  return (
    Number.isSafeInteger(observedEpoch) &&
    observedEpoch >= 0 &&
    Number.isSafeInteger(currentEpoch) &&
    currentEpoch >= 0 &&
    observedEpoch === currentEpoch
  );
}

export function isRefreshRetryEligible(
  facts: RefreshCredentialFacts & {
    readonly observedCredentialEpoch: number;
    readonly currentCredentialEpoch: number;
  },
): boolean {
  return (
    credentialEpochMatches(facts.observedCredentialEpoch, facts.currentCredentialEpoch) &&
    classifyRefreshCredential(facts).kind === 'retry-current'
  );
}

export function isActiveRefreshCredential(facts: RefreshCredentialFacts): boolean {
  return classifyRefreshCredential(facts).kind === 'rotate';
}

export function evaluateSessionBinding(
  expectedBinding: string | null | undefined,
  presentedBinding: string | null | undefined,
): SessionBindingDecision {
  if (expectedBinding == null || expectedBinding === '') return 'unbound';
  if (presentedBinding == null) return 'not-checked';
  return expectedBinding === presentedBinding ? 'match' : 'mismatch';
}

export function sessionSpanMs(
  remembered: boolean | undefined,
  policy: Pick<SessionLifetimePolicy, 'defaultSpanMs' | 'rememberedSpanMs'>,
): number {
  requireNonNegative(policy.defaultSpanMs, 'defaultSpanMs');
  requireNonNegative(policy.rememberedSpanMs, 'rememberedSpanMs');
  return remembered === true ? policy.rememberedSpanMs : policy.defaultSpanMs;
}

export function deriveSessionSpanMs(createdAtMs: number, expiresAtMs: number): number {
  requireFinite(createdAtMs, 'createdAtMs');
  requireFinite(expiresAtMs, 'expiresAtMs');
  return expiresAtMs - createdAtMs;
}

export function sessionIdleWindowMs(spanMs: number, maxIdleMs: number): number {
  requireNonNegative(spanMs, 'spanMs');
  requireNonNegative(maxIdleMs, 'maxIdleMs');
  return Math.min(spanMs, maxIdleMs);
}

export function isSessionActive(revokedAtMs: number | null): boolean {
  return revokedAtMs === null;
}

export function isSessionRevoked(revokedAtMs: number | null): boolean {
  return !isSessionActive(revokedAtMs);
}

export function sessionAgeMs(createdAtMs: number, nowMs: number): number {
  requireFinite(createdAtMs, 'createdAtMs');
  requireFinite(nowMs, 'nowMs');
  return nowMs - createdAtMs;
}

export function isSessionIdle(
  lastActiveAtMs: number,
  idleTimeoutMs: number,
  nowMs: number,
): boolean {
  requireFinite(lastActiveAtMs, 'lastActiveAtMs');
  requireNonNegative(idleTimeoutMs, 'idleTimeoutMs');
  requireFinite(nowMs, 'nowMs');
  return nowMs - lastActiveAtMs > idleTimeoutMs;
}

export function sessionIdleRemainingMs(
  lastActiveAtMs: number,
  idleTimeoutMs: number,
  nowMs: number,
): number {
  requireFinite(lastActiveAtMs, 'lastActiveAtMs');
  requireNonNegative(idleTimeoutMs, 'idleTimeoutMs');
  requireFinite(nowMs, 'nowMs');
  return Math.max(0, idleTimeoutMs - (nowMs - lastActiveAtMs));
}

export function selectSessionsForEviction<Session>(
  sessions: readonly Session[],
  maxSessions: number,
  createdAtMs: (session: Session) => number,
): readonly Session[] {
  if (!Number.isSafeInteger(maxSessions)) {
    throw new RangeError('maxSessions must be a safe integer');
  }
  if (maxSessions <= 0 || sessions.length <= maxSessions) return [];
  const sorted = [...sessions].sort((left, right) => {
    const leftCreatedAt = createdAtMs(left);
    const rightCreatedAt = createdAtMs(right);
    requireFinite(leftCreatedAt, 'session createdAtMs');
    requireFinite(rightCreatedAt, 'session createdAtMs');
    return leftCreatedAt - rightCreatedAt;
  });
  return sorted.slice(0, sessions.length - maxSessions);
}
