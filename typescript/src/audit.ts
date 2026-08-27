export const AUTH_AUDIT_EVENT_TYPES = [
  "token_reuse_detected",
  "token_family_revoked",
  "session_revoked",
  "account_locked",
  "account_unlocked",
  "suspicious_login",
  "new_device_login",
  "device_trusted",
  "device_revoked",
  "password_changed",
  "email_changed",
  "magic_link_requested",
  "magic_link_verified",
  "magic_link_failed",
  "email_otp_requested",
  "email_otp_verified",
  "email_otp_failed",
  "oauth_login_success",
  "oauth_login_failure",
  "oauth_account_created",
  "oauth_link_success",
  "oauth_link_failure",
  "oauth_unlink_success",
  "oauth_unlink_failure",
  "webauthn_registered",
  "webauthn_authentication_success",
  "webauthn_authentication_failure",
  "webauthn_credential_removed",
  "mfa_challenge",
  "mfa_success",
  "mfa_failure",
] as const;

export type AuthAuditEventType = (typeof AUTH_AUDIT_EVENT_TYPES)[number];
export type AuthAuditSeverity = "low" | "medium" | "high" | "critical";
export type AuthAuditOutcome =
  | "success"
  | "failure"
  | "denied"
  | "informational";
export type AuthAuditFactor =
  | "password"
  | "magic-link"
  | "email-otp"
  | "totp"
  | "webauthn"
  | "oauth"
  | "refresh-token"
  | "session"
  | "recovery-code";

export type AuthAuditMetadataValue =
  | null
  | boolean
  | number
  | string
  | readonly AuthAuditMetadataValue[]
  | { readonly [key: string]: AuthAuditMetadataValue };

export type AuthAuditMetadata = Readonly<
  Record<string, AuthAuditMetadataValue>
>;

export interface AuthAuditEvent {
  readonly type: AuthAuditEventType;
  readonly severity: AuthAuditSeverity;
  readonly outcome: AuthAuditOutcome;
  readonly occurredAtMs: number;
  readonly subjectId?: string | undefined;
  readonly actorId?: string | undefined;
  readonly email?: string | undefined;
  readonly factor?: AuthAuditFactor | undefined;
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
  readonly metadata?: AuthAuditMetadata | undefined;
}

export interface CreateAuthAuditEventInput
  extends Omit<AuthAuditEvent, "metadata"> {
  readonly metadata?: Readonly<Record<string, unknown>> | undefined;
}

const SENSITIVE_METADATA_KEYS = new Set([
  "password",
  "passwordhash",
  "passworddigest",
  "token",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "csrftoken",
  "magictoken",
  "secret",
  "clientsecret",
  "code",
  "recoverycode",
  "authorization",
  "cookie",
  "setcookie",
  "apikey",
  "privatekey",
]);

function normalizeMetadataKey(key: string): string {
  return key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
}

export function isSensitiveAuthAuditMetadataKey(key: string): boolean {
  return SENSITIVE_METADATA_KEYS.has(normalizeMetadataKey(key));
}

function protectMetadataValue(
  value: unknown,
  path: string,
): AuthAuditMetadataValue {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError(`${path} must contain only finite numbers`);
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.map((entry, index) =>
        protectMetadataValue(entry, `${path}[${String(index)}]`),
      ),
    );
  }
  if (typeof value !== "object") {
    throw new TypeError(`${path} must contain only JSON-compatible values`);
  }
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    throw new TypeError(`${path} must not contain symbol keys`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${path} must contain only plain objects`);
  }

  const protectedEntries = Object.entries(value).map(([key, entry]) => {
    if (isSensitiveAuthAuditMetadataKey(key)) {
      throw new TypeError(
        `${path}.${key} is not permitted in authentication audit metadata`,
      );
    }
    return [key, protectMetadataValue(entry, `${path}.${key}`)] as const;
  });
  return Object.freeze(Object.fromEntries(protectedEntries));
}

/** Creates an immutable audit event and rejects secret-bearing or non-JSON metadata. */
export function createAuthAuditEvent(
  input: CreateAuthAuditEventInput,
): AuthAuditEvent {
  if (!Number.isSafeInteger(input.occurredAtMs)) {
    throw new RangeError("occurredAtMs must be a safe integer timestamp");
  }
  const { metadata: unprotectedMetadata, ...event } = input;
  const metadata =
    unprotectedMetadata === undefined
      ? undefined
      : (protectMetadataValue(
          unprotectedMetadata,
          "metadata",
        ) as AuthAuditMetadata);
  return Object.freeze({
    ...event,
    ...(metadata === undefined ? {} : { metadata }),
  });
}
