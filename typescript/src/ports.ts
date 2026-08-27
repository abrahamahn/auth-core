import type { AuthAuditEvent } from "./audit.js";

/** Unit-of-work boundary used by storage adapters. */
export interface AuthTransactionPort<Transaction> {
  run<Result>(
    operation: (transaction: Transaction) => Promise<Result>,
  ): Promise<Result>;
}

export interface AuthAuditPort {
  record(event: AuthAuditEvent): Promise<void>;
}

export interface AuthNotification {
  readonly recipientId: string;
  readonly template: string;
  readonly data: Readonly<Record<string, unknown>>;
}

export interface AuthNotificationPort {
  send(notification: AuthNotification): Promise<void>;
}

export interface OAuthIdentity {
  readonly provider: string;
  readonly providerUserId: string;
  readonly email?: string | undefined;
  readonly emailVerified?: boolean | undefined;
  readonly displayName?: string | undefined;
}

export interface OAuthProviderPort {
  readonly id: string;
  createAuthorizationUrl(state: string, redirectUri: string): URL;
  exchangeCode(code: string, redirectUri: string): Promise<OAuthIdentity>;
  refresh?(refreshToken: string): Promise<Readonly<Record<string, unknown>>>;
}

export interface WebAuthnCredentialRecord {
  readonly id: string;
  readonly publicKey: Uint8Array;
  readonly counter: number;
  readonly transports?: readonly string[] | undefined;
}

export interface WebAuthnCredentialPort {
  listForUser(userId: string): Promise<readonly WebAuthnCredentialRecord[]>;
  save(userId: string, credential: WebAuthnCredentialRecord): Promise<void>;
  updateCounter(credentialId: string, counter: number): Promise<void>;
  remove(userId: string, credentialId: string): Promise<void>;
}
