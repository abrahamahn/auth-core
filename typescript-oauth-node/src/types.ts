export type OAuthProvider = 'google' | 'github' | 'kakao' | 'apple';

export interface OAuthTokenSet {
  readonly accessToken: string;
  readonly tokenType: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresAt?: Date;
  readonly refreshTokenExpiresAt?: Date;
  readonly scope?: string;
}

export interface OAuthUserInfo {
  readonly id: string;
  readonly email: string;
  readonly name: string | null;
  readonly emailVerified: boolean;
  readonly picture?: string;
}

export interface AuthorizationRequestOptions {
  readonly codeChallenge?: string;
  readonly loginHint?: string;
  readonly prompt?: string;
}

export interface TokenExchangeOptions {
  readonly codeVerifier?: string;
}

export interface OAuthProviderClient {
  readonly provider: OAuthProvider;
  getAuthorizationUrl(
    state: string,
    redirectUri: string,
    options?: AuthorizationRequestOptions,
  ): string;
  exchangeCode(
    code: string,
    redirectUri: string,
    options?: TokenExchangeOptions,
  ): Promise<OAuthTokenSet>;
  getUserInfo(tokens: OAuthTokenSet | string): Promise<OAuthUserInfo>;
  refreshToken(refreshToken: string): Promise<OAuthTokenSet>;
}

export interface OAuthRuntime {
  readonly fetch?: typeof globalThis.fetch;
  readonly nowMs?: () => number;
}

export type OAuthErrorCode =
  | 'INVALID_CONFIG'
  | 'TOKEN_EXCHANGE_FAILED'
  | 'TOKEN_REFRESH_FAILED'
  | 'USERINFO_FAILED'
  | 'NO_EMAIL'
  | 'MALFORMED_RESPONSE'
  | 'KEYS_FETCH_FAILED'
  | 'KEY_NOT_FOUND'
  | 'INVALID_ID_TOKEN'
  | 'INVALID_ALGORITHM'
  | 'INVALID_SIGNATURE'
  | 'INVALID_ISSUER'
  | 'INVALID_AUDIENCE'
  | 'TOKEN_EXPIRED'
  | 'INVALID_IAT';

export class OAuthError extends Error {
  override readonly name = 'OAuthError';

  constructor(
    message: string,
    readonly provider: OAuthProvider,
    readonly code: OAuthErrorCode,
    readonly status?: number,
  ) {
    super(message);
  }
}
