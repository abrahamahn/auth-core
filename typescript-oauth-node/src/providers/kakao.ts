import {
  accessToken,
  jsonRecord,
  optionalNumber,
  optionalString,
  providerRuntime,
  requireConfig,
  requireOk,
  tokenError,
  tokenSetFromResponse,
} from '../http.js';
import { OAuthError } from '../types.js';

import type {
  AuthorizationRequestOptions,
  OAuthProviderClient,
  OAuthRuntime,
  OAuthTokenSet,
  OAuthUserInfo,
  TokenExchangeOptions,
} from '../types.js';

const AUTH_URL = 'https://kauth.kakao.com/oauth/authorize';
const TOKEN_URL = 'https://kauth.kakao.com/oauth/token';
const USERINFO_URL = 'https://kapi.kakao.com/v2/user/me';
const DEFAULT_SCOPES = ['account_email', 'profile_nickname', 'profile_image'] as const;

export interface KakaoProviderConfig extends OAuthRuntime {
  readonly clientId: string;
  readonly clientSecret?: string;
  readonly scopes?: readonly string[];
}

export function createKakaoProvider(config: KakaoProviderConfig): OAuthProviderClient {
  const provider = 'kakao';
  const clientId = requireConfig(config.clientId, 'clientId', provider);
  const clientSecret = config.clientSecret?.trim() === '' ? undefined : config.clientSecret;
  const runtime = providerRuntime(config);
  const scopes = config.scopes ?? DEFAULT_SCOPES;
  if (scopes.length === 0) {
    throw new OAuthError('At least one scope is required', provider, 'INVALID_CONFIG');
  }

  async function requestTokens(params: URLSearchParams, refresh: boolean): Promise<OAuthTokenSet> {
    const response = await runtime.fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const errorCode = refresh ? 'TOKEN_REFRESH_FAILED' : 'TOKEN_EXCHANGE_FAILED';
    await requireOk(response, provider, errorCode, refresh ? 'Token refresh' : 'Code exchange');
    const data = await jsonRecord(response, provider, errorCode);
    tokenError(data, provider, errorCode);
    return tokenSetFromResponse(data, provider, runtime.nowMs());
  }

  function addCredentials(params: URLSearchParams): URLSearchParams {
    params.set('client_id', clientId);
    if (clientSecret !== undefined) params.set('client_secret', clientSecret);
    return params;
  }

  return {
    provider,

    getAuthorizationUrl(
      state: string,
      redirectUri: string,
      options: AuthorizationRequestOptions = {},
    ): string {
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: scopes.join(','),
        state,
      });
      if (options.prompt !== undefined) params.set('prompt', options.prompt);
      if (options.loginHint !== undefined) params.set('login_hint', options.loginHint);
      if (options.codeChallenge !== undefined) {
        params.set('code_challenge', options.codeChallenge);
        params.set('code_challenge_method', 'S256');
      }
      return `${AUTH_URL}?${params.toString()}`;
    },

    exchangeCode(
      code: string,
      redirectUri: string,
      options: TokenExchangeOptions = {},
    ): Promise<OAuthTokenSet> {
      const params = addCredentials(
        new URLSearchParams({
          grant_type: 'authorization_code',
          redirect_uri: redirectUri,
          code,
        }),
      );
      if (options.codeVerifier !== undefined) params.set('code_verifier', options.codeVerifier);
      return requestTokens(params, false);
    },

    async getUserInfo(tokens: OAuthTokenSet | string): Promise<OAuthUserInfo> {
      const response = await runtime.fetch(USERINFO_URL, {
        headers: { Authorization: `Bearer ${accessToken(tokens)}` },
      });
      await requireOk(response, provider, 'USERINFO_FAILED', 'User info request');
      const data = await jsonRecord(response, provider, 'USERINFO_FAILED');
      const idNumber = optionalNumber(data, 'id');
      const idString = optionalString(data, 'id');
      const account =
        data['kakao_account'] !== null &&
        typeof data['kakao_account'] === 'object' &&
        !Array.isArray(data['kakao_account'])
          ? (data['kakao_account'] as Record<string, unknown>)
          : {};
      const email = optionalString(account, 'email');
      if (email === undefined) {
        throw new OAuthError('No email found on Kakao account', provider, 'NO_EMAIL');
      }
      const profile =
        account['profile'] !== null &&
        typeof account['profile'] === 'object' &&
        !Array.isArray(account['profile'])
          ? (account['profile'] as Record<string, unknown>)
          : {};
      const id = idNumber === undefined ? idString : String(idNumber);
      if (id === undefined) {
        throw new OAuthError('Kakao response is missing id', provider, 'USERINFO_FAILED');
      }
      const result: OAuthUserInfo = {
        id,
        email,
        name: optionalString(profile, 'nickname') ?? null,
        emailVerified:
          account['is_email_verified'] === true || account['is_email_verified'] === 'true',
      };
      const picture = optionalString(profile, 'profile_image_url');
      return picture === undefined ? result : { ...result, picture };
    },

    refreshToken(refreshToken: string): Promise<OAuthTokenSet> {
      return requestTokens(
        addCredentials(
          new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
          }),
        ),
        true,
      );
    },
  };
}
