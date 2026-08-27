import { generateKeyPairSync, sign } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  createAppleProvider,
  createGitHubProvider,
  createGoogleProvider,
  createKakaoProvider,
  generateAppleClientSecret,
} from '../src/index.js';

import type { OAuthTokenSet } from '../src/index.js';

const NOW = 1_718_452_800_000;

describe('Google provider', () => {
  it('builds authorization, exchange, user-info, and credentialed refresh requests', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: 'google-access',
          refresh_token: 'google-refresh',
          id_token: 'google-id',
          expires_in: 3_600,
          token_type: 'Bearer',
          scope: 'openid email profile',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          sub: 'google-user',
          email: 'user@example.com',
          email_verified: true,
          name: 'Example User',
          picture: 'https://images.example/user.png',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ access_token: 'refreshed', expires_in: 1_800, token_type: 'Bearer' }),
      );
    const provider = createGoogleProvider({
      clientId: 'google-client',
      clientSecret: 'google-secret',
      fetch: fetchMock,
      nowMs: () => NOW,
      forceConsent: true,
    });

    const authorizationUrl = new URL(
      provider.getAuthorizationUrl('state', 'https://app.example/callback', {
        codeChallenge: 'challenge',
      }),
    );
    expect(authorizationUrl.searchParams.get('access_type')).toBe('offline');
    expect(authorizationUrl.searchParams.get('prompt')).toBe('consent');
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');

    const tokens = await provider.exchangeCode('code', 'https://app.example/callback', {
      codeVerifier: 'verifier',
    });
    expect(tokens).toEqual({
      accessToken: 'google-access',
      refreshToken: 'google-refresh',
      idToken: 'google-id',
      expiresAt: new Date(NOW + 3_600_000),
      tokenType: 'Bearer',
      scope: 'openid email profile',
    });
    expect(await provider.getUserInfo(tokens)).toEqual({
      id: 'google-user',
      email: 'user@example.com',
      emailVerified: true,
      name: 'Example User',
      picture: 'https://images.example/user.png',
    });
    await provider.refreshToken('stored-refresh');

    const exchangeBody = requestBody(fetchMock, 0);
    expect(exchangeBody.get('code_verifier')).toBe('verifier');
    const refreshBody = requestBody(fetchMock, 2);
    expect(refreshBody.get('client_id')).toBe('google-client');
    expect(refreshBody.get('client_secret')).toBe('google-secret');
    expect(refreshBody.get('refresh_token')).toBe('stored-refresh');
  });
});

describe('GitHub provider', () => {
  it('normalizes expiring tokens and selects a verified email', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: 'github-access',
          refresh_token: 'github-refresh',
          expires_in: 28_800,
          refresh_token_expires_in: 15_897_600,
          token_type: 'bearer',
          scope: 'user:email,read:user',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ id: 42, email: null, name: 'Octo Cat', avatar_url: 'avatar' }),
      )
      .mockResolvedValueOnce(
        jsonResponse([
          { email: 'other@example.com', primary: false, verified: true },
          { email: 'primary@example.com', primary: true, verified: true },
        ]),
      );
    const provider = createGitHubProvider({
      clientId: 'github-client',
      clientSecret: 'github-secret',
      fetch: fetchMock,
      nowMs: () => NOW,
    });

    const tokens = await provider.exchangeCode('code', 'https://app.example/callback');
    expect(tokens.expiresAt).toEqual(new Date(NOW + 28_800_000));
    expect(tokens.refreshTokenExpiresAt).toEqual(new Date(NOW + 15_897_600_000));
    expect(await provider.getUserInfo(tokens)).toEqual({
      id: '42',
      email: 'primary@example.com',
      emailVerified: true,
      name: 'Octo Cat',
      picture: 'avatar',
    });
  });

  it('reports provider errors without copying provider response bodies into logs', async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response('secret-bearing upstream body', { status: 401 }),
    );
    const provider = createGitHubProvider({
      clientId: 'client',
      clientSecret: 'secret',
      fetch: fetchMock,
    });

    await expect(provider.exchangeCode('code', 'https://app.example/callback')).rejects.toMatchObject(
      { code: 'TOKEN_EXCHANGE_FAILED', provider: 'github', status: 401 },
    );
    await expect(provider.exchangeCode('code', 'https://app.example/callback')).rejects.not.toThrow(
      'secret-bearing upstream body',
    );
  });
});

describe('Kakao provider', () => {
  it('supports optional client secrets, user info, and refresh', async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({ access_token: 'access', token_type: 'bearer', expires_in: 100 }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          id: 123,
          kakao_account: {
            email: 'kakao@example.com',
            is_email_verified: true,
            profile: { nickname: 'Kakao User', profile_image_url: 'picture' },
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ access_token: 'refreshed', token_type: 'bearer', expires_in: 100 }),
      );
    const provider = createKakaoProvider({
      clientId: 'kakao-client',
      clientSecret: 'kakao-secret',
      fetch: fetchMock,
      nowMs: () => NOW,
    });

    const tokens = await provider.exchangeCode('code', 'https://app.example/callback');
    expect(await provider.getUserInfo(tokens)).toMatchObject({
      id: '123',
      email: 'kakao@example.com',
      emailVerified: true,
    });
    await provider.refreshToken('refresh');
    expect(requestBody(fetchMock, 2).get('client_secret')).toBe('kakao-secret');
  });
});

describe('Apple provider', () => {
  it('retains id_token, verifies its signature and claims, and caches public keys', async () => {
    const clientSigningKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    });
    const identityKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicJwk = identityKeys.publicKey.export({ format: 'jwk' });
    const idToken = createAppleIdToken(identityKeys.privateKey.export({ type: 'pkcs8', format: 'pem' }));
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: 'apple-access',
          refresh_token: 'apple-refresh',
          id_token: idToken,
          token_type: 'Bearer',
          expires_in: 3_600,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ keys: [{ ...publicJwk, kid: 'apple-key', use: 'sig', alg: 'RS256' }] }),
      );
    const provider = createAppleProvider({
      clientId: 'com.example.web',
      teamId: 'TEAM123',
      keyId: 'CLIENTKEY',
      privateKey: clientSigningKey,
      fetch: fetchMock,
      nowMs: () => NOW,
    });

    const tokens = await provider.exchangeCode('code', 'https://app.example/callback');
    expect(tokens.idToken).toBe(idToken);
    await expect(provider.getUserInfo(tokens)).resolves.toEqual({
      id: 'apple-user',
      email: 'apple@example.com',
      emailVerified: true,
      name: null,
    });
    await expect(provider.getUserInfo(tokens)).resolves.toMatchObject({ id: 'apple-user' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('generates a bounded ES256 client assertion with a raw P-1363 signature', () => {
    const privateKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    });
    const secret = generateAppleClientSecret({
      clientId: 'com.example.web',
      teamId: 'TEAM123',
      keyId: 'KEY123',
      privateKey,
      issuedAtSeconds: Math.floor(NOW / 1_000),
      lifetimeSeconds: 60,
    });
    const [encodedHeader, encodedPayload, encodedSignature] = secret.split('.');

    expect(JSON.parse(Buffer.from(encodedHeader ?? '', 'base64url').toString('utf8'))).toEqual({
      alg: 'ES256',
      kid: 'KEY123',
      typ: 'JWT',
    });
    expect(JSON.parse(Buffer.from(encodedPayload ?? '', 'base64url').toString('utf8'))).toMatchObject({
      iss: 'TEAM123',
      sub: 'com.example.web',
      exp: Math.floor(NOW / 1_000) + 60,
    });
    expect(Buffer.from(encodedSignature ?? '', 'base64url')).toHaveLength(64);
  });

  it('requires the identity token instead of confusing it with the access token', async () => {
    const privateKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    });
    const provider = createAppleProvider({
      clientId: 'client',
      teamId: 'team',
      keyId: 'key',
      privateKey,
      fetch: vi.fn<typeof fetch>(),
    });
    const accessOnly: OAuthTokenSet = { accessToken: 'access', tokenType: 'Bearer' };

    await expect(provider.getUserInfo(accessOnly)).rejects.toMatchObject({
      code: 'INVALID_ID_TOKEN',
      provider: 'apple',
    });
  });
});

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function requestBody(mock: ReturnType<typeof vi.fn<typeof fetch>>, call: number): URLSearchParams {
  const init = mock.mock.calls[call]?.[1];
  if (typeof init?.body !== 'string') throw new Error('Expected a string request body');
  return new URLSearchParams(init.body);
}

function createAppleIdToken(privateKey: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'apple-key' })).toString(
    'base64url',
  );
  const payload = Buffer.from(
    JSON.stringify({
      iss: 'https://appleid.apple.com',
      aud: 'com.example.web',
      exp: Math.floor(NOW / 1_000) + 3_600,
      iat: Math.floor(NOW / 1_000),
      sub: 'apple-user',
      email: 'apple@example.com',
      email_verified: 'true',
    }),
  ).toString('base64url');
  const input = `${header}.${payload}`;
  const signature = sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url');
  return `${input}.${signature}`;
}
