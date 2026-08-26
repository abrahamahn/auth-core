import { createHmac } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  JwtError,
  checkTokenSecret,
  createJwtRotationHandler,
  decode,
  sign,
  verify,
  verifyWithRotation,
} from '../src/index.js';

const CURRENT_SECRET = 'current-secret-for-auth-core-jwt-tests';
const PREVIOUS_SECRET = 'previous-secret-for-auth-core-jwt-tests';
const NOW = 1_718_452_800;

describe('HS256 JWT adapter', () => {
  it('signs, decodes, and verifies object payloads', () => {
    const token = sign(
      { sub: 'user-123', roles: ['user'], profile: { locale: 'ko' } },
      CURRENT_SECRET,
      { expiresIn: '15m', issuedAtSeconds: NOW },
    );

    expect(decode(token)).toEqual({
      sub: 'user-123',
      roles: ['user'],
      profile: { locale: 'ko' },
      iat: NOW,
      exp: NOW + 900,
    });
    expect(verify(token, CURRENT_SECRET, { currentTimeSeconds: NOW })).toEqual(decode(token));
  });

  it.each([
    ['30s', 30],
    ['15m', 900],
    ['24h', 86_400],
    ['7d', 604_800],
    [3_600, 3_600],
  ] as const)('supports the %s expiration form', (expiresIn, seconds) => {
    const token = sign({}, CURRENT_SECRET, { expiresIn, issuedAtSeconds: NOW });
    expect(decode(token)?.exp).toBe(NOW + seconds);
  });

  it('rejects invalid duration, clock, secret, and payload inputs', () => {
    expect(() => sign({}, CURRENT_SECRET, { expiresIn: '1w' })).toThrow(
      'Invalid expiration format',
    );
    expect(() => sign({}, CURRENT_SECRET, { expiresIn: -1 })).toThrow(
      'JWT expiration must be a non-negative integer',
    );
    expect(() => sign({}, '', { issuedAtSeconds: NOW })).toThrow('JWT secret is required');
    expect(() => sign([], CURRENT_SECRET, { issuedAtSeconds: NOW })).toThrow(
      'Malformed token payload',
    );
    expect(() => sign({}, CURRENT_SECRET, { issuedAtSeconds: -1 })).toThrow(
      'issuedAtSeconds must be a non-negative integer',
    );
  });

  it('rejects malformed structure, headers, payloads, and signatures with stable codes', () => {
    expectJwtError(() => verify('a.b', CURRENT_SECRET), 'MALFORMED_TOKEN');

    const unsupportedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url',
    );
    expectJwtError(
      () => verify(`${unsupportedHeader}.e30.fake`, CURRENT_SECRET),
      'INVALID_TOKEN',
    );

    const valid = sign({ sub: 'user-123' }, CURRENT_SECRET, { issuedAtSeconds: NOW });
    expectJwtError(() => verify(valid, PREVIOUS_SECRET), 'INVALID_SIGNATURE');

    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify(['not', 'an', 'object'])).toString('base64url');
    const signature = createHmac('sha256', CURRENT_SECRET)
      .update(`${header}.${payload}`)
      .digest('base64url');
    expectJwtError(
      () => verify(`${header}.${payload}.${signature}`, CURRENT_SECRET),
      'MALFORMED_TOKEN',
    );
  });

  it('enforces expiration boundaries and bounded tolerance', () => {
    const token = sign({ sub: 'user-123' }, CURRENT_SECRET, {
      expiresIn: 60,
      issuedAtSeconds: NOW,
    });

    expect(() => verify(token, CURRENT_SECRET, { currentTimeSeconds: NOW + 59 })).not.toThrow();
    expectJwtError(
      () => verify(token, CURRENT_SECRET, { currentTimeSeconds: NOW + 60 }),
      'TOKEN_EXPIRED',
    );
    expect(() =>
      verify(token, CURRENT_SECRET, {
        currentTimeSeconds: NOW + 60,
        clockToleranceSeconds: 1,
      }),
    ).not.toThrow();
    expectJwtError(
      () =>
        verify(token, CURRENT_SECRET, {
          currentTimeSeconds: NOW,
          clockToleranceSeconds: -1,
        }),
      'INVALID_TOKEN',
    );
  });

  it('never treats decoded content as verified content', () => {
    const token = sign({ role: 'user' }, CURRENT_SECRET, { issuedAtSeconds: NOW });
    expect(decode(token)?.['role']).toBe('user');
    expect(decode('invalid')).toBeNull();
    expect(() => verify(token, PREVIOUS_SECRET)).toThrow('Invalid signature');
  });
});

describe('secret rotation', () => {
  const config = { secret: CURRENT_SECRET, previousSecret: PREVIOUS_SECRET };

  it('signs with the current secret and accepts the previous secret during migration', () => {
    const current = sign({ sub: 'current' }, CURRENT_SECRET, { issuedAtSeconds: NOW });
    const previous = sign({ sub: 'previous' }, PREVIOUS_SECRET, { issuedAtSeconds: NOW });

    expect(verifyWithRotation(current, config, { currentTimeSeconds: NOW })['sub']).toBe('current');
    expect(verifyWithRotation(previous, config, { currentTimeSeconds: NOW })['sub']).toBe(
      'previous',
    );
    expect(checkTokenSecret(current, config, { currentTimeSeconds: NOW }).usedSecret).toBe(
      'current',
    );
    expect(checkTokenSecret(previous, config, { currentTimeSeconds: NOW }).usedSecret).toBe(
      'previous',
    );
  });

  it('does not retry malformed or expired tokens with the previous secret', () => {
    const expired = sign({}, PREVIOUS_SECRET, { expiresIn: 1, issuedAtSeconds: NOW });
    const result = checkTokenSecret(expired, config, { currentTimeSeconds: NOW + 2 });

    expect(result.isValid).toBe(false);
    expect(result.usedSecret).toBe('none');
    expect(result.error?.code).toBe('INVALID_SIGNATURE');
    expectJwtError(
      () => verifyWithRotation('malformed', config, { currentTimeSeconds: NOW }),
      'MALFORMED_TOKEN',
    );
  });

  it('provides a configured facade without exposing key material', () => {
    const handler = createJwtRotationHandler(config);
    const token = handler.sign({ sub: 'user-123' }, { issuedAtSeconds: NOW });

    expect(handler.verify(token, { currentTimeSeconds: NOW })['sub']).toBe('user-123');
    expect(handler.checkSecret(token, { currentTimeSeconds: NOW }).usedSecret).toBe('current');
    expect(handler.isRotating()).toBe(true);
    expect(handler.getConfig()).toEqual({ hasSecret: true, hasPreviousSecret: true });
  });
});

function expectJwtError(operation: () => unknown, code: JwtError['code']): void {
  try {
    operation();
    throw new Error('Expected operation to throw');
  } catch (error) {
    expect(error).toBeInstanceOf(JwtError);
    expect((error as JwtError).code).toBe(code);
  }
}
