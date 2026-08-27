import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

import { AuthWebAuthnError } from './error.js';
import {
  parseWebAuthnAuthenticationResponse,
  parseWebAuthnRegistrationResponse,
  readWebAuthnResponseTransports,
} from './response.js';

import type {
  GenerateWebAuthnAuthenticationOptionsInput,
  GenerateWebAuthnRegistrationOptionsInput,
  VerifyWebAuthnAuthenticationInput,
  VerifyWebAuthnRegistrationInput,
  WebAuthnAuthenticationOptions,
  WebAuthnAuthenticationResult,
  WebAuthnCredentialDescriptor,
  WebAuthnRegistrationOptions,
  WebAuthnRegistrationResult,
  WebAuthnRelyingPartyConfig,
} from './types.js';

interface NormalizedConfig {
  readonly rpName: string;
  readonly rpId: string;
  readonly expectedOrigin: string | string[];
  readonly attestation: 'none' | 'direct' | 'enterprise';
  readonly userVerification: 'required' | 'preferred' | 'discouraged';
  readonly timeoutMs?: number | undefined;
}

function invalidConfig(message: string): AuthWebAuthnError {
  return new AuthWebAuthnError('invalid-config', message);
}

function validateOrigin(origin: string, rpId: string): void {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch (cause) {
    throw invalidConfig(`expectedOrigin is not a valid URL: ${String(cause)}`);
  }
  const localHttp = parsed.protocol === 'http:' && parsed.hostname === 'localhost';
  if (parsed.protocol !== 'https:' && !localHttp) {
    throw invalidConfig('expectedOrigin must use HTTPS except for localhost development');
  }
  if (parsed.username !== '' || parsed.password !== '' || parsed.search !== '' || parsed.hash !== '') {
    throw invalidConfig('expectedOrigin must not contain credentials, query, or fragment');
  }
  if (parsed.pathname !== '/') throw invalidConfig('expectedOrigin must not contain a path');
  if (parsed.hostname !== rpId && !parsed.hostname.endsWith(`.${rpId}`)) {
    throw invalidConfig('rpId must be the origin host or one of its registrable suffixes');
  }
}

function normalizeConfig(config: WebAuthnRelyingPartyConfig): NormalizedConfig {
  if (config.rpName.trim() === '') throw invalidConfig('rpName must not be empty');
  if (config.rpId.trim() === '' || config.rpId.includes('://')) {
    throw invalidConfig('rpId must be a domain name without a URL scheme');
  }
  const origins = typeof config.expectedOrigin === 'string' ? [config.expectedOrigin] : config.expectedOrigin;
  const firstOrigin = origins[0];
  if (firstOrigin === undefined) throw invalidConfig('at least one expectedOrigin is required');
  for (const origin of origins) validateOrigin(origin, config.rpId);
  if (
    config.timeoutMs !== undefined &&
    (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0)
  ) {
    throw invalidConfig('timeoutMs must be a positive safe integer');
  }
  return Object.freeze({
    rpName: config.rpName,
    rpId: config.rpId,
    expectedOrigin: origins.length === 1 ? firstOrigin : [...origins],
    attestation: config.attestation ?? 'none',
    userVerification: config.userVerification ?? 'preferred',
    ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }),
  });
}

function descriptors(
  values: readonly WebAuthnCredentialDescriptor[] | undefined,
): { id: string; transports?: import('./types.js').WebAuthnTransport[] }[] | undefined {
  return values?.map((credential) => ({
    id: credential.id,
    ...(credential.transports === undefined ? {} : { transports: [...credential.transports] }),
  }));
}

export class AuthWebAuthnServer {
  readonly #config: NormalizedConfig;

  constructor(config: WebAuthnRelyingPartyConfig) {
    this.#config = normalizeConfig(config);
  }

  async generateRegistrationOptions(
    input: GenerateWebAuthnRegistrationOptionsInput,
  ): Promise<WebAuthnRegistrationOptions> {
    if (input.userName.trim() === '') throw new RangeError('userName must not be empty');
    return generateRegistrationOptions({
      rpName: this.#config.rpName,
      rpID: this.#config.rpId,
      userName: input.userName,
      ...(input.userDisplayName === undefined ? {} : { userDisplayName: input.userDisplayName }),
      ...(input.userId === undefined ? {} : { userID: Uint8Array.from(input.userId) }),
      ...(this.#config.timeoutMs === undefined ? {} : { timeout: this.#config.timeoutMs }),
      attestationType: this.#config.attestation,
      excludeCredentials: descriptors(input.excludeCredentials) ?? [],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: this.#config.userVerification,
      },
    });
  }

  async verifyRegistration(
    input: VerifyWebAuthnRegistrationInput,
  ): Promise<WebAuthnRegistrationResult> {
    const response = parseWebAuthnRegistrationResponse(input.response);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin: this.#config.expectedOrigin,
      expectedRPID: this.#config.rpId,
      requireUserVerification: this.#config.userVerification !== 'discouraged',
    });
    if (!verification.verified) {
      throw new AuthWebAuthnError('verification-failed', 'WebAuthn registration was not verified');
    }
    const info = verification.registrationInfo;
    const responseTransports = readWebAuthnResponseTransports(input.response);
    return Object.freeze({
      credential: Object.freeze({
        id: info.credential.id,
        publicKey: new Uint8Array(info.credential.publicKey),
        counter: info.credential.counter,
        ...(responseTransports.length === 0 ? {} : { transports: responseTransports }),
      }),
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      userVerified: info.userVerified,
      aaguid: info.aaguid,
      origin: info.origin,
      ...(info.rpID === undefined ? {} : { rpId: info.rpID }),
    });
  }

  async generateAuthenticationOptions(
    input: GenerateWebAuthnAuthenticationOptionsInput = {},
  ): Promise<WebAuthnAuthenticationOptions> {
    const allowCredentials = descriptors(input.allowCredentials);
    return generateAuthenticationOptions({
      rpID: this.#config.rpId,
      ...(this.#config.timeoutMs === undefined ? {} : { timeout: this.#config.timeoutMs }),
      ...(allowCredentials === undefined ? {} : { allowCredentials }),
      userVerification: this.#config.userVerification,
    });
  }

  async verifyAuthentication(
    input: VerifyWebAuthnAuthenticationInput,
  ): Promise<WebAuthnAuthenticationResult> {
    const verification = await verifyAuthenticationResponse({
      response: parseWebAuthnAuthenticationResponse(input.response),
      expectedChallenge: input.expectedChallenge,
      expectedOrigin: this.#config.expectedOrigin,
      expectedRPID: this.#config.rpId,
      requireUserVerification: this.#config.userVerification !== 'discouraged',
      credential: {
        id: input.credential.id,
        publicKey: Uint8Array.from(input.credential.publicKey),
        counter: input.credential.counter,
        ...(input.credential.transports === undefined
          ? {}
          : { transports: [...input.credential.transports] }),
      },
    });
    if (!verification.verified) {
      throw new AuthWebAuthnError('verification-failed', 'WebAuthn authentication was not verified');
    }
    const info = verification.authenticationInfo;
    return Object.freeze({
      credentialId: info.credentialID,
      newCounter: info.newCounter,
      userVerified: info.userVerified,
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
      origin: info.origin,
      rpId: info.rpID,
    });
  }
}

export function createAuthWebAuthnServer(config: WebAuthnRelyingPartyConfig): AuthWebAuthnServer {
  return new AuthWebAuthnServer(config);
}
