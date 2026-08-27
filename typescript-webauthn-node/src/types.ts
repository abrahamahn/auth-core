import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  CredentialDeviceType,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

export type WebAuthnTransport = AuthenticatorTransportFuture;
export type WebAuthnDeviceType = CredentialDeviceType;
export type WebAuthnRegistrationResponse = RegistrationResponseJSON;
export type WebAuthnAuthenticationResponse = AuthenticationResponseJSON;
export type WebAuthnRegistrationOptions =
  PublicKeyCredentialCreationOptionsJSON;
export type WebAuthnAuthenticationOptions =
  PublicKeyCredentialRequestOptionsJSON;

export interface WebAuthnRelyingPartyConfig {
  readonly rpName: string;
  readonly rpId: string;
  readonly expectedOrigin: string | readonly string[];
  readonly attestation?: "none" | "direct" | "enterprise" | undefined;
  readonly userVerification?:
    | "required"
    | "preferred"
    | "discouraged"
    | undefined;
  readonly timeoutMs?: number | undefined;
}

export interface WebAuthnCredentialDescriptor {
  readonly id: string;
  readonly transports?: readonly WebAuthnTransport[] | undefined;
}

export interface GenerateWebAuthnRegistrationOptionsInput {
  readonly userName: string;
  readonly userDisplayName?: string | undefined;
  readonly userId?: Uint8Array | undefined;
  readonly excludeCredentials?:
    | readonly WebAuthnCredentialDescriptor[]
    | undefined;
}

export interface GenerateWebAuthnAuthenticationOptionsInput {
  readonly allowCredentials?:
    | readonly WebAuthnCredentialDescriptor[]
    | undefined;
}

export interface VerifyWebAuthnRegistrationInput {
  readonly response: unknown;
  readonly expectedChallenge: string;
}

export interface WebAuthnRegistrationResult {
  readonly credential: {
    readonly id: string;
    readonly publicKey: Uint8Array;
    readonly counter: number;
    readonly transports?: readonly WebAuthnTransport[] | undefined;
  };
  readonly deviceType: WebAuthnDeviceType;
  readonly backedUp: boolean;
  readonly userVerified: boolean;
  readonly aaguid: string;
  readonly origin: string;
  readonly rpId?: string | undefined;
}

export interface StoredWebAuthnCredential {
  readonly id: string;
  readonly publicKey: Uint8Array;
  readonly counter: number;
  readonly transports?: readonly WebAuthnTransport[] | undefined;
}

export interface VerifyWebAuthnAuthenticationInput {
  readonly response: unknown;
  readonly expectedChallenge: string;
  readonly credential: StoredWebAuthnCredential;
}

export interface WebAuthnAuthenticationResult {
  readonly credentialId: string;
  readonly newCounter: number;
  readonly userVerified: boolean;
  readonly deviceType: WebAuthnDeviceType;
  readonly backedUp: boolean;
  readonly origin: string;
  readonly rpId: string;
}
