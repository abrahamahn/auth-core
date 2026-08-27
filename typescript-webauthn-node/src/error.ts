export type WebAuthnErrorCode =
  | 'invalid-config'
  | 'invalid-response'
  | 'verification-failed'
  | 'ceremony-missing'
  | 'ceremony-expired'
  | 'ceremony-mismatch';

export class AuthWebAuthnError extends Error {
  readonly code: WebAuthnErrorCode;

  constructor(code: WebAuthnErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AuthWebAuthnError';
    this.code = code;
  }
}
