import { JwtError } from "./error.js";
import { sign, verify } from "./jwt.js";

import type {
  JwtPayload,
  JwtSecret,
  SignOptions,
  VerifyOptions,
} from "./error.js";

export interface JwtRotationConfig {
  readonly secret: JwtSecret;
  readonly previousSecret?: JwtSecret;
}

export interface RotatingJwtOptions extends SignOptions {
  readonly config?: JwtRotationConfig;
}

export type UsedJwtSecret = "current" | "previous" | "none";

export interface TokenSecretCheck {
  readonly isValid: boolean;
  readonly usedSecret: UsedJwtSecret;
  readonly error?: JwtError;
}

function hasSecret(secret: JwtSecret | undefined): secret is JwtSecret {
  return (
    secret !== undefined &&
    (typeof secret === "string" ? secret !== "" : secret.byteLength > 0)
  );
}

/** Sign only with the current secret. */
export function signWithRotation(
  payload: object,
  config: JwtRotationConfig,
  options?: SignOptions,
): string {
  return sign(payload, config.secret, options);
}

/** Verify with the current secret, falling back only after a signature mismatch. */
export function verifyWithRotation(
  token: string,
  config: JwtRotationConfig,
  options?: VerifyOptions,
): JwtPayload {
  try {
    return verify(token, config.secret, options);
  } catch (currentError) {
    if (
      currentError instanceof JwtError &&
      currentError.code === "INVALID_SIGNATURE" &&
      hasSecret(config.previousSecret)
    ) {
      try {
        return verify(token, config.previousSecret, options);
      } catch {
        throw currentError;
      }
    }
    throw currentError;
  }
}

/** Report which configured secret verifies a token. */
export function checkTokenSecret(
  token: string,
  config: JwtRotationConfig,
  options?: VerifyOptions,
): TokenSecretCheck {
  try {
    verify(token, config.secret, options);
    return { isValid: true, usedSecret: "current" };
  } catch (currentError) {
    if (
      currentError instanceof JwtError &&
      currentError.code === "INVALID_SIGNATURE" &&
      hasSecret(config.previousSecret)
    ) {
      try {
        verify(token, config.previousSecret, options);
        return { isValid: true, usedSecret: "previous" };
      } catch {
        // Preserve the current-secret error below.
      }
    }
    return currentError instanceof JwtError
      ? { isValid: false, usedSecret: "none", error: currentError }
      : { isValid: false, usedSecret: "none" };
  }
}

export interface JwtRotationHandler {
  sign(payload: object, options?: SignOptions): string;
  verify(token: string, options?: VerifyOptions): JwtPayload;
  checkSecret(token: string, options?: VerifyOptions): TokenSecretCheck;
  isRotating(): boolean;
  getConfig(): {
    readonly hasSecret: boolean;
    readonly hasPreviousSecret: boolean;
  };
}

/** Bind immutable key-rotation configuration to a small signing and verification facade. */
export function createJwtRotationHandler(
  config: JwtRotationConfig,
): JwtRotationHandler {
  return {
    sign: (payload, options) => signWithRotation(payload, config, options),
    verify: (token, options) => verifyWithRotation(token, config, options),
    checkSecret: (token, options) => checkTokenSecret(token, config, options),
    isRotating: () => hasSecret(config.previousSecret),
    getConfig: () => ({
      hasSecret: hasSecret(config.secret),
      hasPreviousSecret: hasSecret(config.previousSecret),
    }),
  };
}
