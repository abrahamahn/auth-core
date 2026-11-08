import {
  calculateEntropy,
  containsUserInput,
  hasKeyboardPattern,
  hasRepeatedChars,
  hasRepeatedPattern,
  hasSequentialChars,
  isCommonPassword,
} from "./password-patterns.js";

export type PasswordScore = 0 | 1 | 2 | 3 | 4;

export interface PasswordConfig {
  readonly minLength: number;
  readonly maxLength: number;
  readonly minScore: PasswordScore;
}

export const DEFAULT_PASSWORD_CONFIG = {
  minLength: 8,
  maxLength: 64,
  minScore: 3,
} as const satisfies PasswordConfig;

export interface PasswordPenalties {
  readonly isCommon: boolean;
  readonly hasRepeats: boolean;
  readonly hasSequence: boolean;
  readonly hasKeyboard: boolean;
  readonly containsInput: boolean;
}

export interface PasswordFeedback {
  readonly warning: string;
  readonly suggestions: string[];
}

export interface StrengthResult {
  readonly score: PasswordScore;
  readonly feedback: PasswordFeedback;
  readonly crackTimeDisplay: string;
  readonly entropy: number;
}

export interface PasswordValidationResult {
  readonly isValid: boolean;
  readonly score: PasswordScore;
  readonly errors: string[];
  readonly feedback: PasswordFeedback;
  readonly crackTimeDisplay: string;
}

export interface BasicPasswordValidationResult {
  readonly isValid: boolean;
  readonly errors: string[];
}

export function estimateCrackTime(entropy: number): {
  seconds: number;
  display: string;
} {
  const seconds = Math.pow(2, entropy) / 10_000 / 2;
  if (seconds < 1) return { seconds, display: "less than a second" };
  if (seconds < 60)
    return { seconds, display: `${String(Math.round(seconds))} seconds` };
  if (seconds < 3600)
    return { seconds, display: `${String(Math.round(seconds / 60))} minutes` };
  if (seconds < 86_400)
    return { seconds, display: `${String(Math.round(seconds / 3600))} hours` };
  if (seconds < 2_592_000)
    return { seconds, display: `${String(Math.round(seconds / 86_400))} days` };
  if (seconds < 31_536_000)
    return {
      seconds,
      display: `${String(Math.round(seconds / 2_592_000))} months`,
    };
  if (seconds < 3_153_600_000)
    return {
      seconds,
      display: `${String(Math.round(seconds / 31_536_000))} years`,
    };
  return { seconds, display: "centuries" };
}

export function calculateScore(
  entropy: number,
  penalties: PasswordPenalties,
): PasswordScore {
  const adjustedEntropy = effectiveEntropy(entropy, penalties);
  if (adjustedEntropy < 20) return 0;
  if (adjustedEntropy < 35) return 1;
  if (adjustedEntropy < 50) return 2;
  if (adjustedEntropy < 65) return 3;
  return 4;
}

function effectiveEntropy(
  entropy: number,
  penalties: PasswordPenalties,
): number {
  if (!Number.isFinite(entropy) || entropy <= 0 || penalties.isCommon) return 0;
  let adjustedEntropy = entropy;
  // Length must never let an obvious repeated or keyboard pattern outrank its weakness.
  if (penalties.hasRepeats)
    adjustedEntropy = Math.min(adjustedEntropy * 0.25, 19);
  if (penalties.hasKeyboard)
    adjustedEntropy = Math.min(adjustedEntropy * 0.5, 34);
  if (penalties.hasSequence)
    adjustedEntropy = Math.min(adjustedEntropy * 0.7, 49);
  if (penalties.containsInput)
    adjustedEntropy = Math.min(adjustedEntropy * 0.5, 34);
  return Math.max(0, adjustedEntropy);
}

export function generateFeedback(
  password: string,
  penalties: PasswordPenalties,
): PasswordFeedback {
  const suggestions: string[] = [];
  let warning = "";
  if (penalties.isCommon) {
    warning = "This is a commonly used password.";
    suggestions.push("Avoid common passwords");
  }
  if (penalties.containsInput) {
    warning ||= "This password contains personal information.";
    suggestions.push("Avoid using personal information in passwords");
  }
  if (penalties.hasKeyboard) {
    warning ||= "This password uses a keyboard pattern.";
    suggestions.push('Avoid keyboard patterns like "qwerty" or "asdf"');
  }
  if (penalties.hasSequence) {
    warning ||= "This password contains sequential characters.";
    suggestions.push('Avoid sequential characters like "abc" or "123"');
  }
  if (penalties.hasRepeats) {
    warning ||= "This password has repeated characters.";
    suggestions.push('Avoid repeated characters like "aaa"');
  }
  if (!/[A-Z]/.test(password)) suggestions.push("Add uppercase letters");
  if (!/[a-z]/.test(password)) suggestions.push("Add lowercase letters");
  if (!/[0-9]/.test(password)) suggestions.push("Add numbers");
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push("Add symbols");
  if (password.length < 12) suggestions.push("Make the password longer");
  return { warning, suggestions: suggestions.slice(0, 3) };
}

export function estimatePasswordStrength(
  password: string,
  userInputs: readonly string[] = [],
): StrengthResult {
  const entropy = calculateEntropy(password);
  const penalties: PasswordPenalties = {
    isCommon: isCommonPassword(password),
    hasRepeats: hasRepeatedChars(password) || hasRepeatedPattern(password),
    hasSequence: hasSequentialChars(password),
    hasKeyboard: hasKeyboardPattern(password),
    containsInput: containsUserInput(password, userInputs),
  };
  const score = calculateScore(entropy, penalties);
  return {
    score,
    feedback: generateFeedback(password, penalties),
    crackTimeDisplay: estimateCrackTime(effectiveEntropy(entropy, penalties))
      .display,
    entropy,
  };
}

export function validatePassword(
  password: string,
  userInputs: readonly string[] = [],
  config: PasswordConfig = DEFAULT_PASSWORD_CONFIG,
): PasswordValidationResult {
  const errors: string[] = [];
  if (password.length < config.minLength) {
    errors.push(
      `Password must be at least ${String(config.minLength)} characters`,
    );
  }
  if (password.length > config.maxLength) {
    errors.push(
      `Password must be at most ${String(config.maxLength)} characters`,
    );
  }
  if (errors.length > 0) {
    return {
      isValid: false,
      score: 0,
      errors,
      feedback: { warning: "", suggestions: [] },
      crackTimeDisplay: "instant",
    };
  }
  const result = estimatePasswordStrength(password, userInputs);
  if (isCommonPassword(password)) {
    errors.push("Password appears on the built-in common-password blocklist");
  }
  if (hasRepeatedChars(password) || hasRepeatedPattern(password)) {
    errors.push("Password cannot be a repeated character or pattern");
  }
  if (result.score < config.minScore) {
    errors.push(
      `Password is too weak (score: ${String(result.score)}/${String(config.minScore)} required)`,
    );
  }
  return {
    isValid: errors.length === 0,
    score: result.score,
    errors,
    feedback: result.feedback,
    crackTimeDisplay: result.crackTimeDisplay,
  };
}

export function validatePasswordBasic(
  password: string,
  config: PasswordConfig = DEFAULT_PASSWORD_CONFIG,
): BasicPasswordValidationResult {
  const errors: string[] = [];
  if (password.length < config.minLength) {
    errors.push(
      `Password must be at least ${String(config.minLength)} characters`,
    );
  }
  if (password.length > config.maxLength) {
    errors.push(
      `Password must be at most ${String(config.maxLength)} characters`,
    );
  }
  if (/^(.)\1+$/.test(password))
    errors.push("Password cannot be all the same character");
  if (/^(012|123|234|345|456|567|678|789|890)+$/.test(password)) {
    errors.push("Password cannot be a simple sequence");
  }
  return { isValid: errors.length === 0, errors };
}

export function getStrengthLabel(score: number): string {
  switch (score) {
    case 0:
      return "Very Weak";
    case 1:
      return "Weak";
    case 2:
      return "Fair";
    case 3:
      return "Strong";
    case 4:
      return "Very Strong";
    default:
      return "Unknown";
  }
}
