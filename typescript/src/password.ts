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

export const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password',
  '123456',
  '12345678',
  '123456789',
  '1234567890',
  'qwerty',
  'abc123',
  '111111',
  'password1',
  'iloveyou',
  'admin',
  'welcome',
  'monkey',
  'dragon',
  'master',
  'letmein',
  'login',
  'princess',
  'football',
  'shadow',
  'sunshine',
  'trustno1',
  'batman',
  'access',
  'hello',
  'charlie',
  'donald',
  '!@#$%^&*',
  'passw0rd',
  'qwerty123',
]);

export const KEYBOARD_PATTERNS: readonly string[] = [
  'qwerty',
  'qwertz',
  'azerty',
  'asdf',
  'asdfgh',
  'zxcv',
  'zxcvbn',
  'qazwsx',
  '1qaz2wsx',
  '1234',
  '12345',
  '123456',
  '1234567',
  '12345678',
  '0987',
  '09876',
  '098765',
  '0987654',
  '09876543',
];

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

export function hasRepeatedChars(password: string, minLength = 3): boolean {
  if (minLength <= 1) return password.length > 0;
  let runLength = 1;
  for (let index = 1; index < password.length; index++) {
    if (password.charCodeAt(index) === password.charCodeAt(index - 1)) {
      runLength += 1;
      if (runLength >= minLength) return true;
    } else {
      runLength = 1;
    }
  }
  return false;
}

export function hasSequentialChars(password: string, minLength = 3): boolean {
  const lower = password.toLowerCase();
  for (let start = 0; start <= lower.length - minLength; start++) {
    let ascending = true;
    let descending = true;
    for (let offset = 1; offset < minLength; offset++) {
      if (lower.charCodeAt(start + offset) !== lower.charCodeAt(start + offset - 1) + 1) {
        ascending = false;
      }
      if (lower.charCodeAt(start + offset) !== lower.charCodeAt(start + offset - 1) - 1) {
        descending = false;
      }
    }
    if (ascending || descending) return true;
  }
  return false;
}

export function hasKeyboardPattern(password: string): boolean {
  const lower = password.toLowerCase();
  return KEYBOARD_PATTERNS.some((pattern) => lower.includes(pattern));
}

export function isCommonPassword(password: string): boolean {
  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return true;
  const normalized = lower
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/8/g, 'b')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's')
    .replace(/!/g, 'i');
  if (COMMON_PASSWORDS.has(normalized)) return true;
  let trimIndex = lower.length;
  while (trimIndex > 0) {
    const code = lower.charCodeAt(trimIndex - 1);
    if (code < 48 || code > 57) break;
    trimIndex -= 1;
  }
  const withoutTrailingNumbers = lower.slice(0, trimIndex);
  return withoutTrailingNumbers.length >= 4 && COMMON_PASSWORDS.has(withoutTrailingNumbers);
}

export function containsUserInput(password: string, userInputs: readonly string[]): boolean {
  const lower = password.toLowerCase();
  return userInputs.some((input) => {
    const candidate = input.toLowerCase();
    return candidate.length >= 3 && lower.includes(candidate);
  });
}

export function getCharsetSize(password: string): number {
  let size = 0;
  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 32;
  return size === 0 ? 1 : size;
}

export function calculateEntropy(password: string): number {
  return password.length * Math.log2(getCharsetSize(password));
}

export function estimateCrackTime(entropy: number): {
  seconds: number;
  display: string;
} {
  const seconds = Math.pow(2, entropy) / 10_000 / 2;
  if (seconds < 1) return { seconds, display: 'less than a second' };
  if (seconds < 60) return { seconds, display: `${String(Math.round(seconds))} seconds` };
  if (seconds < 3600) return { seconds, display: `${String(Math.round(seconds / 60))} minutes` };
  if (seconds < 86_400) return { seconds, display: `${String(Math.round(seconds / 3600))} hours` };
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
  return { seconds, display: 'centuries' };
}

export function calculateScore(entropy: number, penalties: PasswordPenalties): PasswordScore {
  let adjustedEntropy = entropy;
  if (penalties.isCommon) adjustedEntropy *= 0.1;
  if (penalties.hasRepeats) adjustedEntropy *= 0.7;
  if (penalties.hasSequence) adjustedEntropy *= 0.7;
  if (penalties.hasKeyboard) adjustedEntropy *= 0.5;
  if (penalties.containsInput) adjustedEntropy *= 0.5;
  if (adjustedEntropy < 20) return 0;
  if (adjustedEntropy < 35) return 1;
  if (adjustedEntropy < 50) return 2;
  if (adjustedEntropy < 65) return 3;
  return 4;
}

export function generateFeedback(password: string, penalties: PasswordPenalties): PasswordFeedback {
  const suggestions: string[] = [];
  let warning = '';
  if (penalties.isCommon) {
    warning = 'This is a commonly used password.';
    suggestions.push('Avoid common passwords');
  }
  if (penalties.containsInput) {
    warning ||= 'This password contains personal information.';
    suggestions.push('Avoid using personal information in passwords');
  }
  if (penalties.hasKeyboard) {
    warning ||= 'This password uses a keyboard pattern.';
    suggestions.push('Avoid keyboard patterns like "qwerty" or "asdf"');
  }
  if (penalties.hasSequence) {
    warning ||= 'This password contains sequential characters.';
    suggestions.push('Avoid sequential characters like "abc" or "123"');
  }
  if (penalties.hasRepeats) {
    warning ||= 'This password has repeated characters.';
    suggestions.push('Avoid repeated characters like "aaa"');
  }
  if (!/[A-Z]/.test(password)) suggestions.push('Add uppercase letters');
  if (!/[a-z]/.test(password)) suggestions.push('Add lowercase letters');
  if (!/[0-9]/.test(password)) suggestions.push('Add numbers');
  if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Add symbols');
  if (password.length < 12) suggestions.push('Make the password longer');
  return { warning, suggestions: suggestions.slice(0, 3) };
}

export function estimatePasswordStrength(
  password: string,
  userInputs: readonly string[] = [],
): StrengthResult {
  const entropy = calculateEntropy(password);
  const penalties: PasswordPenalties = {
    isCommon: isCommonPassword(password),
    hasRepeats: hasRepeatedChars(password),
    hasSequence: hasSequentialChars(password),
    hasKeyboard: hasKeyboardPattern(password),
    containsInput: containsUserInput(password, userInputs),
  };
  const score = calculateScore(entropy, penalties);
  return {
    score,
    feedback: generateFeedback(password, penalties),
    crackTimeDisplay: estimateCrackTime(entropy).display,
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
    errors.push(`Password must be at least ${String(config.minLength)} characters`);
  }
  if (password.length > config.maxLength) {
    errors.push(`Password must be at most ${String(config.maxLength)} characters`);
  }
  if (errors.length > 0) {
    return {
      isValid: false,
      score: 0,
      errors,
      feedback: { warning: '', suggestions: [] },
      crackTimeDisplay: 'instant',
    };
  }
  const result = estimatePasswordStrength(password, userInputs);
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
    errors.push(`Password must be at least ${String(config.minLength)} characters`);
  }
  if (password.length > config.maxLength) {
    errors.push(`Password must be at most ${String(config.maxLength)} characters`);
  }
  if (/^(.)\1+$/.test(password)) errors.push('Password cannot be all the same character');
  if (/^(012|123|234|345|456|567|678|789|890)+$/.test(password)) {
    errors.push('Password cannot be a simple sequence');
  }
  return { isValid: errors.length === 0, errors };
}

export function getStrengthLabel(score: number): string {
  switch (score) {
    case 0:
      return 'Very Weak';
    case 1:
      return 'Weak';
    case 2:
      return 'Fair';
    case 3:
      return 'Strong';
    case 4:
      return 'Very Strong';
    default:
      return 'Unknown';
  }
}
