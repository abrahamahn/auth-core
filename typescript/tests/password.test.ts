import { describe, expect, it } from 'vitest';

import {
  estimatePasswordStrength,
  hasSequentialChars,
  isCommonPassword,
  validatePassword,
  validatePasswordBasic,
} from '../src/index.js';

describe('password assessment', () => {
  it('preserves configurable length and score policy', () => {
    expect(validatePassword('short').isValid).toBe(false);
    expect(validatePassword('MyStr0ng!P@ssword2024').isValid).toBe(true);
    expect(validatePasswordBasic('123123123').errors).toContain(
      'Password cannot be a simple sequence',
    );
  });

  it('detects common, sequential, and user-derived values deterministically', () => {
    expect(isCommonPassword('p4ssw0rd')).toBe(true);
    expect(hasSequentialChars('cba')).toBe(true);
    const base = estimatePasswordStrength('johnsmith2024');
    const personalized = estimatePasswordStrength('johnsmith2024', ['john', 'smith']);
    expect(personalized.score).toBeLessThanOrEqual(base.score);
  });
});
