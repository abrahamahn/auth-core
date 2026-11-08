export const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  "password",
  "123456",
  "12345678",
  "123456789",
  "1234567890",
  "qwerty",
  "abc123",
  "111111",
  "password1",
  "iloveyou",
  "admin",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "letmein",
  "login",
  "princess",
  "football",
  "shadow",
  "sunshine",
  "trustno1",
  "batman",
  "access",
  "hello",
  "charlie",
  "donald",
  "!@#$%^&*",
  "passw0rd",
  "qwerty123",
]);

export const KEYBOARD_PATTERNS: readonly string[] = [
  "qwerty",
  "qwertz",
  "azerty",
  "asdf",
  "asdfgh",
  "zxcv",
  "zxcvbn",
  "qazwsx",
  "1qaz2wsx",
  "1234",
  "12345",
  "123456",
  "1234567",
  "12345678",
  "0987",
  "09876",
  "098765",
  "0987654",
  "09876543",
];

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

/** Returns true when the complete password is two or more copies of one shorter pattern. */
export function hasRepeatedPattern(password: string): boolean {
  for (
    let patternLength = 1;
    patternLength <= Math.floor(password.length / 2);
    patternLength++
  ) {
    if (password.length % patternLength !== 0) continue;
    let repeated = true;
    for (let index = patternLength; index < password.length; index++) {
      if (
        password.charCodeAt(index) !==
        password.charCodeAt(index % patternLength)
      ) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }
  return false;
}

export function hasSequentialChars(password: string, minLength = 3): boolean {
  const lower = password.toLowerCase();
  for (let start = 0; start <= lower.length - minLength; start++) {
    let ascending = true;
    let descending = true;
    for (let offset = 1; offset < minLength; offset++) {
      if (
        lower.charCodeAt(start + offset) !==
        lower.charCodeAt(start + offset - 1) + 1
      ) {
        ascending = false;
      }
      if (
        lower.charCodeAt(start + offset) !==
        lower.charCodeAt(start + offset - 1) - 1
      ) {
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
    .replace(/0/g, "o")
    .replace(/1/g, "i")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b")
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .replace(/!/g, "i");
  if (COMMON_PASSWORDS.has(normalized)) return true;
  let trimIndex = lower.length;
  while (trimIndex > 0) {
    const code = lower.charCodeAt(trimIndex - 1);
    if (code < 48 || code > 57) break;
    trimIndex -= 1;
  }
  const withoutTrailingNumbers = lower.slice(0, trimIndex);
  return (
    withoutTrailingNumbers.length >= 4 &&
    COMMON_PASSWORDS.has(withoutTrailingNumbers)
  );
}

export function containsUserInput(
  password: string,
  userInputs: readonly string[],
): boolean {
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
