pub const COMMON_PASSWORDS: &[&str] = &[
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
];

pub const KEYBOARD_PATTERNS: &[&str] = &[
    "qwerty", "qwertz", "azerty", "asdf", "asdfgh", "zxcv", "zxcvbn", "qazwsx", "1qaz2wsx", "1234",
    "12345", "123456", "1234567", "12345678", "0987", "09876", "098765", "0987654", "09876543",
];

const SIMPLE_SEQUENCES: &[&[u8]] = &[
    b"012", b"123", b"234", b"345", b"456", b"567", b"678", b"789", b"890",
];

pub(crate) fn javascript_length(value: &str) -> usize {
    value.encode_utf16().count()
}

pub(crate) fn is_simple_numeric_sequence(password: &str) -> bool {
    let bytes = password.as_bytes();
    !bytes.is_empty()
        && bytes.len().is_multiple_of(3)
        && bytes
            .chunks_exact(3)
            .all(|chunk| SIMPLE_SEQUENCES.contains(&chunk))
}

#[must_use]
pub fn has_repeated_chars(password: &str, min_length: usize) -> bool {
    let units = password.encode_utf16().collect::<Vec<_>>();
    if min_length <= 1 {
        return !units.is_empty();
    }
    let mut run_length = 1;
    for pair in units.windows(2) {
        if pair[0] == pair[1] {
            run_length += 1;
            if run_length >= min_length {
                return true;
            }
        } else {
            run_length = 1;
        }
    }
    false
}

/// Returns true when the complete password is two or more copies of one shorter pattern.
#[must_use]
pub fn has_repeated_pattern(password: &str) -> bool {
    let units = password.encode_utf16().collect::<Vec<_>>();
    (1..=units.len() / 2).any(|pattern_length| {
        units.len().is_multiple_of(pattern_length)
            && (pattern_length..units.len())
                .all(|index| units[index] == units[index % pattern_length])
    })
}

#[must_use]
pub fn has_sequential_chars(password: &str, min_length: usize) -> bool {
    if min_length == 0 {
        return true;
    }
    let lower = password.to_lowercase().encode_utf16().collect::<Vec<_>>();
    lower.windows(min_length).any(|window| {
        window
            .windows(2)
            .all(|pair| u32::from(pair[1]) == u32::from(pair[0]) + 1)
            || window
                .windows(2)
                .all(|pair| u32::from(pair[0]) == u32::from(pair[1]) + 1)
    })
}

#[must_use]
pub fn has_keyboard_pattern(password: &str) -> bool {
    let lower = password.to_lowercase();
    KEYBOARD_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

#[must_use]
pub fn is_common_password(password: &str) -> bool {
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        return true;
    }
    let normalized = lower
        .chars()
        .map(|character| match character {
            '0' => 'o',
            '1' | '!' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            other => other,
        })
        .collect::<String>();
    if COMMON_PASSWORDS.contains(&normalized.as_str()) {
        return true;
    }
    let without_trailing_numbers =
        lower.trim_end_matches(|character: char| character.is_ascii_digit());
    javascript_length(without_trailing_numbers) >= 4
        && COMMON_PASSWORDS.contains(&without_trailing_numbers)
}

#[must_use]
pub fn contains_user_input(password: &str, user_inputs: &[&str]) -> bool {
    let lower = password.to_lowercase();
    user_inputs.iter().any(|input| {
        let candidate = input.to_lowercase();
        javascript_length(&candidate) >= 3 && lower.contains(&candidate)
    })
}
