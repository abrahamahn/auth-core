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

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PasswordScore {
    VeryWeak = 0,
    Weak = 1,
    Fair = 2,
    Strong = 3,
    VeryStrong = 4,
}

impl PasswordScore {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for PasswordScore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_u8().fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordConfig {
    pub min_length: usize,
    pub max_length: usize,
    pub min_score: PasswordScore,
}

pub const DEFAULT_PASSWORD_CONFIG: PasswordConfig = PasswordConfig {
    min_length: 8,
    max_length: 64,
    min_score: PasswordScore::Strong,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordPenalties {
    pub is_common: bool,
    pub has_repeats: bool,
    pub has_sequence: bool,
    pub has_keyboard: bool,
    pub contains_input: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordFeedback {
    pub warning: String,
    pub suggestions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StrengthResult {
    pub score: PasswordScore,
    pub feedback: PasswordFeedback,
    pub crack_time_display: String,
    pub entropy: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PasswordValidationResult {
    pub is_valid: bool,
    pub score: PasswordScore,
    pub errors: Vec<String>,
    pub feedback: PasswordFeedback,
    pub crack_time_display: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicPasswordValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

fn javascript_length(value: &str) -> usize {
    value.encode_utf16().count()
}

const SIMPLE_SEQUENCES: &[&[u8]] = &[
    b"012", b"123", b"234", b"345", b"456", b"567", b"678", b"789", b"890",
];

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

#[must_use]
pub fn get_charset_size(password: &str) -> u32 {
    let mut size = 0;
    if password
        .chars()
        .any(|character| character.is_ascii_lowercase())
    {
        size += 26;
    }
    if password
        .chars()
        .any(|character| character.is_ascii_uppercase())
    {
        size += 26;
    }
    if password.chars().any(|character| character.is_ascii_digit()) {
        size += 10;
    }
    if password
        .chars()
        .any(|character| !character.is_ascii_alphanumeric())
    {
        size += 32;
    }
    if size == 0 { 1 } else { size }
}

#[must_use]
pub fn calculate_entropy(password: &str) -> f64 {
    let length = u32::try_from(javascript_length(password)).unwrap_or(u32::MAX);
    f64::from(length) * f64::from(get_charset_size(password)).log2()
}

#[must_use]
pub fn estimate_crack_time(entropy: f64) -> (f64, String) {
    let seconds = 2_f64.powf(entropy) / 10_000.0 / 2.0;
    let display = if seconds < 1.0 {
        "less than a second".to_owned()
    } else if seconds < 60.0 {
        format!("{} seconds", seconds.round())
    } else if seconds < 3_600.0 {
        format!("{} minutes", (seconds / 60.0).round())
    } else if seconds < 86_400.0 {
        format!("{} hours", (seconds / 3_600.0).round())
    } else if seconds < 2_592_000.0 {
        format!("{} days", (seconds / 86_400.0).round())
    } else if seconds < 31_536_000.0 {
        format!("{} months", (seconds / 2_592_000.0).round())
    } else if seconds < 3_153_600_000.0 {
        format!("{} years", (seconds / 31_536_000.0).round())
    } else {
        "centuries".to_owned()
    };
    (seconds, display)
}

#[must_use]
pub fn calculate_score(entropy: f64, penalties: PasswordPenalties) -> PasswordScore {
    let mut adjusted_entropy = entropy;
    if penalties.is_common {
        adjusted_entropy *= 0.1;
    }
    if penalties.has_repeats {
        adjusted_entropy *= 0.7;
    }
    if penalties.has_sequence {
        adjusted_entropy *= 0.7;
    }
    if penalties.has_keyboard {
        adjusted_entropy *= 0.5;
    }
    if penalties.contains_input {
        adjusted_entropy *= 0.5;
    }
    if adjusted_entropy < 20.0 {
        PasswordScore::VeryWeak
    } else if adjusted_entropy < 35.0 {
        PasswordScore::Weak
    } else if adjusted_entropy < 50.0 {
        PasswordScore::Fair
    } else if adjusted_entropy < 65.0 {
        PasswordScore::Strong
    } else {
        PasswordScore::VeryStrong
    }
}

#[must_use]
pub fn generate_feedback(password: &str, penalties: PasswordPenalties) -> PasswordFeedback {
    let mut suggestions = Vec::new();
    let mut warning = String::new();
    if penalties.is_common {
        warning.push_str("This is a commonly used password.");
        suggestions.push("Avoid common passwords".to_owned());
    }
    if penalties.contains_input {
        if warning.is_empty() {
            warning.push_str("This password contains personal information.");
        }
        suggestions.push("Avoid using personal information in passwords".to_owned());
    }
    if penalties.has_keyboard {
        if warning.is_empty() {
            warning.push_str("This password uses a keyboard pattern.");
        }
        suggestions.push("Avoid keyboard patterns like \"qwerty\" or \"asdf\"".to_owned());
    }
    if penalties.has_sequence {
        if warning.is_empty() {
            warning.push_str("This password contains sequential characters.");
        }
        suggestions.push("Avoid sequential characters like \"abc\" or \"123\"".to_owned());
    }
    if penalties.has_repeats {
        if warning.is_empty() {
            warning.push_str("This password has repeated characters.");
        }
        suggestions.push("Avoid repeated characters like \"aaa\"".to_owned());
    }
    if !password
        .chars()
        .any(|character| character.is_ascii_uppercase())
    {
        suggestions.push("Add uppercase letters".to_owned());
    }
    if !password
        .chars()
        .any(|character| character.is_ascii_lowercase())
    {
        suggestions.push("Add lowercase letters".to_owned());
    }
    if !password.chars().any(|character| character.is_ascii_digit()) {
        suggestions.push("Add numbers".to_owned());
    }
    if !password
        .chars()
        .any(|character| !character.is_ascii_alphanumeric())
    {
        suggestions.push("Add symbols".to_owned());
    }
    if javascript_length(password) < 12 {
        suggestions.push("Make the password longer".to_owned());
    }
    suggestions.truncate(3);
    PasswordFeedback {
        warning,
        suggestions,
    }
}

#[must_use]
pub fn estimate_password_strength(password: &str, user_inputs: &[&str]) -> StrengthResult {
    let entropy = calculate_entropy(password);
    let penalties = PasswordPenalties {
        is_common: is_common_password(password),
        has_repeats: has_repeated_chars(password, 3),
        has_sequence: has_sequential_chars(password, 3),
        has_keyboard: has_keyboard_pattern(password),
        contains_input: contains_user_input(password, user_inputs),
    };
    let score = calculate_score(entropy, penalties);
    StrengthResult {
        score,
        feedback: generate_feedback(password, penalties),
        crack_time_display: estimate_crack_time(entropy).1,
        entropy,
    }
}

#[must_use]
pub fn validate_password(
    password: &str,
    user_inputs: &[&str],
    config: PasswordConfig,
) -> PasswordValidationResult {
    let length = javascript_length(password);
    let mut errors = Vec::new();
    if length < config.min_length {
        errors.push(format!(
            "Password must be at least {} characters",
            config.min_length
        ));
    }
    if length > config.max_length {
        errors.push(format!(
            "Password must be at most {} characters",
            config.max_length
        ));
    }
    if !errors.is_empty() {
        return PasswordValidationResult {
            is_valid: false,
            score: PasswordScore::VeryWeak,
            errors,
            feedback: PasswordFeedback {
                warning: String::new(),
                suggestions: Vec::new(),
            },
            crack_time_display: "instant".to_owned(),
        };
    }
    let result = estimate_password_strength(password, user_inputs);
    if result.score < config.min_score {
        errors.push(format!(
            "Password is too weak (score: {}/{} required)",
            result.score, config.min_score
        ));
    }
    PasswordValidationResult {
        is_valid: errors.is_empty(),
        score: result.score,
        errors,
        feedback: result.feedback,
        crack_time_display: result.crack_time_display,
    }
}

#[must_use]
pub fn validate_password_basic(
    password: &str,
    config: PasswordConfig,
) -> BasicPasswordValidationResult {
    let length = javascript_length(password);
    let mut errors = Vec::new();
    if length < config.min_length {
        errors.push(format!(
            "Password must be at least {} characters",
            config.min_length
        ));
    }
    if length > config.max_length {
        errors.push(format!(
            "Password must be at most {} characters",
            config.max_length
        ));
    }
    let units = password.encode_utf16().collect::<Vec<_>>();
    if units.len() > 1 && units.windows(2).all(|pair| pair[0] == pair[1]) {
        errors.push("Password cannot be all the same character".to_owned());
    }
    let bytes = password.as_bytes();
    if !bytes.is_empty()
        && bytes.len().is_multiple_of(3)
        && bytes
            .chunks_exact(3)
            .all(|chunk| SIMPLE_SEQUENCES.contains(&chunk))
    {
        errors.push("Password cannot be a simple sequence".to_owned());
    }
    BasicPasswordValidationResult {
        is_valid: errors.is_empty(),
        errors,
    }
}

#[must_use]
pub const fn get_strength_label(score: PasswordScore) -> &'static str {
    match score {
        PasswordScore::VeryWeak => "Very Weak",
        PasswordScore::Weak => "Weak",
        PasswordScore::Fair => "Fair",
        PasswordScore::Strong => "Strong",
        PasswordScore::VeryStrong => "Very Strong",
    }
}
