use crate::password_patterns::{
    contains_user_input, has_keyboard_pattern, has_repeated_chars, has_repeated_pattern,
    has_sequential_chars, is_common_password, is_simple_numeric_sequence, javascript_length,
};

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
    let adjusted_entropy = effective_entropy(entropy, penalties);
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

fn effective_entropy(entropy: f64, penalties: PasswordPenalties) -> f64 {
    if !entropy.is_finite() || entropy <= 0.0 || penalties.is_common {
        return 0.0;
    }
    let mut adjusted_entropy = entropy;
    if penalties.has_repeats {
        adjusted_entropy = (adjusted_entropy * 0.25).min(19.0);
    }
    if penalties.has_keyboard {
        adjusted_entropy = (adjusted_entropy * 0.5).min(34.0);
    }
    if penalties.has_sequence {
        adjusted_entropy = (adjusted_entropy * 0.7).min(49.0);
    }
    if penalties.contains_input {
        adjusted_entropy = (adjusted_entropy * 0.5).min(34.0);
    }
    adjusted_entropy.max(0.0)
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
        has_repeats: has_repeated_chars(password, 3) || has_repeated_pattern(password),
        has_sequence: has_sequential_chars(password, 3),
        has_keyboard: has_keyboard_pattern(password),
        contains_input: contains_user_input(password, user_inputs),
    };
    let score = calculate_score(entropy, penalties);
    StrengthResult {
        score,
        feedback: generate_feedback(password, penalties),
        crack_time_display: estimate_crack_time(effective_entropy(entropy, penalties)).1,
        entropy,
    }
}

fn validate_length_bounds(password: &str, config: PasswordConfig) -> Vec<String> {
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
    errors
}

#[must_use]
pub fn validate_password(
    password: &str,
    user_inputs: &[&str],
    config: PasswordConfig,
) -> PasswordValidationResult {
    let mut errors = validate_length_bounds(password, config);
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
    if is_common_password(password) {
        errors.push("Password appears on the built-in common-password blocklist".to_owned());
    }
    if has_repeated_chars(password, 3) || has_repeated_pattern(password) {
        errors.push("Password cannot be a repeated character or pattern".to_owned());
    }
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
    let mut errors = validate_length_bounds(password, config);
    let units = password.encode_utf16().collect::<Vec<_>>();
    if units.len() > 1 && units.windows(2).all(|pair| pair[0] == pair[1]) {
        errors.push("Password cannot be all the same character".to_owned());
    }
    if is_simple_numeric_sequence(password) {
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
