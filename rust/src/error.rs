use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    InvalidValue(&'static str),
    ArithmeticOverflow(&'static str),
}

impl Display for AuthError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValue(message) | Self::ArithmeticOverflow(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for AuthError {}

pub type AuthResult<T> = Result<T, AuthError>;
