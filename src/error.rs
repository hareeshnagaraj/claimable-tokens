//! Error types

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use solana_program::{
    decode_error::DecodeError,
    msg,
    program_error::{PrintProgramError, ProgramError},
};
use thiserror::Error;

/// Errors that may be returned by the Claimable-tokens program.
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum ClaimableProgramError {
    /// Example error
    #[error("Example error")]
    ExampleError,
}
impl From<ClaimableProgramError> for ProgramError {
    fn from(e: ClaimableProgramError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
impl<T> DecodeError<T> for ClaimableProgramError {
    fn type_of() -> &'static str {
        "ClaimableProgramError"
    }
}

impl PrintProgramError for ClaimableProgramError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        match self {
            ClaimableProgramError::ExampleError => msg!("Example error message"),
        }
    }
}
