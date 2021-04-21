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
    /// Eth address converting error
    #[error("Eth address converting error")]
    EthAddressConvertingErr,
    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    /// Secp256 instruction losing
    #[error("Secp256 instruction losing")]
    Secp256InstructionLosing,
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
            ClaimableProgramError::EthAddressConvertingErr => msg!("Eth address converting error"),
            ClaimableProgramError::SignatureVerificationFailed => {
                msg!("Signature verification failed")
            }
            ClaimableProgramError::Secp256InstructionLosing => msg!("Secp256 instruction losing"),
        }
    }
}
