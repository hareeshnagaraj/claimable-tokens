//! Extended functionality for Pubkey
use solana_program::{
    program_error::ProgramError,
    pubkey::{Pubkey, PubkeyError},
};

/// some well know often users patters for program derived keys
pub trait PubkeyPatterns {
    /// generate program derived address, self as seedKey
    fn get_pda(
        self,
        string_seeds: &str,
        base_program_id: &Pubkey,
        pda_program_id: &Pubkey,
    ) -> Result<(Pubkey, u8, Pubkey), PubkeyError>;
    /// check that it's generated correct
    fn derived_right(
        self,
        seed_key: &Pubkey,
        string_seeds: &str,
        base_program_id: &Pubkey,
        pda_program_id: &Pubkey,
    ) -> Result<(Pubkey, u8), ProgramError>;
    /// check if program address was generated correct
    fn program_address_generated_correct(
        self,
        seed_key: &Pubkey,
        program_id: &Pubkey,
    ) -> Result<u8, ProgramError>;
}

impl PubkeyPatterns for Pubkey {
    fn get_pda(
        self,
        string_seeds: &str,
        base_program_id: &Pubkey,
        pda_program_id: &Pubkey,
    ) -> Result<(Pubkey, u8, Pubkey), PubkeyError> {
        let (base, bump) = Pubkey::find_program_address(&[&self.to_bytes()[..32]], base_program_id);
        let derived_key = Pubkey::create_with_seed(&base, string_seeds, pda_program_id)?;
        Ok((base, bump, derived_key))
    }

    fn derived_right(
        self,
        seed_key: &Pubkey,
        string_seeds: &str,
        base_program_id: &Pubkey,
        pda_program_id: &Pubkey,
    ) -> Result<(Pubkey, u8), ProgramError> {
        let (base, bump, derived_key) =
            seed_key.get_pda(string_seeds, base_program_id, pda_program_id)?;
        if self != derived_key {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok((base, bump))
    }

    fn program_address_generated_correct(
        self,
        seed_key: &Pubkey,
        program_id: &Pubkey,
    ) -> Result<u8, ProgramError> {
        let (generated, bump_seed) =
            Pubkey::find_program_address(&[&seed_key.to_bytes()[..32]], program_id);
        if self != generated {
            return Err(ProgramError::InvalidSeeds);
        }
        Ok(bump_seed)
    }
}
