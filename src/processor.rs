//! Program state processor

use crate::{error::ClaimableProgramError, instruction::ClaimableProgramInstruction, state::{ETH_ADDRESS_SIZE, SECP_SIGNATURE_SIZE}};
use borsh::BorshDeserialize;
use solana_program::{
    account_info::next_account_info, account_info::AccountInfo, entrypoint::ProgramResult, msg,
    pubkey::Pubkey,
    sysvar::rent::Rent,
    sysvar::Sysvar,
};

/// Program state handler.
pub struct Processor {}
impl Processor {
    /// Initialize user bank
    pub fn process_init_instruction(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        _eth_address: [u8; ETH_ADDRESS_SIZE],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let bank_account_info = next_account_info(account_info_iter)?;
        let funder_account_info = next_account_info(account_info_iter)?;
        let mint_account_info = next_account_info(account_info_iter)?;
        let base_account_info = next_account_info(account_info_iter)?;
        let acc_to_create_info = next_account_info(account_info_iter)?;
        let token_program_id = next_account_info(account_info_iter)?;
        let rent_account_info = next_account_info(account_info_iter)?;
        let rent = &Rent::from_account_info(rent_account_info)?;
        let _system_program = next_account_info(account_info_iter)?;

        Ok(())
    }

    /// Claim user tokens
    pub fn process_claim_instruction(
        _program_id: &Pubkey,
        accounts: &[AccountInfo],
        _eth_signature: [u8; SECP_SIGNATURE_SIZE],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let bank_account_info = next_account_info(account_info_iter)?;
        let banks_token_account_info = next_account_info(account_info_iter)?;
        let users_token_account_info = next_account_info(account_info_iter)?;
        let token_program_id = next_account_info(account_info_iter)?;

        Ok(())
    }

    /// Processes an instruction
    pub fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        input: &[u8],
    ) -> ProgramResult {
        let instruction = ClaimableProgramInstruction::try_from_slice(input)?;
        match instruction {
            ClaimableProgramInstruction::InitUserBank(eth_address) => {
                msg!("Instruction: InitUserBank");
                Self::process_init_instruction(program_id, accounts, eth_address)
            }
            ClaimableProgramInstruction::Claim(signature) => {
                msg!("Instruction: Claim");
                Self::process_claim_instruction(program_id, accounts, signature)
            }
        }
    }
}
