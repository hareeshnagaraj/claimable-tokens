//! Instruction types

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};
use crate::state;

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum ClaimableProgramInstruction {
    /// InitUserBank
    ///
    ///   0. `[sw]` UserBank account
    ///   1. `[sw]` Account to pay for creating token acc
    ///   2. `[r]` Mint account
    ///   3. `[r]` Base acc used in PDA token acc (need because of create_with_seed instruction)
    ///   4. `[w]` PDA token account to create
    ///   5. `[r]` SPL token account id
    ///   6. `[r]` Rent id
    ///   7. `[r]` System program id
    InitUserBank([u8; state::ETH_ADDRESS_SIZE]),

    /// Claim
    /// 
    ///   0. `[r]` UserBank account
    ///   1. `[w]` Token acc from which tokens will be send
    ///   2. `[w]` Receiver token acc
    ///   3. `[r]` SPL token account id
    Claim([u8; state::SECP_SIGNATURE_SIZE])
}

/// Create `InitUserBank` instruction
pub fn init(
    program_id: &Pubkey,
    bank: &Pubkey,
    funder: &Pubkey,
    mint: &Pubkey,
    base_acc: &Pubkey,
    acc_to_create: &Pubkey,
    eth_address: [u8; state::ETH_ADDRESS_SIZE],
) -> Result<Instruction, ProgramError> {
    let init_data = ClaimableProgramInstruction::InitUserBank(eth_address);
    let data = init_data
        .try_to_vec()
        .or(Err(ProgramError::InvalidArgument))?;
    let accounts = vec![
        AccountMeta::new(*bank, true),
        AccountMeta::new(*funder, true),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(*base_acc, false),
        AccountMeta::new(*acc_to_create, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `Claim` instruction
pub fn claim(
    program_id: &Pubkey,
    bank: &Pubkey,
    banks_token_acc: &Pubkey,
    users_token_acc: &Pubkey,
    signature: [u8; state::SECP_SIGNATURE_SIZE]
) -> Result<Instruction, ProgramError> {
    let init_data = ClaimableProgramInstruction::Claim(signature);
    let data = init_data
        .try_to_vec()
        .or(Err(ProgramError::InvalidArgument))?;
    let accounts = vec![
        AccountMeta::new_readonly(*bank, false),
        AccountMeta::new(*banks_token_acc, false),
        AccountMeta::new(*users_token_acc, false),
        AccountMeta::new_readonly(spl_token::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}
