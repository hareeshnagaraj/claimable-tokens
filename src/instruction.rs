//! Instruction types

use crate::state;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};

/// Signature with message to validate
#[derive(Clone, BorshDeserialize, BorshSerialize, PartialEq, Debug)]
pub struct SignatureData {
    /// Secp256k1 signature
    pub signature: [u8; state::SECP_SIGNATURE_SIZE],
    /// Ethereum address
    pub eth_address: [u8; state::ETH_ADDRESS_SIZE],
    /// Ethereum signature recovery ID
    pub recovery_id: u8,
    /// Signed message
    pub message: Vec<u8>,
}

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum ClaimableProgramInstruction {
    /// CreateTokenAccount
    ///
    ///   0. `[sw]` Account to pay for creating token acc
    ///   1. `[r]` Mint account
    ///   2. `[r]` Base acc used in PDA token acc (need because of create_with_seed instruction)
    ///   3. `[w]` PDA token account to create
    ///   4. `[r]` SPL token account id
    ///   5. `[r]` Rent id
    ///   6. `[r]` System program id
    CreateTokenAccount([u8; state::ETH_ADDRESS_SIZE]),

    /// Claim
    ///
    ///   0. `[w]` Token acc from which tokens will be send (bank account)
    ///   1. `[w]` Receiver token acc
    ///   2. `[r]` Banks token account authority
    ///   3. `[r]` SPL token account id
    ///   4. `[r]` Sysvar instruction id
    Claim(SignatureData),
}

/// Create `CreateTokenAccount` instruction
pub fn init(
    program_id: &Pubkey,
    funder: &Pubkey,
    mint: &Pubkey,
    base_acc: &Pubkey,
    acc_to_create: &Pubkey,
    eth_address: [u8; state::ETH_ADDRESS_SIZE],
) -> Result<Instruction, ProgramError> {
    let init_data = ClaimableProgramInstruction::CreateTokenAccount(eth_address);
    let data = init_data
        .try_to_vec()
        .or(Err(ProgramError::InvalidArgument))?;
    let accounts = vec![
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
    banks_token_acc: &Pubkey,
    users_token_acc: &Pubkey,
    authority: &Pubkey,
    signature: SignatureData,
) -> Result<Instruction, ProgramError> {
    let init_data = ClaimableProgramInstruction::Claim(signature);
    let data = init_data
        .try_to_vec()
        .or(Err(ProgramError::InvalidArgument))?;
    let accounts = vec![
        AccountMeta::new(*banks_token_acc, false),
        AccountMeta::new(*users_token_acc, false),
        AccountMeta::new_readonly(*authority, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}
