//! Program state processor

use crate::{
    error::{to_claimable_tokens_error, ClaimableProgramError},
    instruction::ClaimableProgramInstruction,
    utils::program::PubkeyPatterns,
};
use borsh::BorshDeserialize;
use solana_program::{
    account_info::next_account_info,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    secp256k1_program, system_instruction, sysvar,
    sysvar::rent::Rent,
    sysvar::Sysvar,
};

/// Program state handler.
pub struct Processor {}
impl Processor {
    /// Ethereum public key size
    pub const ETH_ADDRESS_SIZE: usize = 20;

    #[allow(clippy::too_many_arguments)]
    fn create_account<'a>(
        program_id: &Pubkey,
        funder: AccountInfo<'a>,
        account_to_create: AccountInfo<'a>,
        mint_key: &Pubkey,
        base: AccountInfo<'a>,
        eth_address: [u8; Self::ETH_ADDRESS_SIZE],
        required_lamports: u64,
        space: u64,
    ) -> ProgramResult {
        base.key
            .program_address_generated_correct(mint_key, program_id)?;

        let seed = bs58::encode(eth_address).into_string();

        let (_, bump_seed) =
            account_to_create
                .key
                .derived_right(mint_key, &seed, program_id, &spl_token::id())?;

        let signature = &[&mint_key.to_bytes()[..32], &[bump_seed]];

        invoke_signed(
            &system_instruction::create_account_with_seed(
                &funder.key,
                &account_to_create.key,
                &base.key,
                &seed,
                required_lamports,
                space,
                &spl_token::id(),
            ),
            &[funder.clone(), account_to_create.clone(), base.clone()],
            &[signature],
        )
    }

    fn initialize_token_account<'a>(
        account_to_initialize: AccountInfo<'a>,
        mint: AccountInfo<'a>,
        owner: AccountInfo<'a>,
        rent_account: AccountInfo<'a>,
    ) -> ProgramResult {
        invoke(
            &spl_token::instruction::initialize_account(
                &spl_token::id(),
                &account_to_initialize.key,
                mint.key,
                owner.key,
            )?,
            &[account_to_initialize, mint, owner, rent_account],
        )
    }

    fn token_transfer<'a>(
        source: AccountInfo<'a>,
        destination: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        program_id: &Pubkey,
        eth_address: [u8; Self::ETH_ADDRESS_SIZE],
        amount: u64,
    ) -> Result<(), ProgramError> {
        let source_data = spl_token::state::Account::unpack(&source.data.borrow())?;

        let seed = bs58::encode(eth_address).into_string();

        let (_, bump_seed) =
            source
                .key
                .derived_right(&source_data.mint, &seed, program_id, &spl_token::id())?;
        let authority_signature_seeds = [&source_data.mint.to_bytes()[..32], &[bump_seed]];
        let signers = &[&authority_signature_seeds[..]];

        let debit_amount = if amount != 0 {
            amount
        } else {
            source_data.amount
        };

        let tx = spl_token::instruction::transfer(
            &spl_token::id(),
            source.key,
            destination.key,
            authority.key,
            &[&authority.key],
            debit_amount,
        )?;
        invoke_signed(&tx, &[source, destination, authority], signers)
    }

    fn validate_eth_signature(
        expected_signer: [u8; Self::ETH_ADDRESS_SIZE],
        message: &[u8],
        secp_instruction_data: Vec<u8>,
    ) -> Result<(), ProgramError> {
        let eth_address_offset = 12;
        let instruction_signer = secp_instruction_data
            [eth_address_offset..eth_address_offset + Self::ETH_ADDRESS_SIZE]
            .to_vec();
        if instruction_signer != expected_signer {
            return Err(ClaimableProgramError::SignatureVerificationFailed.into());
        }

        //NOTE: meta (12) + address (20) + signature (65) = 97
        let message_data_offset = 97; 
        let instruction_message = secp_instruction_data[message_data_offset..].to_vec();
        if instruction_message != *message {
            return Err(ClaimableProgramError::SignatureVerificationFailed.into());
        }

        Ok(())
    }

    /// Initialize user bank
    pub fn process_init_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        eth_address: [u8; Self::ETH_ADDRESS_SIZE],
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let funder_account_info = next_account_info(account_info_iter)?;
        let mint_account_info = next_account_info(account_info_iter)?;
        let base_account_info = next_account_info(account_info_iter)?;
        let acc_to_create_info = next_account_info(account_info_iter)?;
        let rent_account_info = next_account_info(account_info_iter)?;
        let rent = &Rent::from_account_info(rent_account_info)?;

        // check that mint is initialized
        let _mint = spl_token::state::Mint::unpack(&mint_account_info.data.borrow())?;

        Self::create_account(
            program_id,
            funder_account_info.clone(),
            acc_to_create_info.clone(),
            mint_account_info.key,
            base_account_info.clone(),
            eth_address,
            rent.minimum_balance(spl_token::state::Account::LEN),
            spl_token::state::Account::LEN as u64,
        )?;

        Self::initialize_token_account(
            acc_to_create_info.clone(),
            mint_account_info.clone(),
            base_account_info.clone(),
            rent_account_info.clone(),
        )
    }

    /// Claim user tokens
    pub fn process_claim_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        eth_address: [u8; Self::ETH_ADDRESS_SIZE],
        amount: u64,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let banks_token_account_info = next_account_info(account_info_iter)?;
        let users_token_account_info = next_account_info(account_info_iter)?;
        let authority_account_info = next_account_info(account_info_iter)?;
        let instruction_info = next_account_info(account_info_iter)?;
        let index = sysvar::instructions::load_current_index(&instruction_info.data.borrow());

        // check that in this transaction also contains Secp256 program call
        if index == 0 {
            return Err(ClaimableProgramError::Secp256InstructionLosing.into());
        }

        // Instruction data of Secp256 program call
        let secp_instruction = sysvar::instructions::load_instruction_at(
            (index - 1) as usize,
            &instruction_info.data.borrow(),
        )
        .map_err(to_claimable_tokens_error)?;

        if secp_instruction.program_id != secp256k1_program::id() {
            return Err(ClaimableProgramError::Secp256InstructionLosing.into());
        }

        Self::validate_eth_signature(
            eth_address,
            &users_token_account_info.key.to_bytes(),
            secp_instruction.data,
        )?;

        Self::token_transfer(
            banks_token_account_info.clone(),
            users_token_account_info.clone(),
            authority_account_info.clone(),
            program_id,
            eth_address,
            amount,
        )
    }

    /// Processes an instruction
    pub fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        input: &[u8],
    ) -> ProgramResult {
        let instruction = ClaimableProgramInstruction::try_from_slice(input)?;
        match instruction {
            ClaimableProgramInstruction::CreateTokenAccount(eth_address) => {
                msg!("Instruction: CreateTokenAccount");
                Self::process_init_instruction(program_id, accounts, eth_address.eth_address)
            }
            ClaimableProgramInstruction::Claim(instruction) => {
                msg!("Instruction: Claim");
                Self::process_claim_instruction(program_id, accounts, instruction.eth_address, instruction.amount)
            }
        }
    }
}
