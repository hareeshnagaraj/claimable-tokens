//! Program state processor

use crate::{
    error::ClaimableProgramError,
    instruction::ClaimableProgramInstruction,
    state::{UserBank, ETH_ADDRESS_SIZE, SECP_SIGNATURE_SIZE},
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::next_account_info,
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    system_instruction,
    sysvar::rent::Rent,
    sysvar::Sysvar,
};

/// Program state handler.
pub struct Processor {}
impl Processor {
    #[allow(clippy::too_many_arguments)]
    fn create_account<'a>(
        program_id: &Pubkey,
        funder: AccountInfo<'a>,
        account_to_create: AccountInfo<'a>,
        mint_key: &Pubkey,
        base: AccountInfo<'a>,
        seed: &str,
        required_lamports: u64,
        space: u64,
        owner: &Pubkey,
    ) -> ProgramResult {
        let (program_base_address, bump_seed) =
            Pubkey::find_program_address(&[&mint_key.to_bytes()[..32]], program_id);
        if program_base_address != *base.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let generated_address_to_create =
            Pubkey::create_with_seed(&program_base_address, seed, program_id)?;
        if generated_address_to_create != *account_to_create.key {
            return Err(ProgramError::InvalidSeeds);
        }
        let signature = &[&mint_key.to_bytes()[..32], &[bump_seed]];

        invoke_signed(
            &system_instruction::create_account_with_seed(
                &funder.key,
                &account_to_create.key,
                &base.key,
                seed,
                required_lamports,
                space,
                owner,
            ),
            &[funder.clone(), account_to_create.clone(), base.clone()],
            &[signature],
        )
    }

    fn initialize_token_account<'a>(
        token_program_id: &Pubkey,
        account_to_initialize: AccountInfo<'a>,
        mint: AccountInfo<'a>,
        owner: AccountInfo<'a>,
        rent_account: AccountInfo<'a>,
    ) -> ProgramResult {
        invoke(
            &spl_token::instruction::initialize_account(
                token_program_id,
                &account_to_initialize.key,
                mint.key,
                owner.key,
            )?,
            &[account_to_initialize, mint, owner, rent_account],
        )
    }

    /// Initialize user bank
    pub fn process_init_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        eth_address: [u8; ETH_ADDRESS_SIZE],
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

        let mut bank = UserBank::try_from_slice(&bank_account_info.data.borrow())?;
        if bank.is_initialized() {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        if !rent.is_exempt(bank_account_info.lamports(), bank_account_info.data_len()) {
            return Err(ProgramError::AccountNotRentExempt);
        }
        // check that mint is initialized
        let _mint = spl_token::state::Mint::unpack(&mint_account_info.data.borrow())?;

        let eth_address_str: Result<&str, ProgramError> = std::str::from_utf8(&eth_address)
            .map_err(|_e| ClaimableProgramError::EthAddressConvertingErr.into());
        Self::create_account(
            program_id,
            funder_account_info.clone(),
            acc_to_create_info.clone(),
            mint_account_info.key,
            base_account_info.clone(),
            eth_address_str?,
            rent.minimum_balance(UserBank::LEN),
            UserBank::LEN as u64,
            token_program_id.key,
        )?;

        Self::initialize_token_account(
            token_program_id.key,
            acc_to_create_info.clone(),
            mint_account_info.clone(),
            base_account_info.clone(),
            rent_account_info.clone(),
        )?;

        bank.eth_address = eth_address;
        bank.token_account = *acc_to_create_info.key;

        bank
            .serialize(&mut *bank_account_info.data.borrow_mut())
            .map_err(|e| e.into())
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
