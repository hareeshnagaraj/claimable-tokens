//! Program state processor

use crate::{
    error::ClaimableProgramError,
    instruction::{ClaimableProgramInstruction, SignatureData},
    state::{
        SecpSignatureOffsets, UserBank, ETH_ADDRESS_SIZE, SECP_SIGNATURE_SIZE,
        SIGNATURE_OFFSETS_SERIALIZED_SIZE,
    },
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
    system_instruction, sysvar,
    sysvar::rent::Rent,
    sysvar::Sysvar,
};

/// Program state handler.
pub struct Processor {}
impl Processor {
    /// Token acc seed
    pub const TOKEN_ACC_SEED: &'static str = "eth_user_acc";

    #[allow(clippy::too_many_arguments)]
    fn create_account<'a>(
        program_id: &Pubkey,
        funder: AccountInfo<'a>,
        account_to_create: AccountInfo<'a>,
        mint_key: &Pubkey,
        base: AccountInfo<'a>,
        eth_address: [u8; ETH_ADDRESS_SIZE],
        required_lamports: u64,
        space: u64,
        owner: &Pubkey,
    ) -> ProgramResult {
        let (program_base_address, bump_seed) =
            Pubkey::find_program_address(&[&mint_key.to_bytes()[..32], &eth_address], program_id);
        if program_base_address != *base.key {
            return Err(ProgramError::InvalidSeeds);
        }

        let generated_address_to_create =
            Pubkey::create_with_seed(&program_base_address, Self::TOKEN_ACC_SEED, owner)?;
        if generated_address_to_create != *account_to_create.key {
            return Err(ProgramError::InvalidSeeds);
        }
        let signature = &[&mint_key.to_bytes()[..32], &eth_address, &[bump_seed]];

        invoke_signed(
            &system_instruction::create_account_with_seed(
                &funder.key,
                &account_to_create.key,
                &base.key,
                Self::TOKEN_ACC_SEED,
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

    fn token_transfer<'a>(
        token_program: AccountInfo<'a>,
        source: AccountInfo<'a>,
        destination: AccountInfo<'a>,
        authority: AccountInfo<'a>,
        program_id: &Pubkey,
    ) -> Result<(), ProgramError> {
        let source_data = spl_token::state::Account::unpack(&source.data.borrow())?;

        let (generated_authority_key, bump_seed) = Pubkey::find_program_address(&[&source_data.mint.to_bytes()[..32]], program_id);
        if generated_authority_key != *authority.key {
            return Err(ProgramError::InvalidSeeds);
        }
        let authority_signature_seeds = [&source_data.mint.to_bytes()[..32], &[bump_seed]];
        let signers = &[&authority_signature_seeds[..]];

        let tx = spl_token::instruction::transfer(
            token_program.key,
            source.key,
            destination.key,
            authority.key,
            &[&authority.key],
            source_data.amount,
        )?;
        invoke_signed(
            &tx,
            &[source, destination, authority, token_program],
            signers,
        )
    }

    fn validate_eth_signature(
        signature_data: SignatureData,
        eth_address: [u8; ETH_ADDRESS_SIZE],
        secp_instruction_data: Vec<u8>,
    ) -> Result<(), ProgramError> {
        let mut instruction_data = vec![];
        let data_start = 1 + SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        instruction_data.resize(
            data_start + ETH_ADDRESS_SIZE + SECP_SIGNATURE_SIZE + signature_data.message.len() + 1,
            0,
        );
        let eth_address_offset = data_start;
        instruction_data[eth_address_offset..eth_address_offset + ETH_ADDRESS_SIZE]
            .copy_from_slice(&eth_address);

        let signature_offset = data_start + ETH_ADDRESS_SIZE;
        instruction_data[signature_offset..signature_offset + SECP_SIGNATURE_SIZE]
            .copy_from_slice(&signature_data.signature);

        instruction_data[signature_offset + SECP_SIGNATURE_SIZE] = signature_data.recovery_id;

        let message_data_offset = signature_offset + SECP_SIGNATURE_SIZE + 1;
        instruction_data[message_data_offset..].copy_from_slice(&signature_data.message);

        let num_signatures = 1;
        instruction_data[0] = num_signatures;
        let offsets = SecpSignatureOffsets {
            signature_offset: signature_offset as u16,
            signature_instruction_index: 0,
            eth_address_offset: eth_address_offset as u16,
            eth_address_instruction_index: 0,
            message_data_offset: message_data_offset as u16,
            message_data_size: signature_data.message.len() as u16,
            message_instruction_index: 0,
        };
        let packed_offsets = offsets.try_to_vec()?;
        instruction_data[1..data_start].copy_from_slice(packed_offsets.as_slice());

        if instruction_data != secp_instruction_data {
            return Err(ClaimableProgramError::SignatureVerificationFailed.into());
        }
        Ok(())
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

        Self::create_account(
            program_id,
            funder_account_info.clone(),
            acc_to_create_info.clone(),
            mint_account_info.key,
            base_account_info.clone(),
            eth_address,
            rent.minimum_balance(spl_token::state::Account::LEN),
            spl_token::state::Account::LEN as u64,
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

        bank.serialize(&mut *bank_account_info.data.borrow_mut())
            .map_err(|e| e.into())
    }

    /// Claim user tokens
    pub fn process_claim_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        eth_signature: SignatureData,
    ) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let bank_account_info = next_account_info(account_info_iter)?;
        let banks_token_account_info = next_account_info(account_info_iter)?;
        let users_token_account_info = next_account_info(account_info_iter)?;
        let authority_account_info = next_account_info(account_info_iter)?;
        let token_program_id = next_account_info(account_info_iter)?;
        let instruction_info = next_account_info(account_info_iter)?;
        let index = sysvar::instructions::load_current_index(&instruction_info.data.borrow());
        // check that bank_account_info is initialized
        let bank = UserBank::try_from_slice(&bank_account_info.data.borrow())?;
        if !bank.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }

        // check that in this transaction also contains Secp256 program call
        if index == 0 {
            return Err(ClaimableProgramError::Secp256InstructionLosing.into());
        }

        // Instruction data of Secp256 program call
        let secp_instruction = sysvar::instructions::load_instruction_at(
            (index - 1) as usize,
            &instruction_info.data.borrow(),
        )
        .unwrap();

        Self::validate_eth_signature(eth_signature, bank.eth_address, secp_instruction.data)?;

        Self::token_transfer(
            token_program_id.clone(),
            banks_token_account_info.clone(),
            users_token_account_info.clone(),
            authority_account_info.clone(),
            program_id,
        )?;

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
