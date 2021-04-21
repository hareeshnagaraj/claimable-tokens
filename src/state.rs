//! State transition types
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

/// Size of Secp256k1 signature
pub const SECP_SIGNATURE_SIZE: usize = 64;

/// Ethereum public key size
pub const ETH_ADDRESS_SIZE: usize = 20;

/// SIGNATURE_OFFSETS_SERIALIZED_SIZE
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;

/// UserBank struct
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Default)]
pub struct UserBank {
    /// Users ETH address
    pub eth_address: [u8; ETH_ADDRESS_SIZE],
    /// Token account derived from user's ETH address
    pub token_account: Pubkey,
}

/// Secp256k1 signature offsets data
#[derive(Clone, Copy, Debug, Default, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct SecpSignatureOffsets {
    /// Offset of 64+1 bytes
    pub signature_offset: u16,
    /// Index of signature instruction in buffer
    pub signature_instruction_index: u8,
    /// Offset to eth_address of 20 bytes
    pub eth_address_offset: u16,
    /// Index of eth address instruction in buffer
    pub eth_address_instruction_index: u8,
    /// Offset to start of message data
    pub message_data_offset: u16,
    /// Size of message data
    pub message_data_size: u16,
    /// Index on message instruction in buffer
    pub message_instruction_index: u8,
}

impl UserBank {
    /// LEN
    pub const LEN: usize = 52;

    /// Check if UserBank is initialized
    pub fn is_initialized(&self) -> bool {
        *self != UserBank::default()
    }
}
