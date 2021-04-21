//! State transition types
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

/// Size of Secp256k1 signature
pub const SECP_SIGNATURE_SIZE: usize = 64;

/// Ethereum public key size
pub const ETH_ADDRESS_SIZE: usize = 20;

/// UserBank struct
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone, Default)]
pub struct UserBank {
    /// Users ETH address
    pub eth_address: [u8; ETH_ADDRESS_SIZE],
    /// Token account derived from user's ETH address
    pub token_account: Pubkey,
}

impl UserBank {
    /// LEN
    pub const LEN: usize = 52;

    /// Check if UserBank is initialized
    pub fn is_initialized(&self) -> bool {
        *self != UserBank::default()
    }
}
