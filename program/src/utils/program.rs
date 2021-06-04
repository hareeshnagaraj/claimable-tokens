//! Extended functionality for Pubkey
use solana_program::{
    pubkey::{Pubkey, PubkeyError},
};

/// Represent compressed ethereum pubkey
pub type EthereumPubkey = [u8; 20];

/// Return `Base` account with seed and corresponding derive 
/// with seed
pub fn get_address_pair(mint: &Pubkey, eth_address: EthereumPubkey) -> Result<((Pubkey, u8), (Pubkey, String)), PubkeyError> {
    let base = get_base_address(mint);
    let derived = get_derived_address(&base.0.clone(), eth_address)?;
    Ok((base, derived))
}

/// Return PDA(that named `Base`) corresponding to specific mint 
/// and it bump seed 
pub fn get_base_address(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&mint.to_bytes()[..32]], &crate::id())
}

/// Return derived token account address corresponding to specific 
/// ethereum account and it seed
pub fn get_derived_address(
    base: &Pubkey,
    eth_address: EthereumPubkey,
) -> Result<(Pubkey, String), PubkeyError> {
    let seed = bs58::encode(eth_address).into_string();
    Pubkey::create_with_seed(
        &base, 
        seed.as_str(), 
        &spl_token::id()
    )
        .map(|i| (i, seed))
}
