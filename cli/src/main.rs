use std::convert::TryInto;

use anyhow::{Result, bail};
use solana_clap_utils::{
    fee_payer::fee_payer_arg,
    input_parsers::pubkey_of,
    input_validators::{
        is_pubkey, 
        is_url_or_moniker, 
        is_valid_signer
    },
    keypair::signer_from_path,
};
use clap::{
    App,
    Arg,
    crate_name,
    crate_description,
    crate_version,
    AppSettings,
    SubCommand,
    value_t,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, 
    pubkey::Pubkey, signature::Signer, 
    transaction::Transaction,
    secp256k1_instruction::new_secp256k1_instruction,
};
use claimable_tokens::{instruction::{Claim, claim}, processor::Processor};

struct Config {
    owner: Box<dyn Signer>,
    fee_payer: Box<dyn Signer>,
    rpc_client: RpcClient,
}

fn transfer(
    config: Config, 
    priv_key: secp256k1::SecretKey, 
    mint: Pubkey, 
    ethereum_address: [u8; Processor::ETH_ADDRESS_SIZE], 
    amount: u64,
) -> Result<()> {
    let users_token_acc: Pubkey;
    let (generated, bump_seed) = Pubkey::find_program_address(&[&mint.to_bytes()[..32]], &claimable_tokens::id());

    let instructions = &[
        new_secp256k1_instruction(&priv_key, &users_token_acc.to_bytes()),
        claim(
            &claimable_tokens::id(), 
            banks_token_acc, 
            users_token_acc, 
            authority, 
            Claim{ eth_address: ethereum_address },
        )?,
    ];
    let mut tx = Transaction::new_with_payer(instructions, Some(&config.fee_payer.pubkey()));
    let (recent_blockhash, fee_calculator) = config.rpc_client.get_recent_blockhash()?;
    let signers = vec![
    ];
    tx.sign(&signers, recent_blockhash);
    config
        .rpc_client
        .send_and_confirm_transaction_with_spinner(&tx)?;
    println!("Transfer completed");
    Ok(())
}

fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(crate_version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("C")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            if let Some(ref config_file) = *solana_cli_config::CONFIG_FILE {
                arg.default_value(&config_file)
            } else {
                arg
            }
        })
        .arg(
            Arg::with_name("json_rpc_url")
                .short("u")
                .long("url")
                .value_name("URL_OR_MONIKER")
                .takes_value(true)
                .global(true)
                .validator(is_url_or_moniker)
                .help(
                    "URL for Solana's JSON RPC or moniker (or their first letter): \
                   [mainnet-beta, testnet, devnet, localhost] \
                Default from the configuration file.",
                ),
        )
        .arg(
            Arg::with_name("owner")
                .long("owner")
                .value_name("KEYPAIR")
                .validator(is_valid_signer)
                .takes_value(true)
                .global(true)
                .help(
                    "Specify the token owner account. \
             This may be a keypair file, the ASK keyword. \
             Defaults to the client keypair.",
                ),
        )
        .arg(fee_payer_arg().global(true))
        .subcommand(
            SubCommand::with_name("transfer").args(&[
                Arg::with_name("mint")
                    .validator(is_pubkey)
                    .value_name("MINT_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Mint for the token to send"),
                Arg::with_name("address")
                    .validator(is_pubkey)
                    .value_name("ETHEREUM_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum address associated with the token account"),
                Arg::with_name("amount")
                    .value_name("NUMBER")
                    .takes_value(true)
                    .required(true)
                    .help("Amount to send"),
            ]),
        )
        .get_matches();

    let mut wallet_manager = None;

    let cli_config = if let Some(config_file) = matches.value_of("config_file") {
        solana_cli_config::Config::load(config_file)?
    } else {
        println!("Config file not provided and default config unexist. Create config");
        solana_cli_config::Config::default()
    };
    let json_rpc_url = value_t!(matches, "json_rpc_url", String)
        .unwrap_or_else(|_| cli_config.json_rpc_url.clone());
    let owner = signer_from_path(
        &matches,
        matches
            .value_of("owner")
            .unwrap_or(&cli_config.keypair_path),
        "owner",
        &mut wallet_manager,
    )
    .unwrap(); //TODO
    let fee_payer = signer_from_path(
        &matches,
        matches
            .value_of("fee_payer")
            .unwrap_or(&cli_config.keypair_path),
        "fee_payer",
        &mut wallet_manager,
    )
    .unwrap(); //TODO

    let config = Config {
        owner: owner,
        fee_payer: fee_payer,
        rpc_client: RpcClient::new_with_commitment(json_rpc_url, CommitmentConfig::confirmed()),
    };

    solana_logger::setup_with_default("solana=info");

    match matches.subcommand() {
        ("transfer", Some(args)) => {
            let mint = pubkey_of(args, "mint").unwrap();
            let ethereum_address = value_t!(args.value_of("address"), String)?;
            let conv_eth_add: [u8; Processor::ETH_ADDRESS_SIZE] = ethereum_address.as_bytes()
                .try_into()
                .expect(format!("Incorrect ethereum address {}. Because len {}, but must be {}.", ethereum_address, ethereum_address.len(), Processor::ETH_ADDRESS_SIZE).as_str());
            
            let amount = value_t!(args.value_of("amount"), u64)
                .expect("Can't parse amount, it is must present like integer");
                
            transfer(config, mint, conv_eth_add, amount)?
        }
        _ => unreachable!(),
    }
    Ok(())
}
