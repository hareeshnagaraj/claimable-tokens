use std::convert::TryInto;

use anyhow::Result;
use claimable_tokens::{
    instruction::{claim, Claim},
    processor::Processor,
};
use clap::{
    crate_description, crate_name, crate_version, value_t, App, AppSettings, Arg, SubCommand,
};

use solana_clap_utils::{
    fee_payer::fee_payer_arg,
    input_parsers::pubkey_of,
    input_validators::{is_pubkey, is_url_or_moniker},
    keypair::signer_from_path,
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    bs58, commitment_config::CommitmentConfig, pubkey::Pubkey,
    secp256k1_instruction::new_secp256k1_instruction, signature::Signer, transaction::Transaction,
};

struct Config {
    fee_payer: Box<dyn Signer>,
    rpc_client: RpcClient,
}

fn transfer(
    config: Config,
    ethereum_address: [u8; Processor::ETH_ADDRESS_SIZE],
    priv_key: secp256k1::SecretKey,
    mint: Pubkey,
    destination: Pubkey,
    amount: u64,
) -> Result<()> {
    // Get base (PDA unique for different token mint) account address
    let (base, _) = Pubkey::find_program_address(&[&mint.to_bytes()[..32]], &spl_token::id());
    let seed = bs58::encode(ethereum_address).into_string();
    // Get derived token account (associated with base and ethereum user) address
    let derived = Pubkey::create_with_seed(&base, seed.as_str(), &spl_token::id())?;

    let instructions = &[
        new_secp256k1_instruction(&priv_key, &derived.to_bytes()),
        claim(
            &claimable_tokens::id(),
            &derived,
            &destination,
            &base,
            Claim {
                eth_address: ethereum_address, amount,
            },
        )?,
    ];
    let mut tx = Transaction::new_with_payer(instructions, Some(&config.fee_payer.pubkey()));
    let (recent_blockhash, _) = config.rpc_client.get_recent_blockhash()?;
    tx.sign(&[config.fee_payer.as_ref()], recent_blockhash);
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
                Arg::with_name("private_key")
                    .validator(is_pubkey)
                    .value_name("ETHEREUM_PRIVATE_KEY")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum private key for sign transaction"),
                Arg::with_name("destination")
                    .validator(is_pubkey)
                    .value_name("SOLANA_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Solana transfer destination account"),
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
    let fee_payer = signer_from_path(
        &matches,
        matches
            .value_of("fee_payer")
            .unwrap_or(&cli_config.keypair_path),
        "fee_payer",
        &mut wallet_manager,
    )
    .expect("Keypair for set fee pair cannot be found in path");

    let config = Config {
        fee_payer: fee_payer,
        rpc_client: RpcClient::new_with_commitment(json_rpc_url, CommitmentConfig::confirmed()),
    };

    solana_logger::setup_with_default("solana=info");

    match matches.subcommand() {
        ("transfer", Some(args)) => {
            let ethereum_address = value_t!(args.value_of("address"), String)?;
            let conv_eth_add: [u8; Processor::ETH_ADDRESS_SIZE] =
                ethereum_address.as_bytes().try_into().expect(
                    format!(
                        "Incorrect ethereum address {}. Because len {}, but must be {}.",
                        ethereum_address,
                        ethereum_address.len(),
                        Processor::ETH_ADDRESS_SIZE
                    )
                    .as_str(),
                );

            let private_key = value_t!(args.value_of("private_key"), String)?;
            let pk_slice: [u8; 32] = private_key.as_bytes().try_into().expect(
                format!(
                    "Incorrect private key. Because len {}, but must be {}.",
                    private_key.len(),
                    8,
                )
                .as_str(),
            );
            let conv_eth_pk = secp256k1::SecretKey::parse(&pk_slice)?;

            let mint = pubkey_of(args, "mint").unwrap();
            let destination = pubkey_of(args, "destination").unwrap();
            let amount = value_t!(args.value_of("amount"), u64)
                .expect("Can't parse amount, it is must present like integer");

            transfer(config, conv_eth_add, conv_eth_pk, mint, destination, amount)?
        }
        _ => unreachable!(),
    }
    Ok(())
}
