use std::convert::TryInto;

use anyhow::Result;
use claimable_tokens::{
    instruction::{Claim, CreateTokenAccount},
    utils::program::{get_address_pair, EthereumPubkey},
};
use clap::{
    crate_description, crate_name, crate_version, value_t, App, AppSettings, Arg, SubCommand,
};

use solana_clap_utils::{
    fee_payer::fee_payer_arg,
    input_parsers::pubkey_of,
    input_validators::{is_pubkey, is_url_or_moniker, is_valid_signer},
    keypair::signer_from_path,
};
use solana_client::{client_error::ClientError, rpc_client::RpcClient, rpc_response::Response};
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey,
    secp256k1_instruction::new_secp256k1_instruction, signature::Signer, transaction::Transaction,
};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use std::mem::size_of;

struct Config {
    owner: Box<dyn Signer>,
    fee_payer: Box<dyn Signer>,
    rpc_client: RpcClient,
}

fn conver_amount(amount: f64) -> u64 {
    todo!()
}

fn claim(
    config: Config,
    secret_key: secp256k1::SecretKey,
    mint: Pubkey,
    recipient: Option<Pubkey>,
    amount: f64,
) -> Result<()> {
    let mut instructions = vec![];

    let eth_address = secp256k1::PublicKey::from_secret_key(&secret_key).serialize_compressed();
    let mut conv_ath_address = [0u8; 20];
    conv_ath_address.copy_from_slice(&eth_address[..=20]);
    let pair = get_address_pair(&mint, conv_ath_address)?;

    let user_acc = recipient.map_or_else(
        || -> Result<Pubkey, ClientError> {
            let user_acc = get_associated_token_address(&config.owner.pubkey(), &mint);
            // Checking if the associated token account unexist
            // then we must add instruction to create it
            if let Response { value: None, .. } = config
                .rpc_client
                .get_account_with_commitment(&user_acc, config.rpc_client.commitment())?
            {
                instructions.push(create_associated_token_account(
                    &config.fee_payer.pubkey(),
                    &config.owner.pubkey(),
                    &mint,
                ));
            }
            Ok(user_acc)
        },
        Ok,
    )?;

    let instructions = &[
        new_secp256k1_instruction(&secret_key, &pair.derive.address.to_bytes()),
        claimable_tokens::instruction::claim(
            &claimable_tokens::id(),
            &pair.derive.address,
            &user_acc,
            &pair.base.address,
            Claim {
                eth_address: conv_ath_address,
                amount: conver_amount(amount),
            },
        )?,
    ];
    let mut tx = Transaction::new_with_payer(instructions, Some(&config.fee_payer.pubkey()));
    let (recent_blockhash, _) = config.rpc_client.get_recent_blockhash()?;
    tx.sign(&[config.fee_payer.as_ref()], recent_blockhash);
    config
        .rpc_client
        .send_and_confirm_transaction_with_spinner(&tx)?;
    println!("Claim completed");
    Ok(())
}

fn transfer(
    config: Config,
    ethereum_address: EthereumPubkey,
    mint: Pubkey,
    amount: f64,
) -> Result<()> {
    let mut instructions = vec![];

    let pair = get_address_pair(&mint, ethereum_address)?;
    // Checking if the derived address of recipient unexist
    // then we must add instruction to create it
    if let Response { value: None, .. } = config
        .rpc_client
        .get_account_with_commitment(&pair.derive.address, config.rpc_client.commitment())?
    {
        instructions.push(claimable_tokens::instruction::init(
            &claimable_tokens::id(),
            &config.fee_payer.pubkey(),
            &mint,
            CreateTokenAccount {
                eth_address: ethereum_address,
            },
        )?);
    }

    let account = get_associated_token_address(&config.owner.pubkey(), &mint);
    instructions.push(spl_token::instruction::transfer(
        &spl_token::id(),
        &account,
        &pair.derive.address,
        &config.owner.pubkey(),
        &[],
        conver_amount(amount),
    )?);

    let mut tx =
        Transaction::new_with_payer(instructions.as_slice(), Some(&config.fee_payer.pubkey()));
    let (recent_blockhash, _) = config.rpc_client.get_recent_blockhash()?;
    tx.sign(
        &[config.fee_payer.as_ref(), config.owner.as_ref()],
        recent_blockhash,
    );
    config
        .rpc_client
        .send_and_confirm_transaction_with_spinner(&tx)?;

    println!("Transfer completed to recipient: {}", pair.derive.address);
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
        .subcommands(vec![
            SubCommand::with_name("transfer")
                .args(&[
                    Arg::with_name("address")
                        .value_name("ETHEREUM_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("Recipient Ethereum address"),
                    Arg::with_name("mint")
                        .value_name("MINT_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("Mint for the token to send"),
                    Arg::with_name("amount")
                        .value_name("NUMBER")
                        .takes_value(true)
                        .required(true)
                        .help("Amount to send"),
                ])
                .help("Transfer Solana token claimable by Ethereum users"),
            SubCommand::with_name("claim").args(&[
                Arg::with_name("mint")
                    .validator(is_pubkey)
                    .value_name("MINT_ADDRESS")
                    .takes_value(true)
                    .required(true)
                    .help("Mint for the token to send"),
                Arg::with_name("private_key")
                    .validator(is_pubkey)
                    .value_name("ETHEREUM_PRIVATE_KEY")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum private key to sign the transaction"),
                Arg::with_name("destination")
                    .validator(is_pubkey)
                    .value_name("SOLANA_ADDRESS")
                    .takes_value(true)
                    .help("Recipient of transfer"),
                Arg::with_name("amount")
                    .value_name("NUMBER")
                    .takes_value(true)
                    .required(true)
                    .help("Amount to claim"),
            ]),
        ])
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
    .expect("Keypair for set owner cannot be found in path");
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
        owner,
        fee_payer,
        rpc_client: RpcClient::new_with_commitment(json_rpc_url, CommitmentConfig::confirmed()),
    };

    solana_logger::setup_with_default("solana=info");

    match matches.subcommand() {
        ("claim", Some(args)) => {
            let private_key = value_t!(args.value_of("private_key"), String)?;
            let pk_array: [u8; 32] = private_key.as_bytes().try_into().unwrap_or_else(|_| {
                panic!(
                    "Incorrect private key. Because len {}, but must be {}.",
                    private_key.len(),
                    8
                )
            });
            let conv_eth_pk = secp256k1::SecretKey::parse(&pk_array)?;

            let mint = pubkey_of(args, "mint").unwrap();
            let destination = pubkey_of(args, "destination");
            let amount = value_t!(args.value_of("amount"), f64)
                .expect("Can't parse amount, it is must present like integer");

            claim(config, conv_eth_pk, mint, destination, amount)?
        }
        ("transfer", Some(args)) => {
            let ethereum_address = value_t!(args.value_of("address"), String)?;
            let conv_eth_add: EthereumPubkey =
                ethereum_address.as_bytes().try_into().unwrap_or_else(|_| {
                    panic!(
                        "Incorrect ethereum address {}. Because len {}, but must be {}.",
                        ethereum_address,
                        ethereum_address.len(),
                        size_of::<EthereumPubkey>()
                    )
                });

            let mint = pubkey_of(args, "mint").unwrap();
            let amount = value_t!(args.value_of("amount"), f64)
                .expect("Can't parse amount, it is must present like integer");

            transfer(config, conv_eth_add, mint, amount)?
        }
        _ => unreachable!(),
    }
    Ok(())
}
