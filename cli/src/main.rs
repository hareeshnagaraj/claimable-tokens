use anyhow::Result;
use claimable_tokens::{
    instruction::{Claim, CreateTokenAccount},
    utils::program::get_address_pair,
};
use clap::{
    crate_description, crate_name, crate_version, value_t, App, AppSettings, Arg, ArgMatches,
    SubCommand,
};

use solana_clap_utils::{
    fee_payer::fee_payer_arg,
    input_parsers::pubkey_of,
    input_validators::{is_pubkey, is_url_or_moniker, is_valid_signer},
    keypair::signer_from_path,
};
use solana_client::{client_error::ClientError, rpc_client::RpcClient, rpc_response::Response};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    program_pack::Pack,
    pubkey::Pubkey,
    secp256k1_instruction::{construct_eth_pubkey, new_secp256k1_instruction},
    signature::Signer,
    transaction::Transaction,
};
use spl_associated_token_account::{create_associated_token_account, get_associated_token_address};
use spl_token::state::Mint;

struct Config {
    owner: Box<dyn Signer>,
    fee_payer: Box<dyn Signer>,
    rpc_client: RpcClient,
}

fn eth_pubkey_of(matches: &ArgMatches<'_>, name: &str) -> Result<secp256k1::PublicKey> {
    let value = value_t!(matches.value_of(name), String)?;
    let decoded_pk = &hex::decode(value.as_str())?;
    let pk = secp256k1::PublicKey::parse_slice(decoded_pk.as_slice(), None)?;
    Ok(pk)
}

fn eth_seckey_of(matches: &ArgMatches<'_>, name: &str) -> Result<secp256k1::SecretKey> {
    let value = value_t!(matches.value_of(name), String)?;
    let decoded_pk = &hex::decode(value.as_str())?;
    let sk = secp256k1::SecretKey::parse_slice(decoded_pk)?;
    Ok(sk)
}

fn claim(
    config: Config,
    secret_key: secp256k1::SecretKey,
    mint: Pubkey,
    recipient: Option<Pubkey>,
    amount: f64,
) -> Result<()> {
    let mut instructions = vec![];

    let eth_address = secp256k1::PublicKey::from_secret_key(&secret_key);
    let hashed_eth_pk = construct_eth_pubkey(&eth_address);
    let pair = get_address_pair(&mint, hashed_eth_pk)?;

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

    let mint_raw_data = config.rpc_client.get_account_data(&mint)?;
    let mint_data = Mint::unpack(mint_raw_data.as_ref())?;

    let instructions = &[
        new_secp256k1_instruction(&secret_key, &pair.derive.address.to_bytes()),
        claimable_tokens::instruction::claim(
            &claimable_tokens::id(),
            &pair.derive.address,
            &user_acc,
            &pair.base.address,
            Claim {
                hashed_eth_pk,
                amount: spl_token::ui_amount_to_amount(amount, mint_data.decimals),
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
    ethereum_address: secp256k1::PublicKey,
    mint: Pubkey,
    amount: f64,
) -> Result<()> {
    let mut instructions = vec![];

    let hashed_eth_pk = construct_eth_pubkey(&ethereum_address);
    let pair = get_address_pair(&mint, hashed_eth_pk)?;
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
            CreateTokenAccount { hashed_eth_pk },
        )?);
    }

    let mint_raw_data = config.rpc_client.get_account_data(&mint)?;
    let mint_data = Mint::unpack(mint_raw_data.as_ref())?;

    let account = get_associated_token_address(&config.owner.pubkey(), &mint);
    instructions.push(spl_token::instruction::transfer(
        &spl_token::id(),
        &account,
        &pair.derive.address,
        &config.owner.pubkey(),
        &[],
        spl_token::ui_amount_to_amount(amount, mint_data.decimals),
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
                    Arg::with_name("recipient")
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
                    .help("Mint for token to claim"),
                Arg::with_name("private_key")
                    .long("private-key")
                    .validator(is_pubkey)
                    .value_name("ETHEREUM_PRIVATE_KEY")
                    .takes_value(true)
                    .required(true)
                    .help("Ethereum private key to sign the transaction"),
                Arg::with_name("recipient")
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
            let privkey = eth_seckey_of(args, "private_key")?;
            let mint = pubkey_of(args, "mint").unwrap();
            let recipient = pubkey_of(args, "recipient");
            let amount = value_t!(args.value_of("amount"), f64)?;

            claim(config, privkey, mint, recipient, amount)?
        }
        ("transfer", Some(args)) => {
            let pubkey = eth_pubkey_of(args, "recipient")?;
            let mint = pubkey_of(args, "mint").unwrap();
            let amount = value_t!(args.value_of("amount"), f64)?;

            transfer(config, pubkey, mint, amount)?
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[test]
fn test_parse_eth_pv() {
    use secp256k1::*;
    use std::str;

    const INPUT_PV: &str = "09e910621c2e988e9f7f6ffcd7024f54ec1461fa6e86a4b545e9e1fe21c28866";
    const EXPECTED_PUB: &str = "048e66b3e549818ea2cb354fb70749f6c8de8fa484f7530fc447d5fe80a1c424e4f5ae648d648c980ae7095d1efad87161d83886ca4b6c498ac22a93da5099014a";

    let private = SecretKey::parse_slice(&hex::decode(INPUT_PV).unwrap().as_slice()).unwrap();
    let public = PublicKey::from_secret_key(&private);
    let serialized = public.serialize();
    let str_pub = hex::decode(EXPECTED_PUB).unwrap();

    assert_eq!(&str_pub, serialized.as_ref());
}

#[test]
fn test_parse_eth_pk() {
    use secp256k1::*;
    use std::str;

    const EXPECTED_PV: &str = "09e910621c2e988e9f7f6ffcd7024f54ec1461fa6e86a4b545e9e1fe21c28866";
    const INPUT_PUB: &str = "048e66b3e549818ea2cb354fb70749f6c8de8fa484f7530fc447d5fe80a1c424e4f5ae648d648c980ae7095d1efad87161d83886ca4b6c498ac22a93da5099014a";

    let decoded_pk = &hex::decode(INPUT_PUB).unwrap();
    let public = PublicKey::parse_slice(decoded_pk.as_slice(), None).unwrap();

    let decoded_pv = hex::decode(EXPECTED_PV).unwrap();
    let private = SecretKey::parse_slice(decoded_pv.as_slice()).unwrap();
    let derived_pk = PublicKey::from_secret_key(&private);

    assert_eq!(public, derived_pk);
}
