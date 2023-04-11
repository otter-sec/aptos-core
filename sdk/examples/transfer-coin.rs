// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use aptos_rest_client::{Account};
use aptos_sdk::{
    coin_client::{CoinClient, TransferOptions},
    rest_client::{Client, FaucetClient},
    types::LocalAccount, transaction_builder::TransactionBuilder,
};
use aptos_types::{transaction::{TransactionPayload, EntryFunction}, chain_id::ChainId, PeerId};
use move_core_types::{language_storage::{ModuleId, TypeTag}, identifier::Identifier};
use once_cell::sync::Lazy;
use std::{str::FromStr, time::{UNIX_EPOCH, SystemTime}};
use url::Url;
use move_core_types::account_address::AccountAddress;

// :!:>section_1c
static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
            "http://0.0.0.0:8080"
    )
    .unwrap()
});

static FAUCET_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
            "http://0.0.0.0:8081"
    )
    .unwrap()
});
// <:!:section_1c

#[tokio::main]
async fn main() -> Result<()> {
    // :!:>section_1a
    let rest_client = Client::new(NODE_URL.clone());
    let faucet_client = FaucetClient::new(FAUCET_URL.clone(), NODE_URL.clone()); // <:!:section_1a

    let mut alice = LocalAccount::generate(&mut rand::rngs::OsRng);

    faucet_client
        .fund(alice.address(), 100_000_000)
        .await
        .context("Failed to fund Alice's account")?;
    // // :!:>section_1b
    let coin_client = CoinClient::new(&rest_client); // <:!:section_1b
    // rest_client.submit(txn)
    //
    // // Create two accounts locally, Alice and Bob.
    // // :!:>section_2
    // let bob = LocalAccount::generate(&mut rand::rngs::OsRng); // <:!:section_2
    //
    // // Print account addresses.
    // println!("\n=== Addresses ===");
    // println!("Alice: {}", alice.address().to_hex_literal());
    // println!("Bob: {}", bob.address().to_hex_literal());
    //
    // // Create the accounts on chain, but only fund Alice.
    // // :!:>section_3
    // faucet_client
    //     .create_account(bob.address())
    //     .await
    //     .context("Failed to fund Bob's account")?; // <:!:section_3
    //
    // // Print initial balances.
    // println!("\n=== Initial Balances ===");
    // println!(
    //     "Alice: {:?}",
    //     coin_client
    //         .get_account_balance(&alice.address())
    //         .await
    //         .context("Failed to get Alice's account balance")?
    // );
    // println!(
    //     "Bob: {:?}",
    //     coin_client
    //         .get_account_balance(&bob.address())
    //         .await
    //         .context("Failed to get Bob's account balance")?
    // );
    //
    // // Have Alice send Bob some coins.
    // let txn_hash = coin_client
    //     .transfer(&mut alice, bob.address(), 1_000, None)
    //     .await
    //     .context("Failed to submit transaction to transfer coins")?;
    // rest_client
    //     .wait_for_transaction(&txn_hash)
    //     .await
    //     .context("Failed when waiting for the transfer transaction")?;
    //
    // // Print intermediate balances.
    // println!("\n=== Intermediate Balances ===");
    // // :!:>section_4
    // println!(
    //     "Alice: {:?}",
    //     coin_client
    //         .get_account_balance(&alice.address())
    //         .await
    //         .context("Failed to get Alice's account balance the second time")?
    // );
    // println!(
    //     "Bob: {:?}",
    //     coin_client
    //         .get_account_balance(&bob.address())
    //         .await
    //         .context("Failed to get Bob's account balance the second time")?
    // ); // <:!:section_4
    //
    // // Have Alice send Bob some more coins.
    // // :!:>section_5


        // RunnableState {
        //     dep_modules: [],
        //     exec_variant: Script {
        //         script: CompiledScript {
        //             version: 6,
        //             module_handles: [],
        //             struct_handles: [],
        //             function_handles: [],
        //             function_instantiations: [],
        //             signatures: [
        //                 Signature(
        //                     [],
        //                 ),
        //                 Signature(
        //                     [
        //                         U64,
        //                         MutableReference(Bool),
        //                     ],
        //                 ),
        //             ],
        //             identifiers: [],
        //             address_identifiers: [],
        //             constant_pool: [],
        //             metadata: [],
        //             code: CodeUnit {
        //                 locals: SignatureIndex(1),
        //                 code: [],
        //             },
        //             type_parameters: [],
        //             parameters: SignatureIndex(37265),
        //         },
        //         type_args: [
        //             Vector(
        //                 Vector(
        //                     Vector(
        //                         Vector(
        //                             Vector(
        //                                 Vector(
        //                                     Vector(
        //                                         Vector(
        //                                             Vector(
        //                                                 Vector(
        //                                                     Vector(
        //                                                         Vector(
        //                                                             Vector(
        //                                                                 Vector(
        //                                                                     U8,
        //                                                                 ),
        //                                                             ),
        //                                                         ),
        //                                                     ),
        //                                                 ),
        //                                             ),
        //                                         ),
        //                                     ),
        //                                 ),
        //                             ),
        //                         ),
        //                     ),
        //                 ),
        //             ),
        //         ],
        //         args: [],
        //     },
        // }

        let options = TransferOptions::default();
        let mut  tt = TypeTag::U8;
        for _ in 0..32 {
            tt = TypeTag::Vector(Box::new(tt));
        }
        let chain_id = rest_client
            .get_index()
            .await
            .context("Failed to get chain ID")?
            .inner()
            .chain_id;
        let transaction_builder = TransactionBuilder::new(
            TransactionPayload::EntryFunction(EntryFunction::new(
                ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()),
                Identifier::new("transfer").unwrap(),
                vec![tt],
                vec![
                ],
            )),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + options.timeout_secs,
            ChainId::new(chain_id),
        )
        .sender(alice.address())
        .sequence_number(alice.sequence_number())
        .max_gas_amount(options.max_gas_amount)
        .gas_unit_price(options.gas_unit_price);
        let signed_txn = alice.sign_with_transaction_builder(transaction_builder);
        dbg!(rest_client
            .submit(&signed_txn)
            .await
            .context("Failed to submit transfer transaction")?
            .into_inner());
    //                                                                  // :!:>section_6
    // rest_client
    //     .wait_for_transaction(&txn_hash)
    //     .await
    //     .context("Failed when waiting for the transfer transaction")?; // <:!:section_6
    //
    // // Print final balances.
    // println!("\n=== Final Balances ===");
    // println!(
    //     "Alice: {:?}",
    //     coin_client
    //         .get_account_balance(&alice.address())
    //         .await
    //         .context("Failed to get Alice's account balance the second time")?
    // );
    // println!(
    //     "Bob: {:?}",
    //     coin_client
    //         .get_account_balance(&bob.address())
    //         .await
    //         .context("Failed to get Bob's account balance the second time")?
    // );

    Ok(())
}
