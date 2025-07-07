use std::{error::Error, time::{self, Duration}};

use iroh::Endpoint;
use libskyfall::{ Context, Identity, ALPN };
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let alice_id = Identity::default();
    let bob_id = Identity::default();

    let alice_endpoint = Endpoint::builder()
        .secret_key(alice_id.iroh_secret())
        .discovery_n0()
        .discovery_dht()
        .discovery_local_network()
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(iroh::RelayMode::Default)
        .bind().await?;
    let bob_endpoint = Endpoint::builder()
        .secret_key(bob_id.iroh_secret())
        .discovery_n0()
        .discovery_dht()
        .discovery_local_network()
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(iroh::RelayMode::Default)
        .bind().await?;

    let alice_context = Context::new(alice_id.clone(), alice_endpoint)?;
    let bob_context = Context::new(bob_id.clone(), bob_endpoint)?;
    sleep(Duration::from_secs(2)).await;

    while let Err(e) = alice_context.connect(&bob_id.as_public()).await {
        println!("Connect attempt failed: {e:?}");
    }

    println!("CONNECTED");

    loop {
        println!("ALICE: {:?}", alice_context.connected_peers());
        println!("BOB: {:?}", bob_context.connected_peers());
    }
}
