use std::{error::Error, time::{self, Duration}};

use iroh::Endpoint;
use libskyfall::{ handlers::EchoHandler, Client, ClientEvent, Context, Identity, ALPN };
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut source = Client::builder().build().await?;
    let mut sink = Client::builder().build().await?.with_handler(EchoHandler);

    let source_evts = tokio::spawn((|| {
        let events = source.client_events().clone();
        async move {
            loop {
                if let Ok(evt) = events.recv().await {
                    println!("EVENT: {evt:?}");
                }
            }
        }
    })());

    let sink_evts = tokio::spawn((|| {
        let events = sink.client_events().clone();
        let client = sink.clone();
        async move {
            loop {
                if let Ok(evt) = events.recv().await {
                    println!("EVENT: {evt:?}");
                    if let ClientEvent::Connected { peer } = evt {
                        let _ = client.trust_peer(peer.clone());
                        let _ = client.share_info(peer).await;
                    }
                }
            }
        }
    })());

    source.initialize().await?;
    sink.initialize().await?;

    sleep(Duration::from_secs(2)).await;

    let sink_peer = source.trust_peer(source.connect_to(sink.peer_info()).await?)?;
    source.share_info(sink_peer.clone()).await?;

    let channel = source.send_command::<()>(sink_peer.clone(), "ECHO/echo", None, true).await?.1.unwrap();
    let mut name_generator = names::Generator::default();
    loop {
        channel.send(name_generator.next().unwrap().as_bytes().to_vec()).await?;
        sleep(Duration::from_millis(100)).await;
    }
}
