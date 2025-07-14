# Skyfall
*Quantum-Safe P2P Communication System*

> [!WARNING]
> This library is currently tested only *minimally*. Documentation and stability is a work-in-progress.

`libskyfall` implements an abstraction layer over [iroh](https://github.com/n0-computer/iroh), adding quantum-safe encryption, extended peer information gathering, serializable connection states, and REST-like routing support.

### Basic Usage

This example creates two peers, one sending data to the other (`source` and `sink` respectively.)

**Source:**
```rust
use std::{error::Error, time::Duration};

use libskyfall::Client;
use tokio::time::sleep;

// Create an asynchronous context
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build the client (could also load from a saved state)
    let mut client = Client::builder().build().await?;

    // Initialize the client
    client.initialize().await?;

    // Connect to the sink and trust it
    let sink_peer = source.trust_peer(source.connect_to(<NODE ID>).await?)?;

    // Share my profile information with the sink
    source.share_info(sink_peer.clone()).await?;

    // Send a command and set up a stream
    let channel = source.send_command::<()>(sink_peer.clone(), "CORE.ECHO/echo", None, true).await?.1.unwrap();

    // Send data to the stream 10 times per second
    let mut name_generator = names::Generator::default();
    loop {
        channel.send(name_generator.next().unwrap().as_bytes().to_vec()).await?;
        sleep(Duration::from_millis(100)).await;
    }
}
```

**Sink:**
```rust
use std::error::Error;

use libskyfall::{ handlers::EchoHandler, Client, ClientEvent };

// Create an asynchronous context
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Build the client (could also load from a saved state), and add an EchoHandler for commands
    let mut client = Client::builder().build().await?.with_handler(EchoHandler);

    // Initialize the client
    client.initialize().await?;

    // Listen to the incoming event loop, and trust any peers that connect (peers can be trusted at any time after connection)
    let _events = tokio::spawn((|| {
        let events = client.client_events().clone();
        let client = client.clone();
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

    // Run forever
    loop {}
}
```

### Custom Route Handlers

Custom handlers can be created using an included proc-macro. The following example is the implementation of the `EchoHandler` from the previous examples.

```rust
use libskyfall::{handler, route, handlers::Request, Channel};

pub struct Echo;

// Define the handler wrapper information
#[handler(id = "core.echo", about = "Simple testing protocol")]
impl Echo {
    // Define a route, with optional /:path/:segments
    // To get serialized data: data = <data argument name>
    // To get the open channel: channel = <channel argument name>
    // To get information about the request: request = <request argument name>
    #[route(path = "/echo", channel = channel, request = request)]
    pub async fn echo(&self, request: Request, channel: Channel) -> anyhow::Result<()> {
        println!("Got echo request from {:?}", request.peer);
        loop {
            match channel.recv().await {
                Ok(data) => println!("RECV: {}", String::from_utf8(data).unwrap()),
                Err(e) => eprintln!("RECVERR: {e:?}")
            }
        }
    }
}
```