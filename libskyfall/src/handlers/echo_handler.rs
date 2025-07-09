#![allow(missing_docs)]

use libskyfall_macros::{handler, route};

use crate::{handlers::Request, Channel};

pub struct Echo;

#[handler(id = "core.echo", libskyfall = "crate", about = "Simple testing protocol")]
impl Echo {
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