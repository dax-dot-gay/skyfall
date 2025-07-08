use std::collections::HashMap;

use serde_json::Value;
use uuid::Uuid;

use crate::{handlers::{Handler, Route}, Channel, Client, Peer};

pub struct Echo;

#[async_trait::async_trait]
impl Handler for Echo {
    fn id(&self) -> String {
        String::from("core.echo")
    }

    fn get_routes(&self) -> std::collections::HashMap<String,super::Route> {
        HashMap::from_iter(vec![(String::from("echo"), Route::builder("echo", "ECHO/echo").stream(true).build())])
    }

    async fn on_message(
        &mut self,
        selector: String,
        path: String,
        client: Client,
        peer: Peer,
        route: Route,
        id: Uuid,
        captured_segments: Vec<(String, String)>,
        data: Option<Value>,
        stream: Option<Channel>
    ) -> anyhow::Result<()> {
        println!("Got echo request from {peer:?}");
        if let Some(st) = stream {
            loop {
                match st.recv().await {
                    Ok(data) => println!("RECV: {}", String::from_utf8(data).unwrap()),
                    Err(e) => eprintln!("RECVERR: {e:?}")
                }
            }
        } else {
            println!("NO STREAM!");
            Ok(())
        }
    }
}