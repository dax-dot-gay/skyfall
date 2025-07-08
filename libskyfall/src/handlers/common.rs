use std::collections::HashMap;

use bon::Builder;
use serde::{ Deserialize, Serialize };
use serde_json::Value;
use uuid::Uuid;

use crate::{ utils::StreamId, Channel, Client, Peer };

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Command {
    pub id: Uuid,
    pub path: String,
    pub data: Option<Value>,
    pub stream: Option<(String, StreamId)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Route {
    #[builder(into, start_fn)]
    pub selector: String,
    #[builder(into, start_fn)]
    pub path: String,

    #[builder(default)]
    pub data: bool,
    #[builder(default)]
    pub stream: bool,
}

impl Route {
    pub fn new(
        selector: impl AsRef<str>,
        path: impl AsRef<str>,
        expects_data: bool,
        expects_stream: bool
    ) -> Self {
        Self {
            selector: selector.as_ref().to_string(),
            path: path.as_ref().to_string(),
            data: expects_data,
            stream: expects_stream,
        }
    }
}

#[async_trait::async_trait]
pub trait Handler {
    fn id(&self) -> String;
    fn get_routes(&self) -> HashMap<String, Route>;
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
    ) -> anyhow::Result<()>;
}
