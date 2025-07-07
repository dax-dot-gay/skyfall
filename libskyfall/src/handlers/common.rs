use std::collections::HashMap;

use bon::Builder;
use serde::{ Deserialize, Serialize };
use serde_json::Value;
use uuid::Uuid;

use crate::{ utils::StreamId, Channel, Client };

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    id: Uuid,
    path: String,
    data: Option<Value>,
    stream: Option<(String, StreamId)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Listener {
    #[builder(into, start_fn)]
    pub selector: String,
    #[builder(into, start_fn)]
    pub path: String,

    #[builder(default)]
    pub data: bool,
    #[builder(default)]
    pub stream: bool
}

impl Listener {
    pub fn new(selector: impl AsRef<str>, path: impl AsRef<str>, expects_data: bool, expects_stream: bool) -> Self {
        Self { selector: selector.as_ref().to_string(), path: path.as_ref().to_string(), data: expects_data, stream: expects_stream }
    }
}

pub trait Handler {
    fn id(&self) -> String;
    fn get_listeners(&self) -> HashMap<String, Listener>;
    fn on_message(
        &mut self,
        client: Client,
        selector: String,
        id: Uuid,
        path: String,
        data: Option<Value>,
        stream: Option<Channel>
    ) -> anyhow::Result<()>;
}
