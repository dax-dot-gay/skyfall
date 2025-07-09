use serde::{de::DeserializeOwned, Serialize};

use crate::{utils::StreamId, ContextConnection};

/// An abstraction over an open stream.
#[derive(Clone, Debug)]
pub struct Channel {
    stream: String,
    id: StreamId,
    connection: ContextConnection
}

impl Channel {
    pub(crate) fn new(stream: String, id: StreamId, connection: ContextConnection) -> Self {
        Self { stream, id, connection }
    }

    /// Get this Channel's name
    pub fn name(&self) -> String {
        self.stream.clone()
    }

    /// Get this Channel's [StreamId]
    pub fn id(&self) -> StreamId {
        self.id.clone()
    }

    /// Receive a sent bytestream from this channel
    pub async fn recv(&self) -> crate::Result<Vec<u8>> {
        self.connection.receive_from_stream(self.stream.clone()).await
    }

    /// Send a self-contained bytestream to this channel
    pub async fn send(&self, data: impl IntoIterator<Item = u8>) -> crate::Result<()> {
        self.connection.send_to_stream(self.stream.clone(), data).await
    }

    /// Receive a deserialized object from this channel
    pub async fn recv_object<T: DeserializeOwned>(&self) -> crate::Result<T> {
        Ok(rmp_serde::from_slice::<T>(self.recv().await?.as_slice())?)
    }

    /// Send a serialized object to this channel
    pub async fn send_object<T: Serialize>(&self, object: T) -> crate::Result<()> {
        self.send(rmp_serde::to_vec(&object)?).await
    }
}