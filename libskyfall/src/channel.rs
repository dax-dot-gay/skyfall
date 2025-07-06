use serde::{de::DeserializeOwned, Serialize};

use crate::{utils::StreamId, ContextConnection};

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

    pub fn name(&self) -> String {
        self.stream.clone()
    }

    pub fn id(&self) -> StreamId {
        self.id.clone()
    }

    pub async fn recv(&self) -> crate::Result<Vec<u8>> {
        self.connection.receive_from_stream(self.stream.clone()).await
    }

    pub async fn send(&self, data: impl IntoIterator<Item = u8>) -> crate::Result<()> {
        self.connection.send_to_stream(self.stream.clone(), data).await
    }

    pub async fn recv_object<T: DeserializeOwned>(&self) -> crate::Result<T> {
        Ok(rmp_serde::from_slice::<T>(self.recv().await?.as_slice())?)
    }

    pub async fn send_object<T: Serialize>(&self, object: T) -> crate::Result<()> {
        self.send(rmp_serde::to_vec(&object)?).await
    }
}