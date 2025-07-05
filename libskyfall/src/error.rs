use crate::PublicIdentity;

#[derive(thiserror::Error, Debug)]
pub enum IrohError {
    #[error(transparent)]
    Connection(#[from] iroh::endpoint::ConnectionError),

    #[error(transparent)]
    Connect(#[from] iroh::endpoint::ConnectError)
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Encountered an error in the quantum-safe cryptography layer: {0:?}")]
    OQSError(#[from] oqs::Error),

    #[error("A connection to peer {0} already exists. Close it first.")]
    ExistingConnection(String),

    #[error("There is no open connection to {0}.")]
    NotConnected(String),

    #[error("IROH protocol error: {0:?}")]
    Iroh(IrohError),

    #[error("MsgPack encoding error: {0:?}")]
    MsgpackEncoding(#[from] rmp_serde::encode::Error),

    #[error("MsgPack decoding error: {0:?}")]
    MsgpackDecoding(#[from] rmp_serde::decode::Error),

    #[error(transparent)]
    Unhandled(#[from] anyhow::Error)
}

impl<T: Into<IrohError>> From<T> for Error {
    fn from(value: T) -> Self {
        Self::Iroh(value.into())
    }
}

impl Error {
    pub fn existing_connection(peer: &PublicIdentity) -> Self {
        Self::ExistingConnection(peer.id.clone())
    }

    pub fn not_connected(id: impl AsRef<str>) -> Self {
        Self::NotConnected(id.as_ref().to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;