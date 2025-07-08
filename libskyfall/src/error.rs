use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{utils::AsPeerId, PublicIdentity};

#[derive(thiserror::Error, Debug)]
pub enum IrohError {
    #[error(transparent)]
    Connection(#[from] iroh::endpoint::ConnectionError),

    #[error(transparent)]
    Connect(#[from] iroh::endpoint::ConnectError),

    #[error(transparent)]
    ClosedStream(#[from] iroh::endpoint::ClosedStream),

    #[error(transparent)]
    Write(#[from] iroh::endpoint::WriteError),

    #[error(transparent)]
    Read(#[from] iroh::endpoint::ReadError),

    #[error(transparent)]
    ReadExact(#[from] iroh::endpoint::ReadExactError),

    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError)
}

#[derive(thiserror::Error, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BadPacket {
    #[error("Missing magic number (packet is either misaligned or corrupted)")]
    MissingMagic,
    #[error("Unknown packet type: {0}")]
    UnknownType(u8),
    #[error("Unexpected packet type (wrong ordering)")]
    UnexpectedType,
    #[error("Mismatch between START/STOP details (corrupted datastream)")]
    StartStopMismatch
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

    #[error("AES cryptography error: {0:?}")]
    Aes(#[from] aes_gcm::Error),

    #[error("Decrypted message failed signature verification: {0:?}")]
    SignatureVerificationFailed(oqs::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Bad packet: {0:?}")]
    BadPacket(BadPacket),

    #[error("Malformed stream data: expected checksum {0}, received {1}.")]
    StreamChecksumMismatch(u16, u16),

    #[error("Peer identity does not match the expected value.")]
    PeerIdentityMismatch,

    #[error("Unknown stream: {0}")]
    UnknownStream(String),

    #[error("Stream already exists.")]
    StreamExists,

    #[error("Stream ID mismatch.")]
    StreamIdMismatch,

    #[error("Unknown profile: {0:?}")]
    UnknownProfile(Uuid),

    #[error("Unknown peer: {0}")]
    UnknownPeer(String),

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

    pub fn signature_verification(error: oqs::Error) -> Self {
        Self::SignatureVerificationFailed(error)
    }

    pub fn packet_missing_magic() -> Self {
        Self::BadPacket(BadPacket::MissingMagic)
    }

    pub fn packet_unknown_type(typ: impl Into<u8>) -> Self {
        Self::BadPacket(BadPacket::UnknownType(typ.into()))
    }

    pub fn packet_unexpected_type() -> Self {
        Self::BadPacket(BadPacket::UnexpectedType)
    }

    pub fn packet_ss_mismatch() -> Self {
        Self::BadPacket(BadPacket::StartStopMismatch)
    }

    pub fn unknown_stream(id: impl AsRef<str>) -> Self {
        Self::UnknownStream(id.as_ref().to_string())
    }

    pub fn unknown_profile(id: Uuid) -> Self {
        Self::UnknownProfile(id)
    }

    pub fn unknown_peer(id: impl AsPeerId) -> Self {
        Self::UnknownPeer(id.as_peer_id())
    }
}

pub type Result<T> = std::result::Result<T, Error>;