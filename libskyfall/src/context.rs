use std::{ collections::HashMap, fmt::Debug, ops::{ Deref, DerefMut }, sync::Arc };

use aes_gcm::{ aead::{ Aead, AeadCore, OsRng }, Aes256Gcm, Key, KeyInit };
use iroh::{ endpoint::{Connection, RecvStream, SendStream}, Endpoint, NodeAddr };
use oqs::{ kem, sig };
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use crate::{ identity::{ KEM_ALGO, SIG_ALGO }, utils::{InterfaceMessage, StreamId}, Identity, Message, PublicIdentity };

pub const ALPN: &'static [u8] = b"skyfall/0";
pub const CHUNKSIZE: u16 = 512;
pub const MAGIC: u16 = 0x2bf1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(u8)]
enum PacketKind {
    START = 0,
    DATA = 1,
    STOP = 2
}

impl TryFrom<u8> for PacketKind {
    type Error = crate::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::START),
            1 => Ok(Self::DATA),
            2 => Ok(Self::STOP),
            other => Err(crate::Error::packet_unknown_type(other))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Packet {
    Start {
        checksum: u16,
        datasize: u64
    },
    Data(Vec<u8>),
    Stop {
        checksum: u16,
        datasize: u64
    },
}

impl Packet {
    pub async fn read(stream: &mut RecvStream) -> crate::Result<Self> {
        let magic = stream.read_u16().await?;
        if magic != MAGIC {
            let mut _buf = [0; CHUNKSIZE as usize - 2];
            stream.read_exact(&mut _buf).await?;
            return Err(crate::Error::packet_missing_magic());
        }
        let packet_type = match PacketKind::try_from(stream.read_u8().await?) {
            Ok(typ) => typ,
            Err(e) => {
                let mut _buf = [0; CHUNKSIZE as usize - 3];
                stream.read_exact(&mut _buf).await?;
                return Err(e);
            }
        };

        Ok(match packet_type {
            PacketKind::START => {
                let checksum = stream.read_u16().await?;
                let datasize = stream.read_u64().await?;
                let mut _buf = [0; CHUNKSIZE as usize - 13];
                stream.read_exact(&mut _buf).await?;
                Self::Start { checksum, datasize }
            },
            PacketKind::DATA => {
                let mut _buf = [0; CHUNKSIZE as usize - 3];
                stream.read_exact(&mut _buf).await?;
                Self::Data(_buf.to_vec())
            },
            PacketKind::STOP => {
                let checksum = stream.read_u16().await?;
                let datasize = stream.read_u64().await?;
                let mut _buf = [0; CHUNKSIZE as usize - 13];
                stream.read_exact(&mut _buf).await?;
                Self::Stop { checksum, datasize }
            },
        })
    }
}

#[derive(Clone, Debug)]
pub struct ContextConnection {
    pub(self) address: NodeAddr,
    pub(self) connection: Connection,
    pub(self) peer: PublicIdentity,
    pub(self) interface: (Arc<AsyncMutex<SendStream>>, Arc<AsyncMutex<RecvStream>>),
    pub(self) streams: Arc<AsyncRwLock<HashMap<String, (StreamId, Arc<AsyncMutex<SendStream>>, Arc<AsyncMutex<RecvStream>>)>>>
}

impl ContextConnection {
    pub fn connection(&self) -> Connection {
        self.connection.clone()
    }

    pub fn peer(&self) -> PublicIdentity {
        self.peer.clone()
    }

    pub fn address(&self) -> NodeAddr {
        self.address.clone()
    }

    pub(crate) async fn send(stream: &mut SendStream, data: impl IntoIterator<Item = u8>) -> crate::Result<()> {
        let data: Vec<u8> = data.into_iter().collect();
        let checksum = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC).checksum(&data);
        let datasize = data.len() as u64;
        stream.write_u16(MAGIC).await?;
        stream.write_u8(PacketKind::START as u8).await?;
        stream.write_u16(checksum).await?;
        stream.write_u64(datasize).await?;
        stream.write_all(&[0; (CHUNKSIZE - 13) as usize]).await?;

        for chunk in data.chunks((CHUNKSIZE - 1) as usize) {
            stream.write_u16(MAGIC).await?;
            stream.write_u8(PacketKind::DATA as u8).await?;
            if chunk.len() == (CHUNKSIZE - 1) as usize {
                stream.write_all(chunk).await?;
            } else {
                stream.write_all(chunk).await?;
                stream.write_all(Vec::with_capacity(CHUNKSIZE as usize - 3 - chunk.len()).as_slice()).await?;
            }
        }

        stream.write_u16(MAGIC).await?;
        stream.write_u8(PacketKind::STOP as u8).await?;
        stream.write_u16(checksum).await?;
        stream.write_u64(datasize).await?;
        stream.write_all(&[0; (CHUNKSIZE - 13) as usize]).await?;

        Ok(())
    }

    pub(crate) async fn recv(stream: &mut RecvStream) -> crate::Result<Vec<u8>> {
        let mut output = Vec::new();
        let (checksum, datasize) = if let Packet::Start { checksum, datasize } = Packet::read(stream).await? {
            (checksum, datasize)
        } else {
            return Err(crate::Error::packet_unexpected_type());
        };

        loop {
            match Packet::read(stream).await? {
                Packet::Start { .. } => {
                    return Err(crate::Error::packet_unexpected_type());
                },
                Packet::Data(content) => output.extend(content),
                Packet::Stop { checksum: stop_checksum, datasize: stop_datasize } => {
                    if stop_checksum == checksum && stop_datasize == datasize {
                        break;
                    } else {
                        return Err(crate::Error::packet_ss_mismatch());
                    }
                },
            }
        }

        let actual_checksum = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC).checksum(&output);
        if checksum != actual_checksum {
            return Err(crate::Error::StreamChecksumMismatch(checksum, actual_checksum));
        }

        Ok(output)
    }

    pub(crate) async fn send_to_interface(&self, data: impl IntoIterator<Item = u8>) -> crate::Result<()> {
        let mut channel = self.interface.0.lock().await;
        Self::send(&mut channel, data).await
    }

    pub(crate) async fn receive_from_interface(&self) -> crate::Result<Vec<u8>> {
        let mut channel = self.interface.1.lock().await;
        Self::recv(&mut channel).await
    }

    pub(crate) async fn send_to_stream(&self, name: impl AsRef<str>, data: impl IntoIterator<Item = u8>) -> crate::Result<()> {
        let name = name.as_ref().to_string();
        if let Some((_, stream, _)) = self.streams.read().await.get(&name) {
            let mut channel = stream.lock().await;
            Self::send(&mut channel, data).await
        } else {
            Err(crate::Error::unknown_stream(name))
        }
    }

    pub(crate) async fn receive_from_stream(&self, name: impl AsRef<str>) -> crate::Result<Vec<u8>> {
        let name = name.as_ref().to_string();
        if let Some((_, _, stream)) = self.streams.read().await.get(&name) {
            let mut channel = stream.lock().await;
            Self::recv(&mut channel).await
        } else {
            Err(crate::Error::unknown_stream(name))
        }
    }

    pub(crate) async fn streams(&self) -> Vec<String> {
        self.streams.read().await.keys().cloned().collect()
    }

    pub(crate) async fn open_stream(&self, name: impl AsRef<str>) -> crate::Result<StreamId> {
        let name = name.as_ref().to_string();
        let mut streams = self.streams.write().await;
        if streams.contains_key(&name) {
            return Err(crate::Error::StreamExists);
        }
        let (send, recv) = self.open_bi().await?;
        let id = StreamId::from(send.id());
        let _ = streams.insert(name, (id.clone(), Arc::new(AsyncMutex::new(send)), Arc::new(AsyncMutex::new(recv))));
        Ok(id)
    }

    pub(crate) async fn accept_stream(&self, name: String, id: StreamId) -> crate::Result<()> {
        let mut streams = self.streams.write().await;
        if streams.contains_key(&name) {
            return Err(crate::Error::StreamExists);
        }
        let (mut send, mut recv) = self.accept_bi().await?;
        let stream_id = StreamId::from(send.id());
        if stream_id != id {
            let _ = send.finish();
            let _ = recv.stop((1 as u16).into());
            return Err(crate::Error::StreamIdMismatch);
        }

        let _ = streams.insert(name, (id.clone(), Arc::new(AsyncMutex::new(send)), Arc::new(AsyncMutex::new(recv))));
        Ok(())
    }

    pub(crate) async fn get_stream_id(&self, name: impl AsRef<str>) -> crate::Result<StreamId> {
        let name = name.as_ref().to_string();
        if let Some((id, ..)) = self.streams.read().await.get(&name) {
            Ok(id.clone())
        } else {
            Err(crate::Error::unknown_stream(name))
        }
    }

    pub(crate) async fn close_stream(&self, name: impl AsRef<str>) -> crate::Result<()> {
        let name = name.as_ref().to_string();
        let mut streams = self.streams.write().await;
        if let Some((_, asend, arecv)) = streams.remove(&name) {
            let mut send = asend.lock().await;
            let mut recv = arecv.lock().await;
            let _ = send.reset((0 as u8).into());
            let _ = recv.stop((0 as u8).into());
            Ok(())
        } else {
            Err(crate::Error::unknown_stream(name))
        }
    }
}

impl Deref for ContextConnection {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl DerefMut for ContextConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

#[derive(Clone)]
pub struct Context {
    identity: Identity,
    kem: Arc<kem::Kem>,
    sig: Arc<sig::Sig>,
    endpoint: iroh::Endpoint,
    connections: Arc<RwLock<HashMap<String, ContextConnection>>>,
}

impl Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("identity", &self.identity)
            .field("kem", &"Arc<oqs::kem::Kem { ... }>")
            .field("sig", &"Arc<oqs::sig::Sig { ... }>")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl Context {
    pub fn new(identity: Identity, endpoint: Endpoint) -> crate::Result<Self> {
        oqs::init();
        Ok(Self {
            identity: identity,
            kem: Arc::new(kem::Kem::new(KEM_ALGO)?),
            sig: Arc::new(sig::Sig::new(SIG_ALGO)?),
            endpoint: endpoint,
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn connect(&self, peer: &PublicIdentity) -> crate::Result<String> {
        let mut connections = self.connections.write();
        if connections.contains_key(&peer.id) {
            return Err(crate::Error::existing_connection(peer));
        }
        let id = peer.id.clone();

        let mut address = NodeAddr::new(peer.node.clone());
        if let Some(relay) = peer.preferred_relay.clone() {
            address = address.with_relay_url(relay);
        }

        let connection = self.endpoint.connect(address.clone(), ALPN).await?;

        let (mut send, mut recv) = connection.open_bi().await?;
        send.set_priority(1)?;

        ContextConnection::send(&mut send, self.identity.as_public().encode()?).await?;
        let peer_data = PublicIdentity::decode(ContextConnection::recv(&mut recv).await?)?;
        if peer_data != peer.clone() {
            return Err(crate::Error::PeerIdentityMismatch);
        }

        let _ = connections.insert(peer.id.clone(), ContextConnection {
            address,
            connection,
            peer: peer.clone(),
            interface: (Arc::new(AsyncMutex::new(send)), Arc::new(AsyncMutex::new(recv))),
            streams: Arc::new(AsyncRwLock::new(HashMap::new()))
        });
        Ok(id)
    }

    pub(crate) fn connection(&self, id: impl AsRef<str>) -> crate::Result<ContextConnection> {
        self.connections
            .read()
            .get(&id.as_ref().to_string())
            .ok_or(crate::Error::not_connected(&id))
            .cloned()
    }

    pub fn connected_peers(&self) -> Vec<PublicIdentity> {
        self.connections
            .read()
            .values()
            .map(|conn| conn.peer.clone())
            .collect()
    }

    pub fn close_connection(&self, id: impl AsRef<str>) -> crate::Result<()> {
        self.close_connection_with_reason(id, 0, "connection_closed")
    }

    pub fn close_connection_with_reason(
        &self,
        id: impl AsRef<str>,
        code: u32,
        reason: impl AsRef<[u8]>
    ) -> crate::Result<()> {
        if let Some(connection) = self.connections.write().remove(&id.as_ref().to_string()) {
            connection.close(code.into(), reason.as_ref());
            Ok(())
        } else {
            Err(crate::Error::not_connected(&id))
        }
    }

    pub fn encrypt(&self, target: &PublicIdentity, data: Vec<u8>) -> crate::Result<Vec<u8>> {
        let (encapsulated_shared_secret, shared_secret) = self.kem.encapsulate(&target.encryption)?;
        let shared_secret: Key<Aes256Gcm> = Key::<Aes256Gcm>
            ::from_exact_iter(shared_secret.into_vec())
            .expect("OQS generated bad-size key.");
        let aes = Aes256Gcm::new(&shared_secret);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let signature = self.sig.sign(&data, &self.identity.signing_keypair().1)?;
        let encrypted = aes.encrypt(&nonce, &*data)?;

        Message::builder()
            .data(encrypted)
            .nonce(nonce)
            .shared_secret(encapsulated_shared_secret)
            .signature(signature)
            .build()
            .encode()
    }

    pub fn decrypt(&self, origin: &PublicIdentity, data: Vec<u8>) -> crate::Result<Vec<u8>> {
        let message = Message::decode(data)?;
        let shared_secret: Key<Aes256Gcm> = Key::<Aes256Gcm>
            ::from_exact_iter(
                self.kem
                    .decapsulate(&self.identity.encryption_keypair().1, &message.shared_secret())?
                    .into_vec()
            )
            .expect("OQS generated bad-size key.");
        let aes = Aes256Gcm::new(&shared_secret);
        let decrypted = aes.decrypt(&message.nonce(), &*message.data())?;
        self.sig
            .verify(&decrypted, &message.signature(), &origin.signing)
            .or_else(|e| Err(crate::Error::signature_verification(e)))?;
        Ok(decrypted)
    }

    pub async fn send_message_to_peer(&self, id: impl AsRef<str>, message: InterfaceMessage) -> crate::Result<()> {
        let connection = self.connection(id)?;
        let encoded = rmp_serde::to_vec(&message)?;
        let encrypted = self.encrypt(&connection.peer, encoded)?;
        connection.send_to_interface(encrypted).await
    }

    pub async fn recv_message_from_peer(&self, id: impl AsRef<str>) -> crate::Result<InterfaceMessage> {
        let connection = self.connection(id)?;
        let encrypted = connection.receive_from_interface().await?;
        let encoded = self.decrypt(&connection.peer, encrypted)?;
        Ok(rmp_serde::from_slice::<InterfaceMessage>(&encoded)?)
    }
}
