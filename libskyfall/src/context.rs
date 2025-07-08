use std::{ collections::{ HashMap, HashSet }, fmt::Debug, ops::{ Deref, DerefMut }, sync::Arc };

use aes_gcm::{ aead::{ Aead, AeadCore, OsRng }, Aes256Gcm, Key, KeyInit };
use async_channel::{ Receiver, Sender };
use futures::{ stream::FuturesUnordered, StreamExt as _ };
use iroh::{ endpoint::{ Connection, RecvStream, SendStream }, Endpoint, NodeAddr };
use oqs::{ kem, sig };
use parking_lot::RwLock;
use serde::{ Deserialize, Serialize };
use tokio::{ io::{ AsyncReadExt, AsyncWriteExt }, task::JoinHandle };
use tokio::sync::{ Mutex as AsyncMutex, RwLock as AsyncRwLock };

use crate::{
    identity::{ KEM_ALGO, SIG_ALGO },
    utils::{ InterfaceMessage, StreamId },
    Channel,
    Identity,
    Message,
    PublicIdentity,
};

pub const ALPN: &'static [u8] = b"skyfall/0";
pub const CHUNKSIZE: u16 = 512;
pub const MAGIC: u16 = 0x2bf1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(u8)]
enum PacketKind {
    START = 0,
    DATA = 1,
    FINALDATA = 2,
}

impl TryFrom<u8> for PacketKind {
    type Error = crate::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::START),
            1 => Ok(Self::DATA),
            2 => Ok(Self::FINALDATA),
            other => Err(crate::Error::packet_unknown_type(other)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Packet {
    Start {
        checksum: u16,
        datasize: u64,
    },
    Data(Vec<u8>),
    FinalData(Vec<u8>),
}

impl Packet {
    pub async fn read(stream: &mut RecvStream) -> crate::Result<Self> {
        let magic = stream.read_u16().await?;
        if magic != MAGIC {
            let mut _buf = [0; (CHUNKSIZE as usize) - 2];
            stream.read_exact(&mut _buf).await?;
            return Err(crate::Error::packet_missing_magic());
        }
        let packet_type = match PacketKind::try_from(stream.read_u8().await?) {
            Ok(typ) => typ,
            Err(e) => {
                let mut _buf = [0; (CHUNKSIZE as usize) - 3];
                stream.read_exact(&mut _buf).await?;
                return Err(e);
            }
        };

        let result = match packet_type {
            PacketKind::START => {
                let checksum = stream.read_u16().await?;
                let datasize = stream.read_u64().await?;
                let mut _buf = [0; (CHUNKSIZE as usize) - 13];
                stream.read_exact(&mut _buf).await?;
                Self::Start { checksum, datasize }
            }
            PacketKind::DATA => {
                let mut _buf = [0; (CHUNKSIZE as usize) - 3];
                stream.read_exact(&mut _buf).await?;
                Self::Data(_buf.to_vec())
            }
            PacketKind::FINALDATA => {
                let mut _buf = [0; (CHUNKSIZE as usize) - 3];
                stream.read_exact(&mut _buf).await?;
                Self::FinalData(_buf.to_vec())
            }
        };

        //println!("PACKET: {magic:#x}, {packet_type:?}, {result:?}");
        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct ContextConnection {
    pub(self) address: NodeAddr,
    pub(self) connection: Connection,
    pub(self) peer: PublicIdentity,
    pub(self) interface: (Arc<AsyncMutex<SendStream>>, Arc<AsyncMutex<RecvStream>>),
    pub(self) streams: Arc<
        AsyncRwLock<
            HashMap<String, (StreamId, Arc<AsyncMutex<SendStream>>, Arc<AsyncMutex<RecvStream>>)>
        >
    >,
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

    pub(crate) async fn send(
        stream: &mut SendStream,
        data: impl IntoIterator<Item = u8>
    ) -> crate::Result<()> {
        let data: Vec<u8> = data.into_iter().collect();
        let checksum = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC).checksum(&data);
        let datasize = data.len() as u64;
        stream.write_u16(MAGIC).await?;
        stream.write_u8(PacketKind::START as u8).await?;
        stream.write_u16(checksum).await?;
        stream.write_u64(datasize).await?;
        stream.write_all(&[0; (CHUNKSIZE - 13) as usize]).await?;

        for chunk in data.chunks((CHUNKSIZE - 3) as usize) {
            stream.write_u16(MAGIC).await?;
            if chunk.len() == ((CHUNKSIZE - 3) as usize) {
                stream.write_u8(PacketKind::DATA as u8).await?;
                stream.write_all(chunk).await?;
            } else {
                stream.write_u8(PacketKind::FINALDATA as u8).await?;
                stream.write_all(chunk).await?;
                stream.write_all(
                    vec![0u8; (CHUNKSIZE as usize) - 3 - chunk.len()].as_slice()
                ).await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn recv(stream: &mut RecvStream) -> crate::Result<Vec<u8>> {
        let mut output = Vec::new();
        let (checksum, datasize) = if
            let Packet::Start { checksum, datasize } = Packet::read(stream).await?
        {
            (checksum, datasize)
        } else {
            return Err(crate::Error::packet_unexpected_type());
        };

        loop {
            match Packet::read(stream).await? {
                Packet::Start { .. } => {
                    return Err(crate::Error::packet_unexpected_type());
                }
                Packet::Data(content) => output.extend(content),
                Packet::FinalData(content) => {
                    output.extend(content);
                    break;
                }
            }
        }

        let output = output[..datasize as usize].to_vec();

        let actual_checksum = crc::Crc::<u16>::new(&crc::CRC_16_IBM_SDLC).checksum(&output);
        if checksum != actual_checksum {
            return Err(crate::Error::StreamChecksumMismatch(checksum, actual_checksum));
        }

        //println!("GOT DATA: {actual_checksum:#x} || CRC: {checksum:#x}");

        Ok(output)
    }

    pub(crate) async fn send_to_interface(
        &self,
        data: impl IntoIterator<Item = u8>
    ) -> crate::Result<()> {
        let mut channel = self.interface.0.lock().await;
        Self::send(&mut channel, data).await
    }

    pub(crate) async fn receive_from_interface(&self) -> crate::Result<Vec<u8>> {
        let mut channel = self.interface.1.lock().await;
        Self::recv(&mut channel).await
    }

    pub(crate) async fn send_to_stream(
        &self,
        name: impl AsRef<str>,
        data: impl IntoIterator<Item = u8>
    ) -> crate::Result<()> {
        let name = name.as_ref().to_string();
        if let Some((_, stream, _)) = self.streams.read().await.get(&name) {
            let mut channel = stream.lock().await;
            Self::send(&mut channel, data).await
        } else {
            Err(crate::Error::unknown_stream(name))
        }
    }

    pub(crate) async fn receive_from_stream(
        &self,
        name: impl AsRef<str>
    ) -> crate::Result<Vec<u8>> {
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
        let (mut send, mut recv) = self.open_bi().await?;
        println!("SENDING STREAM NAME");
        Self::send(&mut send, name.as_bytes().to_vec()).await?;
        println!("WAITING FOR MAGIC NUMBER REPLY");
        (match recv.read_u16().await {
            Ok(MAGIC) => Ok(()),
            Ok(_) => Err(crate::Error::StreamInitFailure),
            Err(e) => Err(crate::Error::from(e)),
        })?;
        let id = StreamId::from(send.id());
        let _ = streams.insert(name, (
            id.clone(),
            Arc::new(AsyncMutex::new(send)),
            Arc::new(AsyncMutex::new(recv)),
        ));
        Ok(id)
    }

    pub(crate) async fn accept_stream(&self) -> crate::Result<(String, StreamId)> {
        let (mut send, mut recv) = self.accept_bi().await?;
        let name = String::from_utf8(Self::recv(&mut recv).await?)?;
        println!("GOT STREAM NAME");
        send.write_u16(MAGIC).await?;
        println!("SENT MAGIC");
        let stream_id = StreamId::from(send.id());
        let mut streams = self.streams.write().await;

        let _ = streams.insert(name.clone(), (
            stream_id.clone(),
            Arc::new(AsyncMutex::new(send)),
            Arc::new(AsyncMutex::new(recv)),
        ));
        Ok((name, stream_id))
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

#[derive(Debug, Clone)]
pub enum ContextEvent {
    AcceptedConnection(String),
    OpenedConnection(String),
    ClosedConnection(String),
    AcceptedStream(String, String, StreamId),
    ReceivedMessage(PublicIdentity, InterfaceMessage),
    RecvFailure,
    MessageFailure(String),
    ConnectorFailure,
    StreamFailure(String),
}

#[derive(Debug, Clone)]
enum FutureGenericArgs {
    EventListener(Receiver<ContextEvent>),
    MessageListener(String, Context),
    HandlerReply(Context, InterfaceMessage, PublicIdentity),
    AcceptIncoming(Context),
    AcceptStreams(Context, String),
}

#[derive(Clone)]
pub struct Context {
    identity: Identity,
    kem: Arc<kem::Kem>,
    sig: Arc<sig::Sig>,
    endpoint: iroh::Endpoint,
    connections: Arc<RwLock<HashMap<String, ContextConnection>>>,
    event_loop: Option<Arc<JoinHandle<()>>>,
    event_channel: Sender<ContextEvent>,
    parent_channel: Sender<ContextEvent>,
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
    pub fn new(
        identity: Identity,
        endpoint: Endpoint,
        parent_channel: Sender<ContextEvent>
    ) -> crate::Result<Self> {
        oqs::init();

        let (tx, rx) = async_channel::unbounded::<ContextEvent>();

        let mut instance = Self {
            identity: identity,
            kem: Arc::new(kem::Kem::new(KEM_ALGO)?),
            sig: Arc::new(sig::Sig::new(SIG_ALGO)?),
            endpoint: endpoint,
            connections: Arc::new(RwLock::new(HashMap::new())),
            event_loop: None,
            event_channel: tx,
            parent_channel,
        };

        instance.event_loop = Some(Arc::new(tokio::spawn(Self::event_loop(instance.clone(), rx))));
        Ok(instance)
    }

    pub async fn connect(&self, peer: &PublicIdentity) -> crate::Result<String> {
        let mut connections = self.connections.write();
        if connections.contains_key(&peer.id) {
            return Err(crate::Error::existing_connection(peer));
        }
        let id = peer.id.clone();

        let mut address = NodeAddr::new(peer.node.clone());
        if let Some(relay) = peer.relay.clone() {
            address = address.with_relay_url(relay);
        }

        //println!("Waiting for connection...");
        let connection = self.endpoint.connect(address.clone(), ALPN).await?;

        let (mut send, mut recv) = connection.open_bi().await?;
        send.set_priority(1)?;

        ContextConnection::send(&mut send, self.identity.as_public().encode()?).await?;
        //println!("Sent handshake!");
        let peer_data = PublicIdentity::decode(ContextConnection::recv(&mut recv).await?)?;
        if peer_data != peer.clone() {
            return Err(crate::Error::PeerIdentityMismatch);
        }

        let _ = connections.insert(peer.id.clone(), ContextConnection {
            address,
            connection,
            peer: peer.clone(),
            interface: (Arc::new(AsyncMutex::new(send)), Arc::new(AsyncMutex::new(recv))),
            streams: Arc::new(AsyncRwLock::new(HashMap::new())),
        });

        self.event_channel.send(ContextEvent::OpenedConnection(peer.id.clone())).await.unwrap();

        Ok(id)
    }

    async fn accept(&self) -> crate::Result<Option<String>> {
        //println!("Waiting to accept...");
        let connection = if let Some(c) = self.endpoint.accept().await {
            c.accept()?.await?
        } else {
            return Ok(None);
        };

        //println!("Accepted...");

        let (mut send, mut recv) = connection.accept_bi().await?;
        send.set_priority(1)?;

        //println!("Waiting for client's handshake...");
        let peer_data = PublicIdentity::decode(ContextConnection::recv(&mut recv).await?)?;
        //println!("Got client handshake: {peer_data:?}");
        ContextConnection::send(&mut send, self.identity.as_public().encode()?).await?;
        let mut connections = self.connections.write();
        let mut address = NodeAddr::new(peer_data.node.clone());
        if let Some(relay) = peer_data.relay.clone() {
            address = address.with_relay_url(relay);
        }

        let _ = connections.insert(peer_data.id.clone(), ContextConnection {
            address,
            connection,
            peer: peer_data.clone(),
            interface: (Arc::new(AsyncMutex::new(send)), Arc::new(AsyncMutex::new(recv))),
            streams: Arc::new(AsyncRwLock::new(HashMap::new())),
        });
        Ok(Some(peer_data.id))
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
        let id = id.as_ref().to_string();
        if let Some(connection) = self.connections.write().remove(&id) {
            connection.close(code.into(), reason.as_ref());
            self.event_channel.send_blocking(ContextEvent::ClosedConnection(id.clone())).unwrap();
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

    pub(crate) async fn send_message_to_peer(
        &self,
        id: impl AsRef<str>,
        message: InterfaceMessage
    ) -> crate::Result<()> {
        let connection = self.connection(id)?;
        let encoded = rmp_serde::to_vec(&message)?;
        let encrypted = self.encrypt(&connection.peer, encoded)?;
        connection.send_to_interface(encrypted).await
    }

    pub(crate) async fn recv_message_from_peer(
        &self,
        id: impl AsRef<str>
    ) -> crate::Result<(PublicIdentity, InterfaceMessage)> {
        let id = id.as_ref().to_string();
        let connection = self.connection(&id)?;
        let encrypted = connection.receive_from_interface().await?;
        let encoded = self.decrypt(&connection.peer, encrypted)?;
        Ok((connection.peer, rmp_serde::from_slice::<InterfaceMessage>(&encoded)?))
    }

    pub async fn open_channel(
        &self,
        peer: &PublicIdentity,
        name: impl AsRef<str>
    ) -> crate::Result<Channel> {
        let name = name.as_ref().to_string();
        let connection = self.connection(peer.id.clone())?;
        let created_id = connection.open_stream(name.clone()).await?;
        Ok(Channel::new(name.clone(), created_id.clone(), connection))
    }

    pub async fn close_channel(
        &self,
        peer: &PublicIdentity,
        name: impl AsRef<str>
    ) -> crate::Result<()> {
        let name = name.as_ref().to_string();
        let connection = self.connection(peer.id.clone())?;
        connection.close_stream(name.clone()).await?;
        Ok(())
    }

    pub async fn get_channel(
        &self,
        peer: &PublicIdentity,
        name: impl AsRef<str>
    ) -> crate::Result<Channel> {
        let name = name.as_ref().to_string();
        let connection = self.connection(peer.id.clone())?;
        let stream_id = connection.get_stream_id(name.clone()).await?;

        Ok(Channel::new(name, stream_id, connection))
    }

    pub async fn channels(&self, peer: &PublicIdentity) -> crate::Result<Vec<String>> {
        let connection = self.connection(peer.id.clone())?;
        Ok(connection.streams().await)
    }
}

// Event-loop related functions
impl Context {
    async fn _handle_message(ctx: Context, message: InterfaceMessage, peer: PublicIdentity) -> () {
        if let Ok(_connection) = ctx.connection(peer.id.clone()) {
            match message {
                _ => (),
            }
        }
    }

    async fn _get_next_ctx_event(events: Receiver<ContextEvent>) -> Option<ContextEvent> {
        Some(events.recv().await.unwrap_or(ContextEvent::RecvFailure))
    }

    async fn _get_next_message_from_peer(ctx: Context, id: String) -> Option<ContextEvent> {
        if let Ok((peer, message)) = ctx.recv_message_from_peer(id.clone()).await {
            Some(ContextEvent::ReceivedMessage(peer, message))
        } else {
            Some(ContextEvent::MessageFailure(id))
        }
    }

    async fn _accept_incoming_connections(ctx: Context) -> Option<ContextEvent> {
        //println!("WAITING TO ACCEPT INCOMING...");
        match ctx.accept().await {
            Ok(Some(peer)) => Some(ContextEvent::AcceptedConnection(peer)),
            _ => {
                //println!("ACCEPT_FAIL: {other:?}");
                Some(ContextEvent::ConnectorFailure)
            }
        }
    }

    async fn _accept_incoming_streams(ctx: Context, peer: String) -> Option<ContextEvent> {
        if let Ok(connection) = ctx.connection(peer.clone()) {
            if let Ok((name, stream_id)) = connection.accept_stream().await {
                return Some(ContextEvent::AcceptedStream(peer, name, stream_id));
            }
        }

        Some(ContextEvent::StreamFailure(peer))
    }

    async fn event_future(mode: FutureGenericArgs) -> Option<ContextEvent> {
        match mode {
            FutureGenericArgs::EventListener(receiver) => Self::_get_next_ctx_event(receiver).await,
            FutureGenericArgs::MessageListener(id, context) =>
                Self::_get_next_message_from_peer(context, id).await,
            FutureGenericArgs::HandlerReply(context, interface_message, public_identity) => {
                Self::_handle_message(context, interface_message, public_identity).await;
                None
            }
            FutureGenericArgs::AcceptIncoming(context) =>
                Self::_accept_incoming_connections(context).await,
            FutureGenericArgs::AcceptStreams(context, id) =>
                Self::_accept_incoming_streams(context, id).await,
        }
    }

    async fn event_loop(ctx: Self, events: Receiver<ContextEvent>) -> () {
        let mut listening: HashSet<String> = HashSet::new();
        let mut futs = FuturesUnordered::new();
        futs.push(Self::event_future(FutureGenericArgs::EventListener(events.clone())));
        futs.push(Self::event_future(FutureGenericArgs::AcceptIncoming(ctx.clone())));
        while let Some(maybe_evt) = futs.next().await {
            if let Some(evt) = maybe_evt {
                let _ = ctx.parent_channel.send(evt.clone()).await;
                match evt {
                    ContextEvent::AcceptedConnection(id) => {
                        listening.insert(id.clone());
                        futs.push(
                            Self::event_future(FutureGenericArgs::MessageListener(id.clone(), ctx.clone()))
                        );
                        futs.push(
                            Self::event_future(FutureGenericArgs::AcceptIncoming(ctx.clone()))
                        );
                        futs.push(
                                Self::event_future(
                                    FutureGenericArgs::AcceptStreams(ctx.clone(), id)
                                )
                            );
                    }
                    ContextEvent::OpenedConnection(id) => {
                        listening.insert(id.clone());
                        futs.push(
                            Self::event_future(FutureGenericArgs::EventListener(events.clone()))
                        );
                        futs.push(
                            Self::event_future(FutureGenericArgs::MessageListener(id.clone(), ctx.clone()))
                        );
                        futs.push(
                                Self::event_future(
                                    FutureGenericArgs::AcceptStreams(ctx.clone(), id)
                                )
                            );
                    }
                    ContextEvent::ClosedConnection(id) => {
                        listening.remove(&id);
                        futs.push(
                            Self::event_future(FutureGenericArgs::EventListener(events.clone()))
                        );
                    }
                    ContextEvent::ReceivedMessage(public_identity, interface_message) => {
                        futs.push(
                            Self::event_future(
                                FutureGenericArgs::HandlerReply(
                                    ctx.clone(),
                                    interface_message,
                                    public_identity.clone()
                                )
                            )
                        );
                        if listening.contains(&public_identity.id) {
                            futs.push(
                                Self::event_future(
                                    FutureGenericArgs::MessageListener(
                                        public_identity.id,
                                        ctx.clone()
                                    )
                                )
                            );
                        }
                    }
                    ContextEvent::RecvFailure => {
                        futs.push(
                            Self::event_future(FutureGenericArgs::EventListener(events.clone()))
                        );
                    }
                    ContextEvent::AcceptedStream(peer, ..) => {
                        if listening.contains(&peer) {
                            futs.push(
                                Self::event_future(
                                    FutureGenericArgs::AcceptStreams(ctx.clone(), peer)
                                )
                            );
                        }
                    }
                    ContextEvent::MessageFailure(peer) => {
                        if listening.contains(&peer) {
                            futs.push(
                                Self::event_future(
                                    FutureGenericArgs::MessageListener(peer, ctx.clone())
                                )
                            );
                        }
                    }
                    ContextEvent::ConnectorFailure => {
                        futs.push(
                            Self::event_future(FutureGenericArgs::EventListener(events.clone()))
                        );
                    }
                    ContextEvent::StreamFailure(peer) => {
                        if listening.contains(&peer) {
                            futs.push(
                                Self::event_future(
                                    FutureGenericArgs::AcceptStreams(ctx.clone(), peer)
                                )
                            );
                        }
                    }
                }
            }
        }

        ()
    }
}
