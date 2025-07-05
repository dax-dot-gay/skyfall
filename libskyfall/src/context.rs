use std::{ collections::HashMap, fmt::Debug, ops::{ Deref, DerefMut }, sync::Arc };

use iroh::{ endpoint::{ Connection, VarInt }, Endpoint, NodeAddr, NodeId };
use oqs::{ kem, sig };
use parking_lot::RwLock;

use crate::{ identity::{ KEM_ALGO, SIG_ALGO }, Identity, PublicIdentity };

pub const ALPN: &'static [u8] = b"skyfall/0";

#[derive(Clone, Debug)]
pub struct ContextConnection {
    pub(self) address: NodeAddr,
    pub(self) connection: Connection,
    pub(self) peer: PublicIdentity,
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
        let _ = connections.insert(peer.id.clone(), ContextConnection {
            address,
            connection,
            peer: peer.clone(),
        });
        Ok(id)
    }

    pub fn connection(&self, id: impl AsRef<str>) -> crate::Result<ContextConnection> {
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
}
