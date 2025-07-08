use std::{ collections::HashMap, fmt::Debug, sync::Arc };
use async_channel::{ Receiver, Sender };
use bon::Builder;
use enum_common_fields::EnumCommonFields;
use iroh::Endpoint;
use parking_lot::RwLock;
use serde::{ Deserialize, Serialize };
use tokio::task::JoinHandle;
use uuid::Uuid;
use crate::{
    context::ContextEvent,
    handlers::{ Handler, Route },
    utils::{ AsPeerId, RelayMode, Router },
    Context,
    Identity,
    PublicIdentity,
    ALPN,
};

#[derive(Clone, Debug, Serialize, Deserialize, Builder)]
pub struct Profile {
    #[builder(field = Uuid::new_v4())]
    pub id: Uuid,

    #[builder(default = Profile::default_name())]
    pub name: String,

    #[builder(default)]
    pub pronouns: Vec<String>,
    pub about: Option<String>,
}

impl Default for Profile {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Profile {
    pub(self) fn default_name() -> String {
        names::Generator::default().next().unwrap()
    }
}

type PeerActiveProfile = Option<Uuid>;
type PeerProfiles = HashMap<Uuid, Profile>;
type PeerRoutes = HashMap<String, Route>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub identity: PublicIdentity,
    pub active_profile: Option<Uuid>,
    pub profiles: HashMap<Uuid, Profile>,
    pub routes: HashMap<String, Route>,
}

impl PeerInfo {
    pub fn id(&self) -> String {
        self.identity.id.clone()
    }
}

impl From<PublicIdentity> for PeerInfo {
    fn from(value: PublicIdentity) -> Self {
        Self {
            identity: value,
            active_profile: None,
            profiles: HashMap::new(),
            routes: HashMap::new(),
        }
    }
}

impl From<Peer> for PeerInfo {
    fn from(value: Peer) -> Self {
        match value {
            Peer::Trusted(peer_info) | Peer::Untrusted(peer_info) => peer_info,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, EnumCommonFields)]
#[common_field(identity as identity_ref: PublicIdentity)]
#[common_field(mut_only identity as identity_mut: PublicIdentity)]
#[common_field(active_profile as active_profile_ref: PeerActiveProfile)]
#[common_field(mut_only active_profile as active_profile_mut: PeerActiveProfile)]
#[common_field(profiles as profiles_ref: PeerProfiles)]
#[common_field(mut_only profiles as profiles_mut: PeerProfiles)]
#[common_field(routes as routes_ref: PeerRoutes)]
#[common_field(mut_only routes as routes_mut: PeerRoutes)]
pub enum Peer {
    Trusted(PeerInfo),
    Untrusted(PeerInfo),
}

impl Peer {
    pub fn id(&self) -> String {
        match self {
            Peer::Trusted(trusted_peer) => trusted_peer.id(),
            Peer::Untrusted(untrusted_peer) => untrusted_peer.id(),
        }
    }

    pub fn trusted(&self) -> bool {
        match self {
            Self::Trusted(_) => true,
            Self::Untrusted(_) => false,
        }
    }

    pub fn trust(peer: PeerInfo) -> Self {
        Self::Trusted(peer)
    }

    pub fn distrust(peer: PeerInfo) -> Self {
        Self::Untrusted(peer)
    }

    pub fn identity(&self) -> PublicIdentity {
        self.identity_ref().clone()
    }

    pub fn active_profile(&self) -> Option<Uuid> {
        self.active_profile_ref().clone()
    }

    pub fn profiles(&self) -> HashMap<Uuid, Profile> {
        self.profiles_ref().clone()
    }

    pub fn routes(&self) -> HashMap<String, Route> {
        self.routes_ref().clone()
    }
}

impl From<PeerInfo> for Peer {
    fn from(value: PeerInfo) -> Self {
        Self::Trusted(value)
    }
}

impl From<PublicIdentity> for Peer {
    fn from(value: PublicIdentity) -> Self {
        Self::Untrusted(PeerInfo {
            identity: value,
            active_profile: None,
            profiles: HashMap::new(),
            routes: HashMap::new(),
        })
    }
}

impl AsPeerId for Peer {
    fn as_peer_id(&self) -> String {
        self.id()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename = "snake_case", tag = "event")]
pub enum ClientEvent {
    Connected {
        peer: Peer,
    },
    UpdatedPeer {
        peer: Peer,
        identity: PublicIdentity,
        active_profile: Option<Uuid>,
        profiles: HashMap<Uuid, Profile>,
        routes: HashMap<String, Route>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    pub(self) identity: Identity,
    pub(self) profiles: HashMap<Uuid, Profile>,
    pub(self) active_profile: Option<Uuid>,
    pub(self) known_peers: HashMap<String, Peer>,
    pub(self) relay_mode: RelayMode,
}

#[derive(Clone)]
pub struct Client {
    state: Arc<RwLock<ClientState>>,
    context: Context,
    context_events: Receiver<ContextEvent>,
    client_events: (Sender<ClientEvent>, Receiver<ClientEvent>),
    event_loop: Option<Arc<JoinHandle<()>>>,
    handlers: HashMap<String, Arc<RwLock<dyn Handler + 'static + Send + Sync>>>,
    initialized: bool,
}

impl Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handlers_dbg: HashMap<String, String> = self.handlers
            .iter()
            .map(|(key, handler)| (key.clone(), format!("Arc<RwLock<{}>>", handler.read().id())))
            .collect();

        f.debug_struct("Client")
            .field("state", &self.state)
            .field("context", &self.context)
            .field("context_events", &self.context_events)
            .field("event_loop", &self.event_loop)
            .field("handlers", &handlers_dbg)
            .finish()
    }
}

// Initialization functions
#[bon::bon]
impl Client {
    #[builder]
    pub async fn new(
        #[builder(field)] active_profile: Option<Uuid>,
        #[builder(field)] profiles: HashMap<Uuid, Profile>,
        #[builder(field)] known_peers: HashMap<String, Peer>,
        #[builder(default)] identity: Identity,
        #[builder(default, into)] relay_mode: RelayMode
    ) -> crate::Result<Self> {
        let (context_sender, context_receiver) = async_channel::unbounded::<ContextEvent>();
        let endpoint = Endpoint::builder()
            .discovery_dht()
            .discovery_local_network()
            .discovery_n0()
            .relay_mode(relay_mode.clone().into())
            .alpns(vec![ALPN.to_vec()])
            .secret_key(identity.iroh_secret())
            .bind().await?;

        let context = Context::new(identity.clone(), endpoint, context_sender)?;

        Ok(Self {
            state: Arc::new(
                RwLock::new(ClientState {
                    identity,
                    profiles,
                    active_profile,
                    known_peers,
                    relay_mode,
                })
            ),
            context,
            context_events: context_receiver,
            client_events: async_channel::unbounded(),
            event_loop: None,
            handlers: HashMap::new(),
            initialized: false,
        })
    }

    pub async fn from_state(state: ClientState) -> crate::Result<Self> {
        let (context_sender, context_receiver) = async_channel::unbounded::<ContextEvent>();
        let endpoint = Endpoint::builder()
            .discovery_dht()
            .discovery_local_network()
            .discovery_n0()
            .relay_mode(state.relay_mode.clone().into())
            .alpns(vec![ALPN.to_vec()])
            .secret_key(state.identity.iroh_secret())
            .bind().await?;

        let context = Context::new(state.identity.clone(), endpoint, context_sender)?;

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            context,
            context_events: context_receiver,
            client_events: async_channel::unbounded(),
            event_loop: None,
            handlers: HashMap::new(),
            initialized: false,
        })
    }

    pub async fn initialize(&mut self) -> crate::Result<()> {
        if self.initialized {
            panic!("Already initialized!");
        }

        self.initialized = true;
        let cloned_ctx = self.context.clone();
        let _ = futures::future::join_all(
            self
                .peers()
                .iter()
                .map(move |peer| {
                    let ctx = cloned_ctx.clone();
                    async move {
                        let _ = ctx.connect(&peer.identity()).await;
                    }
                })
        ).await;
        self.event_loop = Some(Arc::new(tokio::spawn(self.clone().event_loop())));
        Ok(())
    }

    pub fn into_state(self) -> ClientState {
        self.state.read().clone()
    }

    pub fn with_handler(mut self, handler: impl Handler + 'static + Send + Sync) -> Self {
        if self.initialized {
            panic!("Cannot add a handler to an initialized client.");
        }

        let _ = self.handlers.insert(handler.id(), Arc::new(RwLock::new(handler)));
        self
    }

    pub fn identity(&self) -> Identity {
        self.state.read().identity.clone()
    }

    pub fn profiles(&self) -> HashMap<Uuid, Profile> {
        self.state.read().profiles.clone()
    }

    pub fn profile(&self, id: Uuid) -> Option<Profile> {
        self.state.read().profiles.get(&id).cloned()
    }

    pub async fn add_profile(&self, profile: Profile) -> crate::Result<()> {
        let _ = self.state.write().profiles.insert(profile.id.clone(), profile);
        // Update peers about this profile change
        Ok(())
    }

    pub async fn remove_profile(&self, id: Uuid) -> crate::Result<()> {
        let _ = self.state.write().profiles.remove(&id);
        if
            self.state
                .read()
                .active_profile.clone()
                .is_some_and(|v| v == id)
        {
            self.clear_active_profile().await;
        }
        // Update peers about this profile change
        Ok(())
    }

    pub async fn set_active_profile(&self, id: Uuid) -> crate::Result<Profile> {
        if let Some(profile) = self.profile(id.clone()) {
            let mut state = self.state.write();
            state.active_profile = Some(id);
            // Update peers about this profile change
            Ok(profile)
        } else {
            Err(crate::Error::unknown_profile(id))
        }
    }

    pub async fn clear_active_profile(&self) -> () {
        let mut state = self.state.write();
        state.active_profile = None;
        // Update peers about this profile change
    }

    pub fn active_profile(&self) -> Option<Profile> {
        if let Some(active) = self.state.read().active_profile.clone() {
            self.profile(active)
        } else {
            None
        }
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.state.read().known_peers.clone().values().cloned().collect()
    }

    pub fn peer(&self, id: impl AsPeerId) -> Option<Peer> {
        self.state.read().known_peers.get(&id.as_peer_id()).cloned()
    }

    pub fn connected_peers(&self) -> Vec<Peer> {
        let mut result = Vec::new();
        let connected = self.context.connected_peers();

        for peer in self.peers() {
            if connected.contains(&peer.identity()) {
                result.push(peer);
            }
        }

        result
    }

    pub fn insert_peer(&self, peer: impl Into<Peer>) -> bool {
        let peer: Peer = peer.into();
        self.state.write().known_peers.insert(peer.id(), peer).is_some()
    }

    pub fn remove_peer(&self, id: impl AsPeerId) -> bool {
        self.state.write().known_peers.remove(&id.as_peer_id()).is_some()
    }

    pub fn set_peer_info(
        &self,
        id: impl AsPeerId,
        active_profile: Option<Uuid>,
        profiles: HashMap<Uuid, Profile>,
        routes: HashMap<String, Route>
    ) -> crate::Result<Peer> {
        let id = id.as_peer_id();
        if let Some(mut peer) = self.peer(id.clone()) {
            *peer.active_profile_mut() = active_profile;
            *peer.profiles_mut() = profiles;
            *peer.routes_mut() = routes;
            self.insert_peer(peer.clone());
            Ok(peer)
        } else {
            Err(crate::Error::unknown_peer(id))
        }
    }

    pub fn trust_peer(&self, id: impl AsPeerId) -> crate::Result<Peer> {
        let id = id.as_peer_id();
        if let Some(peer) = self.peer(id.clone()) {
            let _ = self.insert_peer(Peer::Trusted(peer.clone().into()));
            Ok(Peer::Trusted(peer.into()))
        } else {
            Err(crate::Error::unknown_peer(id))
        }
    }

    pub fn distrust_peer(&self, id: impl AsPeerId) -> crate::Result<Peer> {
        let id = id.as_peer_id();
        if let Some(peer) = self.peer(id.clone()) {
            let _ = self.insert_peer(Peer::Untrusted(peer.clone().into()));
            Ok(Peer::Untrusted(peer.into()))
        } else {
            Err(crate::Error::unknown_peer(id))
        }
    }
}

use client_builder::State;

impl<S: State> ClientBuilder<S> {
    pub fn with_profile(mut self, profile: Profile) -> Self {
        let _ = self.profiles.insert(profile.id.clone(), profile);
        self
    }

    pub fn with_active_profile(mut self, profile: Profile) -> Self {
        let id = profile.id.clone();
        let _ = self.profiles.insert(id.clone(), profile);
        self.active_profile = Some(id);
        self
    }

    pub fn with_trusted_peer(mut self, peer: impl Into<PeerInfo>) -> Self {
        let peer: PeerInfo = peer.into();
        let _ = self.known_peers.insert(peer.id(), Peer::trust(peer.into()));
        self
    }

    pub fn with_untrusted_peer(mut self, peer: impl Into<PeerInfo>) -> Self {
        let peer: PeerInfo = peer.into();
        let _ = self.known_peers.insert(peer.id(), Peer::distrust(peer.into()));
        self
    }
}

// Event loop for Client
impl Client {
    pub fn client_events(&self) -> Receiver<ClientEvent> {
        self.client_events.1.clone()
    }

    async fn client_event(&self, event: ClientEvent) -> () {
        let _ = self.client_events.0.send(event).await;
    }

    async fn event_loop(self) -> () {
        loop {
            if let Ok(event) = self.context_events.recv().await {
                match event {
                    ContextEvent::AcceptedConnection(peer_id) => {
                        match self.peer(peer_id.clone()) {
                            Some(Peer::Trusted(trusted)) =>
                                self.client_event(ClientEvent::Connected {
                                    peer: trusted.into(),
                                }).await,
                            Some(Peer::Untrusted(untrusted)) =>
                                self.client_event(ClientEvent::Connected {
                                    peer: untrusted.into(),
                                }).await,
                            None => {
                                if let Ok(conn) = self.context.connection(peer_id.clone()) {
                                    self.insert_peer(conn.peer());
                                    self.client_event(ClientEvent::Connected {
                                        peer: conn.peer().into(),
                                    }).await;
                                }
                            }
                        }
                    }
                    ContextEvent::OpenedConnection(_) => (),
                    ContextEvent::ClosedConnection(_) => (),
                    ContextEvent::ReceivedMessage(public_identity, interface_message) =>
                        match interface_message {
                            crate::utils::InterfaceMessage::OpeningStream { id: _, name: _ } => (),
                            crate::utils::InterfaceMessage::ClosingStream { name: _ } => (),
                            crate::utils::InterfaceMessage::IdentifySelf {
                                profiles,
                                active_profile,
                                routes,
                            } => {
                                if
                                    let Ok(updated) = self.set_peer_info(
                                        public_identity,
                                        active_profile,
                                        profiles,
                                        routes
                                    )
                                {
                                    self.client_event(ClientEvent::UpdatedPeer {
                                        peer: updated.clone(),
                                        identity: updated.identity(),
                                        active_profile: updated.active_profile(),
                                        profiles: updated.profiles(),
                                        routes: updated.routes(),
                                    }).await;
                                }
                            }
                        }
                    ContextEvent::RecvFailure => (),
                }
            }
        }
    }
}
