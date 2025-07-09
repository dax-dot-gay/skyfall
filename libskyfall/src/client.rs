#![allow(missing_docs)]

use std::{ collections::HashMap, fmt::Debug, sync::Arc };
use async_channel::{ Receiver, Sender };
use bon::Builder;
use enum_common_fields::EnumCommonFields;
use iroh::{Endpoint, NodeId};
use parking_lot::RwLock;
use serde::{ de::DeserializeOwned, Deserialize, Serialize };
use serde_json::Value;
use tokio::task::JoinHandle;
use uuid::Uuid;
use crate::{
    context::ContextEvent,
    handlers::{ Command, Handler, Route },
    utils::{ AsPeerId, InterfaceMessage, RelayMode, Router },
    Channel,
    Context,
    Identity,
    PublicIdentity,
    ALPN,
};

/// Profile information, shared with trusted peers
#[derive(Clone, Debug, Serialize, Deserialize, Builder)]
pub struct Profile {
    /// Profile ID
    #[builder(field = Uuid::new_v4())]
    pub id: Uuid,

    /// Profile display name
    #[builder(default = Profile::default_name())]
    pub name: String,

    /// Load-bearing pronouns
    #[builder(default)]
    pub pronouns: Vec<String>,

    /// About blurb
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

/// Peer data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer identity
    pub identity: PublicIdentity,

    /// Active profile ID
    pub active_profile: Option<Uuid>,

    /// Mapping of profiles
    pub profiles: HashMap<Uuid, Profile>,

    /// Mapping of active routes
    pub routes: HashMap<String, Route>,
}

impl PeerInfo {
    /// Return the ID string
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

/// Known peer (whether trusted or untrusted)
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

impl Into<NodeId> for Peer {
    fn into(self) -> NodeId {
        self.identity().node
    }
}

/// Client events
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
    CommandFailure {
        reason: String,
        route: Route,
        path: String,
        segments: Vec<(String, String)>,
        data: Option<Value>,
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

/// Primary client
#[derive(Clone)]
pub struct Client {
    state: Arc<RwLock<ClientState>>,
    context: Context,
    context_events: Receiver<ContextEvent>,
    client_events: (Sender<ClientEvent>, Receiver<ClientEvent>),
    event_loop: Option<Arc<JoinHandle<()>>>,
    handlers: HashMap<String, Arc<RwLock<dyn Handler + 'static + Send + Sync>>>,
    routes: HashMap<String, Route>,
    router: Router<String>,
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
            .user_data_for_discovery(format!("/{}/{}", identity.id(), identity.identifier()).try_into()?)
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
            routes: HashMap::new(),
            router: Router::new(),
            initialized: false,
        })
    }

    /// Construct from a saved state
    pub async fn from_state(state: ClientState) -> crate::Result<Self> {
        let (context_sender, context_receiver) = async_channel::unbounded::<ContextEvent>();
        let endpoint = Endpoint::builder()
            .discovery_dht()
            .discovery_local_network()
            .discovery_n0()
            .user_data_for_discovery(format!("/{}/{}", state.identity.id(), state.identity.identifier()).try_into()?)
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
            routes: HashMap::new(),
            router: Router::new(),
            initialized: false,
        })
    }

    /// Initialize client and send updated info to peers
    pub async fn initialize(&mut self) -> crate::Result<()> {
        if self.initialized {
            panic!("Already initialized!");
        }

        self.initialized = true;
        let cloned_ctx = self.context.clone();
        let cloned_self = self.clone();
        let _ = futures::future::join_all(
            self
                .peers()
                .iter()
                .map(move |peer| {
                    let ctx = cloned_ctx.clone();
                    let this = cloned_self.clone();
                    async move {
                        let _ = ctx.connect(peer.identity()).await;
                        if peer.trusted() {
                            let _ = this.share_info(peer.clone()).await;
                        }
                    }
                })
        ).await;
        self.event_loop = Some(Arc::new(tokio::spawn(self.clone().event_loop())));
        Ok(())
    }

    /// Convert into saved state
    pub fn into_state(self) -> ClientState {
        self.state.read().clone()
    }

    /// Add handler
    pub fn with_handler(mut self, handler: impl Handler + 'static + Send + Sync) -> Self {
        if self.initialized {
            panic!("Cannot add a handler to an initialized client.");
        }

        if self.handlers.contains_key(&handler.id()) {
            panic!("Cannot add the same handler twice!");
        }

        let new_routes = handler.get_routes();
        let handler_id = handler.id();
        let _ = self.handlers.insert(handler_id.clone(), Arc::new(RwLock::new(handler)));
        for (selector, listener) in new_routes {
            let select = format!("{handler_id}::{selector}");
            let _ = self.routes.insert(select.clone(), listener.clone());
            self.router.add(listener.path, select);
        }

        self
    }

    /// Get identity
    pub fn identity(&self) -> Identity {
        self.state.read().identity.clone()
    }

    /// Get profile mapping
    pub fn profiles(&self) -> HashMap<Uuid, Profile> {
        self.state.read().profiles.clone()
    }

    /// Get a single profile
    pub fn profile(&self, id: Uuid) -> Option<Profile> {
        self.state.read().profiles.get(&id).cloned()
    }

    /// Add a new profile
    pub async fn add_profile(&self, profile: Profile) -> crate::Result<()> {
        let _ = self.state.write().profiles.insert(profile.id.clone(), profile);
        // Update peers about this profile change
        Ok(())
    }

    /// Remove a profile
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

    /// Set the active profile
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

    /// Set the active profile to [None]
    pub async fn clear_active_profile(&self) -> () {
        let mut state = self.state.write();
        state.active_profile = None;
        // Update peers about this profile change
    }

    /// Retrieves the active profile, if any
    pub fn active_profile(&self) -> Option<Profile> {
        if let Some(active) = self.state.read().active_profile.clone() {
            self.profile(active)
        } else {
            None
        }
    }

    /// Returns a list of all peers
    pub fn peers(&self) -> Vec<Peer> {
        self.state.read().known_peers.clone().values().cloned().collect()
    }

    /// Gets a specific peer
    pub fn peer(&self, id: impl AsPeerId) -> Option<Peer> {
        self.state.read().known_peers.get(&id.as_peer_id()).cloned()
    }

    /// Returns a list of all connected peers
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

    /// Checks if a peer is connected
    pub fn is_connected(&self, peer: impl Into<Peer>) -> bool {
        let peer: Peer = peer.into();
        let connected = self.context.connected_peers();
        connected.contains(&peer.identity())
    }

    /// Adds a new peer (or updates it if it exists)
    pub fn insert_peer(&self, peer: impl Into<Peer>) -> bool {
        let peer: Peer = peer.into();
        self.state.write().known_peers.insert(peer.id(), peer).is_some()
    }

    /// Removes a peer
    pub fn remove_peer(&self, id: impl AsPeerId) -> bool {
        self.state.write().known_peers.remove(&id.as_peer_id()).is_some()
    }

    /// Connects to a peer by ID
    pub async fn connect_to(&self, peer: impl Into<NodeId>) -> crate::Result<Peer> {
        let peer: NodeId = peer.into();

        let connected_to = self.context.connect(peer).await?;
        let connected_peer = Peer::from(self.context.connection(connected_to)?.peer());
        self.insert_peer(connected_peer.clone());
        Ok(connected_peer)
    }

    /// Sets the current peer info
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

    /// Gets current peer info
    pub fn peer_info(&self) -> PeerInfo {
        PeerInfo {
            identity: self.identity().as_public(),
            active_profile: self.active_profile().and_then(|p| Some(p.id)),
            profiles: self.profiles(),
            routes: self.routes.clone(),
        }
    }

    /// Trust a peer by ID
    pub fn trust_peer(&self, id: impl AsPeerId) -> crate::Result<Peer> {
        let id = id.as_peer_id();
        if let Some(peer) = self.peer(id.clone()) {
            let _ = self.insert_peer(Peer::Trusted(peer.clone().into()));
            Ok(Peer::Trusted(peer.into()))
        } else {
            Err(crate::Error::unknown_peer(id))
        }
    }

    /// Distrust a peer by ID
    pub fn distrust_peer(&self, id: impl AsPeerId) -> crate::Result<Peer> {
        let id = id.as_peer_id();
        if let Some(peer) = self.peer(id.clone()) {
            let _ = self.insert_peer(Peer::Untrusted(peer.clone().into()));
            Ok(Peer::Untrusted(peer.into()))
        } else {
            Err(crate::Error::unknown_peer(id))
        }
    }

    /// Share peer info with a peer
    pub async fn share_info(&self, peer: impl Into<Peer>) -> crate::Result<()> {
        let peer: Peer = peer.into();
        if self.is_connected(peer.clone()) {
            self.context.send_message_to_peer(
                peer.id(),
                crate::utils::InterfaceMessage::IdentifySelf {
                    profiles: self.profiles(),
                    active_profile: self.active_profile().and_then(|p| Some(p.id)),
                    routes: self.routes.clone(),
                }
            ).await
        } else {
            Err(crate::Error::disconnected_peer(peer))
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
    /// Gets a receiver of client events
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
                            crate::utils::InterfaceMessage::Command(command) => {
                                Self::_handle_command(self.clone(), command, public_identity);
                            }
                        }
                    _ => (),
                }
            }
        }
    }

    fn _handle_command(client: Client, command: Command, public_identity: PublicIdentity) {
        tokio::spawn(
            (move || async move {
                if let Some(Peer::Trusted(peer_info)) = client.peer(public_identity) {
                    if let Some((selectors, captured)) = client.router.find(command.path.clone()) {
                        for s in selectors {
                            if let Some(route) = client.routes.get(&s) {
                                let (handler, selector) = s.split_once("::").unwrap();
                                if
                                    let Some(handler_arc) = client.handlers.get(
                                        &handler.to_string()
                                    )
                                {
                                    let mut handler = handler_arc.write();
                                    let stream = if let Some((name, _)) = command.stream.clone() {
                                        if
                                            let Ok(_stream) = client.context.get_channel(
                                                &peer_info.identity,
                                                name
                                            ).await
                                        {
                                            Some(_stream)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };
                                    if
                                        let Err(e) = handler.on_message(
                                            selector.to_string(),
                                            command.path.clone(),
                                            client.clone(),
                                            Peer::Trusted(peer_info.clone()),
                                            route.clone(),
                                            command.id.clone(),
                                            captured.clone(),
                                            command.data.clone(),
                                            stream
                                        ).await
                                    {
                                        client.client_event(ClientEvent::CommandFailure {
                                            reason: e.to_string(),
                                            route: route.clone(),
                                            path: command.path.clone(),
                                            segments: captured.clone(),
                                            data: command.data.clone(),
                                        }).await;
                                    }
                                }
                            }
                        }
                    }
                }
            })()
        );
    }
}

impl Client {
    /// Sends a command to a peer
    pub async fn send_command<Data: Serialize + DeserializeOwned>(
        &self,
        peer: impl AsPeerId,
        path: impl AsRef<str>,
        data: Option<Data>,
        create_channel: bool
    ) -> crate::Result<(Uuid, Option<Channel>)> {
        let peer = peer.as_peer_id();
        if let Some(peer) = self.peer(peer.clone()) {
            if self.is_connected(peer.clone()) {
                let id = Uuid::new_v4();
                let path = path.as_ref().to_string();
                let data = if let Some(d) = data { Some(serde_json::to_value(d)?) } else { None };

                let channel = if create_channel {
                    Some(
                        self.context.open_channel(
                            &peer.identity(),
                            format!("com:{}", id.to_string())
                        ).await?
                    )
                } else {
                    None
                };

                self.context.send_message_to_peer(
                    peer.id(),
                    InterfaceMessage::Command(Command {
                        id: id.clone(),
                        path,
                        data,
                        stream: channel.clone().and_then(|c| Some((c.name(), c.id()))),
                    })
                ).await?;
                Ok((id, channel))
            } else {
                Err(crate::Error::disconnected_peer(peer))
            }
        } else {
            Err(crate::Error::unknown_peer(peer))
        }
    }
}
