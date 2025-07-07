use std::{ collections::HashMap, fmt::Debug, sync::Arc };
use async_channel::{ Receiver, Sender };
use bon::Builder;
use iroh::Endpoint;
use parking_lot::RwLock;
use serde::{ Deserialize, Serialize };
use tokio::task::JoinHandle;
use uuid::Uuid;
use crate::{
    context::ContextEvent,
    handlers::Handler,
    utils::RelayMode,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownPeer {
    pub identity: PublicIdentity,
    pub active_profile: Option<Uuid>,
    pub profiles: HashMap<Uuid, Profile>,
}

impl KnownPeer {
    pub fn id(&self) -> String {
        self.identity.id.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename = "snake_case", tag = "event")]
pub enum ClientEvent {
    UnknownConnection {
        peer: PublicIdentity,
    },
    KnownConnection {
        peer: PublicIdentity,
        known: KnownPeer,
    },
    PeerIdentified {
        peer: PublicIdentity,
        known: KnownPeer,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientState {
    pub(self) identity: Identity,
    pub(self) profiles: HashMap<Uuid, Profile>,
    pub(self) active_profile: Option<Uuid>,
    pub(self) known_peers: HashMap<String, KnownPeer>,
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
        #[builder(field)] known_peers: HashMap<String, KnownPeer>,
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
                .known_peer_ids()
                .iter()
                .map(move |peer| {
                    let ctx = cloned_ctx.clone();
                    async move {
                        let _ = ctx.connect(&peer).await;
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

    pub fn get_peer(&self, identity: PublicIdentity) -> Option<KnownPeer> {
        self.state.read().known_peers.get(&identity.id).cloned()
    }

    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.state.read().known_peers.values().cloned().collect()
    }

    pub fn known_peer_ids(&self) -> Vec<PublicIdentity> {
        self.state
            .read()
            .known_peers.values()
            .map(|p| p.identity.clone())
            .collect()
    }

    pub fn connected_peers(&self) -> Vec<PublicIdentity> {
        self.context.connected_peers()
    }

    pub fn known_connected_peers(&self) -> Vec<KnownPeer> {
        let known_peers: HashMap<String, KnownPeer> = self
            .known_peers()
            .iter()
            .map(|p| (p.identity.id.clone(), p.clone()))
            .collect();
        let known_ids: Vec<PublicIdentity> = known_peers
            .values()
            .map(|p| p.identity.clone())
            .collect();
        let known_connected_ids: Vec<PublicIdentity> = self
            .connected_peers()
            .iter()
            .filter(|p| known_ids.contains(*p))
            .cloned()
            .collect();

        known_connected_ids
            .iter()
            .map(|i| known_peers.get(&i.id).unwrap().clone())
            .collect()
    }

    pub fn unknown_connected_peers(&self) -> Vec<PublicIdentity> {
        let known_ids: Vec<PublicIdentity> = self
            .known_peers()
            .iter()
            .map(|p| p.identity.clone())
            .collect();
        let unknown_connected_ids: Vec<PublicIdentity> = self
            .connected_peers()
            .iter()
            .filter(|p| !known_ids.contains(*p))
            .cloned()
            .collect();

        unknown_connected_ids
    }

    pub fn add_known_peer(
        &self,
        peer: PublicIdentity,
        active_profile: Option<Uuid>,
        profiles: HashMap<Uuid, Profile>
    ) -> () {
        let mut state = self.state.write();
        let _ = state.known_peers.insert(peer.id.clone(), KnownPeer {
            identity: peer,
            active_profile,
            profiles,
        });
    }

    pub fn remove_known_peer(&self, id: impl AsRef<str>) -> () {
        let mut state = self.state.write();
        let _ = state.known_peers.remove(&id.as_ref().to_string());
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

    pub fn with_known_peer(mut self, peer: KnownPeer) -> Self {
        let _ = self.known_peers.insert(peer.id(), peer);
        self
    }

    pub fn with_unknown_peer(self, peer: PublicIdentity) -> Self {
        self.with_known_peer(KnownPeer {
            identity: peer,
            active_profile: None,
            profiles: HashMap::new(),
        })
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
                        let peer = self.context.connection(peer_id).unwrap().peer();
                        if let Some(known) = self.get_peer(peer.clone()) {
                            self.client_event(ClientEvent::KnownConnection { peer, known }).await;
                        } else {
                            self.client_event(ClientEvent::UnknownConnection { peer }).await;
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
                            } => {
                                self.client_event(ClientEvent::PeerIdentified {
                                    peer: public_identity.clone(),
                                    known: KnownPeer {
                                        identity: public_identity.clone(),
                                        active_profile,
                                        profiles,
                                    },
                                }).await;
                            }
                        }
                    ContextEvent::RecvFailure => (),
                }
            }
        }
    }
}
