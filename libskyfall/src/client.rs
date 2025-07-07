use std::{ collections::HashMap, sync::Arc };
use bon::Builder;
use iroh::Endpoint;
use parking_lot::RwLock;
use serde::{ Deserialize, Serialize };
use uuid::Uuid;
use crate::{ utils::RelayMode, Context, Identity, PublicIdentity, ALPN };

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
pub struct ClientState {
    pub(self) identity: Identity,
    pub(self) profiles: HashMap<Uuid, Profile>,
    pub(self) active_profile: Option<Uuid>,
    pub(self) known_peers: HashMap<String, KnownPeer>,
    pub(self) relay_mode: RelayMode,
}

#[derive(Clone, Debug)]
pub struct Client {
    state: Arc<RwLock<ClientState>>,
    context: Context,
}

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
        let endpoint = Endpoint::builder()
            .discovery_dht()
            .discovery_local_network()
            .discovery_n0()
            .relay_mode(relay_mode.clone().into())
            .alpns(vec![ALPN.to_vec()])
            .secret_key(identity.iroh_secret())
            .bind().await?;

        let context = Context::new(identity.clone(), endpoint)?;

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
        })
    }

    pub async fn from_state(state: ClientState) -> crate::Result<Self> {
        let endpoint = Endpoint::builder()
            .discovery_dht()
            .discovery_local_network()
            .discovery_n0()
            .relay_mode(state.relay_mode.clone().into())
            .alpns(vec![ALPN.to_vec()])
            .secret_key(state.identity.iroh_secret())
            .bind().await?;

        let context = Context::new(state.identity.clone(), endpoint)?;

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            context,
        })
    }

    pub fn into_state(self) -> ClientState {
        self.state.read().clone()
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
        self.with_known_peer(KnownPeer { identity: peer, active_profile: None, profiles: HashMap::new() })
    }
}