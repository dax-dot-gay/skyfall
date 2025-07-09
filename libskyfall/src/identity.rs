use std::fmt::Debug;

use aes_gcm::aead::rand_core;
use bon::Builder;
use iroh::{NodeId, RelayUrl};
use oqs::{ kem, sig };
use rmp_serde::config::BytesMode;
use serde::{ Deserialize, Serialize };
use sha2::Digest;

use crate::utils::AsPeerId;

/// Used encryption algorithm
pub const KEM_ALGO: kem::Algorithm = kem::Algorithm::MlKem768;

/// Used signing algorithm
pub const SIG_ALGO: sig::Algorithm = sig::Algorithm::MlDsa65;

/// Encryption identity.
#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Identity {
    #[builder(default = Identity::generate_iroh_secret())]
    iroh_secret_key: iroh::SecretKey,

    #[builder(default = Identity::generate_kem_keypair())]
    kem_keypair: (kem::PublicKey, kem::SecretKey),

    #[builder(default = Identity::generate_sig_keypair())]
    sig_keypair: (sig::PublicKey, sig::SecretKey),

    relay: Option<RelayUrl>,

    #[builder(
        default = names::Generator::default().next().unwrap(),
        with = |username: impl Into<String>| {
            let username: String = username.into();
            username[..176].to_string()
        }
    )]
    username: String,
}

impl Identity {
    pub(self) fn generate_iroh_secret() -> iroh::SecretKey {
        let mut rng = rand_core::OsRng;
        iroh::SecretKey::generate(&mut rng)
    }

    pub(self) fn generate_kem_keypair() -> (kem::PublicKey, kem::SecretKey) {
        oqs::init();
        let _kem = kem::Kem::new(KEM_ALGO).expect("Unable to create KEM instance");
        _kem.keypair().expect("Unable to generate KEM keypair")
    }

    pub(self) fn generate_sig_keypair() -> (sig::PublicKey, sig::SecretKey) {
        oqs::init();
        let _sig = sig::Sig::new(SIG_ALGO).expect("Unable to create SIG instance");
        _sig.keypair().expect("Unable to generate SIG keypair")
    }

    /// Iroh secret key
    pub fn iroh_secret(&self) -> iroh::SecretKey {
        self.iroh_secret_key.clone()
    }

    /// Iroh public key
    pub fn iroh_public(&self) -> iroh::PublicKey {
        self.iroh_secret().public()
    }

    /// Quantum safe encryption keypair
    pub fn encryption_keypair(&self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem_keypair.clone()
    }

    /// Quantum safe signing keypair
    pub fn signing_keypair(&self) -> (sig::PublicKey, sig::SecretKey) {
        self.sig_keypair.clone()
    }

    /// An ID constructed from this identity's public keys
    pub fn id(&self) -> String {
        let mut combined = Vec::new();
        combined.extend(self.iroh_public().as_bytes().to_vec());
        combined.extend(self.encryption_keypair().0.into_vec());
        combined.extend(self.signing_keypair().0.into_vec());
        base16ct::lower::encode_string(&sha2::Sha256::digest(combined))
    }

    /// Preferred relay URL
    pub fn relay(&self) -> Option<RelayUrl> {
        self.relay.clone()
    }

    /// Set preferred relay URL
    pub fn set_relay(&mut self, relay: Option<RelayUrl>) {
        self.relay = relay;
    }

    /// Generate [PublicIdentity]
    pub fn as_public(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id(),
            identifier: self.identifier(),
            node: self.iroh_public(),
            encryption: self.encryption_keypair().0,
            signing: self.signing_keypair().0,
            relay: self.relay(),
        }
    }

    /// Get the username
    pub fn username(&self) -> String {
        self.username.clone()
    }

    /// Generate discriminator from ID
    pub fn discriminator(&self) -> String {
        self.id()[..4].to_string().to_lowercase()
    }

    /// Combined username/discriminator string
    pub fn identifier(&self) -> String {
        format!("{}#{}", self.username(), self.discriminator())
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl AsPeerId for Identity {
    fn as_peer_id(&self) -> String {
        self.id()
    }
}

/// Public identity - shared with all peers that connect
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    /// ID string
    pub id: String,

    /// Identifier string (`username#discriminator`)
    pub identifier: String,

    /// Iroh public key
    pub node: iroh::NodeId,

    /// OQS encryption key
    pub encryption: kem::PublicKey,

    /// OQS signing key
    pub signing: sig::PublicKey,

    /// Preferred relay URL (currently unused)
    pub relay: Option<RelayUrl>,
}

impl PublicIdentity {
    /// Encode identity as bytes
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let buffer: Vec<u8> = Vec::new();
        let mut serializer = rmp_serde::encode::Serializer
            ::new(buffer)
            .with_bytes(BytesMode::ForceIterables);
        self.serialize(&mut serializer)?;
        Ok(serializer.into_inner())
    }

    /// Decode identity from bytes
    pub fn decode(data: Vec<u8>) -> crate::Result<Self> {
        Ok(rmp_serde::decode::from_slice::<Self>(&data)?)
    }
}

impl AsPeerId for PublicIdentity {
    fn as_peer_id(&self) -> String {
        self.id.clone()
    }
}

impl Debug for PublicIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicIdentity")
            .field("id", &self.id)
            .field("identifier", &self.identifier)
            .field("node", &self.node)
            .field("encryption", &"oqs::kem::PublicKey(...)")
            .field("signing", &"oqs::sig::PublicKey(...)")
            .field("relay", &self.relay)
            .finish()
    }
}

impl Into<NodeId> for PublicIdentity {
    fn into(self) -> NodeId {
        self.node
    }
}
