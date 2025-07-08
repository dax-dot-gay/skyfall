use std::fmt::Debug;

use aes_gcm::aead::rand_core;
use bon::Builder;
use iroh::RelayUrl;
use oqs::{ kem, sig };
use rmp_serde::config::BytesMode;
use serde::{ Deserialize, Serialize };
use sha2::Digest;
use base64::prelude::*;

use crate::utils::AsPeerId;

pub const KEM_ALGO: kem::Algorithm = kem::Algorithm::MlKem768;
pub const SIG_ALGO: sig::Algorithm = sig::Algorithm::MlDsa65;

#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Identity {
    #[builder(default = Identity::generate_iroh_secret())]
    iroh_secret_key: iroh::SecretKey,

    #[builder(default = Identity::generate_kem_keypair())]
    kem_keypair: (kem::PublicKey, kem::SecretKey),

    #[builder(default = Identity::generate_sig_keypair())]
    sig_keypair: (sig::PublicKey, sig::SecretKey),

    relay: Option<RelayUrl>,
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

    pub fn iroh_secret(&self) -> iroh::SecretKey {
        self.iroh_secret_key.clone()
    }

    pub fn iroh_public(&self) -> iroh::PublicKey {
        self.iroh_secret().public()
    }

    pub fn encryption_keypair(&self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem_keypair.clone()
    }

    pub fn signing_keypair(&self) -> (sig::PublicKey, sig::SecretKey) {
        self.sig_keypair.clone()
    }

    pub fn id(&self) -> String {
        let mut combined = Vec::new();
        combined.extend(self.iroh_public().as_bytes().to_vec());
        combined.extend(self.encryption_keypair().0.into_vec());
        combined.extend(self.signing_keypair().0.into_vec());
        BASE64_URL_SAFE.encode(sha2::Sha256::digest(combined))
    }

    pub fn relay(&self) -> Option<RelayUrl> {
        self.relay.clone()
    }

    pub fn set_relay(&mut self, relay: Option<RelayUrl>) {
        self.relay = relay;
    }

    pub fn as_public(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id(),
            node: self.iroh_public(),
            encryption: self.encryption_keypair().0,
            signing: self.signing_keypair().0,
            relay: self.relay(),
        }
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub id: String,
    pub node: iroh::NodeId,
    pub encryption: kem::PublicKey,
    pub signing: sig::PublicKey,
    pub relay: Option<RelayUrl>,
}

impl PublicIdentity {
    pub fn encode(self) -> crate::Result<Vec<u8>> {
        let buffer: Vec<u8> = Vec::new();
        let mut serializer = rmp_serde::encode::Serializer
            ::new(buffer)
            .with_bytes(BytesMode::ForceIterables);
        self.serialize(&mut serializer)?;
        Ok(serializer.into_inner())
    }

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
            .field("node", &self.node)
            .field("encryption", &"oqs::kem::PublicKey(...)")
            .field("signing", &"oqs::sig::PublicKey(...)")
            .field("relay", &self.relay)
            .finish()
    }
}
