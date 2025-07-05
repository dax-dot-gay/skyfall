use aes_gcm::aead::rand_core;
use bon::Builder;
use names::Generator;
use oqs::{ kem, sig };
use serde::{ Deserialize, Serialize };
use sha2::Digest;
use base64::prelude::*;

pub const KEM_ALGO: kem::Algorithm = kem::Algorithm::MlKem768;
pub const SIG_ALGO: sig::Algorithm = sig::Algorithm::MlDsa65;

#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Profile {
    #[builder(default = Generator::default().next().unwrap())]
    pub display_name: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Builder)]
pub struct Identity {
    #[builder(default = Identity::generate_iroh_secret())]
    iroh_secret_key: iroh::SecretKey,

    #[builder(default = Identity::generate_kem_keypair())]
    kem_keypair: (kem::PublicKey, kem::SecretKey),

    #[builder(default = Identity::generate_sig_keypair())]
    sig_keypair: (sig::PublicKey, sig::SecretKey),

    #[builder(default)]
    profile: Profile,
}

impl Identity {
    pub(self) fn generate_iroh_secret() -> iroh::SecretKey {
        let mut rng = rand_core::OsRng;
        iroh::SecretKey::generate(&mut rng)
    }

    pub(self) fn generate_kem_keypair() -> (kem::PublicKey, kem::SecretKey) {
        let _kem = kem::Kem::new(KEM_ALGO).expect("Unable to create KEM instance");
        _kem.keypair().expect("Unable to generate KEM keypair")
    }

    pub(self) fn generate_sig_keypair() -> (sig::PublicKey, sig::SecretKey) {
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

    pub fn profile(&self) -> Profile {
        self.profile.clone()
    }

    pub fn id(&self) -> String {
        let mut combined = Vec::new();
        combined.extend(self.iroh_public().as_bytes().to_vec());
        combined.extend(self.encryption_keypair().0.into_vec());
        combined.extend(self.signing_keypair().0.into_vec());
        BASE64_URL_SAFE.encode(sha2::Sha256::digest(combined))
    }

    pub fn as_public(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id(),
            profile: self.profile(),
            node: self.iroh_public(),
            encryption: self.encryption_keypair().0,
            signing: self.signing_keypair().0,
        }
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicIdentity {
    pub id: String,
    pub profile: Profile,
    pub node: iroh::NodeId,
    pub encryption: kem::PublicKey,
    pub signing: sig::PublicKey,
}
