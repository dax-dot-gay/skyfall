#![allow(missing_docs)]

use aes_gcm::Nonce;
use bon::bon;
use oqs::{kem::Ciphertext, sig::Signature};
use rmp_serde::config::BytesMode;
use serde::{ Deserialize, Serialize };
use serde_with::base64::Base64;
use typenum::U12;
use uuid::Uuid;

type UB64 = Base64<serde_with::base64::UrlSafe, serde_with::formats::Unpadded>;

#[serde_with::serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    id: Uuid,

    #[serde_as(as = "UB64")]
    nonce: Vec<u8>,
    shared_secret: Ciphertext,
    #[serde_as(as = "UB64")]
    data: Vec<u8>,
    signature: Signature
}

#[bon]
impl Message {
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

    #[builder]
    pub(crate) fn new(nonce: Nonce<U12>, shared_secret: Ciphertext, data: Vec<u8>, signature: Signature) -> Self {
        Self {
            id: Uuid::new_v4(),
            nonce: nonce.to_vec(),
            shared_secret,
            data,
            signature
        }
    }

    pub fn id(&self) -> Uuid {
        self.id.clone()
    }

    pub fn nonce(&self) -> Nonce<U12> {
        Nonce::<U12>::from_iter(self.nonce.clone())
    }

    pub fn shared_secret(&self) -> Ciphertext {
        self.shared_secret.clone()
    }

    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn signature(&self) -> Signature {
        self.signature.clone()
    }
}
