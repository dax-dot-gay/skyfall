mod error;

pub mod identity;
pub use identity::{Identity, Profile, PublicIdentity};

pub mod context;
mod crypto;

pub use crypto::Message;

pub(crate) use error::{Error, Result};
pub use error::{Error as SkyfallError, Result as SkyfallResult};