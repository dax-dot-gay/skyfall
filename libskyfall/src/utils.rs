use serde::{ Deserialize, Serialize };
use iroh_quinn_proto::{ Side as IrohSide, Dir as IrohDir };

use crate::PublicIdentity;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    Client = 0,
    Server = 1,
}

impl Into<IrohSide> for Side {
    fn into(self) -> IrohSide {
        match self {
            Side::Client => IrohSide::Client,
            Side::Server => IrohSide::Server,
        }
    }
}

impl From<IrohSide> for Side {
    fn from(value: IrohSide) -> Self {
        match value {
            IrohSide::Client => Self::Client,
            IrohSide::Server => Self::Server,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dir {
    Uni = 1,
    Bi = 0,
}

impl Into<IrohDir> for Dir {
    fn into(self) -> IrohDir {
        match self {
            Dir::Uni => IrohDir::Uni,
            Dir::Bi => IrohDir::Bi,
        }
    }
}

impl From<IrohDir> for Dir {
    fn from(value: IrohDir) -> Self {
        match value {
            IrohDir::Bi => Self::Bi,
            IrohDir::Uni => Self::Uni,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StreamId {
    initiator: Side,
    dir: Dir,
    index: u64,
}

impl Into<iroh::endpoint::StreamId> for StreamId {
    fn into(self) -> iroh::endpoint::StreamId {
        iroh::endpoint::StreamId::new(
            self.initiator.clone().into(),
            self.dir.clone().into(),
            self.index
        )
    }
}

impl From<iroh::endpoint::StreamId> for StreamId {
    fn from(value: iroh::endpoint::StreamId) -> Self {
        Self { initiator: value.initiator().into(), dir: value.dir().into(), index: value.index() }
    }
}

impl StreamId {
    pub fn new(initiator: impl Into<Side>, dir: impl Into<Dir>, index: u64) -> Self {
        Self { initiator: initiator.into(), dir: dir.into(), index }
    }

    pub fn initiator(&self) -> Side {
        self.initiator.clone()
    }

    pub fn dir(&self) -> Dir {
        self.dir.clone()
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn raw(&self) -> u64 {
        (self.index() << 2) | ((self.dir() as u64) << 1) | (self.initiator() as u64)
    }
}

impl Ord for StreamId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw().cmp(&other.raw())
    }
}

impl PartialOrd for StreamId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.raw().partial_cmp(&other.raw())
    }
}

impl PartialEq for StreamId {
    fn eq(&self, other: &Self) -> bool {
        self.raw().eq(&other.raw())
    }
}

impl Eq for StreamId {}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum InterfaceMessage {
    OpeningStream {
        id: StreamId,
        name: String
    },
    ChangingProfile {
        new_profile: PublicIdentity
    }
}
