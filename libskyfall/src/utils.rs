use std::{collections::{HashMap, HashSet}, hash::Hash};

use iroh::{RelayMap, RelayMode as IrohRelayMode, RelayUrl};
use serde::{ Deserialize, Serialize };
use iroh_quinn_proto::{ Side as IrohSide, Dir as IrohDir };
use uuid::Uuid;

use crate::{handlers::{Command, Route}, Profile};

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
    IdentifySelf {
        profiles: HashMap<Uuid, Profile>,
        active_profile: Option<Uuid>,
        routes: HashMap<String, Route>
    },
    Command(Command)
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub enum RelayMode {
    #[default]
    Default,
    Disabled,
    Staging,
    Custom(HashSet<RelayUrl>)
}

impl FromIterator<RelayUrl> for RelayMode {
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self::Custom(iter.into_iter().collect())
    }
}

impl Into<IrohRelayMode> for RelayMode {
    fn into(self) -> IrohRelayMode {
        match self {
            RelayMode::Default => IrohRelayMode::Default,
            RelayMode::Disabled => IrohRelayMode::Disabled,
            RelayMode::Staging => IrohRelayMode::Staging,
            RelayMode::Custom(relay_map) => IrohRelayMode::Custom(RelayMap::from_iter(relay_map)),
        }
    }
}

impl From<IrohRelayMode> for RelayMode {
    fn from(value: IrohRelayMode) -> Self {
        match value {
            IrohRelayMode::Disabled => Self::Disabled,
            IrohRelayMode::Default => Self::Default,
            IrohRelayMode::Staging => Self::Staging,
            IrohRelayMode::Custom(relay_map) => Self::Custom(relay_map.urls().cloned().collect()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Router<T: Eq + Hash + Clone> {
    label: String,
    value: Option<(HashSet<T>, Vec<String>)>,
    branches: Vec<Router<T>>
}

impl<T: Eq + Hash + Clone> Router<T> {
    /// Constructs a new routing Router.
    pub fn new() -> Router<T> {
        Router {
            label: "".to_string(),
            value: None,
            branches: Vec::new()
        }
    }
    /// Adds a new path and its associated value to the Router. Prefix a segment
    /// with a colon (:) to enable capturing on the segment.
    ///
    /// # Panics
    ///
    /// Panics if a duplicate route is added.
    ///
    pub fn add(&mut self, key: impl AsRef<str>, value: T) {
        let key = key.as_ref().to_string();
        let segments = key.split('/').filter_map(|s| if s.is_empty() {None} else {Some(s.to_string())});
        let capture_labels = Vec::new();    // Will be filled while iterating
        self.add_(segments, value, capture_labels);
    }
    fn add_<I: Iterator<Item=String>>(
        &mut self, mut segments: I, value: T,
        mut capture_labels: Vec<String>) {
        match segments.next() {
            None => {
                self.value = if let Some(mut current) = self.value.clone() {
                    current.0.insert(value);
                    Some(current)
                } else {
                    Some((HashSet::from_iter(vec![value]), capture_labels))
                };
            },
            Some(segment) => {
                if let Some(existing_branch) =
                    self.branches.iter_mut().find(|t| t.label == segment) {
                        existing_branch.add_(segments, value, capture_labels);
                        return;
                    }
                if segment.starts_with(':') {
                    capture_labels.push(segment[1..].to_string());
                    if let Some(existing_branch) =
                        self.branches.iter_mut().find(|t| t.label.is_empty()) {
                            existing_branch.add_(
                                segments, value, capture_labels);
                            return;
                        }
                    let mut branch = Router {
                        label: "".to_string(),
                        value: None,
                        branches: Vec::new()
                    };
                    branch.add_(segments, value, capture_labels);
                    self.branches.push(branch);
                } else {
                    let mut branch = Router {
                        label: segment,
                        value: None,
                        branches: Vec::new()
                    };
                    branch.add_(segments, value, capture_labels);
                    self.branches.push(branch);
                }
            }
        }
    }
    pub fn find(
        &self,
        key: impl AsRef<str>
        ) -> Option<(HashSet<T>, Vec<(String, String)>)> {
        let key = key.as_ref().to_string();
        let segments: Vec<String> = key.split('/')
            .filter_map(|s| if s.is_empty() {None} else {Some(s.to_string())})
            .collect();
        let mut captured = Vec::new();  // Will be filled while iterating
        self.find_(segments, &mut captured)
            .map(|&(ref v, ref labels)| {
                (v.clone(), labels.iter().cloned().zip(captured).collect())
            })
    }
    fn find_(
        &self,
        segments: Vec<String>,
        captured: &mut Vec<String>
        ) -> Option<&(HashSet<T>, Vec<String>)> {
        match segments.split_first() {
            None => self.value.as_ref(),
            Some((segment, remaining)) => self.branches.iter().filter_map(|t| {
                if t.label == *segment {
                    t.find_(remaining.to_vec(), captured)
                } else if t.label == "" {
                    captured.push(segment.clone());
                    let result = t.find_(remaining.to_vec(), captured);
                    if result.is_none() {
                        captured.pop();
                    }
                    result
                } else {
                    None
                }
            }).next()
        }
    }
}

pub trait AsPeerId {
    fn as_peer_id(&self) -> String;
}

impl<T: AsRef<str>> AsPeerId for T {
    fn as_peer_id(&self) -> String {
        self.as_ref().to_string()
    }
}
