use crate::{Context, ContextConnection};

#[derive(Clone, Debug)]
pub struct Channel {
    stream: String,
    context: Context,
    connection: ContextConnection
}