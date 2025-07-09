pub(crate) mod route;
pub(crate) mod util;

pub(crate) use util::*;

#[manyhow::manyhow]
#[proc_macro_attribute]
pub fn handler(args: proc_macro::TokenStream, item: proc_macro::TokenStream) -> manyhow::Result {
    route::parse_handler_attr(args.into(), item.into())
}

#[manyhow::manyhow]
#[proc_macro_attribute]
pub fn route(args: proc_macro::TokenStream, item: proc_macro::TokenStream) -> manyhow::Result {
    route::parse_route_attr_validator(args.into(), item.into())
}