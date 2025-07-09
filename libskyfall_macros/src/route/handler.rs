use convert_case::{Case, Casing};
use darling::FromMeta;
use proc_macro::Span;
use proc_macro2::TokenStream;
use syn::{Ident, ImplItem, ItemImpl, Path};

use crate::route::RouteInfo;

#[derive(FromMeta, Clone, Debug)]
struct HandlerArgs {
    pub id: String,

    #[darling(default)]
    pub prefix: Option<String>,
    #[darling(default)]
    pub about: Option<String>
}

pub fn parse_handler_attr(args: TokenStream, item: TokenStream) -> manyhow::Result {
    let args = crate::parse_meta::<HandlerArgs>(args)?;
    let container = syn::parse2::<ItemImpl>(item.clone())?;
    let id = crate::as_valid(args.id.clone())?;
    let prefix = crate::as_valid(args.prefix.unwrap_or(args.id.clone()))?.to_case(Case::Constant);

    let mut routes: Vec<RouteInfo> = Vec::new();
    for iitem in container.items {
        if let ImplItem::Fn(method) = iitem {
            let attrs = method.attrs.clone();
            for attr in attrs {
                if let Some(segment) = attr.path().segments.last() {
                    if segment.ident.to_string() == String::from("route") {
                        routes.push(crate::route::parse_route(id.clone(), prefix.clone(), attr, method.clone())?);
                    }
                }
            }
        }
    }

    eprintln!("{routes:?}");

    Ok(item)
}