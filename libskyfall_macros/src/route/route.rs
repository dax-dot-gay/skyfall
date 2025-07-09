use std::collections::HashMap;

use darling::FromMeta;
use proc_macro2::TokenStream;
use syn::{ Attribute, FnArg, Ident, ImplItemFn, Pat, PatIdent, PatType, Type };

#[derive(Clone, Debug, FromMeta)]
pub struct RouteArgs {
    pub path: String,

    #[darling(default)]
    pub selector: Option<String>,

    #[darling(default)]
    pub data: Option<Ident>,

    #[darling(default)]
    pub channel: Option<Ident>,

    #[darling(default)]
    pub request: Option<Ident>,
}

pub fn parse_route_attr_validator(args: TokenStream, item: TokenStream) -> manyhow::Result {
    let args = crate::parse_meta::<RouteArgs>(args)?;
    let method = syn::parse2::<ImplItemFn>(item.clone())?;
    if method.sig.asyncness.is_none() {
        return Err(crate::error("Route handlers should be asynchronous."));
    }

    match method.sig.inputs.first() {
        Some(&FnArg::Typed(_)) => {
            return Err(crate::error("Route handlers should at least reference &self/&mut self"));
        }
        None => {
            return Err(crate::error("Route handlers should at least reference &self/&mut self"));
        }
        _ => (),
    }

    if let Some(sel) = args.selector.clone() {
        crate::as_valid(sel)?;
    }

    if args.path.starts_with("/") && !args.path.ends_with("/") {
        for segment in args.path.trim_matches('/').split("/") {
            if segment.starts_with(":") {
                if let Err(reason) = syn::parse_str::<Ident>(segment.trim_start_matches(':')) {
                    return Err(
                        crate::error(
                            format!("Capture segment must be a valid identifier: {reason:?}")
                        )
                    );
                }
            } else if segment.len() == 0 {
                return Err(crate::error(format!("Empty path parts are not allowed.")));
            }
        }
    } else {
        return Err(crate::error("Paths must start with a leading / and not contain a trailing /"));
    }

    Ok(item)
}

#[derive(Clone, Debug)]
pub struct RouteInfo {
    pub handler_id: String,
    pub prefix: String,
    pub selector: String,
    pub method_name: String,
    pub fields: HashMap<String, usize>,
    pub captures: Vec<String>,
    pub data_field: Option<String>,
    pub channel_field: Option<String>,
    pub request_field: Option<String>,
}

pub fn parse_route(
    handler_id: String,
    prefix: String,
    attr: Attribute,
    method: ImplItemFn
) -> manyhow::Result<RouteInfo> {
    let args = RouteArgs::from_meta(&attr.meta)?;
    let selector = crate::as_valid(args.selector.unwrap_or(method.sig.ident.to_string()))?;

    let all_fields: HashMap<String, usize> = method.sig.inputs
        .iter()
        .enumerate()
        .filter_map(|(index, f)| {
            if let FnArg::Typed(PatType { pat, .. }) = f.clone() {
                match *pat {
                    Pat::Ident(PatIdent { ident, .. }) => Some((ident.to_string(), index)),
                    _ => panic!("Unprocessable method argument: {:?}", f.clone()),
                }
            } else {
                None
            }
        })
        .collect();

    let mut captures: Vec<String> = Vec::new();
    for segment in args.path.clone().trim_matches('/').split("/") {
        if all_fields.contains_key(&segment.trim_start_matches(':').to_string()) {
            captures.push(segment.trim_start_matches(':').to_string());
        }
    }

    Ok(RouteInfo {
        handler_id,
        prefix,
        fields: all_fields,
        captures,
        data_field: args.data.clone().and_then(|f| Some(f.to_string())),
        channel_field: args.channel.clone().and_then(|f| Some(f.to_string())),
        request_field: args.request.clone().and_then(|f| Some(f.to_string())),
        selector,
        method_name: method.sig.ident.to_string(),
    })
}
