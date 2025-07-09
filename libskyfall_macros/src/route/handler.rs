use convert_case::{Case, Casing};
use darling::FromMeta;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::quote;
use syn::LitBool;
use syn::{punctuated::Punctuated, Expr, Ident, ImplItem, ItemImpl, Token, Type, TypePath};

use crate::route::RouteInfo;

#[derive(FromMeta, Clone, Debug)]
struct HandlerArgs {
    pub id: String,

    #[darling(default)]
    pub prefix: Option<String>,
    #[darling(default)]
    pub about: Option<String>,
    #[darling(default)]
    pub libskyfall: Option<String>
}

pub fn parse_handler_attr(args: TokenStream, item: TokenStream) -> manyhow::Result {
    let args = crate::parse_meta::<HandlerArgs>(args)?;
    let mut container = syn::parse2::<ItemImpl>(item.clone())?;

    container.attrs = container.attrs.clone().iter().filter_map(|a| {
        if a.path().is_ident("handler") {None} else {Some(a.clone())}
    }).collect();

    let id = crate::as_valid(args.id.clone())?;
    let prefix = crate::as_valid(args.prefix.unwrap_or(args.id.clone()))?.to_case(Case::Constant);

    let (impl_generics, type_generics, where_clause) = container.generics.split_for_impl();
    let target = (if let Type::Path(TypePath {path, ..}) = *container.self_ty.clone() {
        path.get_ident().cloned()
    } else {None}).expect("This should be a TypePath.");
    let about = syn::parse2::<Expr>(if let Some(about_msg) = args.about.clone() {
        quote! {Some(String::from(#about_msg))}
    } else {
        quote! {None}
    })?;

    let skyfall = Ident::new(&args.libskyfall.unwrap_or("libskyfall".to_string()), Span::call_site());

    let mut routes: Vec<RouteInfo> = Vec::new();
    for iitem in container.items.clone() {
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

    let mut match_arms: Vec<TokenStream> = Vec::new();
    let mut route_items: Vec<TokenStream> = Vec::new();

    for route in routes {
        let (match_arm, route_item) = interpret_route(route, skyfall.clone())?;
        match_arms.push(match_arm);
        route_items.push(route_item);
    }

    let output = quote! {
        #container

        #[#skyfall ::reexport::async_trait::async_trait]
        impl #impl_generics #skyfall::handlers::Handler for #target #type_generics #where_clause {
            fn id(&self) -> String {
                String::from(#id)
            }
            fn about(&self) -> Option<String> {
                #about
            }
            fn get_routes(&self) -> std::collections::HashMap<String, #skyfall::handlers::Route> {
                let mut mapping = std::collections::HashMap::<String, #skyfall::handlers::Route>::new();

                #(#route_items)*

                mapping
            }
            async fn on_message(
                &mut self,
                selector: String,
                path: String,
                client: #skyfall::Client,
                peer: #skyfall::Peer,
                route: #skyfall::handlers::Route,
                id: #skyfall::reexport::uuid::Uuid,
                captured_segments: Vec<(String, String)>,
                data: Option<#skyfall::reexport::serde_json::Value>,
                stream: Option<#skyfall::Channel>
            ) -> #skyfall::reexport::anyhow::Result<()> {
                let request = #skyfall::handlers::Request {
                    selector: selector.clone(),
                    path,
                    client,
                    peer,
                    route,
                    id
                };

                let segmentmap: std::collections::HashMap<String, String> = captured_segments.iter().cloned().collect();

                match selector.as_str() {
                    #(#match_arms),*,
                    _ => Ok(())
                }
            }
        }
    };

    Ok(output)
}

fn interpret_route(route: RouteInfo, skyfall: Ident) -> manyhow::Result<(TokenStream, TokenStream)> {
    let mut arg_map: Punctuated<Expr, Token![,]> = Punctuated::new();
    let method_name = Ident::new(&route.method_name.clone(), Span::call_site());
    let selector = route.selector.clone();

    let data_field = route.data_field.clone();
    let channel_field = route.channel_field.clone();
    let request_field = route.request_field.clone();

    let mut sorted_fields = route.fields.iter().map(|(a, b)| (a.clone(), b.clone())).collect::<Vec<(String, usize)>>();
    sorted_fields.sort_by_key(|(_, ind)| ind.clone());

    for (field, _) in sorted_fields {
        let tokens = 
            if data_field.clone().is_some_and(|f| f == field) {
                quote! {#skyfall::reexport::serde_json::from_value(data.unwrap())?}
            } else if channel_field.clone().is_some_and(|f| f == field) {
                quote! {stream.unwrap()}
            } else if request_field.clone().is_some_and(|f| f == field) {
                quote! {request.clone()}
            } else {
                quote! {segmentmap.get(&String::from(#field)).unwrap().clone()}
            }
        ;

        arg_map.push(syn::parse2::<Expr>(tokens)?);
    }

    let arm = quote! {#selector => self.#method_name(#arg_map).await};

    let expects_data = LitBool::new(data_field.is_some(), Span::call_site());
    let expects_stream = LitBool::new(channel_field.is_some(), Span::call_site());
    let about = syn::parse2::<Expr>(if let Some(about_msg) = route.about.clone() {
        quote! {Some(String::from(#about_msg))}
    } else {
        quote! {None::<String>}
    })?;
    let path = route.full_path.clone();

    Ok((arm, quote! {
        let _ = mapping.insert(String::from(#selector), #skyfall::handlers::Route::new(#selector, #path, #expects_data, #expects_stream, #about));
    }))
    
}