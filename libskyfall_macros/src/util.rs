use std::fmt::Display;

use darling::{ast::NestedMeta, FromMeta};
use proc_macro::Span;
use proc_macro2::TokenStream;

pub fn parse_meta<T: FromMeta>(args: impl Into<TokenStream>) -> manyhow::Result<T> {
    let args: TokenStream = args.into();
    let args_list = NestedMeta::parse_meta_list(args)?;
    Ok(T::from_list(&args_list)?)
}

pub fn error(data: impl Display) -> manyhow::Error {
    manyhow::Error::from(manyhow::ErrorMessage::new(Span::call_site(), data))
}

pub fn as_valid(value: String) -> manyhow::Result<String> {
    let re = regex::Regex::new(r"^[a-zA-Z0-9.\-_]*$").or_else(|e| Err(manyhow::ErrorMessage::new(Span::call_site(), e)))?;
    if re.is_match(&value) {
        Ok(value)
    } else {
        Err(crate::error("Only alphanumeric characters and ._- are allowed."))
    }
}