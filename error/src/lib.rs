//! `#[derive(Error)]`, covering the subset of `thiserror` this workspace uses.
//!
//! Supported on enums only:
//!
//! - `#[error("...")]` on a variant, with the variant's fields in scope. Tuple
//!   fields are also available positionally, so `{0}` works.
//! - `#[error("...", extra = EXPR)]` to pass further arguments to the format.
//! - `#[error(transparent)]` to defer both `Display` and `source` to the single
//!   inner field.
//! - `#[from]` on a field, which additionally generates the `From` impl.
//! - `#[source]` on a field, which only marks it as the source.
//!
//! Deliberately unsupported, because nothing here needs them: structs,
//! generics, `#[backtrace]`, and a variant with more than one `#[from]`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Data, DeriveInput, Expr, Fields,
    Ident, LitStr, Token, Variant,
};

#[proc_macro_derive(Error, attributes(error, from, source))]
pub fn derive_error(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// How a variant renders itself.
enum Display {
    /// A format string plus any extra arguments given after it.
    Format(LitStr, Vec<Expr>),
    /// Defer to the inner field.
    Transparent,
}

/// Which field, if any, is this variant's source, and whether it gets a `From`.
struct Source {
    index: usize,
    ident: Option<Ident>,
    from: bool,
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let data = match &input.data {
        Data::Enum(data) => data,
        Data::Struct(data) => return expand_struct(input, data),
        Data::Union(_) => {
            return Err(syn::Error::new(
                input.span(),
                "bwk_error::Error does not support unions",
            ))
        }
    };
    if !input.generics.params.is_empty() {
        return Err(syn::Error::new(
            input.generics.span(),
            "bwk_error::Error does not support generics",
        ));
    }

    let name = &input.ident;
    let mut display_arms = Vec::new();
    let mut source_arms = Vec::new();
    let mut from_impls = Vec::new();

    for variant in &data.variants {
        let display = parse_display(variant)?;
        let source = parse_source(variant)?;
        let variant_name = &variant.ident;

        let bindings = bindings_for(&variant.fields);
        let pattern = pattern_for(&variant.fields, &bindings);

        let body = match &display {
            Display::Transparent => {
                let Some(first) = bindings.first() else {
                    return Err(syn::Error::new(
                        variant.span(),
                        "transparent needs exactly one field",
                    ));
                };
                if bindings.len() != 1 {
                    return Err(syn::Error::new(
                        variant.span(),
                        "transparent needs exactly one field",
                    ));
                }
                quote! { ::core::fmt::Display::fmt(#first, f) }
            }
            Display::Format(literal, extra) => {
                // Tuple fields have no names to capture, so rewrite `{0}` and
                // `{}` to the `_0`, `_1`, ... bindings the pattern introduces.
                // Named fields already resolve as inline captures.
                let literal = rewrite_positional(literal, !extra.is_empty());
                quote! { write!(f, #literal #(, #extra)*) }
            }
        };
        display_arms.push(quote! { Self::#variant_name #pattern => #body, });

        let source_expr = match (&display, &source) {
            (Display::Transparent, _) => bindings.first().map(|b| quote! { #b }),
            (_, Some(source)) => bindings.get(source.index).map(|b| quote! { #b }),
            _ => None,
        };
        let source_arm = match source_expr {
            Some(expr) => {
                quote! { Self::#variant_name #pattern => ::core::option::Option::Some(#expr.as_dyn_error()), }
            }
            None => quote! { Self::#variant_name { .. } => ::core::option::Option::None, },
        };
        source_arms.push(source_arm);

        if let Some(source) = &source {
            if source.from {
                let field = &variant.fields.iter().nth(source.index).expect("checked").ty;
                let construct = match &source.ident {
                    Some(ident) => quote! { Self::#variant_name { #ident: value } },
                    None => quote! { Self::#variant_name(value) },
                };
                from_impls.push(quote! {
                    impl ::core::convert::From<#field> for #name {
                        fn from(value: #field) -> Self {
                            #construct
                        }
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl ::core::fmt::Display for #name {
            #[allow(unused_variables)]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    #(#display_arms)*
                }
            }
        }

        impl ::std::error::Error for #name {
            #[allow(unused_variables)]
            fn source(&self) -> ::core::option::Option<&(dyn ::std::error::Error + 'static)> {
                // A source may be a concrete error or a boxed trait object, and
                // only the former coerces on its own.
                trait AsDynError<'a> {
                    fn as_dyn_error(&self) -> &(dyn ::std::error::Error + 'a);
                }
                impl<'a, T: ::std::error::Error + 'a> AsDynError<'a> for T {
                    fn as_dyn_error(&self) -> &(dyn ::std::error::Error + 'a) {
                        self
                    }
                }
                impl<'a> AsDynError<'a> for dyn ::std::error::Error + 'a {
                    fn as_dyn_error(&self) -> &(dyn ::std::error::Error + 'a) {
                        self
                    }
                }
                impl<'a> AsDynError<'a> for dyn ::std::error::Error + ::core::marker::Send + 'a {
                    fn as_dyn_error(&self) -> &(dyn ::std::error::Error + 'a) {
                        self
                    }
                }
                impl<'a> AsDynError<'a> for dyn ::std::error::Error + ::core::marker::Send + ::core::marker::Sync + 'a {
                    fn as_dyn_error(&self) -> &(dyn ::std::error::Error + 'a) {
                        self
                    }
                }

                match self {
                    #(#source_arms)*
                }
            }
        }

        #(#from_impls)*
    })
}

/// Rewrites implicit and numbered placeholders to the `_0`, `_1`, ... bindings,
/// leaving named ones and `{{`/`}}` escapes alone.
fn rewrite_positional(literal: &LitStr, has_extra_args: bool) -> LitStr {
    let source = literal.value();
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut next_implicit = 0usize;

    while let Some(c) = chars.next() {
        if c == '{' {
            if chars.peek() == Some(&'{') {
                out.push_str("{{");
                chars.next();
                continue;
            }
            let mut placeholder = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                placeholder.push(c);
            }
            let (name, spec) = match placeholder.find(':') {
                Some(i) => (&placeholder[..i], &placeholder[i..]),
                None => (placeholder.as_str(), ""),
            };
            let name = if name.is_empty() {
                // With explicit arguments present, `{}` consumes one of those
                // rather than a field, so leave it for `format!` to resolve.
                if has_extra_args {
                    out.push('{');
                    out.push_str(&placeholder);
                    out.push('}');
                    continue;
                }
                let name = format!("_{next_implicit}");
                next_implicit += 1;
                name
            } else if name.chars().all(|c| c.is_ascii_digit()) {
                format!("_{name}")
            } else {
                name.to_string()
            };
            out.push('{');
            out.push_str(&name);
            out.push_str(spec);
            out.push('}');
            continue;
        }
        if c == '}' && chars.peek() == Some(&'}') {
            out.push_str("}}");
            chars.next();
            continue;
        }
        out.push(c);
    }

    LitStr::new(&out, literal.span())
}

fn expand_struct(input: &DeriveInput, data: &syn::DataStruct) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let display = parse_display_from(&input.attrs, input.span())?;
    let bindings = bindings_for(&data.fields);
    let pattern = pattern_for(&data.fields, &bindings);
    let destructure = quote! { let Self #pattern = self; };

    let body = match &display {
        Display::Transparent => {
            let Some(first) = bindings.first().filter(|_| bindings.len() == 1) else {
                return Err(syn::Error::new(
                    input.span(),
                    "transparent needs exactly one field",
                ));
            };
            quote! { ::core::fmt::Display::fmt(#first, f) }
        }
        Display::Format(literal, extra) => {
            let literal = rewrite_positional(literal, !extra.is_empty());
            quote! { write!(f, #literal #(, #extra)*) }
        }
    };

    Ok(quote! {
        impl ::core::fmt::Display for #name {
            #[allow(unused_variables)]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #destructure
                #body
            }
        }

        impl ::std::error::Error for #name {}
    })
}

fn parse_display(variant: &Variant) -> syn::Result<Display> {
    parse_display_from(&variant.attrs, variant.span())
}

fn parse_display_from(attrs: &[syn::Attribute], span: proc_macro2::Span) -> syn::Result<Display> {
    let mut found = None;
    for attr in attrs {
        if !attr.path().is_ident("error") {
            continue;
        }
        if found.is_some() {
            return Err(syn::Error::new(attr.span(), "duplicate #[error] attribute"));
        }
        // `#[error(transparent)]` or `#[error("literal", extra...)]`
        if let Ok(ident) = attr.parse_args::<Ident>() {
            if ident == "transparent" {
                found = Some(Display::Transparent);
                continue;
            }
            return Err(syn::Error::new(ident.span(), "expected a format string"));
        }
        let args = attr.parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)?;
        let mut args = args.into_iter();
        let Some(Expr::Lit(literal)) = args.next() else {
            return Err(syn::Error::new(attr.span(), "expected a format string"));
        };
        let syn::Lit::Str(literal) = literal.lit else {
            return Err(syn::Error::new(attr.span(), "expected a format string"));
        };
        found = Some(Display::Format(literal, args.collect()));
    }
    found.ok_or_else(|| syn::Error::new(span, "missing #[error] attribute"))
}

fn parse_source(variant: &Variant) -> syn::Result<Option<Source>> {
    let mut found: Option<Source> = None;
    for (index, field) in variant.fields.iter().enumerate() {
        for attr in &field.attrs {
            let from = attr.path().is_ident("from");
            if !from && !attr.path().is_ident("source") {
                continue;
            }
            if found.is_some() {
                return Err(syn::Error::new(
                    attr.span(),
                    "only one #[from] or #[source] field per variant",
                ));
            }
            found = Some(Source {
                index,
                ident: field.ident.clone(),
                from,
            });
        }
    }
    Ok(found)
}

fn bindings_for(fields: &Fields) -> Vec<Ident> {
    match fields {
        Fields::Unit => Vec::new(),
        Fields::Unnamed(f) => (0..f.unnamed.len())
            .map(|i| format_ident!("_{}", i))
            .collect(),
        Fields::Named(f) => f
            .named
            .iter()
            .map(|field| field.ident.clone().expect("named"))
            .collect(),
    }
}

fn pattern_for(fields: &Fields, bindings: &[Ident]) -> TokenStream2 {
    match fields {
        Fields::Unit => quote! {},
        Fields::Unnamed(_) => quote! { ( #(#bindings),* ) },
        Fields::Named(_) => quote! { { #(#bindings),* } },
    }
}
