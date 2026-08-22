//! Covers each shape the workspace's error enums actually use.

use bwk_error::Error;
use std::error::Error as _;

const EXPECTED_SIZE: usize = 80;

#[derive(Debug, Error)]
enum Simple {
    #[error("no inputs")]
    NoInputs,
    #[error("bad value: {0}")]
    BadValue(u32),
    #[error("{0} does not match {1}")]
    Mismatch(String, String),
    #[error("debug formatting: {0:?}")]
    Debugged(Vec<u8>),
}

#[derive(Debug, Error)]
enum WithSource {
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse failed")]
    Parse(#[source] std::num::ParseIntError),
    #[error(transparent)]
    Inner(#[from] Simple),
}

#[derive(Debug, Error)]
enum Named {
    #[error("address {address:?} is invalid on {network}")]
    InvalidAddress { address: String, network: String },
    #[error("wrong size, expected {expected}")]
    WrongSize { expected: usize },
}

#[derive(Debug, Error)]
enum ExtraArgs {
    #[error("header must be {size} bytes", size = EXPECTED_SIZE)]
    BadHeader,
    #[error("got {0}, expected {expected}", expected = EXPECTED_SIZE)]
    Mismatch(usize),
}

#[test]
fn unit_and_tuple_variants_render() {
    assert_eq!(Simple::NoInputs.to_string(), "no inputs");
    assert_eq!(Simple::BadValue(7).to_string(), "bad value: 7");
    assert_eq!(
        Simple::Mismatch("a".into(), "b".into()).to_string(),
        "a does not match b"
    );
    assert_eq!(
        Simple::Debugged(vec![1, 2]).to_string(),
        "debug formatting: [1, 2]"
    );
}

#[test]
fn named_fields_render_by_name() {
    let e = Named::InvalidAddress {
        address: "bc1".into(),
        network: "signet".into(),
    };
    assert_eq!(e.to_string(), "address \"bc1\" is invalid on signet");
    assert_eq!(
        Named::WrongSize { expected: 4 }.to_string(),
        "wrong size, expected 4"
    );
}

#[test]
fn extra_format_arguments_are_passed_through() {
    assert_eq!(ExtraArgs::BadHeader.to_string(), "header must be 80 bytes");
    assert_eq!(ExtraArgs::Mismatch(3).to_string(), "got 3, expected 80");
}

#[test]
fn from_generates_the_conversion() {
    let e: WithSource = std::io::Error::other("boom").into();
    assert_eq!(e.to_string(), "io failed: boom");
    assert!(matches!(e, WithSource::Io(_)));
}

#[test]
fn source_is_exposed_for_from_and_source_fields() {
    let e: WithSource = std::io::Error::other("boom").into();
    assert_eq!(e.source().unwrap().to_string(), "boom");

    let inner = "x".parse::<u32>().unwrap_err();
    let e = WithSource::Parse(inner);
    assert_eq!(e.to_string(), "parse failed");
    assert!(e.source().is_some());
}

#[test]
fn variants_without_a_source_report_none() {
    assert!(Simple::NoInputs.source().is_none());
    assert!(Simple::BadValue(1).source().is_none());
    assert!(Named::WrongSize { expected: 1 }.source().is_none());
}

#[test]
fn transparent_defers_display_and_source_to_the_inner_error() {
    let e = WithSource::Inner(Simple::BadValue(9));
    // Display is the inner error's, with no wrapper text of its own.
    assert_eq!(e.to_string(), "bad value: 9");
    assert_eq!(e.source().unwrap().to_string(), "bad value: 9");
}

#[test]
fn errors_work_as_boxed_trait_objects() {
    fn boxed() -> Result<(), Box<dyn std::error::Error>> {
        Err(Simple::NoInputs)?
    }
    assert_eq!(boxed().unwrap_err().to_string(), "no inputs");
}

#[derive(Debug, Error)]
#[error("{0}")]
struct NewtypeError(String);

#[derive(Debug, Error)]
enum BoxedSource {
    #[error("boxed: {0}")]
    Boxed(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("with an explicit argument {0} of {:?}", LIMITS)]
    Explicit(u8),
}

const LIMITS: [u8; 2] = [1, 2];

#[test]
fn struct_errors_render_and_are_errors() {
    let e = NewtypeError("bad config".into());
    assert_eq!(e.to_string(), "bad config");
    let _: &dyn std::error::Error = &e;
}

#[test]
fn boxed_trait_object_sources_are_exposed() {
    let inner: Box<dyn std::error::Error + Send + Sync> = Box::new(Simple::NoInputs);
    let e = BoxedSource::Boxed(inner);
    assert_eq!(e.to_string(), "boxed: no inputs");
    assert_eq!(e.source().unwrap().to_string(), "no inputs");
}

#[test]
fn explicit_arguments_fill_implicit_slots_while_numbered_refer_to_fields() {
    assert_eq!(
        BoxedSource::Explicit(9).to_string(),
        "with an explicit argument 9 of [1, 2]"
    );
}
