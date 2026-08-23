#![cfg(feature = "gen")]

use bwk_qr::{
    gen::{self, Generator},
    Config, Encoder, Error,
};

const ADDRESS: &str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
const DESCRIPTOR: &str = "tr([f00dbabe/86h/0h/0h]xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)#abcdefgh";
const SP_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";

fn assert_render_size(text: &str, size: u32, pixels: usize) {
    let encoder = Encoder::new(Config::default()).unwrap();
    let image = encoder.encode_text(text).unwrap();
    assert_eq!(image.width, size);
    assert_eq!(image.height, size);
    assert_eq!(image.data.len(), pixels);
}

#[test]
fn short_text_renders_version_one() {
    assert_render_size("bwk", 116, 13456);
}

#[test]
fn address_renders_version_three() {
    assert_render_size(ADDRESS, 148, 21904);
}

#[test]
fn descriptor_renders_version_seven() {
    assert_render_size(DESCRIPTOR, 212, 44944);
}

#[test]
fn sp_address_fits_default_version_cap() {
    assert_render_size(SP_ADDRESS, 196, 38416);
}

#[test]
fn empty_text_renders_version_one() {
    assert_render_size("", 116, 13456);
}

#[test]
fn version_cap_rejects_payload_that_does_not_fit() {
    let capped = Encoder::new(Config {
        max_qr_version: 3,
        ..Config::default()
    })
    .unwrap();
    assert_eq!(
        capped.encode_text(SP_ADDRESS),
        Err(Error::Gen(gen::Error::TooLong))
    );

    let default = Encoder::new(Config::default()).unwrap();
    assert!(default.encode_text(SP_ADDRESS).is_ok());
}

#[test]
fn a_version_cap_does_not_block_construction() {
    // a generation-only consumer never renders a BBQR part, so none is probed here
    assert!(Encoder::new(Config {
        max_qr_version: 10,
        ..Config::default()
    })
    .is_ok());
}

#[test]
fn an_inverted_version_range_is_rejected() {
    let params = gen::Params {
        min_version: 20,
        max_version: 5,
        correction: gen::Correction::Low,
        boost_correction: false,
    };
    assert_eq!(
        gen::Qrcodegen.generate("BWK", params),
        Err(gen::Error::VersionRange)
    );
}
