//! QR generation, scanning and BBQR framing over swappable backends.
//!
//! [`Encoder`] and [`Decoder`] bind the pipeline to the `qrcodegen` and `quircs`
//! backends and carry plain text or any byte payload split into BBQR frames. With
//! the `protocol` feature they also carry the signing-flow messages of [`protocol`].
//!
//! [`gen::Generator`] and [`scan::Scanner`] are the seam for another backend:
//! [`encoder::Encoder`] and [`decoder::Decoder`] are generic over them.

pub mod bbqr;
mod config;
pub mod decoder;
pub mod encoder;
mod error;
pub mod gen;
mod image;
pub mod scan;

#[cfg(feature = "protocol")]
pub use bwk_qr_protocol as protocol;

pub use bbqr::Progress;
pub use config::Config;
pub use decoder::Decoded;
pub use error::Error;
pub use image::Image;

#[cfg(feature = "gen")]
pub type Encoder = encoder::Encoder<gen::Qrcodegen>;
#[cfg(feature = "scan")]
pub type Decoder = decoder::Decoder<scan::Quircs>;
