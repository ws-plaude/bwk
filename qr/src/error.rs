use crate::{bbqr, gen, scan};

#[cfg(feature = "protocol")]
use crate::protocol::encode;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid QR frame")]
    BadFrame,
    #[error("QR version {0} is out of range")]
    QrVersion(u8),
    #[error("BBQR part size is zero")]
    ZeroPartSize,
    #[error("image limit is zero")]
    ZeroImageLimit,
    #[error("BBQR part of {bytes} bytes does not fit QR version {version}")]
    PartTooLarge { bytes: usize, version: u8 },
    #[error("BBQR part is not alphanumeric")]
    PartNotAlphanumeric,
    #[error(transparent)]
    Gen(#[from] gen::Error),
    #[error(transparent)]
    Scan(#[from] scan::Error),
    #[error(transparent)]
    Bbqr(#[from] bbqr::Error),
    #[cfg(feature = "protocol")]
    #[error(transparent)]
    Encode(#[from] encode::Error),
}
