use crate::Image;

/// The module count of a version 40 symbol, the largest QR code there is.
pub const MAX_MODULES: u16 = 177;
pub const QUIET_ZONE: u16 = 4;
pub const MODULE_SCALE: u16 = 4;

const ALPHANUMERIC_CHARSET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("QR payload is too long")]
    TooLong,
    #[error("QR version {0} is out of range")]
    UnsupportedVersion(u8),
    #[error("module count {len} does not match the matrix size {size}")]
    ModuleCount { size: u16, len: usize },
    #[error("QR version range is inverted")]
    VersionRange,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correction {
    Low = 0,
    Medium = 1,
    Quartile = 2,
    High = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub min_version: u8,
    pub max_version: u8,
    pub correction: Correction,
    pub boost_correction: bool,
}

/// A generated symbol as a square bit matrix, without quiet zone or scaling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modules {
    size: u16,
    dark: Vec<bool>,
}

impl Modules {
    pub fn new(size: u16, dark: Vec<bool>) -> Result<Self, Error> {
        let count = size.checked_mul(size).map(usize::from);
        if !(1..=MAX_MODULES).contains(&size) || count != Some(dark.len()) {
            return Err(Error::ModuleCount {
                size,
                len: dark.len(),
            });
        }
        Ok(Self { size, dark })
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub fn is_dark(&self, x: u16, y: u16) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.dark[usize::from(y) * usize::from(self.size) + usize::from(x)]
    }

    /// Rasterizes to a grayscale image, dark modules 0 and light modules 255.
    ///
    /// The quiet zone and the scale live here rather than in a [`Generator`] so that
    /// an [`Encoder`](crate::encoder::Encoder) frame is always readable by a
    /// [`Decoder`](crate::decoder::Decoder), whatever backend produced the matrix.
    pub fn render(&self) -> Image {
        let quiet = i32::from(QUIET_ZONE);
        let scale = i32::from(MODULE_SCALE);
        let qr_size = i32::from(self.size);
        let modules = qr_size + quiet * 2;
        let size = modules * scale;
        let mut data = Vec::with_capacity((size * size) as usize);
        for y in -quiet..qr_size + quiet {
            for _ in 0..scale {
                for x in -quiet..qr_size + quiet {
                    let value = if self.is_dark_at(x, y) { 0 } else { 255 };
                    for _ in 0..scale {
                        data.push(value);
                    }
                }
            }
        }
        Image {
            data,
            width: size as u32,
            height: size as u32,
        }
    }

    fn is_dark_at(&self, x: i32, y: i32) -> bool {
        match (u16::try_from(x), u16::try_from(y)) {
            (Ok(x), Ok(y)) => self.is_dark(x, y),
            _ => false,
        }
    }
}

pub trait Generator {
    fn generate(&self, text: &str, params: Params) -> Result<Modules, Error>;
}

/// Whether `text` can be carried by a single alphanumeric segment.
pub fn is_alphanumeric(text: &str) -> bool {
    text.chars().all(|c| ALPHANUMERIC_CHARSET.contains(c))
}

#[cfg(feature = "gen")]
mod backend {
    use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

    use super::{Correction, Error, Generator, Modules, Params};

    /// The `qrcodegen` generation backend.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Qrcodegen;

    impl Generator for Qrcodegen {
        fn generate(&self, text: &str, params: Params) -> Result<Modules, Error> {
            // `encode_segments_advanced` asserts the range is ordered
            if params.min_version > params.max_version {
                return Err(Error::VersionRange);
            }
            let min = version(params.min_version)?;
            let max = version(params.max_version)?;
            let segments = QrSegment::make_segments(text);
            let qr = QrCode::encode_segments_advanced(
                &segments,
                ecc(params.correction),
                min,
                max,
                None,
                params.boost_correction,
            )
            .map_err(|_| Error::TooLong)?;
            let size = qr.size();
            let mut dark = Vec::with_capacity((size * size) as usize);
            for y in 0..size {
                for x in 0..size {
                    dark.push(qr.get_module(x, y));
                }
            }
            Modules::new(size as u16, dark)
        }
    }

    // `Version::new` panics outside 1..=40, so the range is checked before it is called
    fn version(value: u8) -> Result<Version, Error> {
        if !(1..=40).contains(&value) {
            return Err(Error::UnsupportedVersion(value));
        }
        Ok(Version::new(value))
    }

    fn ecc(correction: Correction) -> QrCodeEcc {
        match correction {
            Correction::Low => QrCodeEcc::Low,
            Correction::Medium => QrCodeEcc::Medium,
            Correction::Quartile => QrCodeEcc::Quartile,
            Correction::High => QrCodeEcc::High,
        }
    }
}

#[cfg(feature = "gen")]
pub use backend::Qrcodegen;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_single_module() {
        let image = Modules::new(1, vec![true]).unwrap().render();
        assert_eq!((image.width, image.height), (36, 36));
        assert_eq!(image.data.len(), 36 * 36);
        // the dark module lands at 4 quiet modules times a scale of 4
        assert_eq!(image.data[16 * 36 + 16], 0);
        assert_eq!(image.data[16 * 36 + 19], 0);
        assert_eq!(image.data[19 * 36 + 19], 0);
        assert_eq!(image.data[16 * 36 + 15], 255);
        assert_eq!(image.data[15 * 36 + 16], 255);
        assert_eq!(image.data[20 * 36 + 16], 255);
        assert_eq!(image.data[16 * 36 + 20], 255);
    }

    #[test]
    fn renders_a_three_by_three_checkerboard() {
        let dark = vec![true, false, true, false, true, false, true, false, true];
        let image = Modules::new(3, dark).unwrap().render();
        assert_eq!((image.width, image.height), (44, 44));
        assert_eq!(image.data.len(), 44 * 44);
        assert_eq!(image.data[16 * 44 + 16], 0);
        assert_eq!(image.data[16 * 44 + 20], 255);
        assert_eq!(image.data[16 * 44 + 24], 0);
        assert_eq!(image.data[20 * 44 + 20], 0);
        // the quiet zone stays light on every edge
        assert!(image.data[..16 * 44].iter().all(|v| *v == 255));
        assert!(image.data[28 * 44..].iter().all(|v| *v == 255));
        assert_eq!(image.data[16 * 44 + 15], 255);
        assert_eq!(image.data[16 * 44 + 28], 255);
    }

    #[test]
    fn rejects_a_mismatched_module_count() {
        assert_eq!(
            Modules::new(3, vec![false; 8]),
            Err(Error::ModuleCount { size: 3, len: 8 })
        );
        assert_eq!(
            Modules::new(0, vec![]),
            Err(Error::ModuleCount { size: 0, len: 0 })
        );
        assert!(Modules::new(MAX_MODULES + 1, vec![false; 178 * 178]).is_err());
    }

    #[test]
    fn alphanumeric_matches_the_qr_charset() {
        assert!(is_alphanumeric("B$HB0300ABCDEF"));
        assert!(is_alphanumeric(" $%*+-./:"));
        assert!(!is_alphanumeric("abc"));
        assert!(!is_alphanumeric("a\u{e9}"));
        assert!(!is_alphanumeric("#"));
    }
}
