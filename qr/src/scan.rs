/// Variant-free: the `quircs` backend skips an unreadable candidate rather than
/// failing. The seam stays fallible for a backend that does report failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the QR scanner failed: {0}")]
    Backend(String),
}

/// A grayscale camera frame, already checked against the configured pixel bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub data: &'a [u8],
    pub width: u32,
    pub height: u32,
}

pub trait Scanner {
    /// Returns the raw payload of every symbol read from the frame. A frame routinely
    /// holds unreadable candidates, so those are skipped rather than reported.
    fn scan(&mut self, frame: Frame<'_>) -> Result<Vec<Vec<u8>>, Error>;
}

#[cfg(feature = "scan")]
mod backend {
    use quircs::Quirc;

    use super::{Error, Frame, Scanner};

    /// The `quircs` scanning backend.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Quircs;

    impl Scanner for Quircs {
        fn scan(&mut self, frame: Frame<'_>) -> Result<Vec<Vec<u8>>, Error> {
            // a camera frame routinely holds unreadable candidates, they must not sink
            // the readable ones
            let mut quirc = Quirc::default();
            let mut payloads = Vec::new();
            for code in quirc.identify(frame.width as usize, frame.height as usize, frame.data) {
                let Ok(code) = code else { continue };
                let Ok(data) = code.decode() else { continue };
                payloads.push(data.payload);
            }
            Ok(payloads)
        }
    }
}

#[cfg(feature = "scan")]
pub use backend::Quircs;
