use crate::{
    bbqr::{self, Progress},
    scan::{Frame, Scanner},
    Config, Error, Image,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Text(String),
    /// A reassembled BBQR payload. The transport does not know what it carries,
    /// so the caller hands it to whichever codec it speaks.
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Decoder<S> {
    config: Config,
    scanner: S,
    joiner: bbqr::Joiner,
}

impl<S: Scanner + Default> Decoder<S> {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_scanner(config, S::default())
    }
}

impl<S: Scanner> Decoder<S> {
    pub fn with_scanner(config: Config, scanner: S) -> Result<Self, Error> {
        if config.max_image_pixels == 0 {
            return Err(Error::ZeroImageLimit);
        }
        Ok(Self {
            config,
            scanner,
            joiner: bbqr::Joiner::new(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn process(&mut self, image: &Image) -> Result<Vec<Decoded>, Error> {
        // the frame is bounded here so a backend never sees an inconsistent one
        if !image.validate_len() || image.data.len() > self.config.max_image_pixels {
            return Err(Error::BadFrame);
        }
        let mut payloads = self.scanner.scan(Frame {
            data: &image.data,
            width: image.width,
            height: image.height,
        })?;
        if self.config.scan_inverted {
            let inverted = image.data.iter().map(|v| 255 - *v).collect::<Vec<_>>();
            let rescan = self.scanner.scan(Frame {
                data: &inverted,
                width: image.width,
                height: image.height,
            })?;
            for payload in rescan {
                if !payloads.contains(&payload) {
                    payloads.push(payload);
                }
            }
        }
        let mut decoded = Vec::new();
        for payload in payloads {
            let text = String::from_utf8_lossy(&payload);
            if bbqr::is_part(&text) {
                if let Some(data) = self.joiner.add_part(&text, self.config.max_message_bytes)? {
                    decoded.push(Decoded::Bytes(data));
                }
                continue;
            }
            decoded.push(Decoded::Text(text.into_owned()));
        }
        Ok(decoded)
    }

    pub fn progress(&self) -> Option<Progress> {
        self.joiner.progress()
    }

    pub fn reset(&mut self) {
        self.joiner = bbqr::Joiner::new();
    }
}
