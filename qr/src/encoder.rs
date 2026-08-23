use crate::{
    bbqr,
    gen::{self, Correction, Generator, Params},
    Config, Error, Image,
};

#[derive(Debug, Clone)]
pub struct Encoder<G> {
    config: Config,
    generator: G,
}

impl<G: Generator + Default> Encoder<G> {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_generator(config, G::default())
    }
}

impl<G: Generator> Encoder<G> {
    pub fn with_generator(config: Config, generator: G) -> Result<Self, Error> {
        if !(1..=40).contains(&config.max_qr_version) {
            return Err(Error::QrVersion(config.max_qr_version));
        }
        if config.bbqr_part_bytes == 0 {
            return Err(Error::ZeroPartSize);
        }
        Ok(Self { config, generator })
    }

    pub fn encode_text(&self, text: &str) -> Result<Image, Error> {
        let params = Params {
            min_version: 1,
            max_version: self.config.max_qr_version,
            correction: Correction::Low,
            boost_correction: true,
        };
        Ok(self.generator.generate(text, params)?.render())
    }

    /// Splits `data` into BBQR parts and renders one frame per part.
    pub fn encode_bytes(&self, data: &[u8]) -> Result<Vec<Image>, Error> {
        let split = bbqr::split(data, self.config.bbqr_part_bytes)?;
        split
            .parts
            .iter()
            .map(|part| self.encode_part(part))
            .collect()
    }

    #[cfg(feature = "protocol")]
    pub fn encode_request(&self, request: &crate::protocol::Request) -> Result<Vec<Image>, Error> {
        self.encode_bytes(&crate::protocol::encode_request(request)?)
    }

    #[cfg(feature = "protocol")]
    pub fn encode_response(
        &self,
        response: &crate::protocol::Response,
    ) -> Result<Vec<Image>, Error> {
        self.encode_bytes(&crate::protocol::encode_response(response)?)
    }

    // A part is pinned to `max_qr_version` so every frame of a message is the same size.
    fn encode_part(&self, part: &str) -> Result<Image, Error> {
        if !gen::is_alphanumeric(part) {
            return Err(Error::PartNotAlphanumeric);
        }
        let version = self.config.max_qr_version;
        let params = Params {
            min_version: version,
            max_version: version,
            correction: Correction::Low,
            boost_correction: false,
        };
        match self.generator.generate(part, params) {
            Ok(modules) => Ok(modules.render()),
            // the version is pinned, so a part that does not render simply does not fit it
            Err(gen::Error::TooLong) => Err(Error::PartTooLarge {
                bytes: self.config.bbqr_part_bytes,
                version,
            }),
            Err(error) => Err(error.into()),
        }
    }
}
