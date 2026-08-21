use super::api;

#[cfg(not(any(feature = "minreq", feature = "ureq")))]
compile_error!("the jade feature needs an http client, enable either minreq or ureq");

/// The request is a single round trip to the pin server, give it room for a slow link.
#[cfg(feature = "minreq")]
const TIMEOUT_SECS: u64 = 30;

pub struct PinServerClient {
    // ureq pools connections, so the agent is worth keeping around. minreq has no such object.
    #[cfg(all(feature = "ureq", not(feature = "minreq")))]
    agent: ureq::Agent,
}

impl Default for PinServerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PinServerClient {
    pub fn new() -> Self {
        Self {
            #[cfg(all(feature = "ureq", not(feature = "minreq")))]
            agent: ureq::Agent::new_with_defaults(),
        }
    }

    pub fn request<D>(&self, req: api::PinServerRequestParams) -> Result<D, Error>
    where
        D: serde::de::DeserializeOwned,
    {
        let url = match &req.urls {
            api::PinServerUrls::Array(urls) => urls.first().ok_or(Error::NoUrlProvided)?,
            api::PinServerUrls::Object { url, .. } => url,
        };

        self.post_json(url, &req.data)
    }

    #[cfg(feature = "minreq")]
    fn post_json<D>(&self, url: &str, data: &api::PinParams) -> Result<D, Error>
    where
        D: serde::de::DeserializeOwned,
    {
        let res = minreq::post(url)
            .with_json(data)
            .map_err(|e| Error::Client(e.to_string()))?
            .with_timeout(TIMEOUT_SECS)
            .send()
            .map_err(|e| Error::Client(e.to_string()))?;

        if !(200..300).contains(&res.status_code) {
            return Err(Error::Server(format!(
                "{} {}",
                res.status_code,
                res.as_str().unwrap_or_default()
            )));
        }

        res.json().map_err(|e| Error::Client(e.to_string()))
    }

    #[cfg(all(feature = "ureq", not(feature = "minreq")))]
    fn post_json<D>(&self, url: &str, data: &api::PinParams) -> Result<D, Error>
    where
        D: serde::de::DeserializeOwned,
    {
        let mut res = self
            .agent
            .post(url)
            .send_json(data)
            .map_err(|e| Error::Client(e.to_string()))?;

        res.body_mut()
            .read_json()
            .map_err(|e| Error::Client(e.to_string()))
    }
}

#[derive(Debug)]
pub enum Error {
    NoUrlProvided,
    /// The http client failed, its error rendered by the backend in use.
    Client(String),
    Server(String),
}
