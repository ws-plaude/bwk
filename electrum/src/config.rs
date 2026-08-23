//! Configuration for the scanner half of a wallet.
//!
//! This is what an [`ElectrumScanner`](crate::scanner::ElectrumScanner) needs
//! to watch a descriptor: where to store its data, which server to talk to and
//! how far to look ahead. Wallet-level settings such as a mnemonic live in the
//! consumer's own config.

use std::path::PathBuf;

use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

use bwk_persist::PersistenceKind;

/// Filename for the binary header cache under [`ScannerConfig::account_dir`].
/// Headers are always binary-backed, independent of `persist_kind`.
pub const HEADERS_FILENAME: &str = "headers.bin";

/// The derivation indexes reached on each keychain.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tip {
    pub receive: u32,
    pub change: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScannerConfig {
    #[serde(skip)]
    pub data_dir: PathBuf,
    #[serde(skip)]
    pub dir_name: String,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub electrum_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub electrum_port: Option<u16>,
    #[serde(default)]
    pub offline: Option<bool>,
    /// Whether to validate the server's TLS certificate against its hostname.
    /// `None` means the consumer expressed no preference; see
    /// [`ScannerConfig::validate_certificate`].
    #[serde(default)]
    pub validate_certificate: Option<bool>,
    pub network: miniscript::bitcoin::Network,
    pub look_ahead: u32,
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub persist: bool,
    /// When true, the label store is not loaded from or persisted to disk.
    /// Used by `bwk_sp::Account` to delegate label management to the parent's
    /// SpLabelStore.
    #[serde(skip)]
    pub skip_labels: bool,
    #[serde(skip)]
    pub persist_kind: PersistenceKind,
}

impl ScannerConfig {
    /// A scanner watching `descriptor`, with the defaults for everything the
    /// caller has no opinion on: online, no server pinned, 20 addresses of
    /// look-ahead.
    pub fn new(
        descriptor: Descriptor<DescriptorPublicKey>,
        data_dir: PathBuf,
        dir_name: String,
        account: String,
        network: miniscript::bitcoin::Network,
        persist: bool,
    ) -> Self {
        Self {
            data_dir,
            dir_name,
            account,
            electrum_url: None,
            electrum_port: None,
            offline: None,
            validate_certificate: None,
            network,
            look_ahead: 20,
            descriptor,
            persist,
            skip_labels: false,
            persist_kind: PersistenceKind::default(),
        }
    }

    /// Open the persistence backend this config selects, rooted at
    /// [`ScannerConfig::account_dir`]. `NoopBackend` when `persist` is off.
    pub fn build_backend(
        &self,
    ) -> Result<std::sync::Arc<dyn bwk_persist::PersistenceBackend>, bwk_persist::PersistError>
    {
        bwk_persist::build_backend(
            self.persist.then_some(self.persist_kind),
            self.account_dir(),
        )
    }

    pub fn set_offline(&mut self, offline: bool) {
        self.offline = Some(offline);
    }

    pub fn set_validate_certificate(&mut self, validate: bool) {
        self.validate_certificate = Some(validate);
    }

    /// Validating unless the consumer asked otherwise, so a config predating
    /// the field does not silently stop checking certificates on upgrade.
    pub fn validate_certificate(&self) -> bool {
        self.validate_certificate.unwrap_or(true)
    }

    /// Where this account's files (or SQLite DB) live.
    pub fn account_dir(&self) -> PathBuf {
        let mut dir = self.data_dir.clone();
        dir.push(&self.dir_name);
        dir.push(&self.account);
        dir
    }

    /// This account's binary header cache.
    pub fn headers_path(&self) -> PathBuf {
        self.account_dir().join(HEADERS_FILENAME)
    }

    pub fn electrum_url(&self) -> String {
        self.electrum_url.clone().unwrap_or_default()
    }

    pub fn electrum_port(&self) -> String {
        self.electrum_port
            .map(|p| p.to_string())
            .unwrap_or_default()
    }

    pub fn look_ahead(&self) -> String {
        self.look_ahead.to_string()
    }

    pub fn network(&self) -> miniscript::bitcoin::Network {
        self.network
    }

    pub fn offline(&self) -> bool {
        self.offline.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bwk_descriptor::descriptor::wpkh;
    use bwk_sign::{bip39::Mnemonic, hot_signer::HotSigner};
    use miniscript::bitcoin::{bip32::DerivationPath, Network};
    use std::str::FromStr;

    fn config() -> ScannerConfig {
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer = HotSigner::new_from_mnemonics(Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        ScannerConfig::new(
            wpkh(xpub),
            PathBuf::default(),
            String::new(),
            "test".into(),
            Network::Regtest,
            false,
        )
    }

    #[test]
    fn certificate_validation_is_on_until_the_consumer_says_otherwise() {
        let mut config = config();
        // Unset stays distinguishable from an explicit choice, so a consumer
        // can apply its own default to a config predating the field.
        assert_eq!(config.validate_certificate, None);
        assert!(config.validate_certificate());

        config.set_validate_certificate(false);
        assert_eq!(config.validate_certificate, Some(false));
        assert!(!config.validate_certificate());

        config.set_validate_certificate(true);
        assert_eq!(config.validate_certificate, Some(true));
        assert!(config.validate_certificate());
    }

    #[test]
    fn a_config_written_before_the_field_existed_still_validates() {
        let json = r#"{"account":"test","network":"regtest","look_ahead":20,
            "descriptor":"wpkh(tpubDCbK3Ysvk8HjcF6mPyrgMu3KgLiaaP19RjKpNezd8GrbAbNg6v5BtWLaCt8FNm6QkLseopKLf5MNYQFtochDTKHdfgG6iqJ8cqnLNAwtXuP/<0;1>/*)","persist":false}"#;
        let config: ScannerConfig = serde_json::from_str(json).expect("decodes without the field");
        assert_eq!(config.validate_certificate, None);
        assert!(config.validate_certificate());
    }

    #[test]
    fn the_choice_survives_a_round_trip() {
        let mut config = config();
        config.set_validate_certificate(false);
        let encoded = serde_json::to_string(&config).expect("encodes");
        let decoded: ScannerConfig = serde_json::from_str(&encoded).expect("decodes");
        assert_eq!(decoded.validate_certificate, Some(false));
        assert!(!decoded.validate_certificate());
    }
}
