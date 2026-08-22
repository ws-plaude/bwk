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
    pub network: miniscript::bitcoin::Network,
    pub look_ahead: u32,
    pub descriptor: Descriptor<DescriptorPublicKey>,
    pub persist: bool,
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
            network,
            look_ahead: 20,
            descriptor,
            persist,
            persist_kind: PersistenceKind::default(),
        }
    }

    pub fn account_dir(&self) -> PathBuf {
        let mut dir = self.data_dir.clone();
        dir.push(&self.account);
        dir
    }

    pub fn headers_path(&self) -> PathBuf {
        let mut dir = self.data_dir.clone();
        dir.push("headers");
        dir
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
