//! The wallet half: an [`ElectrumScanner`] plus signers.
//!
//! [`Account`] wraps a scanner and adds what a wallet has that a scan does
//! not: hot signers, the mnemonic that seeds them and a transaction builder
//! wired to the scanner's coins. Everything scan-related is delegated, so the
//! two halves cannot drift.

use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Mutex},
};

use bwk_descriptor::derivator::SpkDerivator;
use bwk_electrum::{
    address_store::AddressEntry,
    coin_store::{CoinEntry, CoinStore, CoinStoreSource, Payment},
    config::ScannerConfig,
    header_store::HeaderStore,
    history::{AccountHistory, TxContribution},
    label_store::LabelStore,
    profile::OpenScanFromBackend,
    scanner::ConfigHook,
    ElectrumScanner,
};
use bwk_persist::{ConfigStore, NoopConfigStore, PersistError, PersistenceBackend};
use bwk_sign::signing_manager::SigningManager;
use bwk_tx::{tx_builder::TxBuilder, ChangeRecipientProvider, Coin};

use miniscript::{
    bitcoin::{self, OutPoint, Txid},
    Descriptor, DescriptorPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    profile::{OpenFromBackend, StorageProfile, Stores},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AddrAccount {
    Receive,
    Change,
}

pub use bwk_electrum::coin_state::CoinState;
pub use bwk_electrum::notification::OpenError;
#[cfg(feature = "sp")]
pub use bwk_electrum::notification::SpNotification;
pub use bwk_electrum::notification::{
    Error, Notification, TxListenerError, TxListenerNotif, ValidationFailure,
};

pub struct Account<P: StorageProfile = crate::profile::RamProfile<crate::profile::DefaultBackend>> {
    scanner: ElectrumScanner<P>,
    /// Seed for the hot signers. The scanner never sees it.
    mnemonic: Option<String>,
    /// Persistence sink for the account config. [`NoopConfigStore`] by
    /// default. Consumers wire whatever shape suits them: a
    /// [`bwk_persist::FileConfigStore`] for file-backed persistence, a
    /// [`bwk_persist::CallbackConfigStore`] to bridge save/load through
    /// host-supplied closures, or any other [`ConfigStore`] impl.
    config_store: Arc<dyn ConfigStore<Config>>,
    signing_manager: SigningManager<P::SignerStore>,
}

impl<P: StorageProfile> std::fmt::Debug for Account<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account").finish()
    }
}

fn default_config_store() -> Arc<dyn ConfigStore<Config>> {
    Arc::new(NoopConfigStore::<Config>::default())
}

/// The hook the scanner calls on every config change: fold the scanner's view
/// back into a full [`Config`] and save it.
fn config_hook(mnemonic: Option<String>, config_store: Arc<dyn ConfigStore<Config>>) -> ConfigHook {
    Arc::new(move |scan: &ScannerConfig| {
        let cfg = Config::from_parts(scan.clone(), mnemonic.clone()).for_persistence();
        if let Err(e) = config_store.save(&cfg) {
            log::warn!("config save failed: {e}");
        }
    })
}

impl<P: OpenFromBackend> Account<P> {
    /// An account backed by `config`, opening its stores against whatever
    /// backend the config selects ([`JsonBackend`][bwk_persist::JsonBackend]
    /// by default, `SqliteBackend` under `PersistenceKind::Sqlite`).
    ///
    /// Builds its own [`HeaderStore`]; use
    /// [`Account::try_new_with_header_store`] to share an existing one.
    ///
    /// Config persistence defaults to [`NoopConfigStore`]; use
    /// [`Account::try_with_config_store`] to wire a concrete impl
    /// ([`bwk_persist::FileConfigStore`] for file-backed,
    /// [`bwk_persist::CallbackConfigStore`] to bridge through
    /// caller-supplied closures, or any other [`ConfigStore`]).
    ///
    /// Returns [`OpenError`] if the account name is empty, the backend cannot
    /// be built (e.g. the account directory is already locked by another
    /// instance), or a stored blob fails to decode.
    pub fn try_new(config: Config) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_with_header_store(config, header_store)
    }

    /// Like [`Account::try_new`] but sharing an existing [`HeaderStore`]
    /// handle instead of building one.
    pub fn try_new_with_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
    ) -> Result<Self, OpenError> {
        let (sender, receiver) = mpsc::channel();
        let mut account =
            Self::try_new_inner(config, header_store, sender, default_config_store())?;
        account.scanner.set_receiver(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an explicit config store.
    pub fn try_with_config_store(
        config: Config,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        let (sender, receiver) = mpsc::channel();
        let mut account = Self::try_new_inner(config, header_store, sender, config_store)?;
        account.scanner.set_receiver(receiver);
        Ok(account)
    }

    /// Like [`Account::try_new`] but with an external notification sender.
    pub fn try_new_with_sender(
        config: Config,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_inner(config, header_store, sender, default_config_store())
    }

    /// Like [`Account::try_new_with_sender`] but sharing an existing
    /// [`HeaderStore`] handle instead of building one. Used to fan a
    /// shared chain across several accounts routed through the same
    /// notification channel (e.g. `bwk_sp::Account`'s BIP32 sub-accounts).
    pub fn try_new_with_sender_and_header_store(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        Self::try_new_inner(config, header_store, sender, default_config_store())
    }

    /// Infallible test helper. Not exposed to consumers: production
    /// callers use [`Account::try_new`] so a bad/locked store surfaces
    /// as an error instead of aborting.
    #[cfg(any(test, feature = "test"))]
    pub fn new(config: Config) -> Self {
        Self::try_new(config).expect("Account::new: failed to open stores")
    }

    /// Infallible test helper; see [`Account::new`].
    #[cfg(any(test, feature = "test"))]
    pub fn with_config_store(config: Config, config_store: Arc<dyn ConfigStore<Config>>) -> Self {
        Self::try_with_config_store(config, config_store)
            .expect("Account::with_config_store: failed to open stores")
    }

    /// See [`ElectrumScanner::build_header_store`].
    fn build_header_store(config: &Config) -> Result<Arc<HeaderStore<P::HeaderStore>>, OpenError> {
        ElectrumScanner::<P>::build_header_store(&config.scanner())
    }

    fn try_new_inner(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
    ) -> Result<Self, OpenError> {
        if config.account.is_empty() {
            return Err(OpenError::EmptyAccount);
        }
        let backend: Arc<dyn PersistenceBackend> = config.build_backend()?;
        // Hot-signer material must not land on the SQLite DB; route the
        // SignerStore slot through a NoopBackend in that case.
        let secrets_backend: Arc<dyn PersistenceBackend> =
            if matches!(config.persist_kind, bwk_persist::PersistenceKind::Sqlite) {
                Arc::new(bwk_persist::NoopBackend)
            } else {
                backend.clone()
            };
        let reopen_backend = backend.clone();
        let reopen_statuses: Arc<dyn Fn() -> Result<P::StatusesStore, PersistError> + Send + Sync> =
            Arc::new(move || <P as OpenFromBackend>::open_statuses(reopen_backend.clone()));
        let stores = <P as OpenFromBackend>::open(backend, secrets_backend)?;
        Ok(Self::from_stores(
            config,
            header_store,
            sender,
            config_store,
            stores,
            Some(reopen_statuses),
        ))
    }

    /// See [`ElectrumScanner::restart_electrum`].
    pub fn restart_electrum(&mut self) {
        self.scanner.restart_electrum();
    }
}

impl<P: StorageProfile> Account<P> {
    fn from_stores(
        config: Config,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        config_store: Arc<dyn ConfigStore<Config>>,
        stores: Stores<P>,
        reopen_statuses: Option<
            Arc<dyn Fn() -> Result<P::StatusesStore, PersistError> + Send + Sync>,
        >,
    ) -> Self {
        let mnemonic = config.mnemonic.clone();
        let hook = config_hook(mnemonic.clone(), config_store.clone());
        let Stores {
            tx,
            label,
            statuses,
            account,
            signers,
        } = stores;
        let mut signing_manager = SigningManager::from_store(signers);
        if let Some(mnemo) = mnemonic.clone() {
            signing_manager.new_bip32_signer_from_mnemonic(config.network(), mnemo);
            signing_manager.register_bip32_descriptor(config.descriptor.clone());
        }
        let scanner = ElectrumScanner::from_stores(
            config.scanner(),
            header_store,
            sender,
            Some(hook),
            bwk_electrum::profile::ScanStores {
                tx,
                label,
                statuses,
                account,
            },
            reopen_statuses,
        );
        Account {
            scanner,
            mnemonic,
            config_store,
            signing_manager,
        }
    }

    /// The scanner this account is built on, for callers that want the scan
    /// surface directly.
    pub fn scanner(&self) -> &ElectrumScanner<P> {
        &self.scanner
    }

    pub fn scanner_mut(&mut self) -> &mut ElectrumScanner<P> {
        &mut self.scanner
    }

    /// Push the current config to the configured [`ConfigStore`].
    ///
    /// Under [`bwk_persist::PersistenceKind::Sqlite`] the saved view has
    /// signer material stripped via [`Config::for_persistence`].
    fn persist_config(&self) {
        let cfg = self.get_config().for_persistence();
        if let Err(e) = self.config_store.save(&cfg) {
            log::warn!("config save failed: {e}");
        }
    }

    fn coin_store(&self) -> &Arc<Mutex<CoinStore<P>>> {
        self.scanner.coin_store()
    }

    fn label_store(&self) -> &Arc<Mutex<LabelStore<P>>> {
        self.scanner.label_store()
    }

    fn signing_manager(&self) -> &SigningManager<P::SignerStore> {
        &self.signing_manager
    }
}

// Non (b)locking API
impl<P: StorageProfile> Account<P> {
    pub fn network(&self) -> bitcoin::Network {
        self.scanner.network()
    }

    pub fn name(&self) -> String {
        self.scanner.name()
    }

    pub fn descriptor_str(&self) -> String {
        self.scanner.descriptor_str()
    }

    pub fn descriptor(&self) -> Descriptor<DescriptorPublicKey> {
        self.scanner.descriptor()
    }

    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.scanner.receiver()
    }

    /// The account's configuration: the scanner's view plus the wallet-only
    /// settings.
    pub fn get_config(&self) -> Config {
        Config::from_parts(self.scanner.config(), self.mnemonic.clone())
    }

    pub fn coin_source(&self) -> CoinStoreSource<P> {
        self.scanner.coin_source()
    }

    pub fn sign(&self, psbt: String) {
        self.signing_manager().sign(psbt);
    }

    pub fn sign_psbt(&self, psbt: &mut bitcoin::Psbt) {
        self.signing_manager().sign_psbt(psbt);
    }

    /// Returns master xprivs from all BIP32 hot signers, keyed by fingerprint.
    pub fn master_xprivs(&self) -> BTreeMap<bitcoin::bip32::Fingerprint, bitcoin::bip32::Xpriv> {
        self.signing_manager().master_xprivs()
    }
}

// Locking API
impl<P: StorageProfile> Account<P> {
    pub fn tx_builder(&self) -> TxBuilder {
        let tip_updater = bwk_electrum::address_store::ChangeTipUpdater::new(
            self.coin_store().lock().expect("poisoned").address_store(),
        );
        let change_provider = Box::new(ChangeRecipientProvider::new_with_updater(
            tip_updater,
            self.descriptor(),
            self.network(),
        ));
        let coin_source = Box::new(CoinStoreSource::new(self.coin_store().clone()));
        TxBuilder::new(change_provider).coin_source(coin_source)
    }

    pub fn balance(&self) -> (u64, Vec<Payment>) {
        self.scanner.balance()
    }

    pub fn coins(&self) -> BTreeMap<OutPoint, CoinEntry> {
        self.scanner.coins()
    }

    /// The coin matching `outpoint`, if tracked.
    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.scanner.get_coin(outpoint)
    }

    pub fn spendable_coins(&self) -> CoinState {
        self.scanner.spendable_coins()
    }

    pub fn tx_history(&self) -> Vec<bwk_electrum::tx_store::TxEntry> {
        self.scanner.tx_history()
    }

    pub fn payment_history(&self) -> Vec<Payment> {
        self.scanner.payment_history()
    }

    /// See [`ElectrumScanner::record_unconfirmed_spend`].
    pub fn record_unconfirmed_spend(&self, tx: &bitcoin::Transaction) {
        self.scanner.record_unconfirmed_spend(tx);
    }

    /// Label the coin at `outpoint`, or clear its label when `label` is empty.
    pub fn update_coin_label(&self, outpoint: String, label: String) {
        self.scanner.update_coin_label(outpoint, label);
    }

    /// Derive and start watching the next receive address.
    pub fn new_addr(&mut self) -> AddressEntry {
        self.scanner.new_addr()
    }

    #[allow(unused)]
    fn new_recv_addr(&mut self) -> bitcoin::Address {
        self.scanner.new_recv_addr()
    }

    #[allow(unused)]
    fn new_change_addr(&mut self) -> bitcoin::Address {
        self.scanner.new_change_addr()
    }
}

impl<P: StorageProfile> AccountHistory for Account<P> {
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
        self.scanner.tx_contributions()
    }
}

// Derivation specific implementation
impl<P: StorageProfile> Account<P> {
    pub fn derivator(&self) -> SpkDerivator {
        self.scanner.derivator()
    }

    #[allow(unused)] // Internal usage only
    fn recv_at(&self, index: u32) -> bitcoin::Address {
        self.scanner.recv_at(index)
    }

    #[allow(unused)] // Internal usage only
    fn change_at(&self, index: u32) -> bitcoin::Address {
        self.scanner.change_at(index)
    }

    pub fn recv_watch_tip(&self) -> u32 {
        self.scanner.recv_watch_tip()
    }

    pub fn change_watch_tip(&self) -> u32 {
        self.scanner.change_watch_tip()
    }

    pub fn generated_addresses(
        &self,
    ) -> (
        Vec<AddressEntry>, /* receive */
        Vec<AddressEntry>, /* change*/
    ) {
        self.scanner.generated_addresses()
    }

    /// Snapshot of every address entry the account currently tracks
    /// (receive + change, all derivation indices). Cloned, so the
    /// caller doesn't hold any lock.
    pub fn address_entries(&self) -> Vec<AddressEntry> {
        self.scanner.address_entries()
    }
}

// Electrum specific implementation
impl<P: StorageProfile> Account<P> {
    /// Re-generate coin_store from tx_store
    pub fn generate_coins(&mut self) {
        self.scanner.generate_coins();
    }

    pub fn electrum_url(&self) -> String {
        self.scanner.electrum_url()
    }

    pub fn electrum_port(&self) -> String {
        self.scanner.electrum_port()
    }

    pub fn look_ahead(&self) -> String {
        self.scanner.look_ahead()
    }

    /// Sets the Electrum server URL and port for the account.
    pub fn set_electrum(&mut self, url: String, port: String) {
        self.scanner.set_electrum(url, port);
    }

    /// Sets the Electrum URL and port in memory without writing to file.
    pub fn set_electrum_config(&mut self, url: Option<String>, port: Option<u16>) {
        self.scanner.set_electrum_config(url, port);
    }

    pub fn start_electrum(&mut self) {
        self.scanner.start_electrum();
    }

    pub fn stop_electrum(&mut self) {
        self.scanner.stop_electrum();
    }

    pub fn electrum_offline(&self) -> bool {
        self.scanner.electrum_offline()
    }

    /// Test-only accessor for the account's `HeaderStore` handle, used to
    /// assert store identity (`Arc::ptr_eq`) across accounts sharing one.
    #[cfg(any(test, feature = "test"))]
    pub fn header_store(&self) -> &Arc<HeaderStore<P::HeaderStore>> {
        self.scanner.header_store()
    }

    /// Sets the look-ahead value for the account.
    pub fn set_look_ahead(&mut self, look_ahead: String) {
        self.scanner.set_look_ahead(look_ahead);
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use bwk_descriptor::descriptor::{wpkh, ScriptType};
    use bwk_electrum::config::ScannerConfig;
    use bwk_persist::Store;
    use bwk_sign::bip39::Mnemonic;
    use bwk_sign::hot_signer::HotSigner;
    use bwk_utils::test::setup_logger;
    use miniscript::bitcoin::ScriptBuf;
    use miniscript::bitcoin::{bip32::ChildNumber, Network};
    use std::{path::PathBuf, str::FromStr};
    use temp_dir::TempDir;

    fn persisted_offline_config(dir: &TempDir, look_ahead: u32) -> Config {
        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "acct".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            dir.path().to_path_buf(),
            ".bwk".to_string(),
            true, // persist
        )
        .unwrap();
        config.look_ahead = look_ahead;
        config.set_offline(true);
        config
    }

    #[test]
    fn restart_restores_deep_change_tip_and_high_index_history_no_panic() {
        // Regression for the `address_store.rs "must be there"` panic on
        // wallets whose used range exceeds look_ahead. Drive the change tip
        // past look_ahead, reopen, then deliver history for a script beyond
        // the restored window.
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 2);
        let saved = config.clone();

        let derivator;
        {
            let mut account: Account = Account::new(config);
            for _ in 0..10 {
                account.new_change_addr();
            }
            derivator = account.derivator();
            assert!(account.change_watch_tip() >= 10);
            drop(account);
        }

        // Reopen: the tip must be restored (fix 1), not reset to 0.
        let account: Account = Account::new(saved);
        assert!(
            account.change_watch_tip() >= 10,
            "change tip must survive restart, got {}",
            account.change_watch_tip()
        );

        // History for a change script past the restored window must extend the
        // store rather than panic (fix 3).
        let beyond = account.change_watch_tip() + 5;
        let spk = derivator.change_at(beyond).script_pubkey();
        {
            let mut store = account.coin_store().lock().expect("poisoned");
            let mut map = BTreeMap::new();
            map.insert(spk.clone(), vec![]);
            store.handle_history_response(map);
        }
        assert!(
            account.change_watch_tip() > beyond,
            "store must extend to cover the reported high-index script"
        );
        drop(account);
    }

    #[test]
    fn tip_restored_from_statuses_when_account_store_empty() {
        // The watch window must cover persisted subscriptions even when the
        // tip rows are absent (fix 2): seed statuses with a high-index change
        // script, write no tip, then open the account.
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, 2);

        let account_dir = config.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .unwrap();
            statuses
                .insert(ScriptBuf::from_bytes(vec![0x00; 22]), (None, 1, 30))
                .unwrap();
            statuses.flush().unwrap();
        }

        let account: Account = Account::new(config);
        assert!(
            account.change_watch_tip() >= 30,
            "change tip must be floored by the statuses max index, got {}",
            account.change_watch_tip()
        );
        drop(account);
    }

    #[cfg(feature = "test")]
    #[test]
    fn statuses_floor_does_not_inflate_generated_tip() {
        // The statuses store spans the whole watch window (generated tip plus
        // look-ahead), so its max index is `generated + look_ahead`. Flooring the
        // restored tip with that raw max would climb the generated tip by one
        // look-ahead on every reopen. Seed a change status at the top of the
        // window for generated tip 10 (look-ahead 2, so index 12) and assert the
        // restored watch tip is 13 (generated 10 + 2 + 1), not 15 (an inflated
        // generated tip of 12).
        let look_ahead = 2u32;
        let generated = 10u32;
        let dir = TempDir::new().unwrap();
        let config = persisted_offline_config(&dir, look_ahead);

        let account_dir = config.account_dir();
        {
            let backend: Arc<dyn PersistenceBackend> =
                Arc::new(bwk_persist::JsonBackend::open(account_dir).unwrap());
            let mut statuses = bwk_persist::RamStore::open(
                backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .unwrap();
            statuses
                .insert(
                    ScriptBuf::from_bytes(vec![0x01; 22]),
                    (None, 1, generated + look_ahead),
                )
                .unwrap();
            statuses.flush().unwrap();
        }

        let account: Account = Account::new(config);
        assert_eq!(
            account.change_watch_tip(),
            generated + look_ahead + 1,
            "generated tip must not be inflated by the look-ahead on reopen"
        );
        drop(account);
    }
}

#[cfg(test)]
mod integration_tests {

    use rand::random_range;
    use std::{
        collections::BTreeMap, env, path::PathBuf, sync::mpsc, thread::sleep, time::Duration,
    };

    use super::{Notification, TxListenerNotif};
    use crate::{
        coin_store::Payment,
        config::{maybe_create_dir, Config},
        header_store::HeaderStore,
        log::INIT,
        Account,
    };
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_electrum::client::Client;
    use miniscript::bitcoin::{
        self, bip32::ChildNumber, Address, Amount, Network, Transaction, Txid,
    };
    use miniscript::psbt::PsbtExt;
    use temp_dir::TempDir;

    use electrsd::{
        bitcoind::{
            bitcoincore_rpc::{jsonrpc::serde_json::Value, RpcApi},
            BitcoinD, P2P,
        },
        ElectrsD,
    };

    pub fn bootstrap_electrs() -> (
        String, /* url */
        u16,    /* port */
        ElectrsD,
        BitcoinD,
    ) {
        let mut cwd: PathBuf = env::current_dir().expect("Failed to get current directory");
        cwd.push("tests");

        let mut electrs_path = cwd.clone();
        electrs_path.push("bin");
        electrs_path.push("electrs_0_9_11");

        let mut bitcoind_path = cwd.clone();
        bitcoind_path.push("bin");
        bitcoind_path.push("bitcoind_25_2");

        let mut conf = electrsd::bitcoind::Conf::default();
        conf.p2p = P2P::Yes;
        let bitcoind = BitcoinD::with_conf(bitcoind_path, &conf).unwrap();

        let mut electrsd_conf = electrsd::Conf::default();
        electrsd_conf.args = vec!["--log-filters", "DEBUG"];
        electrsd_conf.buffered_logs = true;

        let electrsd = ElectrsD::with_conf(electrs_path, &bitcoind, &electrsd_conf).unwrap();
        let (url, port) = electrsd.electrum_url.split_once(':').unwrap();
        let port = port.parse::<u16>().unwrap();

        // mine 101 blocks
        let node_address = bitcoind.client.call::<Value>("getnewaddress", &[]).unwrap();
        bitcoind
            .client
            .call::<Value>("generatetoaddress", &[101.into(), node_address])
            .unwrap();

        // Without root we cannot raise electrsd's priority directly, so lower
        // the test process instead. Gives electrsd's indexer relatively more
        // CPU when the host is under load (the source of past flakes).
        #[cfg(unix)]
        unsafe {
            libc::nice(5);
        }

        // Wait until electrsd has caught up with bitcoind's tip before any
        // test starts pushing transactions. Avoids a race where the first
        // send_to_address lands while the indexer is still ingesting the
        // initial 101 blocks.
        wait_electrsd_synced(&bitcoind, &electrsd);

        (url.into(), port, electrsd, bitcoind)
    }

    fn wait_electrsd_synced(bitcoind: &BitcoinD, electrsd: &ElectrsD) {
        use electrsd::electrum_client::ElectrumApi;
        let target = bitcoind
            .client
            .call::<Value>("getblockcount", &[])
            .unwrap()
            .as_u64()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            if let Ok(header) = electrsd.client.block_headers_subscribe() {
                if header.height as u64 >= target {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[allow(unused)]
    pub fn tcp_client() -> (Client, ElectrsD, BitcoinD) {
        let (url, port, e, b) = bootstrap_electrs();
        let client = Client::new(&url, port).unwrap();

        (client, e, b)
    }

    pub fn send_to_address(bitcoind: &BitcoinD, addr: &Address, amount: Amount) -> Txid {
        let txid = bitcoind
            .client
            .send_to_address(addr, amount, None, None, None, None, None, None)
            .unwrap();
        log::debug!("send_to_address({addr}, {amount}) => {txid}");
        txid
    }

    #[allow(unused)]
    pub fn get_tx(bitcoind: &BitcoinD, txid: Txid) -> Transaction {
        bitcoind.client.get_raw_transaction(&txid, None).unwrap()
    }

    #[allow(unused)]
    pub fn broadcast(bitcoind: &BitcoinD, transaction: Transaction) {
        let _txid = bitcoind.client.send_raw_transaction(&transaction).unwrap();
    }

    pub fn get_block_hash(bitcoind: &BitcoinD, height: u32) -> String {
        bitcoind
            .client
            .call("getblockhash", &[height.into()])
            .unwrap()
    }

    pub fn get_block_height(bitcoind: &BitcoinD) -> u32 {
        bitcoind.client.call("getblockcount", &[]).unwrap()
    }

    pub fn generate(bitcoind: &BitcoinD, blocks: u32) {
        let node_address = bitcoind.client.call::<Value>("getnewaddress", &[]).unwrap();
        bitcoind
            .client
            .call::<Value>("generatetoaddress", &[blocks.into(), node_address])
            .unwrap();
    }

    pub fn reorg_chain(bitcoind: &BitcoinD, blocks: u32) {
        let chain_height: u32 = get_block_height(bitcoind);
        let reorg_height = chain_height - blocks;
        let block_hash = get_block_hash(bitcoind, reorg_height);

        invalidate_block(bitcoind, block_hash);

        generate(bitcoind, blocks);
    }

    pub fn invalidate_block(bitcoind: &BitcoinD, block_hash: String) {
        bitcoind
            .client
            .call::<Value>("invalidateblock", &[block_hash.clone().into()])
            .unwrap();

        log::info!("Invalidated block with hash: {block_hash}");
    }

    pub fn dump_logs(e: &mut ElectrsD) {
        while let Ok(msg) = e.logs.try_recv() {
            println!("{msg}");
        }
    }

    #[allow(unused)]
    pub fn setup_logger() {
        INIT.call_once(|| {
            env_logger::builder()
                .is_test(true)
                .filter_level(log::LevelFilter::Debug)
                .filter_module("bitcoind", log::LevelFilter::Info)
                .filter_module("bitcoincore_rpc", log::LevelFilter::Info)
                .filter_module("bwk::account", log::LevelFilter::Debug)
                .filter_module("bwk-electrum::electrum", log::LevelFilter::Debug)
                .filter_module("bwk-electrum::raw_client", log::LevelFilter::Debug)
                .init();
        });
    }

    pub fn wait_until_timeout<F>(condition: F, timeout: u64)
    where
        F: Fn() -> bool,
    {
        let delay = Duration::from_millis(100);
        let start_time = std::time::Instant::now();

        while start_time.elapsed().as_secs() < timeout {
            if condition() {
                return;
            }
            sleep(delay);
        }
        panic!("Timeout elapsed while waiting for condition.");
    }

    /// Per-block wait budget for integration tests.
    ///
    /// `n_blocks * 3` was the historical formula but flaked in CI when
    /// `random_range(2..15)` returned the low end (6 s isn't enough for
    /// electrs to index + notify + bwk to process under load). Floor at
    /// 30 s and use a higher per-block factor.
    pub fn block_wait(blocks: u32) -> u64 {
        ((blocks as u64) * 5).max(30)
    }

    #[test]
    fn test_reorg() {
        // setup_logger();
        let (_, _, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        reorg_chain(&bitcoind, 5);
    }

    #[test]
    fn simple_wallet() {
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        const TIMEOUT: u64 = 120;
        const BLOCKS: u32 = 1;

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.new_recv_addr();
        let change_addr = account.new_change_addr();

        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 1
            },
            TIMEOUT,
        );

        // Test change address
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        // receive at look_ahead bound
        let recv_addr = account.recv_at(look_ahead);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 3
            },
            TIMEOUT,
        );

        // change at look_ahead bound
        let change_addr = account.change_at(look_ahead);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 4
            },
            TIMEOUT,
        );

        let undiscovered_tip = account.recv_watch_tip() + 1;

        // receive beyond the look_ahead bound
        let recv_addr = account.recv_at(undiscovered_tip);
        send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.coins();
        // the coin is not detected for receiving address
        assert_eq!(coins.len(), 4);

        // change beyond the look_ahead bound
        let change_addr = account.change_at(undiscovered_tip);
        send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        generate(&bitcoind, BLOCKS);
        let coins = account.coins();
        // the coin is not detected for change address
        assert_eq!(coins.len(), 4);

        // move the watch tip forward
        account.new_recv_addr();
        account.new_recv_addr();
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 5
            },
            TIMEOUT,
        );

        account.new_change_addr();
        account.new_change_addr();
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 6
            },
            TIMEOUT,
        );
    }

    #[test]
    fn simple_reorg_e2e() {
        // setup_logger();
        let (url, port, mut electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 110);

        const TIMEOUT: u64 = 120;

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account: Account = Account::new(config);
        sleep(Duration::from_millis(300));

        let recv_addr = account.new_recv_addr();
        let change_addr = account.new_change_addr();

        sleep(Duration::from_secs(1));

        // send to recv address
        let recv_txid = send_to_address(&bitcoind, &recv_addr, Amount::from_btc(0.1).unwrap());
        let recv_tx = bitcoind
            .client
            .get_raw_transaction(&recv_txid, None)
            .unwrap();

        generate(&bitcoind, 1);

        sleep(Duration::from_secs(1));
        dump_logs(&mut electrsd);

        // send to change address
        let change_txid = send_to_address(&bitcoind, &change_addr, Amount::from_btc(0.1).unwrap());
        let change_tx = bitcoind
            .client
            .get_raw_transaction(&change_txid, None)
            .unwrap();
        generate(&bitcoind, 1);

        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 2
            },
            TIMEOUT,
        );

        let coins = account.coins();
        let coins_height: BTreeMap<_, _> =
            coins.into_iter().map(|(c, e)| (c, e.height())).collect();

        // With the pending-claims queue and merkle verification in
        // place, both coins are confirmed at this point and should carry
        // a height.
        assert!(coins_height.iter().all(|(_, e)| e.is_some()));

        let height_before_reorg = get_block_height(&bitcoind);
        let h_before_reorg = get_block_hash(&bitcoind, height_before_reorg);

        sleep(Duration::from_secs(2));

        electrsd.clear_logs();
        log::warn!(" ------------------------------- reorg now ------------------------");
        reorg_chain(&bitcoind, 7);
        generate(&bitcoind, 2);
        dump_logs(&mut electrsd);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        // FIXME:
        // NOTE: here we likely hitting an `electrs` bug:
        // - we can see in the electrs logs that 2 status (None) updates are assumed sent
        //   from electrs end
        // - only 1 status update is received on our raw client TCP stream end

        log::warn!(" ------------------------------- rebroadcast recv ------------------------");
        let _ = bitcoind.client.send_raw_transaction(&recv_tx);
        generate(&bitcoind, 1);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        log::warn!(" ------------------------------- rebroadcast change ------------------------");
        let _ = bitcoind.client.send_raw_transaction(&change_tx);
        generate(&bitcoind, 1);
        sleep(Duration::from_secs(2));
        dump_logs(&mut electrsd);

        let new_h = get_block_hash(&bitcoind, height_before_reorg);
        assert_ne!(h_before_reorg, new_h);

        let coins = account.coins();
        // there is still 2 coins
        assert_eq!(coins.len(), 2);
    }

    #[cfg(feature = "test")]
    use bwk_tx::tx_builder::TxBuilder;

    #[cfg(feature = "test")]
    fn spend(
        account: &mut Account,
        builder: &mut TxBuilder,
        bitcoind: &BitcoinD,
        amount: u64,
    ) -> (bitcoin::Txid, u32) {
        let coins = account.spendable_coins().coins.into_values().collect();
        builder.new_template();
        builder.tx_template.inputs = coins;
        builder.dummy_external_output(amount);
        let mut psbt = builder.generate().unwrap();
        account.sign_psbt(&mut psbt);
        PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new()).unwrap();
        let tx = psbt.extract_tx_unchecked_fee_rate();
        let txid = bitcoind.client.send_raw_transaction(&tx).unwrap();
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        (txid, blocks)
    }

    fn receive(account: &mut Account, bitcoind: &BitcoinD, amount: u64) -> u32 {
        let recv_addr = account.new_recv_addr();
        send_to_address(bitcoind, &recv_addr, Amount::from_sat(amount));
        let blocks: u32 = random_range(2..15);
        generate(bitcoind, blocks);
        blocks
    }

    #[allow(unused)]
    fn sort_payments(payments: &Vec<Payment>) -> (usize, usize) {
        let mut recv = 0;
        let mut sent = 0;
        for p in payments {
            match p.payment_type {
                crate::coin_store::PaymentType::Receive => recv += 1,
                crate::coin_store::PaymentType::Send => sent += 1,
                crate::coin_store::PaymentType::ToSelf => {}
            }
        }
        (recv, sent)
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_list_payments() {
        // setup_logger();
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account = Account::new(config);
        sleep(Duration::from_millis(300));
        let mut builder = account.tx_builder();

        let blocks = receive(&mut account, &bitcoind, 200_000);
        wait_until_timeout(
            || {
                let coins = account.coins();
                coins.len() == 1
            },
            block_wait(blocks),
        );
        let (_, blocks) = spend(&mut account, &mut builder, &bitcoind, 100_000);
        wait_until_timeout(
            || {
                let payments = account.payment_history();
                payments.len() == 2
            },
            block_wait(blocks),
        );

        let payments = account.payment_history();
        assert_eq!(2, payments.len());
        let sorted = sort_payments(&payments);
        assert_eq!(sorted, (1, 1));

        // Every confirmed payment gets a block timestamp from the listener.
        wait_until_timeout(
            || {
                account
                    .payment_history()
                    .iter()
                    .filter(|p| p.height.is_some())
                    .all(|p| p.timestamp.is_some_and(|t| t > 0))
            },
            block_wait(5),
        );
        let confirmed: Vec<_> = account
            .payment_history()
            .into_iter()
            .filter(|p| p.height.is_some())
            .collect();
        assert!(!confirmed.is_empty(), "expected a confirmed payment");
        for p in &confirmed {
            assert!(
                p.timestamp.is_some_and(|t| t > 0),
                "confirmed payment {} should have a block timestamp",
                p.txid
            );
        }
    }

    #[cfg(feature = "test")]
    #[test]
    fn test_electrum_restart() {
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = 20;
        config.set_electrum_url(url);
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let mut account = Account::new(config);
        let notif = account.receiver().expect("receiver");
        sleep(Duration::from_millis(300));

        // Blocks until a notification matching `want` arrives (drain first so
        // the match is post-restart).
        let wait_notif =
            |notif: &mpsc::Receiver<Notification>, want: fn(&Notification) -> bool| -> bool {
                let deadline = std::time::Instant::now() + Duration::from_secs(15);
                while std::time::Instant::now() < deadline {
                    if let Ok(n) = notif.recv_timeout(Duration::from_millis(200)) {
                        if want(&n) {
                            return true;
                        }
                    }
                }
                false
            };
        let is_started =
            |n: &Notification| matches!(n, Notification::Electrum(TxListenerNotif::Started));
        let is_stopped =
            |n: &Notification| matches!(n, Notification::Electrum(TxListenerNotif::Stopped));

        // The listener works before any restart.
        let blocks = receive(&mut account, &bitcoind, 200_000);
        wait_until_timeout(|| account.coins().len() == 1, block_wait(blocks));

        // stop marks the account offline and the listener emits Stopped; a
        // following start restarts it in place (no panic, fresh Started) and the
        // statuses store handed back through the channel keeps the wallet tracked.
        while notif.try_recv().is_ok() {}
        account.stop_electrum();
        assert!(
            account.electrum_offline(),
            "stop_electrum did not mark offline"
        );
        assert!(
            wait_notif(&notif, is_stopped),
            "listener did not emit Stopped"
        );
        account.start_electrum();
        assert!(
            wait_notif(&notif, is_started),
            "listener did not restart on stop+start"
        );
        wait_until_timeout(|| !account.electrum_offline(), 15);
        let blocks = receive(&mut account, &bitcoind, 150_000);
        wait_until_timeout(|| account.coins().len() == 2, block_wait(blocks));

        // restart_electrum() (the in-place path) behaves the same.
        while notif.try_recv().is_ok() {}
        account.restart_electrum();
        assert!(
            wait_notif(&notif, is_started),
            "listener did not restart on restart_electrum"
        );
        let blocks = receive(&mut account, &bitcoind, 120_000);
        wait_until_timeout(|| account.coins().len() == 3, block_wait(blocks));
    }

    #[test]
    fn test_persist_payments() {
        use rand::random;

        // setup_logger();
        let (url, port, _electrsd, bitcoind) = bootstrap_electrs();
        generate(&bitcoind, 100);

        let look_ahead = 20;

        let dir = TempDir::new().unwrap();
        let mut path = dir.path().to_path_buf();
        path.push(".bwk");
        maybe_create_dir(&path);
        let path = path.parent().unwrap().to_path_buf();

        let mnemonic = Mnemonic::generate(12).unwrap();
        let mut config = Config::new(
            Some(mnemonic.to_string()),
            "account_dir".to_string(),
            bitcoin::Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            path,
            ".bwk".to_string(),
            true,
        )
        .unwrap();
        config.network = Network::Regtest;
        config.look_ahead = look_ahead;
        config.set_electrum_url(url.clone());
        config.set_electrum_port(port.to_string());
        config.set_mnemonic(mnemonic.to_string());
        let saved_config = config.clone();
        // Scoped so `builder` and `account` drop in reverse
        // declaration order at the closing brace, the tx_builder
        // holds Arc<Mutex<CoinStore>> clones that would otherwise
        // keep the backend (and its DirLock on the account dir)
        // alive past account's explicit drop.
        {
            let mut account = Account::new(config);
            sleep(Duration::from_millis(300));
            let mut builder = account.tx_builder();

            let mut prev_blocks = receive(&mut account, &bitcoind, 100_000_000);
            for _ in 0..15 {
                wait_until_timeout(
                    || !account.spendable_coins().coins.is_empty(),
                    block_wait(prev_blocks),
                );
                sleep(Duration::from_millis(1000));
                let coins = account.spendable_coins();
                let balance = coins
                    .coins
                    .into_iter()
                    .fold(0, |a, (_, c)| a + c.txout.value.to_sat());
                assert!(balance > 1_100_000);
                let pay: bool = random();
                if pay {
                    let blocks: u32 = random_range(1..5);
                    let addr = bitcoind
                        .client
                        .get_new_address(None, None)
                        .unwrap()
                        .assume_checked();
                    let amount = random_range(10_000..1_000_000);
                    // The wallet may not have synced a prior spend yet (electrum lag
                    // under CI load), so a freshly built tx can select an already
                    // spent coin (-25 bad-txns-inputs-missingorspent). Rebuild from
                    // the wallet's current coins and retry, letting sync catch up,
                    // until bitcoind accepts it.
                    let mut attempt = 0;
                    loop {
                        let mut psbt = builder.pay(amount, addr.clone(), 1000).unwrap();
                        account.sign_psbt(&mut psbt);
                        PsbtExt::finalize_mut(&mut psbt, &bitcoin::secp256k1::Secp256k1::new())
                            .unwrap();
                        let tx = psbt.extract_tx_unchecked_fee_rate();
                        match bitcoind.client.send_raw_transaction(&tx) {
                            Ok(_) => break,
                            Err(_) if attempt < 30 => {
                                attempt += 1;
                                sleep(Duration::from_millis(500));
                            }
                            Err(e) => {
                                panic!("send_raw_transaction failed after {attempt} retries: {e:?}")
                            }
                        }
                    }
                    generate(&bitcoind, blocks);
                    prev_blocks = blocks;
                } else {
                    prev_blocks = receive(&mut account, &bitcoind, random_range(10_000..1_000_000));
                }
            }
            // Wait for the actual target (1 initial receive + 15 loop
            // iterations = 16 payments) rather than `len() == 15` plus a
            // 3 s grace. Use an absolute 120 s budget here: after 15
            // iterations of generate-and-index, the listener thread can
            // be queued up well past `block_wait(prev_blocks)`'s 30 s
            // floor under CI / CPU pressure.
            wait_until_timeout(|| account.payment_history().len() >= 16, 120);
            let payments = account.payment_history();
            assert_eq!(payments.len(), 16);
        }

        let account: Account = Account::new(saved_config);
        sleep(Duration::from_millis(300));
        let payments = account.payment_history();
        assert_eq!(payments.len(), 16);
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_signer_exclusion {
    use super::*;
    use crate::config::{Config, CONFIG_FILENAME};
    use bip39::Mnemonic;
    use bwk_descriptor::descriptor::ScriptType;
    use bwk_persist::{FileConfigStore, PersistenceKind};
    use miniscript::bitcoin::{bip32::ChildNumber, Network};
    use temp_dir::TempDir;

    /// Recursively scan all files under `dir` and assert `needle` is not
    /// present in any of their bytes (text or binary).
    fn assert_needle_absent(dir: &std::path::Path, needle: &str) {
        let needle_bytes = needle.as_bytes();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(p) = stack.pop() {
            for entry in std::fs::read_dir(&p).expect("read_dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                let ft = entry.file_type().expect("file_type");
                if ft.is_dir() {
                    stack.push(path);
                } else if ft.is_file() {
                    let bytes = std::fs::read(&path).expect("read file");
                    let found = bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes);
                    assert!(
                        !found,
                        "needle {needle:?} found in on-disk file {}",
                        path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn sqlite_mode_keeps_mnemonic_off_disk() {
        let temp = TempDir::new().expect("tempdir");
        let unique = Mnemonic::generate(12).expect("mnemonic").to_string();

        let mut cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            true,
        )
        .expect("config");
        cfg.set_offline(true);
        cfg.persist_kind = PersistenceKind::Sqlite;

        // Wire a FileConfigStore against the account dir's config.json,
        // build the account, drive a config save + a label write to
        // exercise multiple persist paths. SQLite mode must not write
        // the mnemonic anywhere under the account dir.
        let account_dir = cfg.account_dir();
        let config_store: Arc<dyn ConfigStore<Config>> = Arc::new(FileConfigStore::<Config>::new(
            account_dir.join(CONFIG_FILENAME),
        ));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        account.label_store().lock().expect("poisoned").persist();
        drop(account);

        assert!(account_dir.exists(), "account dir created");
        assert_needle_absent(&account_dir, &unique);
    }

    #[test]
    fn json_mode_writes_mnemonic_to_config_json() {
        let temp = TempDir::new().expect("tempdir");
        let unique = Mnemonic::generate(12).expect("mnemonic").to_string();

        let cfg = Config::new(
            Some(unique.clone()),
            "alice".to_string(),
            Network::Regtest,
            ScriptType::Segwit(ChildNumber::from_hardened_idx(0).unwrap()),
            temp.path().to_path_buf(),
            "wallet".to_string(),
            true,
        )
        .expect("config")
        .with_persist_kind(PersistenceKind::Json);

        let account_dir = cfg.account_dir();
        let config_path = account_dir.join(CONFIG_FILENAME);
        let config_store: Arc<dyn ConfigStore<Config>> =
            Arc::new(FileConfigStore::<Config>::new(config_path.clone()));
        let account: Account = Account::with_config_store(cfg.clone(), config_store);
        account.persist_config();
        drop(account);

        let on_disk = std::fs::read_to_string(&config_path).expect("config.json");
        assert!(
            on_disk.contains(&unique),
            "mnemonic must appear in config.json under JSON mode (default)"
        );
    }
}
