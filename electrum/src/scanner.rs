//! Watching a descriptor on an Electrum server.
//!
//! [`ElectrumScanner`] owns everything a scan needs and nothing a wallet
//! adds: the stores, the validated header chain, the listener thread and the
//! notification channel it reports through. It knows how to derive addresses,
//! but not how to sign or how to build a transaction.
//!
//! `bwk::Account` wraps one of these and adds the wallet half (signers,
//! mnemonic, transaction building). A consumer that only needs coin state —
//! a daemon tracking its own descriptor, say — uses the scanner directly and
//! never pulls the wallet crate in.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use bwk_coin::{Coin, KeyChain};
use bwk_descriptor::derivator::SpkDerivator;
use bwk_persist::{PersistError, PersistenceBackend, Store};
use miniscript::{
    bitcoin::{self, OutPoint, Txid},
    Descriptor, DescriptorPublicKey,
};

use crate::{
    address_store::{AddressEntry, AddressStatus, AddressTip},
    client::{CoinRequest, CoinResponse},
    coin_state::CoinState,
    coin_store::{CoinEntry, CoinStore, CoinStoreSource, Payment, PaymentType},
    config::{ScannerConfig, Tip},
    header_store::HeaderStore,
    history::{AccountHistory, TxContribution},
    label_store::{LabelKey, LabelStore},
    listener::listen_txs,
    notification::{Error, Notification, OpenError, TxListenerError, TxListenerNotif},
    profile::{DefaultBackend, OpenScanFromBackend, RamProfile, ScanProfile, ScanStores},
    tx_store::{TxEntry, TxStore},
};

/// Called whenever the scanner mutates its own config (endpoint, look-ahead,
/// connection state). The wallet wrapper uses it to fold the change back into
/// its own config and persist it; standalone scanners leave it unset.
pub type ConfigHook = Arc<dyn Fn(&ScannerConfig) + Send + Sync>;

/// Keychain discriminants stored in the statuses value `(status, keychain,
/// index)`, shared by the writer (`handle_address_tip`) and the reader
/// (`max_tip_from_statuses`).
pub(crate) const STATUS_KEYCHAIN_RECEIVE: u32 = 0;
pub(crate) const STATUS_KEYCHAIN_CHANGE: u32 = 1;

/// Largest receive and change index recorded in the statuses store. Used as a
/// floor for the restored tip. The statuses store covers the whole watch window
/// (generated tip plus look-ahead), so the caller subtracts the look-ahead to
/// get back to the generated tip.
fn max_tip_from_statuses<S>(statuses: &S) -> (u32, u32)
where
    S: Store<Value = (Option<String>, u32, u32)>,
{
    let mut max_recv = 0;
    let mut max_change = 0;
    match statuses.values() {
        Ok(values) => {
            for (_, keychain, index) in values {
                match keychain {
                    STATUS_KEYCHAIN_RECEIVE => max_recv = max_recv.max(index),
                    STATUS_KEYCHAIN_CHANGE => max_change = max_change.max(index),
                    _ => {}
                }
            }
        }
        Err(e) => log::error!("max_tip_from_statuses(): failed to read statuses values: {e}"),
    }
    (max_recv, max_change)
}

/// Where a starting listener gets its statuses store from.
enum StatusesSource<P: ScanProfile> {
    /// Held directly: a fresh scanner, or one whose listener has stopped.
    Direct(P::StatusesStore),
    /// Coming back from the previous listener as it winds down.
    Handback(mpsc::Receiver<P::StatusesStore>),
}

pub struct ElectrumScanner<P: ScanProfile = RamProfile<DefaultBackend>> {
    coin_store: Arc<Mutex<CoinStore<P>>>,
    label_store: Arc<Mutex<LabelStore<P>>>,
    receiver: Option<mpsc::Receiver<Notification>>,
    sender: mpsc::Sender<Notification>,
    tx_listener: Option<JoinHandle<()>>,
    config: ScannerConfig,
    /// Notified on every config mutation; see [`ConfigHook`].
    on_config_change: Option<ConfigHook>,
    electrum_stop: Option<Arc<AtomicBool>>,
    /// Holds the statuses store while no listener owns it (fresh or idle
    /// scanner). `take()`-n in `start_listen_txs` for the `Direct` source; once
    /// a listener has run, the store travels through `statuses_rx` instead.
    statuses_store: Option<P::StatusesStore>,
    /// Handback channel of the current or last listener. A stopping listener
    /// sends its statuses store here, so the next start reclaims it without the
    /// caller blocking on a thread join.
    statuses_rx: Option<mpsc::Receiver<P::StatusesStore>>,
    /// Validated header chain. Shared across scanners; the scanner reads
    /// `block_hash` / `tip` on every CTA to promote claims.
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    /// Live offline flag, shared with the Electrum listener thread. The
    /// listener clears it on `Connected`; `stop_electrum` sets it. Single
    /// runtime source for `electrum_offline()` and the persisted view.
    offline: Arc<AtomicBool>,
    /// Reopen the statuses store from the backend, the fallback when a panicked
    /// listener cannot hand its store back. Cloned into the listener thread,
    /// which resolves the store itself. `None` for stores-only (test)
    /// construction with no backend.
    reopen_statuses: Option<Arc<dyn Fn() -> Result<P::StatusesStore, PersistError> + Send + Sync>>,
}

impl<P: ScanProfile> std::fmt::Debug for ElectrumScanner<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumScanner").finish()
    }
}

impl<P: ScanProfile> Drop for ElectrumScanner<P> {
    fn drop(&mut self) {
        // Signal the Electrum listener thread to stop, then block until
        // it has actually exited. The listener holds Arc clones of the
        // persistence backend; without the join, the DirLock on the
        // account directory would stay acquired past Drop and refuse a
        // subsequent reopen.
        if let Some(stop) = self.electrum_stop.as_mut() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(handle) = self.tx_listener.take() {
            let _ = handle.join();
        }
    }
}

impl<P: OpenScanFromBackend> ElectrumScanner<P> {
    /// A scanner watching `config`'s descriptor, opening its stores against
    /// whatever backend the config selects and building its own
    /// [`HeaderStore`].
    ///
    /// Returns [`OpenError`] if the account name is empty, the backend cannot
    /// be built (e.g. the account directory is already locked by another
    /// instance), or a stored blob fails to decode.
    pub fn try_new(config: ScannerConfig) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_with_header_store(config, header_store)
    }

    /// Like [`ElectrumScanner::try_new`] but sharing an existing
    /// [`HeaderStore`] handle instead of building one.
    pub fn try_new_with_header_store(
        config: ScannerConfig,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
    ) -> Result<Self, OpenError> {
        let (sender, receiver) = mpsc::channel();
        let mut scanner = Self::try_new_inner(config, header_store, sender, None)?;
        scanner.receiver = Some(receiver);
        Ok(scanner)
    }

    /// Like [`ElectrumScanner::try_new`] but with an external notification
    /// sender.
    pub fn try_new_with_sender(
        config: ScannerConfig,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        let header_store = Self::build_header_store(&config)?;
        Self::try_new_inner(config, header_store, sender, None)
    }

    /// Like [`ElectrumScanner::try_new_with_sender`] but sharing an existing
    /// [`HeaderStore`] handle instead of building one. Used to fan a shared
    /// chain across several scanners routed through the same notification
    /// channel.
    pub fn try_new_with_sender_and_header_store(
        config: ScannerConfig,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
    ) -> Result<Self, OpenError> {
        Self::try_new_inner(config, header_store, sender, None)
    }

    /// Infallible test helper. Not exposed to consumers: production callers
    /// use [`ElectrumScanner::try_new`] so a bad/locked store surfaces as an
    /// error instead of aborting.
    #[cfg(any(test, feature = "test"))]
    pub fn new(config: ScannerConfig) -> Self {
        Self::try_new(config).expect("ElectrumScanner::new: failed to open stores")
    }

    /// Build this scanner's own [`HeaderStore`]: online (via
    /// [`HeaderStore::start`]) when `config` carries an Electrum endpoint
    /// and is not offline, file-backed/in-memory otherwise. Headers are
    /// always binary-backed through [`bwk_persist::HeaderBackend`] at
    /// [`ScannerConfig::headers_path`], independent of the account's own
    /// persistence kind.
    ///
    /// Returns [`OpenError::HeaderStore`] if a configured (non-offline)
    /// endpoint cannot be reached: header-sync progress gates `Verified`
    /// state, so a dead store must fail loud rather than open silently
    /// degraded.
    pub fn build_header_store(
        config: &ScannerConfig,
    ) -> Result<Arc<HeaderStore<P::HeaderStore>>, OpenError> {
        let path = config.persist.then(|| config.headers_path());
        let (url, port) = if config.offline() {
            (None, None)
        } else {
            (config.electrum_url.clone(), config.electrum_port)
        };
        Ok(HeaderStore::start_or_open(
            url,
            port,
            config.network,
            path,
            None,
            config.validate_certificate(),
        )?)
    }

    /// Open the stores from the config's backend and build a scanner around
    /// them. `on_config_change` is invoked on every config mutation, starting
    /// with the one the listener makes when it connects.
    pub fn try_new_inner(
        config: ScannerConfig,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        on_config_change: Option<ConfigHook>,
    ) -> Result<Self, OpenError> {
        if config.account.is_empty() {
            return Err(OpenError::EmptyAccount);
        }
        let backend: Arc<dyn PersistenceBackend> = config.build_backend()?;
        let reopen_backend = backend.clone();
        let reopen_statuses: Arc<dyn Fn() -> Result<P::StatusesStore, PersistError> + Send + Sync> =
            Arc::new(move || P::open_statuses(reopen_backend.clone()));
        let stores = P::open(backend)?;
        Ok(Self::from_stores(
            config,
            header_store,
            sender,
            on_config_change,
            stores,
            Some(reopen_statuses),
        ))
    }

    /// Restart the Electrum listener in place, keeping the scanner and all its
    /// channels alive. On a normal reconnect the offline flag is driven by the
    /// listener, which clears it once connected; with no endpoint configured
    /// nothing starts and `start_electrum` marks the scanner offline.
    pub fn restart_electrum(&mut self) {
        self.stop_listener();
        self.start_electrum();
        // The previous connection died; the shared HeaderStore worker still
        // holds the same dead socket, so reconnect it too or `Verified`
        // promotions would stall.
        if let (Some(url), Some(port)) =
            (self.config.electrum_url.clone(), self.config.electrum_port)
        {
            if let Err(e) = self.header_store.restart(url, port) {
                log::error!("restart_electrum(): header store restart failed: {e}");
                let _ = self
                    .sender
                    .send(Notification::Error(Error::HeaderStoreRestart));
            }
        }
    }
}

impl<P: ScanProfile> ElectrumScanner<P> {
    /// Build a scanner around already-open stores. Starts the listener unless
    /// the config says offline.
    pub fn from_stores(
        config: ScannerConfig,
        header_store: Arc<HeaderStore<P::HeaderStore>>,
        sender: mpsc::Sender<Notification>,
        on_config_change: Option<ConfigHook>,
        stores: ScanStores<P>,
        reopen_statuses: Option<
            Arc<dyn Fn() -> Result<P::StatusesStore, PersistError> + Send + Sync>,
        >,
    ) -> Self {
        let tx_store = TxStore::from_store(stores.tx);
        let label_store = Arc::new(Mutex::new(LabelStore::from_store(stores.label)));
        let account_store = Arc::new(Mutex::new(stores.account));
        // Tip is loaded from the account_store.
        let tip = {
            let store = account_store.lock().expect("poisoned");
            Tip::from_account_store(&*store)
        };
        let Tip { receive, change } = tip;
        // Floor the tip with the highest index recorded in statuses, so the
        // regenerated watch window covers every persisted subscribed script even
        // when the tip rows are missing or stale. The statuses store spans the
        // whole watch window (generated tip plus look-ahead), so drop the
        // look-ahead to recover the generated tip. Without this the generated tip
        // would climb by one look-ahead window on every reopen.
        let (stat_recv, stat_change) = max_tip_from_statuses(&stores.statuses);
        let look_ahead = config.look_ahead;
        let receive = receive.max(stat_recv.saturating_sub(look_ahead));
        let change = change.max(stat_change.saturating_sub(look_ahead));
        let coin_store = Arc::new(Mutex::new(CoinStore::new(
            config.network,
            config.descriptor.clone(),
            sender.clone(),
            receive,
            change,
            config.look_ahead,
            tx_store,
            label_store.clone(),
            config.clone(),
            account_store.clone(),
        )));
        coin_store.lock().expect("poisoned").generate();
        let _ = account_store; // owned by CoinStore→AddressStore; not stored here
        let offline = Arc::new(AtomicBool::new(config.offline()));
        let mut scanner = ElectrumScanner {
            coin_store,
            label_store,
            tx_listener: None,
            electrum_stop: None,
            receiver: None,
            sender,
            config,
            on_config_change,
            statuses_store: Some(stores.statuses),
            statuses_rx: None,
            header_store,
            offline,
            reopen_statuses,
        };
        if !scanner.offline.load(Ordering::Relaxed) {
            scanner.start_electrum();
        }
        scanner
    }

    /// Attach the notification receiver a constructor built alongside the
    /// scanner's sender.
    pub fn set_receiver(&mut self, receiver: mpsc::Receiver<Notification>) {
        self.receiver = Some(receiver);
    }

    /// Replace the hook notified on config changes; see [`ConfigHook`].
    pub fn set_config_hook(&mut self, hook: ConfigHook) {
        self.on_config_change = Some(hook);
    }

    /// Report the current config, with the live offline flag folded in, to
    /// whatever hook the wrapper installed.
    fn publish_config(&self) {
        if let Some(hook) = self.on_config_change.as_ref() {
            let mut cfg = self.config.clone();
            cfg.set_offline(self.offline.load(Ordering::Relaxed));
            hook(&cfg);
        }
    }

    pub fn coin_store(&self) -> &Arc<Mutex<CoinStore<P>>> {
        &self.coin_store
    }

    pub fn label_store(&self) -> &Arc<Mutex<LabelStore<P>>> {
        &self.label_store
    }

    pub fn network(&self) -> bitcoin::Network {
        self.config.network()
    }

    pub fn name(&self) -> String {
        self.config.account.clone()
    }

    pub fn descriptor_str(&self) -> String {
        self.config.descriptor.to_string()
    }

    pub fn descriptor(&self) -> Descriptor<DescriptorPublicKey> {
        self.config.descriptor.clone()
    }

    pub fn receiver(&mut self) -> Option<mpsc::Receiver<Notification>> {
        self.receiver.take()
    }

    /// The scanner's own config, with the live offline flag folded in.
    pub fn config(&self) -> ScannerConfig {
        let mut cfg = self.config.clone();
        cfg.set_offline(self.offline.load(Ordering::Relaxed));
        cfg
    }

    pub fn coin_source(&self) -> CoinStoreSource<P> {
        CoinStoreSource::<P>::new(self.coin_store.clone())
    }

    /// Total spendable balance and the payment history it was derived from.
    pub fn balance(&self) -> (u64, Vec<Payment>) {
        let payments = self.payment_history();
        let total = payments.iter().fold(0i128, |a, b| match b.payment_type {
            PaymentType::Receive => a + (b.amount as i128),
            // A send and a self-send both reduce the balance by their outflow
            // (a self-send keeps the change but still pays the fee).
            PaymentType::Send | PaymentType::ToSelf => a - (b.amount as i128),
        });
        // A negative total means the history is inconsistent (e.g. a send whose
        // funding receive was dropped). Report zero loudly rather than wrapping
        // the cast into a huge balance.
        let balance = if total < 0 {
            log::error!("balance(): negative running total {total}, reporting 0");
            0
        } else {
            total as u64
        };
        (balance, payments)
    }

    /// Every coin the scanner tracks, keyed by outpoint.
    pub fn coins(&self) -> BTreeMap<OutPoint, CoinEntry> {
        self.coin_store.lock().expect("poisoned").coins()
    }

    /// The coin matching `outpoint`, if tracked.
    pub fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .get(outpoint)
            .map(|e| e.coin)
    }

    pub fn spendable_coins(&self) -> CoinState {
        self.coin_store.lock().expect("poisoned").spendable_coins()
    }

    pub fn tx_history(&self) -> Vec<TxEntry> {
        self.coin_store.lock().expect("poisoned").tx_history()
    }

    pub fn payment_history(&self) -> Vec<Payment> {
        crate::history::aggregate_payments([self as &dyn AccountHistory])
    }

    /// Record a just-broadcast spend as unconfirmed: owned inputs flip to
    /// `Spent` and any owned change is surfaced immediately, before the listener
    /// or a scan sees the tx on-chain.
    pub fn record_unconfirmed_spend(&self, tx: &bitcoin::Transaction) {
        self.coin_store
            .lock()
            .expect("poisoned")
            .record_unconfirmed_tx(tx.clone());
    }

    /// Label the coin at `outpoint`, or clear its label when `label` is empty.
    pub fn update_coin_label(&self, outpoint: String, label: String) {
        if let Ok(outpoint) = bitcoin::OutPoint::from_str(&outpoint) {
            if !label.is_empty() {
                self.label_store
                    .lock()
                    .expect("poisoned")
                    .edit(LabelKey::OutPoint(outpoint), Some(label));
            } else {
                self.label_store
                    .lock()
                    .expect("poisoned")
                    .remove(LabelKey::OutPoint(outpoint));
            }
        }
        if let Ok(mut store) = self.coin_store.try_lock() {
            store.generate();
        }
    }

    /// Derive and start watching the next receive address.
    pub fn new_addr(&mut self) -> AddressEntry {
        let addr = self.new_recv_addr();
        let index = self.coin_store.lock().expect("poisoned").recv_tip();
        AddressEntry {
            status: AddressStatus::NotUsed,
            address: addr.as_unchecked().clone(),
            account: KeyChain::Receive,
            index,
            funding_txids: BTreeSet::new(),
            spending_txids: BTreeSet::new(),
        }
    }

    pub fn new_recv_addr(&mut self) -> bitcoin::Address {
        self.coin_store.lock().expect("poisoned").new_recv_addr()
    }

    pub fn new_change_addr(&mut self) -> bitcoin::Address {
        self.coin_store.lock().expect("poisoned").new_change_addr()
    }

    pub fn derivator(&self) -> SpkDerivator {
        self.coin_store.lock().expect("poisoned").derivator()
    }

    pub fn recv_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .receive_at(index)
    }

    pub fn change_at(&self, index: u32) -> bitcoin::Address {
        self.coin_store
            .lock()
            .expect("poisoned")
            .derivator_ref()
            .change_at(index)
    }

    pub fn recv_watch_tip(&self) -> u32 {
        self.coin_store.lock().expect("poisoned").recv_watch_tip()
    }

    pub fn change_watch_tip(&self) -> u32 {
        self.coin_store.lock().expect("poisoned").change_watch_tip()
    }

    pub fn generated_addresses(
        &self,
    ) -> (
        Vec<AddressEntry>, /* receive */
        Vec<AddressEntry>, /* change*/
    ) {
        self.coin_store
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .get_generated_addresses()
    }

    /// Snapshot of every address entry the scanner currently tracks
    /// (receive + change, all derivation indices). Cloned, so the caller
    /// doesn't hold any lock.
    pub fn address_entries(&self) -> Vec<AddressEntry> {
        self.coin_store
            .lock()
            .expect("poisoned")
            .address_store()
            .lock()
            .expect("poisoned")
            .entries()
    }

    /// Re-generate coin_store from tx_store
    pub fn generate_coins(&mut self) {
        self.coin_store.lock().expect("poisoned").generate();
    }

    pub fn electrum_url(&self) -> String {
        self.config.electrum_url()
    }

    pub fn electrum_port(&self) -> String {
        self.config.electrum_port()
    }

    pub fn look_ahead(&self) -> String {
        self.config.look_ahead()
    }

    /// Spawn the listener thread against `addr:port`, returning the address-tip
    /// channel it watches and the flag that stops it.
    fn start_listen_txs(
        &mut self,
        addr: String,
        port: u16,
    ) -> (mpsc::Sender<AddressTip>, Arc<AtomicBool>) {
        log::debug!("ElectrumScanner::start_listen_txs()");
        let (sender, address_tip) = mpsc::channel();
        let coin_store = self.coin_store.clone();
        let notification = self.sender.clone();
        let derivator = self.derivator();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_request = stop.clone();
        // A fresh scanner still holds the store directly; once a listener has
        // run, the store returns through the previous listener's handback
        // channel. Resolving it inside the thread keeps the caller unblocked.
        let source = match (self.statuses_store.take(), self.statuses_rx.take()) {
            (Some(store), _) => StatusesSource::<P>::Direct(store),
            (None, Some(rx)) => StatusesSource::Handback(rx),
            (None, None) => {
                // Unreachable in normal flow (one of the two always holds); route
                // it through the in-thread unavailable path rather than panic.
                let (_, rx) = mpsc::channel::<P::StatusesStore>();
                StatusesSource::Handback(rx)
            }
        };
        let (handback_tx, handback_rx) = mpsc::channel();
        self.statuses_rx = Some(handback_rx);
        let header_store = self.header_store.clone();
        // Register a fresh CTA receiver and hand it straight to the
        // listener thread; the scanner never needs to hold it.
        let chain_rx = self.header_store.register();
        // Shared with the thread so it can mark the scanner online once the
        // connection is up, instead of the caller claiming it optimistically.
        let offline = self.offline.clone();
        let validate_certificate = self.config.validate_certificate();
        let on_config_change = self.on_config_change.clone();
        let config = self.config.clone();
        // Fallback for a panicked previous listener that could not hand its
        // store back: the thread reopens it from disk rather than giving up.
        let reopen_statuses = self.reopen_statuses.clone();

        let poller = thread::spawn(move || {
            let statuses_store = match source {
                StatusesSource::Direct(store) => store,
                StatusesSource::Handback(rx) => match rx.recv() {
                    Ok(store) => store,
                    Err(_) => match reopen_statuses.as_ref().map(|reopen| reopen()) {
                        Some(Ok(store)) => store,
                        other => {
                            if let Some(Err(e)) = other {
                                log::error!("start_listen_txs(): reopen statuses failed: {e}");
                            }
                            log::error!(
                                "start_listen_txs(): statuses store unavailable, listener not started"
                            );
                            let _ = notification.send(
                                TxListenerNotif::Error(TxListenerError::StatusesUnavailable).into(),
                            );
                            return;
                        }
                    },
                },
            };
            let client = match crate::client::Client::new(&addr, port, validate_certificate) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("start_listen_txs(): fail to create electrum client {e}");
                    let _ = notification.send(TxListenerNotif::Error(e.into()).into());
                    let _ = handback_tx.send(statuses_store);
                    return;
                }
            };

            let addr = format!("{addr}:{port}");
            let _ = notification.send(TxListenerNotif::Connected(addr).into());
            offline.store(false, Ordering::Relaxed);
            if let Some(hook) = on_config_change.as_ref() {
                let mut cfg = config;
                cfg.set_offline(false);
                hook(&cfg);
            }

            let (request, response) = client.listen_txs::<CoinRequest, CoinResponse>();

            let statuses_store = listen_txs(
                coin_store,
                derivator,
                notification,
                address_tip,
                stop_request,
                request,
                response,
                statuses_store,
                header_store,
                chain_rx,
            );
            let _ = handback_tx.send(statuses_store);
        });
        self.tx_listener = Some(poller);
        (sender, stop)
    }

    /// Set the Electrum endpoint and report the change to the config hook.
    pub fn set_electrum(&mut self, url: String, port: String) {
        if let Ok(port) = port.parse::<u16>() {
            self.config.electrum_url = Some(url);
            self.config.electrum_port = Some(port);
            self.publish_config();
        } else {
            self.sender
                .send(Notification::InvalidElectrumConfig)
                .expect("cannot fail");
        }
    }

    /// Set the Electrum endpoint without reporting it to the config hook.
    pub fn set_electrum_config(&mut self, url: Option<String>, port: Option<u16>) {
        self.config.electrum_url = url;
        self.config.electrum_port = port;
    }

    /// Start the Electrum listener.
    pub fn start_electrum(&mut self) {
        // A listener that already finished (e.g. failed to connect at startup)
        // still occupies `tx_listener`; reclaim it so this retry can restart.
        if self.tx_listener.as_ref().is_some_and(|h| h.is_finished()) {
            self.stop_listener();
        }
        match (self.config.electrum_url.clone(), self.config.electrum_port) {
            (Some(addr), Some(port)) if self.tx_listener.is_none() => {
                let (tx_listener, electrum_stop) = self.start_listen_txs(addr, port);
                self.coin_store.lock().expect("poisoned").init(tx_listener);
                self.electrum_stop = Some(electrum_stop);
            }
            (None, _) | (_, None) => {
                // No endpoint to connect to: nothing can listen, so report
                // offline honestly instead of leaving a stale online flag.
                self.offline.store(true, Ordering::Relaxed);
                self.publish_config();
            }
            _ => {}
        }
    }

    /// Signal the listener to stop and detach it, without blocking. The
    /// listener winds down on its own and hands its statuses store back through
    /// `statuses_rx`, which the next start reclaims. Mechanical only: leaves the
    /// offline flag and published config untouched.
    fn stop_listener(&mut self) {
        if let Some(stop) = self.electrum_stop.as_mut() {
            stop.store(true, Ordering::Relaxed);
        }
        self.electrum_stop = None;
        self.tx_listener = None;
    }

    /// Stop the Electrum listener and mark the scanner offline.
    pub fn stop_electrum(&mut self) {
        self.stop_listener();
        self.offline.store(true, Ordering::Relaxed);
        self.publish_config();
    }

    pub fn electrum_offline(&self) -> bool {
        self.offline.load(Ordering::Relaxed)
    }

    /// The scanner's [`HeaderStore`] handle. Test-only: used to assert store
    /// identity (`Arc::ptr_eq`) across scanners sharing one.
    #[cfg(any(test, feature = "test"))]
    pub fn header_store(&self) -> &Arc<HeaderStore<P::HeaderStore>> {
        &self.header_store
    }

    /// Set the look-ahead window and report the change to the config hook.
    pub fn set_look_ahead(&mut self, look_ahead: String) {
        if let Ok(la) = look_ahead.parse::<u32>() {
            self.config.look_ahead = la;
            self.publish_config();
        } else {
            self.sender
                .send(Notification::InvalidLookAhead)
                .expect("cannot fail");
        }
    }
}

impl<P: ScanProfile> AccountHistory for ElectrumScanner<P> {
    fn tx_contributions(&self) -> BTreeMap<Txid, TxContribution> {
        let mut map = BTreeMap::new();
        // Read tx history (which locks coin_store) before taking the label
        // lock. On the listener thread CoinStore::generate holds coin_store and
        // then locks label_store; taking the two in the opposite order here
        // would deadlock the two threads.
        let history = self.tx_history();
        let labels = self.label_store.lock().expect("poisoned");
        for entry in history {
            let txid = entry.txid();
            let owned_in = entry
                .inputs
                .values()
                .filter(|m| m.owned)
                .map(|m| {
                    m.value.unwrap_or_else(|| {
                        // populate_tx_metadata guarantees an owned input carries
                        // its value; a missing one is a broken invariant.
                        log::error!("tx_contributions: owned input without value in tx {txid}");
                        0
                    })
                })
                .sum();
            let mut owned_out = 0u64;
            let mut owned_vouts = BTreeSet::new();
            for (idx, meta) in entry.outputs.iter() {
                if meta.owned {
                    if let Some(txout) = entry.tx().output.get(*idx) {
                        owned_out += txout.value.to_sat();
                        owned_vouts.insert(*idx as u32);
                    }
                }
            }
            // The tx label if set, else a label on any owned output's coin.
            let label = labels.transaction(txid).or_else(|| {
                owned_vouts
                    .iter()
                    .find_map(|vout| labels.outpoint(OutPoint::new(txid, *vout)))
            });
            map.insert(
                txid,
                TxContribution {
                    owned_in,
                    owned_out,
                    owned_vouts,
                    height: entry.height(),
                    timestamp: entry.timestamp(),
                    label,
                    tx: Some(entry.tx().clone()),
                },
            );
        }
        map
    }
}
