//! The Electrum listener loop.
//!
//! Runs on the thread [`ElectrumScanner::start_electrum`](crate::scanner::ElectrumScanner::start_electrum)
//! spawns: subscribes to the watched scripts, pulls history and transactions,
//! verifies merkle proofs against the validated header chain and folds the
//! result into the coin store.

use std::{
    collections::BTreeMap,
    ops::ControlFlow,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, MutexGuard,
    },
};

use bwk_backoff::Backoff;
use bwk_descriptor::derivator::SpkDerivator;
use bwk_persist::Store;
use miniscript::bitcoin::{self, BlockHash, ScriptBuf, TxMerkleNode, Txid};

use crate::{
    address_store::AddressTip,
    client::{CoinRequest, CoinResponse},
    coin_store::{ChainUpdateOutcome, ClaimAt, CoinStore},
    header_store::HeaderStore,
    notification::{Notification, TxListenerError, TxListenerNotif, ValidationFailure},
    profile::ScanProfile,
    scanner::{STATUS_KEYCHAIN_CHANGE, STATUS_KEYCHAIN_RECEIVE},
    tx_store::Inclusion,
};

// On a dead channel the listener bails out and hands `$statuses` back to the
// caller (so a later restart can reuse it), mirroring the normal return paths.
macro_rules! send_notif {
    ($notification:expr, $request:expr, $statuses:expr, $msg:expr) => {
        let res = $notification.send($msg.into());
        if res.is_err() {
            // stop detached client
            let _ = $request.send(CoinRequest::Stop);
            return $statuses;
        }
    };
}

macro_rules! send_electrum {
    ($request:expr, $notification:expr, $statuses:expr, $msg:expr) => {
        if $request.send($msg).is_err() {
            send_notif!($notification, $request, $statuses, TxListenerNotif::Stopped);
            return $statuses;
        }
    };
}

/// Listens for transactions on the specified address and port.
///
/// # Arguments
///
/// * `addr` - The address to listen on.
/// * `port` - The port to listen on.
/// * `coin_store` - The coin store to update with transaction data.
/// * `signer` - The signer for the account.
/// * `notification` - The sender for notifications.
/// * `address_tip` - The receiver for address tips.
/// * `stop_request` - The stop flag for the listener.
#[allow(clippy::too_many_arguments)]
pub fn listen_txs<P>(
    coin_store: Arc<Mutex<CoinStore<P>>>,
    derivator: SpkDerivator,
    notification: mpsc::Sender<Notification>,
    address_tip: mpsc::Receiver<AddressTip>,
    stop_request: Arc<AtomicBool>,
    request: mpsc::Sender<CoinRequest>,
    response: mpsc::Receiver<CoinResponse>,
    mut statuses: P::StatusesStore,
    header_store: Arc<HeaderStore<P::HeaderStore>>,
    chain_rx: mpsc::Receiver<()>,
) -> P::StatusesStore
where
    P: ScanProfile,
{
    log::info!("listen_txs(): started");
    send_notif!(notification, request, statuses, TxListenerNotif::Started);

    requeue_confirmed_unverified(&coin_store, &request);

    let initial_keys: Vec<ScriptBuf> = match statuses.keys() {
        Ok(it) => it.collect(),
        Err(e) => {
            log::error!("listen_txs(): statuses keys: {e}");
            Vec::new()
        }
    };
    if !initial_keys.is_empty() {
        send_electrum!(
            request,
            notification,
            statuses,
            CoinRequest::Subscribe(initial_keys)
        );
    }

    refresh_unconfirmed_history(&coin_store, &request);
    // Stamp any already-confirmed entries loaded from disk (e.g. a quiet wallet
    // that gets no fresh history traffic) from the validated header chain.
    stamp_confirmation_times(&coin_store, &header_store);

    let mut backoff = Backoff::new_ms(20);
    loop {
        // stop request from consumer side
        if stop_request.load(Ordering::Relaxed) {
            send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
            let _ = request.send(CoinRequest::Stop);
            return statuses;
        }

        let mut received = false;

        // listen for AddressTip update
        match address_tip.try_recv() {
            Ok(tip) => {
                log::debug!("listen_txs() receive {tip:?}");
                received = true;
                if handle_address_tip::<P>(tip, &derivator, &mut statuses, &request, &notification)
                    .is_break()
                {
                    return statuses;
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    log::error!("listen_txs(): address store disconnected");
                    send_notif!(
                        notification,
                        request,
                        statuses,
                        TxListenerNotif::Error(TxListenerError::AddressStoreDisconnected)
                    );
                    // FIXME: what should we do there?
                    // it's AddressStore being dropped, but she should keep upating
                    // the actual spk set even if it cannot grow anymore
                }
            },
        }

        // listen for response
        match response.try_recv() {
            Ok(rsp) => {
                log::debug!("listen_txs() receive {}", rsp.summary());
                received = true;
                match rsp {
                    CoinResponse::Status(elct_status) => {
                        if handle_status_response(
                            elct_status,
                            &mut statuses,
                            &coin_store,
                            &request,
                            &notification,
                        )
                        .is_break()
                        {
                            return statuses;
                        }
                    }
                    CoinResponse::History(map) => {
                        if handle_history_response_msg(
                            map,
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                        )
                        .is_break()
                        {
                            return statuses;
                        }
                        // Newly confirmed entries can now be stamped from the chain.
                        stamp_confirmation_times(&coin_store, &header_store);
                    }
                    CoinResponse::Txs(txs) => {
                        handle_txs_response_msg(
                            txs,
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                        );
                        // Tx bodies just completed newly confirmed entries; stamp them.
                        stamp_confirmation_times(&coin_store, &header_store);
                    }
                    CoinResponse::TxMerkle {
                        txid,
                        height,
                        branch,
                        pos,
                    } => {
                        handle_tx_merkle(
                            &coin_store,
                            &header_store,
                            &request,
                            &notification,
                            txid,
                            height,
                            branch,
                            pos,
                        );
                    }
                    CoinResponse::Stopped => {
                        send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                        let _ = request.send(CoinRequest::Stop);
                        return statuses;
                    }
                    CoinResponse::Error(e) => {
                        send_notif!(
                            notification,
                            request,
                            statuses,
                            TxListenerNotif::Error(e.into())
                        );
                    }
                }
            }
            Err(e) => match e {
                mpsc::TryRecvError::Empty => {}
                mpsc::TryRecvError::Disconnected => {
                    // NOTE: here the electrum client is dropped, we cannot continue
                    log::error!("listen_txs() electrum client stopped unexpectedly");
                    send_notif!(notification, request, statuses, TxListenerNotif::Stopped);
                    let _ = request.send(CoinRequest::Stop);
                    return statuses;
                }
            },
        }

        // Drain the HeaderStore CTA receiver. Multiple () are coalesced
        // into a single on_chain_update pass.
        let mut chain_tick = false;
        loop {
            match chain_rx.try_recv() {
                Ok(()) => {
                    chain_tick = true;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // HeaderStore was dropped. Stop draining; the
                    // Account itself still owns its Arc, so this only
                    // fires once the public Account is gone.
                    break;
                }
            }
        }
        if chain_tick {
            received = true;
            on_chain_update(&coin_store, &header_store, &request, &notification);
            // Promotions may have just given entries a height whose header has
            // now landed; stamp their confirmation time from the chain.
            stamp_confirmation_times(&coin_store, &header_store);
        }

        if received {
            continue;
        }
        backoff.snooze();
    }
}

fn flush_statuses<S: Store>(statuses: &mut S) {
    if let Err(e) = statuses.flush() {
        log::error!("listen_txs(): statuses flush: {e}");
    }
}

/// Replicate the `send_electrum!`/`send_notif!` failure path: tell the consumer
/// the listener stopped, and if even that fails, ask the client to stop. Returns
/// `Break` so the caller can end the listener thread.
fn signal_stopped(
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    if notification.send(TxListenerNotif::Stopped.into()).is_err() {
        let _ = request.send(CoinRequest::Stop);
    }
    ControlFlow::Break(())
}

/// Gate every claim-promotion pass on header validation: `true` when the
/// store is validated, otherwise notify `ValidationFailed(HeaderStore(_))`
/// (when the store rejected its own replay) and return `false` so the
/// caller refuses to promote against an unvalidated header.
fn header_store_ready<P: ScanProfile>(
    header_store: &HeaderStore<P::HeaderStore>,
    notification: &mpsc::Sender<Notification>,
) -> bool {
    if header_store.is_validated() {
        return true;
    }
    if let Some(reason) = header_store.validation_failed_reason() {
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::HeaderStore(reason),
        ));
    }
    false
}

/// Apply a resolved [`ChainUpdateOutcome`]: persist and regenerate when it
/// changed state, release the coin-store lock, dispatch the queued merkle
/// fetches, and notify `HeaderStoreUpdated` on a change.
fn apply_chain_update<P: ScanProfile>(
    mut store: MutexGuard<'_, CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    outcome: ChainUpdateOutcome,
) {
    if outcome.changed {
        store.tx_store_mut().persist();
        store.generate();
    }
    drop(store);
    queue_merkle_fetches(request, outcome.to_fetch);
    if outcome.changed {
        let _ = notification.send(Notification::HeaderStoreUpdated);
    }
}

/// Grow the watched spk set for an `AddressTip`: register the new receive/change
/// gaps in `statuses`, then subscribe to them. `Break` ends the listener thread.
fn handle_address_tip<P: ScanProfile>(
    tip: AddressTip,
    derivator: &SpkDerivator,
    statuses: &mut P::StatusesStore,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let AddressTip { recv, change } = tip;
    let mut sub = vec![];
    let r_spk = derivator.receive_at(recv).script_pubkey();
    if !statuses.contains_key(&r_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..recv {
            let spk = derivator.receive_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_RECEIVE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    let c_spk = derivator.change_at(change).script_pubkey();
    if !statuses.contains_key(&c_spk).unwrap_or(false) {
        // FIXME: here we can be smart and not start at 0 but at `actual_tip`
        for i in 0..change {
            let spk = derivator.change_at(i).script_pubkey();
            if !statuses.contains_key(&spk).unwrap_or(false) {
                if let Err(e) = statuses.insert(spk.clone(), (None, STATUS_KEYCHAIN_CHANGE, i)) {
                    log::error!("listen_txs(): statuses insert: {e}");
                    continue;
                }
                sub.push(spk);
            }
        }
    }
    if !sub.is_empty() {
        flush_statuses(statuses);
        if request.send(CoinRequest::Subscribe(sub)).is_err() {
            return signal_stopped(request, notification);
        }
    }
    ControlFlow::Continue(())
}

/// Fold an Electrum `Status` response: diff against the local statuses, request
/// history for changed-non-empty scripthashes, clear the cleared ones, and flush
/// if any local status changed. `Break` ends the listener thread.
fn handle_status_response<P: ScanProfile>(
    elct_status: BTreeMap<ScriptBuf, Option<String>>,
    statuses: &mut P::StatusesStore,
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut history = vec![];
    let mut dirty = false;
    for (spk, status) in elct_status {
        match statuses.get(&spk) {
            Ok(Some((s, _, _))) => {
                // status is registered
                if s != status {
                    // status changed
                    if status.is_some() {
                        // not empty: ask for tx changes
                        history.push(spk.clone());
                    } else {
                        // Some(_) -> None: clear coin_store
                        let mut store = coin_store.lock().expect("poisoned");
                        let mut map = BTreeMap::new();
                        map.insert(spk.clone(), vec![]);
                        let _ = store.handle_history_response(map);
                        store.generate();
                    }
                    // record the local status change
                    let new_status = status.clone();
                    match statuses.modify(&spk, |v| v.0 = new_status.clone()) {
                        Ok(true) => dirty = true,
                        Ok(false) => {
                            // race-free under single-listener thread:
                            // we just observed the entry above
                        }
                        Err(e) => {
                            log::error!("listen_txs(): statuses modify: {e}");
                        }
                    }
                }
            }
            Ok(None) => {
                // not registered: previous behaviour was an
                // `entry(spk).and_modify(...)`, which is a no-op
                // for vacant entries. Preserve that, only the
                // history-side effect remains.
                if status.is_some() {
                    history.push(spk);
                } else {
                    let mut store = coin_store.lock().expect("poisoned");
                    let mut map = BTreeMap::new();
                    map.insert(spk.clone(), vec![]);
                    let _ = store.handle_history_response(map);
                }
            }
            Err(e) => {
                log::error!("listen_txs(): statuses get: {e}");
            }
        }
    }
    if !history.is_empty() {
        let hist = CoinRequest::History(history);
        log::debug!("listen_txs() send {}", hist.summary());
        if request.send(hist).is_err() {
            return signal_stopped(request, notification);
        }
    }
    if dirty {
        flush_statuses(statuses);
    }
    ControlFlow::Continue(())
}

/// Fold a `History` response into the coin store, fetch any missing txs, and
/// resolve the reported heights. `Break` ends the listener thread.
fn handle_history_response_msg<P: ScanProfile>(
    map: BTreeMap<ScriptBuf, Vec<(Txid, Option<u64>)>>,
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) -> ControlFlow<()> {
    let mut store = coin_store.lock().expect("poisoned");
    let outcome = store.handle_history_response(map);
    if !outcome.missing_txs.is_empty()
        && request.send(CoinRequest::Txs(outcome.missing_txs)).is_err()
    {
        return signal_stopped(request, notification);
    }
    // Folding the history above is unconditional; promoting the reported
    // heights against an unvalidated header is not. When the store is not
    // validated, persist any folded height changes but skip promotion.
    if !header_store_ready::<P>(header_store, notification) {
        if outcome.height_updated {
            store.tx_store_mut().persist();
            store.generate();
        }
        return ControlFlow::Continue(());
    }
    // Promote (or queue) heights now that the history is folded into the tx store.
    let promo = store.resolve_reported_heights(header_store, &outcome.reported);
    let changed = outcome.height_updated || promo.changed;
    apply_chain_update(
        store,
        request,
        notification,
        ChainUpdateOutcome {
            to_fetch: promo.to_fetch,
            changed,
        },
    );
    ControlFlow::Continue(())
}

/// Fold a `Txs` response into the coin store, then run a resolve-only pass:
/// newly-inserted txs may have a `(txid, height)` already queued in
/// `pending_claims` from a prior `History`, so promote them now instead of
/// waiting for the next header tick. Only `resolve_pending_claims` runs here;
/// `reverify_remined_entries` stays on the chain-tick path.
fn handle_txs_response_msg<P: ScanProfile>(
    txs: Vec<bitcoin::Transaction>,
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) {
    let mut store = coin_store.lock().expect("poisoned");
    store.handle_txs_response(txs);
    if !header_store_ready::<P>(header_store, notification) {
        return;
    }
    let promote = store.resolve_pending_claims(header_store);
    apply_chain_update(store, request, notification, promote);
}

/// Verify a `TxMerkle` response and promote the entry to `Verified`, or mark it
/// terminally `VerifyFailed` on a hard proof mismatch.
fn handle_tx_merkle<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    txid: Txid,
    height: u32,
    branch: Vec<[u8; 32]>,
    pos: u32,
) {
    // A TxMerkle response means the in-flight fetch resolved, whatever the
    // outcome; free the re-queue slot before anything else so a superseded
    // or dropped fetch can be re-issued by a later CTA pass.
    coin_store
        .lock()
        .expect("poisoned")
        .clear_merkle_in_flight(&txid);

    if !header_store_ready::<P>(header_store, notification) {
        return;
    }
    let Some(target) = resolve_tx_merkle_target(coin_store, header_store, txid, height) else {
        return;
    };
    apply_tx_merkle(coin_store, request, notification, target, &branch, pos);
}

/// The verified target of a `TxMerkle` response: the entry is
/// `ConfirmedUnverified` at exactly `height`, its stored hash still matches
/// the header there, and `expected_root` is that header's merkle root.
struct MerkleTarget {
    txid: Txid,
    height: u32,
    block_hash: BlockHash,
    expected_root: TxMerkleNode,
}

/// Guard a `TxMerkle` response against stale or mismatched state and return
/// the target to verify, or `None` (with a debug log) when it must be skipped.
fn resolve_tx_merkle_target<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    txid: Txid,
    height: u32,
) -> Option<MerkleTarget> {
    // Read header data first (without holding the coin_store lock). If
    // headers were pruned by a recent reorg between request and response,
    // the CTA re-fetch pass (`reverify_remined_entries`) re-queues the
    // proof once a header is present at this height again.
    let (expected_root, block_hash) = match header_store.merkle_root_and_hash(height) {
        Some(v) => v,
        None => {
            log::debug!(
                "handle_tx_merkle(): TxMerkle for {txid}@{height} but no header in header_store; skipping"
            );
            return None;
        }
    };

    let mut store = coin_store.lock().expect("poisoned");
    let current = match store.tx_store_mut().get(&txid) {
        Some(entry) => entry.inclusion().clone(),
        None => {
            log::debug!("handle_tx_merkle(): TxMerkle for unknown txid {txid}; skipping");
            return None;
        }
    };
    let (entry_height, entry_hash) = match current {
        Inclusion::ConfirmedUnverified { height, block_hash } => (height, block_hash),
        _ => {
            log::debug!(
                "handle_tx_merkle(): TxMerkle for {txid} not in ConfirmedUnverified state ({current:?}); skipping"
            );
            return None;
        }
    };
    // Only verify the proof against the height the entry is actually
    // claimed at; a stale response for a different height must not promote.
    if entry_height != height {
        log::debug!(
            "handle_tx_merkle(): TxMerkle height {height} != entry height {entry_height} for {txid}; skipping"
        );
        return None;
    }
    // The entry's stored hash no longer matches the header at this height:
    // a reorg raced the merkle fetch. This is not a lying server, so stay
    // silent; the reorg re-queue (reverify_remined_entries) owns recovery.
    if entry_hash != block_hash {
        log::debug!(
            "handle_tx_merkle(): TxMerkle for {txid}@{height} stored hash {entry_hash} != current hash {block_hash}; reorg race, skipping"
        );
        return None;
    }
    Some(MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    })
}

/// Verify the branch against `target` and update the entry: `Verified` via the
/// shared CTA apply on a good proof, else terminal `VerifyFailed` with a
/// one-shot `ValidationFailed(MerkleProof)` notification.
fn apply_tx_merkle<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    request: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
    target: MerkleTarget,
    branch: &[[u8; 32]],
    pos: u32,
) {
    let MerkleTarget {
        txid,
        height,
        block_hash,
        expected_root,
    } = target;
    let mut store = coin_store.lock().expect("poisoned");
    // The branch arrives in internal (little-endian) order from
    // `decode_tx_merkle_branch`, so it feeds `verify_merkle_branch` directly.
    if crate::header_store::verify_merkle_branch(txid, branch, pos, expected_root) {
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::Verified { height, block_hash });
        apply_chain_update(
            store,
            request,
            notification,
            ChainUpdateOutcome {
                to_fetch: Vec::new(),
                changed: true,
            },
        );
    } else {
        // Hard proof mismatch: mark the entry terminally VerifyFailed so it is
        // not re-fetched every tick, and surface the failure exactly once.
        // reverify_remined_entries clears it only if the header hash changes.
        store
            .tx_store_mut()
            .update_inclusion(&txid, Inclusion::VerifyFailed { height, block_hash });
        store.tx_store_mut().persist();
        store.generate();
        drop(store);
        let _ = notification.send(Notification::ValidationFailed(
            ValidationFailure::MerkleProof { txid, height },
        ));
    }
}

/// Stamp confirmed, un-timestamped txs with their block time, read from the
/// validated header chain. Entries whose header has not synced yet are left for
/// a later pass.
fn stamp_confirmation_times<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
) {
    let mut store = coin_store.lock().expect("poisoned");
    store.stamp_confirmation_times(|h| header_store.header(h as u32).map(|hdr| hdr.time as u64));
}

/// Chain-tip-advance pass: promote-only, resolves pending claims and queues merkle fetches against the validated chain.
fn on_chain_update<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    header_store: &HeaderStore<P::HeaderStore>,
    electrum_req: &mpsc::Sender<CoinRequest>,
    notification: &mpsc::Sender<Notification>,
) {
    if !header_store_ready::<P>(header_store, notification) {
        return;
    }

    let mut store = coin_store.lock().expect("poisoned");

    let reverify = store.reverify_remined_entries(header_store);
    let promote = store.resolve_pending_claims(header_store);
    let changed = reverify.changed || promote.changed;
    let mut to_fetch = reverify.to_fetch;
    to_fetch.extend(promote.to_fetch);

    apply_chain_update(
        store,
        electrum_req,
        notification,
        ChainUpdateOutcome { to_fetch, changed },
    );
}

/// Dispatch the collected merkle-proof fetches outside the CoinStore lock.
fn queue_merkle_fetches(electrum_req: &mpsc::Sender<CoinRequest>, to_fetch: Vec<ClaimAt>) {
    for ClaimAt { txid, height } in to_fetch {
        let _ = electrum_req.send(CoinRequest::GetTxMerkle { txid, height });
    }
}

/// Re-queue a `GetTxMerkle` fetch for every `ConfirmedUnverified` entry on
/// listener (re)connect, covering entries stranded while the listener was
/// down; between reconnects the CTA re-fetch pass retries them.
fn requeue_confirmed_unverified<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    electrum_req: &mpsc::Sender<CoinRequest>,
) {
    let to_fetch = coin_store
        .lock()
        .expect("poisoned")
        .confirmed_unverified_claims();
    queue_merkle_fetches(electrum_req, to_fetch);
}

/// On listener (re)connect, force a `History` refresh for every spk that
/// owns a still-`Inclusion::Unconfirmed` tx. `pending_claims` is an
/// in-memory cache a restart wipes, and the resubscribed status matches the
/// persisted `StatusesStore`, so no status-diff `History` fires on its own;
/// without this a tx already confirmed at some height would stay Unconfirmed
/// until an unrelated status change. The server re-reports the height, which
/// `resolve_reported_heights` turns back into a promotion or a fresh claim.
fn refresh_unconfirmed_history<P: ScanProfile>(
    coin_store: &Mutex<CoinStore<P>>,
    electrum_req: &mpsc::Sender<CoinRequest>,
) {
    let spks = coin_store
        .lock()
        .expect("poisoned")
        .spks_with_unconfirmed_txs();
    if !spks.is_empty() {
        let _ = electrum_req.send(CoinRequest::History(spks));
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use crate::label_store::LabelStore;
    use crate::profile::{DefaultBackend, RamProfile};
    use crate::{
        address_store::AddressStore,
        coin_store::{CoinEntry, CoinStoreSource},
        config::ScannerConfig,
        notification::TxListenerError,
        tx_store::TxStore,
    };
    use bwk_coin::KeyChain;
    use bwk_descriptor::descriptor::{wpkh, ScriptType};
    use bwk_persist::NoopBackend;
    use bwk_persist::PersistenceBackend;
    use bwk_sign::bip39::Mnemonic;
    use bwk_sign::hot_signer::HotSigner;
    use bwk_tx::CoinStatus;
    use bwk_utils::test::{funding_tx, setup_logger, spending_tx};
    use miniscript::bitcoin::{
        bip32::{ChildNumber, DerivationPath},
        Network, OutPoint,
    };
    use std::{
        collections::BTreeMap,
        path::PathBuf,
        str::FromStr,
        sync::{mpsc::TryRecvError, Mutex},
        thread::{self, JoinHandle},
        time::Duration,
    };
    use temp_dir::TempDir;

    struct CoinStoreMock {
        pub store: Arc<Mutex<CoinStore>>,
        pub notif: mpsc::Receiver<Notification>,
        pub request: mpsc::Receiver<CoinRequest>,
        pub response: mpsc::Sender<CoinResponse>,
        pub listener: JoinHandle<()>,
        pub stop: Arc<AtomicBool>,
        pub derivator: SpkDerivator,
    }

    impl Drop for CoinStoreMock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    impl CoinStoreMock {
        fn new(recv_tip: u32, change_tip: u32, look_ahead: u32) -> Self {
            let (notif_sender, notif_recv) = mpsc::channel();
            let (tip_sender, tip_receiver) = mpsc::channel();
            let (req_sender, req_receiver) = mpsc::channel();
            let (resp_sender, resp_receiver) = mpsc::channel();
            let mnemonic = Mnemonic::generate(12).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let signer =
                HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, &mnemonic.to_string())
                    .unwrap();
            let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
            let descriptor = wpkh(xpub);
            let derivator =
                SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
            let dummy_config = ScannerConfig::new(
                descriptor.clone(),
                PathBuf::default(),
                String::new(),
                "dummy".into(),
                Network::Regtest,
                false,
            );

            let tx_store = TxStore::new();
            let label_store = Arc::new(Mutex::new(LabelStore::new()));
            let mock_backend: Arc<dyn PersistenceBackend> = Arc::new(NoopBackend);
            let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
                mock_backend.clone(),
                bwk_persist::ACCOUNT_STORE_KEY,
                crate::profile::encode_account_key,
                crate::profile::encode_account_value,
            )));
            let statuses_store = bwk_persist::RamStore::open(
                mock_backend,
                bwk_persist::STATUSES_STORE_KEY,
                crate::profile::encode_status_key,
                crate::profile::decode_status_key,
                crate::profile::encode_status_value,
                crate::profile::decode_status_value,
            )
            .expect("open statuses RamStore");
            let coin_store = Arc::new(Mutex::new(CoinStore::new(
                bitcoin::Network::Regtest,
                descriptor.clone(),
                notif_sender.clone(),
                recv_tip,
                change_tip,
                look_ahead,
                tx_store,
                label_store,
                dummy_config,
                account_store,
            )));
            coin_store.lock().expect("poisoned").init(tip_sender);
            let store = coin_store.clone();
            let cloned_stop = stop.clone();
            let cloned_derivator = derivator.clone();

            let header_store = HeaderStore::new_in_memory(Network::Regtest);
            let chain_rx = header_store.register();
            let header_store_t = header_store.clone();

            let listener_handle = thread::spawn(move || {
                listen_txs::<RamProfile<DefaultBackend>>(
                    coin_store,
                    cloned_derivator,
                    notif_sender,
                    tip_receiver,
                    stop,
                    req_sender,
                    resp_receiver,
                    statuses_store,
                    header_store_t,
                    chain_rx,
                );
            });

            CoinStoreMock {
                store,
                notif: notif_recv,
                request: req_receiver,
                response: resp_sender,
                listener: listener_handle,
                stop: cloned_stop,
                derivator,
            }
        }

        fn coins(&mut self) -> BTreeMap<OutPoint, CoinEntry> {
            self.store.lock().expect("poisoned").coins()
        }

        fn stop(&self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    // Build a bare `CoinStore` (no listener thread) for testing the
    // CTA helpers directly.

    fn bare_coin_store() -> (Arc<Mutex<CoinStore>>, SpkDerivator) {
        let (notif_sender, _notif_recv) = mpsc::channel();
        let mnemo = Mnemonic::generate(12).unwrap();
        let signer =
            HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, &mnemo.to_string()).unwrap();
        let xpub = signer.xpub(&DerivationPath::from_str("m/84'/0'/0'/1").unwrap());
        let descriptor = wpkh(xpub);
        let derivator = SpkDerivator::new(descriptor.clone(), bitcoin::Network::Regtest).unwrap();
        let dummy_config = ScannerConfig::new(
            descriptor.clone(),
            PathBuf::default(),
            String::new(),
            "dummy".into(),
            Network::Regtest,
            false,
        );
        let label_store = Arc::new(Mutex::new(LabelStore::new()));
        let backend: Arc<dyn bwk_persist::PersistenceBackend> = Arc::new(NoopBackend);
        let account_store = Arc::new(Mutex::new(bwk_persist::RamStore::empty(
            backend,
            bwk_persist::ACCOUNT_STORE_KEY,
            crate::profile::encode_account_key,
            crate::profile::encode_account_value,
        )));
        let coin_store = Arc::new(Mutex::new(CoinStore::new(
            bitcoin::Network::Regtest,
            descriptor,
            notif_sender,
            0,
            0,
            20,
            TxStore::new(),
            label_store,
            dummy_config,
            account_store,
        )));
        (coin_store, derivator)
    }

    /// Build a regtest header chain of `len` blocks (heights `0..len`),
    /// returning the (height -> raw) map and the tip block hash.
    fn build_header_map(len: u32) -> (BTreeMap<u32, [u8; 80]>, miniscript::bitcoin::BlockHash) {
        use miniscript::bitcoin::{
            block::{Header, Version},
            hashes::Hash,
            BlockHash, CompactTarget, TxMerkleNode,
        };
        let bits = CompactTarget::from_consensus(0x207fffff);
        let mut map = BTreeMap::new();
        let mut prev = BlockHash::all_zeros();
        let mut tip = prev;
        for h in 0..len {
            let hdr = Header {
                version: Version::ONE,
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1_700_000_000 + h,
                bits,
                nonce: h,
            };
            prev = hdr.block_hash();
            tip = prev;
            let bytes = miniscript::bitcoin::consensus::serialize(&hdr);
            let mut arr = [0u8; 80];
            arr.copy_from_slice(&bytes);
            map.insert(h, arr);
        }
        (map, tip)
    }

    // Regression: after a deep reorg re-confirms a tx at a height
    // M different from the originally-claimed height N, the stale
    // `(N, txid)` entry must not linger in `pending_claims`.

    #[test]
    fn deep_reorg_clears_stale_pending_claims() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        // Seed a tx that is Verified at height M = 7.
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let m: u32 = 7;

        // Build a HeaderStore holding a header at M. `on_chain_update`
        // never demotes, so the Verified-at-M claim is left untouched; the
        // header is present so the seeded state is internally consistent.
        let (map, hash_at_m) = build_header_map(m + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: m,
                    block_hash: hash_at_m,
                },
            );
        }

        // Stale pending claim at the OLD height N = 4 (pre-reorg).
        let n: u32 = 4;
        coin_store
            .lock()
            .unwrap()
            .insert_pending_claim(ClaimAt { txid, height: n });

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // The stale (N, txid) entry must have been swept (tx is Verified
        // at M != N).
        let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
        assert!(
            snapshot.get(&n).map(|s| !s.contains(&txid)).unwrap_or(true),
            "stale pending claim at N={n} was not cleared: {snapshot:?}",
        );
    }

    // Regression: a claim whose tx is still in flight (History folded, Txs
    // response not yet) must survive a CTA pass. Dropping it as "removed
    // from the chain" wedges the tx Unconfirmed forever once it folds.

    #[test]
    fn pending_claim_survives_tx_fetch_in_flight() {
        use crate::header_store::HeaderStore;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_at(0).script_pubkey();
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();
        let (notif_tx, _notif_rx) = mpsc::channel();

        // History reports the confirmed tx before its bytes are known: the
        // update stays incomplete and the claim is queued, not promoted.
        {
            let mut store = coin_store.lock().unwrap();
            let mut hist = BTreeMap::new();
            hist.insert(spk, vec![(txid, Some(h as u64))]);
            let outcome = store.handle_history_response(hist);
            assert_eq!(outcome.missing_txs, vec![txid], "tx bytes must be missing");
            let promo = store.resolve_reported_heights(&header_store, &outcome.reported);
            assert!(promo.to_fetch.is_empty(), "nothing to fetch yet");
        }

        // CTA fires while the Txs response is still in flight: the claim
        // must survive (the txid is referenced by an incomplete update).
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        {
            let store = coin_store.lock().unwrap();
            let snapshot = store.pending_claims_snapshot();
            assert!(
                snapshot.get(&h).map(|s| s.contains(&txid)).unwrap_or(false),
                "in-flight claim was dropped: {snapshot:?}",
            );
        }

        // The Txs response folds the tx, then the next CTA promotes it.
        coin_store.lock().unwrap().handle_txs_response(vec![tx]);
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert_eq!(
                entry.inclusion(),
                &Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
                "claim was not promoted after the tx folded",
            );
        }
        match req_rx.try_recv() {
            Ok(CoinRequest::GetTxMerkle { txid: t, height }) => {
                assert_eq!(t, txid);
                assert_eq!(height, h);
            }
            other => panic!("expected GetTxMerkle, got {other:?}"),
        }
    }

    // Regression: history re-reports EVERY confirmed tx, not just the ones
    // whose height changed. An already-Verified tx re-reported at its SAME
    // height must stay Verified (the pass is promote-only); it must not be
    // demoted to ConfirmedUnverified nor trigger a fresh GetTxMerkle.

    #[test]
    fn re_report_does_not_demote_verified() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 6;

        // HeaderStore holds a real header at H, so the seeded Verified state
        // is internally consistent.
        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel::<CoinRequest>();

        // Server re-reports the same tx at the same height.
        {
            let mut store = coin_store.lock().unwrap();
            let promo =
                store.resolve_reported_heights(&header_store, &[ClaimAt { txid, height: h }]);
            queue_merkle_fetches(&req_tx, promo.to_fetch);
        }

        // The entry is STILL Verified at H (not demoted).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::Verified {
                    height, block_hash, ..
                } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, hash_at_h, "block_hash changed");
                }
                other => panic!("expected Verified{{H}}, got {other:?}"),
            }
        }

        // No GetTxMerkle was queued.
        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a re-reported Verified tx",
        );
    }

    // A ConfirmedUnverified entry whose stored hash still matches the header
    // (its single-shot merkle fetch was dropped or errored) must be
    // re-queued by the CTA pass, without mutating state or notifying.

    #[test]
    fn stuck_confirmed_unverified_refetched_by_cta() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // Exactly one re-queued fetch.
        assert!(matches!(
            req_rx.try_recv().unwrap(),
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        assert!(matches!(req_rx.try_recv(), Err(TryRecvError::Empty)));

        // No state change: entry untouched, nothing notified.
        assert!(matches!(notif_rx.try_recv(), Err(TryRecvError::Empty)));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash }
                if *height == h && *block_hash == hash_at_h
        ));
    }

    // A Verified entry whose stored hash matches the header must NOT be
    // re-fetched by the CTA pass.

    #[test]
    fn verified_with_matching_hash_not_refetched_by_cta() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        let (map, hash_at_h) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        assert!(
            matches!(req_rx.try_recv(), Err(TryRecvError::Empty)),
            "GetTxMerkle wrongly queued for a Verified entry with a matching hash",
        );
    }

    // Same-height reorg re-verification: a tx left `Verified` at height H
    // against a now-stale `block_hash` (the server re-mined it at the SAME
    // height in a DIFFERENT block, so the scripthash status is unchanged and
    // the history path never demotes it). `on_chain_update` must notice the
    // stored hash no longer matches the HeaderStore header at H, reset the
    // entry to `ConfirmedUnverified { H, B_new }`, and queue a fresh
    // `GetTxMerkle { H }`. It must NOT push the entry to `Unconfirmed`.

    #[test]
    fn same_height_reorg_reverifies_stale_block_hash() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // Build a HeaderStore whose header at H has block hash B_new,
        // distinct from the B_old we seed the tx with below.
        let (map, b_new) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // A clearly different (stale) block hash B_old, distinct from B_new.
        let b_old = miniscript::bitcoin::BlockHash::from_byte_array([0x7au8; 32]);
        assert_ne!(b_old, b_new);

        // Seed the tx Verified at H with the stale hash B_old.
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: b_old,
                },
            );
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        // The entry was reset to ConfirmedUnverified at the SAME height with
        // the NEW block hash (re-verification, not demotion).
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            match entry.inclusion() {
                Inclusion::ConfirmedUnverified { height, block_hash } => {
                    assert_eq!(*height, h, "height changed");
                    assert_eq!(*block_hash, b_new, "block_hash not updated to B_new");
                }
                other => panic!("expected ConfirmedUnverified{{H,B_new}}, got {other:?}"),
            }
        }

        // A GetTxMerkle for (txid, H) must have been queued.
        let mut saw_merkle = false;
        while let Ok(req) = req_rx.try_recv() {
            if let CoinRequest::GetTxMerkle { txid: t, height } = req {
                if t == txid && height == h {
                    saw_merkle = true;
                }
            }
        }
        assert!(saw_merkle, "GetTxMerkle{{H}} was not queued");
    }

    #[test]
    fn chain_update_waits_for_header_validation_then_retries_pending_claim() {
        use crate::header_store::{HeaderStore, HeaderValidationState};
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();
        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 4;

        let (map, block_hash) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store.set_validation_state_for_test(HeaderValidationState::Validating);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
        }
        coin_store
            .lock()
            .unwrap()
            .insert_pending_claim(ClaimAt { txid, height: h });

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);
        assert!(
            req_rx.try_recv().is_err(),
            "validation-gated update queued merkle proof too early"
        );
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert!(matches!(entry.inclusion(), Inclusion::Unconfirmed));
        }

        header_store.set_validation_state_for_test(HeaderValidationState::Valid);
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        let req = req_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("validation recovery should queue merkle proof");
        assert!(matches!(
            req,
            CoinRequest::GetTxMerkle { txid: t, height } if t == txid && height == h
        ));
        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(matches!(
            entry.inclusion(),
            Inclusion::ConfirmedUnverified { height, block_hash: bh }
                if *height == h && *bh == block_hash
        ));
    }

    // Regression for the stale-pending-claim wedge: a tx queued at an OLD
    // height N_old (whose header IS present) must not be promoted to N_old
    // after a reorg re-reports it at N_new. `resolve_reported_heights` must
    // drop the stale `(N_old, txid)` claim before queueing `(N_new, txid)`,
    // so the subsequent `on_chain_update` cannot promote the tx to the
    // wrong (N_old) height and wedge it ConfirmedUnverified forever.

    #[test]
    fn re_report_purges_stale_pending_claim() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let n_old: u32 = 4;
        let n_new: u32 = 9;

        // HeaderStore holds headers 0..=n_old only. Height n_new has NO
        // header yet, so the re-report at n_new takes the queue branch
        // while n_old IS reachable (the dangerous case).
        let (map, _tip) = build_header_map(n_old + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        // Seed the tx as Unconfirmed (post-reorg history reset state).
        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
        }

        // Pre-existing stale pending claim at the OLD height N_old.
        coin_store.lock().unwrap().insert_pending_claim(ClaimAt {
            txid,
            height: n_old,
        });

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, _notif_rx) = mpsc::channel();

        // History re-reports the tx at N_new (its new post-reorg height).
        {
            let mut store = coin_store.lock().unwrap();
            store.resolve_reported_heights(
                &header_store,
                &[ClaimAt {
                    txid,
                    height: n_new,
                }],
            );
        }

        // The stale (N_old, txid) entry is gone; only (N_new, txid) remains.
        {
            let snapshot = coin_store.lock().unwrap().pending_claims_snapshot();
            assert!(
                snapshot
                    .get(&n_old)
                    .map(|s| !s.contains(&txid))
                    .unwrap_or(true),
                "stale pending claim at N_old={n_old} not purged: {snapshot:?}",
            );
            assert!(
                snapshot
                    .get(&n_new)
                    .map(|s| s.contains(&txid))
                    .unwrap_or(false),
                "new pending claim at N_new={n_new} not queued: {snapshot:?}",
            );
        }

        // A subsequent CTA must NOT promote the tx to N_old (its header is
        // reachable, but the stale claim is gone). The tx stays Unconfirmed.
        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "tx wrongly promoted to {:?} (expected Unconfirmed)",
            entry.inclusion(),
        );
    }

    #[test]
    fn simple_start_stop() {
        setup_logger();
        let mock = CoinStoreMock::new(0, 0, 20);
        thread::sleep(Duration::from_millis(10));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));
        mock.stop();
        thread::sleep(Duration::from_secs(1));
        assert!(mock.listener.is_finished());
    }

    fn simple_recv() -> (bitcoin::Transaction, CoinStoreMock) {
        setup_logger();
        let look_ahead = 5;
        let mut mock = CoinStoreMock::new(0, 0, look_ahead);
        thread::sleep(Duration::from_millis(500));
        assert!(!mock.listener.is_finished());
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::AddressTipChanged,
        ));
        assert!(matches!(
            mock.notif.try_recv().unwrap(),
            Notification::Electrum(TxListenerNotif::Started)
        ));

        let mut init_spks = vec![];
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.receive_spk_at(i);
            init_spks.push(spk);
        }
        for i in 0..(look_ahead + 1) {
            let spk = mock.derivator.change_spk_at(i);
            init_spks.push(spk);
        }

        // receive initial subscriptions
        if let Ok(CoinRequest::Subscribe(v)) = mock.request.try_recv() {
            // NOTE: we expect (tip + 1 + look_ahead )
            assert_eq!(v.len(), 12);
            for spk in &init_spks {
                assert!(v.contains(spk));
            }
        } else {
            panic!()
        }

        // electrum server send spks statuses (None)
        let statuses: BTreeMap<_, _> = init_spks.clone().into_iter().map(|s| (s, None)).collect();
        mock.response.send(CoinResponse::Status(statuses)).unwrap();

        thread::sleep(Duration::from_millis(100));

        assert!(mock.coins().is_empty());

        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_unco".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        let tx_0 = funding_tx(spk_recv_0.clone(), 0.1);

        // server must send history response
        let mut history = BTreeMap::new();
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), None)]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_0.compute_txid()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_0.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);

        // NOTE: the coin is now confirmed

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_conf".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(1))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // NOTE: coin_store already have the tx it should not ask it
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // The server reports inclusion at height 1. `insert_history`
        // resets the entry to `Unconfirmed`, then `resolve_reported_heights`
        // tries to re-claim it, but this mock's HeaderStore is empty, so
        // there is no header at height 1 and the claim is queued in
        // `pending_claims` rather than promoted. The derived coin height
        // therefore stays None and the status stays Unconfirmed until a
        // header at that height arrives.
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;
        assert_eq!(coin.height(), None);
        assert_eq!(coin.status(), CoinStatus::Unconfirmed);
        (tx_0, mock)
    }

    #[test]
    fn recv_and_spend() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // spend this coin
        let outpoint = mock.coins().pop_first().unwrap().0;
        let tx_1 = spending_tx(outpoint);

        // NOTE: the coin is now spent

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_spent".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // the coin have now 1 confirmation
        history.insert(
            spk_recv_0.clone(),
            vec![(tx_0.compute_txid(), Some(1)), (tx_1.compute_txid(), None)],
        );
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server should receive a tx request only for tx_1
        if let Ok(CoinRequest::Txs(v)) = mock.request.try_recv() {
            assert!(v == vec![tx_1.compute_txid()]);
        } else {
            panic!()
        }

        // server send the requested tx
        mock.response
            .send(CoinResponse::Txs(vec![tx_1.clone()]))
            .unwrap();

        thread::sleep(Duration::from_millis(100));

        // now the store contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // the coin is unconfirmed
        assert_eq!(coin.status(), CoinStatus::Spent);
    }

    #[test]
    fn simple_reorg() {
        // init & receive one coin
        let (tx_0, mut mock) = simple_recv();
        let spk_recv_0 = mock.derivator.receive_spk_at(0);

        // NOTE: the coin is now spent we can reorg it

        // server send a status update at recv(0)
        let mut statuses = BTreeMap::new();
        statuses.insert(spk_recv_0.clone(), Some("1_tx_reorg".to_string()));
        mock.response.send(CoinResponse::Status(statuses)).unwrap();
        thread::sleep(Duration::from_millis(100));

        // server should receive an history request for this spk
        if let Ok(CoinRequest::History(v)) = mock.request.try_recv() {
            assert!(v == vec![spk_recv_0.clone()]);
        } else {
            panic!()
        }

        thread::sleep(Duration::from_millis(100));

        // server must send history response
        let mut history = BTreeMap::new();
        // NOTE: confirmation height is changed to 2
        history.insert(spk_recv_0.clone(), vec![(tx_0.compute_txid(), Some(2))]);
        mock.response.send(CoinResponse::History(history)).unwrap();

        thread::sleep(Duration::from_millis(100));

        // server do not receive a tx request as the store already go the tx
        assert!(matches!(mock.request.try_recv(), Err(TryRecvError::Empty)));

        // the store still contain one spent coin
        let mut coins = mock.coins();
        assert_eq!(coins.len(), 1);
        let coin = coins.pop_first().unwrap().1;

        // The server reorgs the entry to height 2. The reported-height
        // change drives `insert_history` to reset the entry to
        // `Inclusion::Unconfirmed` (this is the demotion path, owned by
        // history, not by `on_chain_update`). `resolve_reported_heights`
        // then re-claims it at height 2, but this mock's HeaderStore is
        // empty so the claim is only queued in `pending_claims` and the
        // entry stays Unconfirmed, hence the derived coin height is None.
        assert_eq!(coin.height(), None);
    }

    // Deterministic demotion: a tx seeded as `Inclusion::Verified` at height H
    // is reset to `Inclusion::Unconfirmed` when the server re-reports it at a
    // DIFFERENT height. This is the history-owned path
    // (`update_spk_history` resets `diff.changed` txids), distinct from the
    // same-height hash-change case (`Verified -> ConfirmedUnverified`).

    #[test]
    fn reported_height_change_demotes_verified_to_unconfirmed() {
        use crate::tx_store::TxEntry;

        let (coin_store, derivator) = bare_coin_store();

        let spk = derivator.receive_spk_at(0);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 5;

        // A concrete block hash at height H so the seeded Verified state is
        // internally consistent.
        let (_map, hash_at_h) = build_header_map(h + 1);

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::Verified {
                    height: h,
                    block_hash: hash_at_h,
                },
            );
        }

        // Prime the spk history at the seeded height: the tx lands in
        // `diff.added`, which never resets inclusion, so Verified survives.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some(h as u64))]);
        {
            let mut store = coin_store.lock().unwrap();
            let entry = store.tx_store_mut().get(&txid).expect("tx present");
            assert!(
                matches!(
                    entry.inclusion(),
                    Inclusion::Verified { height, block_hash }
                        if *height == h && *block_hash == hash_at_h
                ),
                "priming report must not demote; got {:?}",
                entry.inclusion(),
            );
        }

        // Server re-reports the SAME tx at a DIFFERENT height: the txid lands
        // in `diff.changed`, which resets it to Unconfirmed.
        coin_store
            .lock()
            .unwrap()
            .update_spk_history(spk.clone(), vec![(txid, Some((h + 3) as u64))]);

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert_eq!(
            *entry.inclusion(),
            Inclusion::Unconfirmed,
            "reported-height change must demote Verified -> Unconfirmed",
        );
    }

    // Refusal path: when the HeaderStore itself is Invalid, `on_chain_update`
    // must refuse to promote any pending claim and instead notify
    // `ValidationFailed(HeaderStore(_))`.

    #[test]
    fn invalid_header_store_blocks_promotion() {
        use crate::header_store::{HeaderStore, HeaderValidationState, InvalidCause};
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        // Header at H is present, so a Valid store would promote the claim;
        // the Invalid state below is what must block it.
        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        header_store
            .set_validation_state_for_test(HeaderValidationState::Invalid(InvalidCause::Sanity));

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(&txid, Inclusion::Unconfirmed);
            store.insert_pending_claim(ClaimAt { txid, height: h });
        }

        let (req_tx, req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();

        on_chain_update(&coin_store, &header_store, &req_tx, &notif_tx);

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::HeaderStore(_))
            ),
            "expected ValidationFailed(HeaderStore(_)), got {notif:?}"
        );

        assert!(
            req_rx.try_recv().is_err(),
            "no merkle fetch should be queued while the header store is invalid"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(entry.inclusion(), Inclusion::Unconfirmed),
            "claim wrongly promoted to {:?} despite invalid header store",
            entry.inclusion(),
        );
    }

    // FIX A: after a restart, `pending_claims` (a non-persisted cache) is
    // empty while a confirmed tx sits `Unconfirmed`. The reconnect refresh
    // must issue a `History` for that tx's spk so the server re-reports its
    // height and the claim is rebuilt.

    #[test]
    fn reconnect_refreshes_history_for_unconfirmed_spk() {
        use crate::tx_store::TxEntry;

        let (coin_store, deriv) = bare_coin_store();
        let spk = deriv.receive_spk_at(2);
        let tx = funding_tx(spk.clone(), 0.1);
        let txid = tx.compute_txid();
        {
            let mut store = coin_store.lock().unwrap();
            store.tx_store_mut().update(TxEntry::for_test(tx));
            store
                .tx_store_mut()
                .update_inclusion(&txid, Inclusion::Unconfirmed);
            store.generate();
            // As after a restart: the in-memory pending-claims cache is empty.
            assert!(store.pending_claims_snapshot().is_empty());
        }

        let (req_tx, req_rx) = mpsc::channel();
        refresh_unconfirmed_history(&coin_store, &req_tx);

        match req_rx.try_recv() {
            Ok(CoinRequest::History(spks)) => assert!(
                spks.contains(&spk),
                "History must cover the spk owning the Unconfirmed tx"
            ),
            other => panic!("expected History for the unconfirmed spk, got {other:?}"),
        }
    }

    // FIX B: a pending claim whose txid was removed from the tx store (a
    // reorg dropped it) must be dropped by `resolve_pending_claims` rather
    // than left queued forever.

    #[test]
    fn resolve_pending_claims_drops_removed_txid() {
        let (coin_store, _deriv) = bare_coin_store();
        let (map, _tip) = build_header_map(5);
        let header_store = HeaderStore::from_map(Network::Regtest, map);

        let txid = funding_tx(bitcoin::ScriptBuf::new(), 0.1).compute_txid();
        let h: u32 = 3;
        {
            let mut store = coin_store.lock().unwrap();
            store.insert_pending_claim(ClaimAt { txid, height: h });
            assert!(!store.pending_claims_snapshot().is_empty());
        }

        let mut store = coin_store.lock().unwrap();
        let outcome = store.resolve_pending_claims(&header_store);
        assert!(!outcome.changed, "no promotion for an absent txid");
        assert!(
            store.pending_claims_snapshot().is_empty(),
            "stale claim for a removed txid must be dropped"
        );
    }

    // Refusal path: a tampered merkle branch against a header whose hash
    // still matches the entry's stored hash must notify
    // `ValidationFailed(MerkleProof)` and move the entry to the terminal
    // `VerifyFailed` state so it is not re-fetched every tick.

    #[test]
    fn handle_tx_merkle_tampered_branch_notifies() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let block_hash = header_store.block_hash(h).expect("header at h present");

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash,
                },
            );
        }

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();
        // A sibling that does not fold to the header's (all-zero) merkle
        // root: the proof fails verification.
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &req_tx,
            &notif_tx,
            txid,
            h,
            vec![[0x11u8; 32]],
            0,
        );

        let notif = notif_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("refusal must notify ValidationFailed");
        assert!(
            matches!(
                notif,
                Notification::ValidationFailed(ValidationFailure::MerkleProof { txid: t, height })
                    if t == txid && height == h
            ),
            "expected ValidationFailed(MerkleProof), got {notif:?}"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::VerifyFailed { height, block_hash: b }
                    if *height == h && *b == block_hash
            ),
            "entry not moved to VerifyFailed: {:?}",
            entry.inclusion(),
        );
    }

    // Reorg race: the entry's stored hash no longer matches the header at
    // its height (a reorg landed between the fetch and the response). This
    // must stay silent, no notification and no state change; the reorg
    // re-queue (reverify_remined_entries) owns recovery.

    #[test]
    fn handle_tx_merkle_hash_mismatch_stays_silent() {
        use crate::header_store::HeaderStore;
        use crate::tx_store::TxEntry;
        use miniscript::bitcoin::hashes::Hash;

        let (coin_store, _derivator) = bare_coin_store();

        let tx = funding_tx(bitcoin::ScriptBuf::new(), 0.1);
        let txid = tx.compute_txid();
        let h: u32 = 3;

        let (map, _tip) = build_header_map(h + 1);
        let header_store = HeaderStore::from_map(Network::Regtest, map);
        let stale_hash = bitcoin::BlockHash::all_zeros();
        assert_ne!(
            header_store.block_hash(h).expect("header at h present"),
            stale_hash
        );

        {
            let mut store = coin_store.lock().unwrap();
            let tx_store = store.tx_store_mut();
            tx_store.update(TxEntry::for_test(tx.clone()));
            tx_store.update_inclusion(
                &txid,
                Inclusion::ConfirmedUnverified {
                    height: h,
                    block_hash: stale_hash,
                },
            );
        }

        let (req_tx, _req_rx) = mpsc::channel();
        let (notif_tx, notif_rx) = mpsc::channel();
        handle_tx_merkle(
            &coin_store,
            &header_store,
            &req_tx,
            &notif_tx,
            txid,
            h,
            Vec::new(),
            0,
        );

        assert!(
            notif_rx.try_recv().is_err(),
            "reorg race must stay silent, got a notification"
        );

        let mut store = coin_store.lock().unwrap();
        let entry = store.tx_store_mut().get(&txid).expect("tx present");
        assert!(
            matches!(
                entry.inclusion(),
                Inclusion::ConfirmedUnverified { height, block_hash: b }
                    if *height == h && *b == stale_hash
            ),
            "entry state changed on hash mismatch: {:?}",
            entry.inclusion(),
        );
    }
}
