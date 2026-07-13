//! # hop-store-firestore
//!
//! A durable [`Store`](hop_core::store::Store) for a relay node, backed by Firestore
//! so the mailbox survives scale-to-zero (DESIGN.md §19/§21). **Per node**, not a
//! global store: each relay owns the subcollection
//! `relays/{node}/bundles`, so there's no cross-region contention.
//!
//! The relay's driver loop is synchronous and single-owner, so we never block it on
//! a Firestore round-trip: a [`MemoryStore`] is the hot path and a **background
//! writer thread** mirrors writes/deletes to Firestore (a FIFO channel preserves
//! per-id order). On startup we **load** the held bundles back from Firestore into
//! memory; the node's `rehydrate` then resumes them.
//!
//! Two durable surfaces are mirrored, both loaded on open and write-through on mutation:
//!
//!  * **bundles** (`relays/{node}/bundles`): the store-and-forward mailbox.
//!  * **kv** (`relays/{node}/kv`, stores-07): the small key -> bytes side store the Store trait
//!    exposes (DESIGN.md §25) for state that must survive a scale cycle but isn't a bundle:
//!    forward-secret ratchet sessions, prekey secrets, pending content. Before stores-07 this was
//!    memory-only on the relay, so a scale-to-zero dropped every relay-hosted session and forced a
//!    re-secure churn against mobile peers; now it round-trips through the same mirror seam.
//!
//! The dedup `seen` set stays in-memory (losing it across a scale cycle costs at most some
//! re-flooding, which the receiver dedups; §7).
//!
//! stores-09: the mirror channel is **bounded** (drop-oldest under sustained backpressure), so a
//! degraded Firestore backing the queue up cannot grow relay memory without bound. Dropped ops are
//! counted ([`FirestoreStore::mirror_dropped`]) so `/healthz` can surface a store that is silently
//! shedding durable writes rather than pretending everything persisted.
//!
//! Durable cleanup of expired bundles is left to a **Firestore TTL policy** on the
//! `expireAt` timestamp field (a one-time setup; TTL only sweeps `timestampValue`
//! fields, so every doc carries one — see `doc_json`), keeping `prune` a fast
//! in-memory op. One policy on the `bundles` collection group covers both the
//! per-relay handoff inbox and the §39 mailbox spool.
//!
//! Auth: a Bearer token from the GCE/Cloud Run **metadata server** (workload
//! identity), or the `FIRESTORE_ACCESS_TOKEN` env var for local runs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use hop_core::bundle::{Bundle, BundleId};
use hop_core::store::{HaveSet, MemoryStore, Store};

/// stores-09: bound on the in-memory mirror backlog. A degraded Firestore backs writes up (each op
/// has a 15s reqwest timeout + 3 retries), so without a cap the queue grows with relay memory. Past
/// this we drop the OLDEST pending op (and count it) rather than block the single-owner driver or
/// grow unbounded. Generous for a transient blip; a sustained outage sheds oldest-first.
const MIRROR_QUEUE_CAP: usize = 4_096;

/// Wall-clock epoch-milliseconds. The relay stamps dedup/TTL deadlines in epoch-ms (the same clock
/// relayd's tick uses), so rehydrate must anchor against the real clock, not a zero origin (stores-02).
fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A write/delete to mirror to Firestore (bundle or kv).
enum Op {
    Write {
        id: BundleId,
        data: Vec<u8>,
        expires_at: u64,
    },
    Delete {
        id: BundleId,
    },
    /// stores-07: a kv upsert (`relays/{node}/kv/{key}`). `key` is a caller-chosen string
    /// (e.g. `session/<peer>`); `value` is opaque bytes.
    KvWrite {
        key: String,
        value: Vec<u8>,
    },
    /// stores-07: a kv delete (idempotent).
    KvDelete {
        key: String,
    },
    /// F-21: drain sentinel. The worker acks this AFTER processing every op ahead of it (mpsc is
    /// FIFO), so `flush()` blocking on the ack means all pending mirrors have been attempted.
    Flush(mpsc::SyncSender<()>),
}

/// The durable mirror seam behind [`FirestoreStore`] (stores-11). The real relay uses
/// [`FirestoreClient`] (a live REST endpoint); tests inject a fake so the Store impl's
/// durability-critical paths (rehydrate expiry anchoring, flush drain, mirror ordering) are
/// unit-testable without touching Firestore. All three methods run only on `open()` (list) and the
/// background writer thread (put/delete), never the hot path.
pub trait BundleMirror: Send + 'static {
    /// Load durably-held bundles as `(sealed bytes, expires_at)` for rehydrate.
    fn list_bundles(&self) -> Result<Vec<(Vec<u8>, u64)>, String>;
    /// Mirror a write (upsert).
    fn put_bundle(&self, id: &BundleId, data: &[u8], expires_at: u64) -> Result<(), String>;
    /// Mirror a delete (idempotent).
    fn delete_bundle(&self, id: &BundleId) -> Result<(), String>;

    // --- kv surface (stores-07) -----------------------------------------------------------
    // A durable key -> bytes side store mirrored the same way bundles are: loaded on open,
    // write-through on mutation. Defaults keep bundle-only fakes/backends compiling unchanged.

    /// Load all persisted kv pairs as `(key, value)` for rehydrate. Default: none.
    fn list_kv(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        Ok(Vec::new())
    }
    /// Mirror a kv upsert. Default: no-op success (bundle-only backend).
    fn put_kv(&self, _key: &str, _value: &[u8]) -> Result<(), String> {
        Ok(())
    }
    /// Mirror a kv delete (idempotent). Default: no-op success.
    fn delete_kv(&self, _key: &str) -> Result<(), String> {
        Ok(())
    }
}

impl BundleMirror for FirestoreClient {
    fn list_bundles(&self) -> Result<Vec<(Vec<u8>, u64)>, String> {
        FirestoreClient::list_bundles(self)
    }
    fn put_bundle(&self, id: &BundleId, data: &[u8], expires_at: u64) -> Result<(), String> {
        FirestoreClient::put_bundle(self, id, data, expires_at)
    }
    fn delete_bundle(&self, id: &BundleId) -> Result<(), String> {
        FirestoreClient::delete_bundle(self, id)
    }
    fn list_kv(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        FirestoreClient::list_kv(self)
    }
    fn put_kv(&self, key: &str, value: &[u8]) -> Result<(), String> {
        FirestoreClient::put_kv(self, key, value)
    }
    fn delete_kv(&self, key: &str) -> Result<(), String> {
        FirestoreClient::delete_kv(self, key)
    }
}

/// Durable per-node store: in-memory hot path + Firestore mirror.
pub struct FirestoreStore {
    inner: MemoryStore,
    /// The bounded mirror queue (stores-09). Enqueue is drop-oldest under backpressure; the worker
    /// thread is the sole consumer. A [`SyncSender`] alone can't drop-oldest, so the queue is an
    /// explicit `VecDeque` behind a `Mutex` + `Condvar` and `tx` carries the drop policy.
    tx: MirrorTx,
    /// stores-09: count of durable ops shed because the mirror backlog was at [`MIRROR_QUEUE_CAP`].
    /// Non-zero means Firestore is degraded and this store is NOT durable right now; `/healthz`
    /// surfaces it. `Arc` so a boxed store's owner can read it without owning the store.
    dropped: Arc<AtomicU64>,
    /// stores-r2-05: the background writer's join handle. Drop signals `closed` then best-effort
    /// joins (bounded wait) so ops enqueued-but-not-yet-flushed on an UNCLEAN teardown (panic, early
    /// return, a drop not preceded by `flush()`) still get drained rather than silently lost. `Option`
    /// so Drop can `take()` it and `join()`.
    writer: Option<std::thread::JoinHandle<()>>,
}

/// The bounded, drop-oldest mirror queue's producer end (stores-09). Wraps a shared
/// `Mutex<VecDeque<Op>>` + `Condvar`; enqueue pops the oldest op when the backlog is at the cap
/// (bumping `dropped`) so a degraded backend sheds oldest-first instead of growing relay memory or
/// blocking the single-owner driver.
#[derive(Clone)]
struct MirrorTx {
    queue: Arc<(Mutex<MirrorQueue>, std::sync::Condvar)>,
    dropped: Arc<AtomicU64>,
}

struct MirrorQueue {
    ops: std::collections::VecDeque<Op>,
    /// Set on drop of the store so the worker exits once drained (mirrors an mpsc hangup).
    closed: bool,
}

impl MirrorTx {
    /// Enqueue an op, dropping the OLDEST pending op if the backlog is already at the cap. A `Flush`
    /// sentinel is never dropped (it carries the caller's ack channel and must reach the worker).
    fn send(&self, op: Op) {
        let (lock, cvar) = &*self.queue;
        let mut q = lock.lock().unwrap();
        if q.ops.len() >= MIRROR_QUEUE_CAP {
            // Drop the oldest NON-flush op to make room; never discard a flush ack.
            if let Some(pos) = q.ops.iter().position(|o| !matches!(o, Op::Flush(_))) {
                q.ops.remove(pos);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        q.ops.push_back(op);
        cvar.notify_one();
    }
}

impl FirestoreStore {
    /// Open the store for `node_addr` in `project`, loading any held bundles + kv back
    /// into memory. Spawns the background writer thread.
    pub fn open(project: &str, node_addr: &[u8]) -> Result<Self, String> {
        Self::open_with_mirror(FirestoreClient::new(project, node_addr))
    }

    /// stores-09: how many durable ops have been shed because the mirror backlog hit its cap. `0`
    /// means the mirror is keeping up (the store is durable); non-zero means Firestore is degraded
    /// and writes are being lost, which `/healthz` should surface rather than report all-green.
    pub fn mirror_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// stores-09: a shared handle to the dropped-op counter, so a supervisor (e.g. relayd's
    /// `/healthz`) can read it from another thread without owning the (driver-owned) store.
    pub fn mirror_dropped_handle(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }

    /// stores-r2-01: re-mirror an already-held bundle (after a spray-and-wait split or a retransmit
    /// set_copies) reusing the RECEIVER-anchored `expires_at` this store recorded at `put` time,
    /// NOT `created_at + lifetime_ms`. `created_at` is the SENDER's advisory clock (§8, defaults to
    /// 0): re-deriving from it can rewrite the durable doc's `expireAt` into the past (created_at=0
    /// -> ~1970), so the Firestore TTL policy would sweep a still-live spooled/handoff bundle early
    /// and silently drop an offline recipient's §39-spooled message. The stored `seen_expiry` is the
    /// same clamped `now + lifetime` `put()` mirrored, so every re-mirror carries the identical
    /// bound. Falls back to skipping the mirror if the id is no longer tracked (nothing to persist).
    fn remirror(&self, id: &BundleId) {
        let Some(expires_at) = self.inner.seen_expiry(id) else {
            return;
        };
        if let Some(b) = self.inner.get(id) {
            if let Ok(data) = b.to_bytes() {
                self.tx.send(Op::Write {
                    id: *id,
                    data,
                    expires_at,
                });
            }
        }
    }

    /// Open over an arbitrary [`BundleMirror`] (stores-11 seam). `open()` is the production wiring
    /// (a live [`FirestoreClient`]); tests pass a fake mirror to exercise rehydrate/flush/mirror.
    pub fn open_with_mirror<M: BundleMirror>(mirror: M) -> Result<Self, String> {
        let mut inner = MemoryStore::new();

        // Rehydrate held bundles from Firestore into memory (mark seen so dedup holds). The dedup
        // expiry must be reinstated at each bundle's REAL absolute deadline (stores-02), not
        // re-anchored at `now + lifetime`: a `put(_, 0)` would stamp expiry at epoch 0, and the
        // relay's first real-clock prune (~1s after cold start) would wipe every rehydrated bundle
        // and its seen row, killing cold-start mailbox delivery. Reading the stored `expires_at`
        // back also means a re-list never re-extends the Firestore TTL of a gone-forever device's
        // bundle. Already-expired rows are skipped (the TTL policy will sweep the durable copy).
        let now_ms = epoch_ms();
        for (data, expires) in mirror.list_bundles()? {
            // stores-r3-02: `expires <= now_ms` is "past its §8 lifetime; don't resurrect it". This
            // now includes `expires == 0`. The old code special-cased 0 as a "never-expire" sentinel
            // and stored `put_with_expiry(_, 0)`, but MemoryStore::prune drops any id with
            // `exp <= now_ms` — and `0 <= now_ms` is ALWAYS true — so a 0-expiry bundle was wiped on
            // the very first real-clock prune (~1s after cold start). The sentinel was therefore
            // false and dead (every live writer stamps a real now+lifetime, never 0). We treat 0 like
            // any past deadline and skip it, so the contract matches prune's actual semantics.
            if expires <= now_ms {
                continue;
            }
            // stores-r2-03: clamp the reinstated dedup window to now + MAX_SEEN_LIFETIME_MS. New docs
            // are already bounded on the write side (put()), but a doc written by a PRE-FIX relay (or
            // any doc with a hostile ~49-day `expiresAt`) that survives a scale cycle must not
            // reinstate a 49-day seen window on cold start. A legitimate far-future-within-a-week
            // value is unchanged.
            let expires = expires.min(now_ms.saturating_add(hop_core::store::MAX_SEEN_LIFETIME_MS));
            if let Ok(bundle) = Bundle::from_bytes(&data) {
                inner.put_with_expiry(bundle, expires);
            }
        }

        // stores-07: rehydrate the durable kv side store (sessions/prekeys/pending) so a relay that
        // scaled to zero comes back with its forward-secret sessions intact instead of re-securing
        // against every mobile peer. kv has no per-row expiry (unlike bundles); it lives until the
        // owner removes it.
        for (key, value) in mirror.list_kv()? {
            inner.put_kv(&key, value);
        }

        let dropped = Arc::new(AtomicU64::new(0));
        let queue = Arc::new((
            Mutex::new(MirrorQueue {
                ops: std::collections::VecDeque::new(),
                closed: false,
            }),
            std::sync::Condvar::new(),
        ));
        let tx = MirrorTx {
            queue: queue.clone(),
            dropped: dropped.clone(),
        };
        let writer = std::thread::spawn(move || {
            let (lock, cvar) = &*queue;
            loop {
                let op = {
                    let mut q = lock.lock().unwrap();
                    loop {
                        if let Some(op) = q.ops.pop_front() {
                            break op;
                        }
                        if q.closed {
                            return; // producer gone and backlog drained
                        }
                        q = cvar.wait(q).unwrap();
                    }
                };
                // F-21: a flush sentinel just acks — everything before it in the FIFO is done.
                if let Op::Flush(ack) = &op {
                    let _ = ack.send(());
                    continue;
                }
                // Best-effort with a couple of retries; the hot path never blocks here.
                for attempt in 0..3 {
                    let ok = match &op {
                        Op::Write {
                            id,
                            data,
                            expires_at,
                        } => mirror.put_bundle(id, data, *expires_at),
                        Op::Delete { id } => mirror.delete_bundle(id),
                        Op::KvWrite { key, value } => mirror.put_kv(key, value),
                        Op::KvDelete { key } => mirror.delete_kv(key),
                        Op::Flush(_) => break,
                    };
                    if ok.is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
                }
            }
        });

        Ok(Self {
            inner,
            tx,
            dropped,
            writer: Some(writer),
        })
    }
}

/// stores-r2-05: how long Drop waits for the writer to drain remaining ops before giving up. Bounded
/// so an unclean teardown against a WEDGED/degraded Firestore can't hang the drop indefinitely, while
/// a healthy backend (each op is fast) drains its small tail well within this. The clean path already
/// calls `flush()` (SIGTERM); this is the safety net for panic/early-return drops that do not.
const DROP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

impl Drop for FirestoreStore {
    fn drop(&mut self) {
        // Signal the worker to exit once it has drained the backlog (mirrors an mpsc hangup, which
        // the old `Sender` did implicitly). Without this the worker parks on the Condvar forever.
        {
            let (lock, cvar) = &*self.tx.queue;
            lock.lock().unwrap().closed = true;
            cvar.notify_all();
        }
        // stores-r2-05: best-effort join so ops enqueued-but-not-flushed on an unclean teardown get a
        // chance to drain instead of vanishing silently. Bounded (poll is_finished up to
        // DROP_DRAIN_TIMEOUT) so a wedged backend can't make Drop block forever; if the writer is
        // still going at the deadline we detach (the process is exiting anyway).
        if let Some(handle) = self.writer.take() {
            let deadline = Instant::now() + DROP_DRAIN_TIMEOUT;
            while !handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}

impl Store for FirestoreStore {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        let id = bundle.id();
        // stores-r2-03: clamp the durable `expires_at` with the SAME bound the in-memory dedup uses
        // (MAX_SEEN_LIFETIME_MS, F-07). Without it, a §39 private bundle with a hostile ~49-day
        // `lifetime_ms` writes a 49-day `expiresAt` to Firestore; a cold-start rehydrate then reads
        // that raw value straight into the seen map, reinstating a 49-day dedup window and defeating
        // the clamp for exactly the bundles that survive a scale cycle. Bounding the write bounds
        // both the Firestore TTL retention and everything rehydrate can reinstate.
        let lifetime = (bundle.inner.lifetime_ms as u64).min(hop_core::store::MAX_SEEN_LIFETIME_MS);
        let expires_at = now_ms.saturating_add(lifetime);
        let data = match bundle.to_bytes() {
            Ok(d) => d,
            Err(_) => return false,
        };
        if self.inner.put(bundle, now_ms) {
            self.tx.send(Op::Write {
                id,
                data,
                expires_at,
            });
            true
        } else {
            false
        }
    }

    fn rehydrate(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        // relay-A audit: re-hold an evicted-but-durable bundle whose `seen` row survived, and re-mirror
        // it durably. Same shape as put but the in-memory inner re-holds past its dedup gate.
        let id = bundle.id();
        let lifetime = (bundle.inner.lifetime_ms as u64).min(hop_core::store::MAX_SEEN_LIFETIME_MS);
        let expires_at = now_ms.saturating_add(lifetime);
        let data = match bundle.to_bytes() {
            Ok(d) => d,
            Err(_) => return false,
        };
        let held = self.inner.rehydrate(bundle, now_ms);
        if held {
            self.tx.send(Op::Write {
                id,
                data,
                expires_at,
            });
        }
        held
    }

    fn get(&self, id: &BundleId) -> Option<Bundle> {
        self.inner.get(id)
    }

    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        let removed = self.inner.remove(id);
        if removed.is_some() {
            self.tx.send(Op::Delete { id: *id });
        }
        removed
    }

    fn seen(&self, id: &BundleId) -> bool {
        self.inner.seen(id)
    }

    fn contains(&self, id: &BundleId) -> bool {
        self.inner.contains(id)
    }

    fn have(&self) -> HaveSet {
        self.inner.have()
    }

    fn prune(&mut self, now_ms: u64) {
        // In-memory only; the durable copies are reaped by a Firestore TTL policy on
        // the `expireAt` timestamp (one-time setup), keeping prune off the network.
        self.inner.prune(now_ms);
    }

    fn split_copies(&mut self, id: &BundleId) -> u16 {
        let give = self.inner.split_copies(id);
        if give > 0 {
            self.remirror(id);
        }
        give
    }

    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        self.inner.set_copies(id, copies);
        self.remirror(id);
    }

    fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        // stores-r3-01: expose the hot-path MemoryStore's receiver-anchored dedup deadline so the
        // relay's handoff/spool path anchors the durable Firestore `expireAt` to it (not to the
        // sender's advisory created_at, which can be 0 and would sweep a live message early).
        self.inner.seen_expiry(id)
    }

    // --- kv surface (stores-07): write-through to the durable `relays/{node}/kv` collection. ---

    fn put_kv(&mut self, key: &str, value: Vec<u8>) {
        self.inner.put_kv(key, value.clone());
        self.tx.send(Op::KvWrite {
            key: key.to_string(),
            value,
        });
    }

    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        // The in-memory copy is authoritative in-process (loaded on open, kept in sync on write).
        self.inner.get_kv(key)
    }

    fn remove_kv(&mut self, key: &str) {
        self.inner.remove_kv(key);
        self.tx.send(Op::KvDelete {
            key: key.to_string(),
        });
    }

    fn list_kv(&self, prefix: &str) -> Vec<(String, Vec<u8>)> {
        self.inner.list_kv(prefix)
    }

    /// F-21: block until the background writer has drained every pending mirror (or `timeout`
    /// elapses). The queue is FIFO, so an acked Flush means every prior Write/Delete/kv op was
    /// attempted. The Flush sentinel is never drop-oldest'd (stores-09), so this can't wedge.
    fn flush(&self, timeout: std::time::Duration) -> bool {
        let (ack_tx, ack_rx) = mpsc::sync_channel::<()>(0);
        self.tx.send(Op::Flush(ack_tx));
        ack_rx.recv_timeout(timeout).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Firestore REST client (blocking; runs only on the background thread + open()).
// ---------------------------------------------------------------------------

struct FirestoreClient {
    http: reqwest::blocking::Client,
    collection_url: String, // .../documents/relays/{node}/bundles
    kv_url: String,         // .../documents/relays/{node}/kv (stores-07)
    token: Mutex<Option<(String, Instant)>>,
}

impl FirestoreClient {
    fn new(project: &str, node_addr: &[u8]) -> Self {
        let node = bs58::encode(node_addr).into_string();
        let base = "https://firestore.googleapis.com/v1";
        let collection_url = format!(
            "{base}/projects/{project}/databases/(default)/documents/relays/{node}/bundles"
        );
        let kv_url =
            format!("{base}/projects/{project}/databases/(default)/documents/relays/{node}/kv");
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            collection_url,
            kv_url,
            token: Mutex::new(None),
        }
    }

    /// A cached OAuth token: metadata server (Cloud Run/GCE) or `FIRESTORE_ACCESS_TOKEN`.
    fn token(&self) -> Result<String, String> {
        cached_token(&self.token, &self.http)
    }

    fn put_bundle(&self, id: &BundleId, data: &[u8], expires_at: u64) -> Result<(), String> {
        let doc = bs58::encode(id).into_string();
        let url = format!("{}/{doc}", self.collection_url);
        let body = doc_json(data, expires_at);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("put {}", resp.status()))
        }
    }

    fn delete_bundle(&self, id: &BundleId) -> Result<(), String> {
        let doc = bs58::encode(id).into_string();
        let url = format!("{}/{doc}", self.collection_url);
        let token = self.token()?;
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;
        // 404 is fine — already gone.
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("delete {}", resp.status()))
        }
    }

    fn list_bundles(&self) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{}?pageSize=300", self.collection_url);
            if let Some(t) = &page_token {
                url.push_str(&format!("&pageToken={t}"));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 404 {
                return Ok(out); // collection doesn't exist yet
            }
            if !resp.status().is_success() {
                return Err(format!("list {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                for d in docs {
                    if let Some((data, expires)) = parse_doc(d) {
                        out.push((data, expires));
                    }
                }
            }
            match v["nextPageToken"].as_str() {
                Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    // --- kv surface (stores-07) -----------------------------------------------------------
    // A caller's kv key (e.g. `session/<peer>`) can contain `/` and other characters Firestore
    // forbids in a document id, so the doc id is `bs58(key-bytes)` and the ORIGINAL key is carried
    // as a field so `list_kv` recovers it exactly. Values are opaque bytes (base64 bytesValue).

    fn put_kv(&self, key: &str, value: &[u8]) -> Result<(), String> {
        let doc = bs58::encode(key.as_bytes()).into_string();
        let url = format!("{}/{doc}", self.kv_url);
        let body = kv_doc_json(key, value);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("put_kv {}", resp.status()))
        }
    }

    fn delete_kv(&self, key: &str) -> Result<(), String> {
        let doc = bs58::encode(key.as_bytes()).into_string();
        let url = format!("{}/{doc}", self.kv_url);
        let token = self.token()?;
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("delete_kv {}", resp.status()))
        }
    }

    fn list_kv(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{}?pageSize=300", self.kv_url);
            if let Some(t) = &page_token {
                url.push_str(&format!("&pageToken={t}"));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 404 {
                return Ok(out); // collection doesn't exist yet
            }
            if !resp.status().is_success() {
                return Err(format!("list_kv {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                for d in docs {
                    if let Some(pair) = parse_kv_doc(d) {
                        out.push(pair);
                    }
                }
            }
            match v["nextPageToken"].as_str() {
                Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Build a Firestore document body for a kv pair: the original key (so `list_kv` recovers it
/// exactly, since the doc id is a base58 of the key bytes) plus the opaque value as base64 bytes.
fn kv_doc_json(key: &str, value: &[u8]) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD.encode(value);
    serde_json::json!({
        "fields": {
            "key": { "stringValue": key },
            "value": { "bytesValue": b64 },
        }
    })
}

/// Parse a Firestore kv document into `(key, value)`.
fn parse_kv_doc(d: &serde_json::Value) -> Option<(String, Vec<u8>)> {
    let fields = d.get("fields")?;
    let key = fields["key"]["stringValue"].as_str()?.to_string();
    let b64 = fields["value"]["bytesValue"].as_str()?;
    let value = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some((key, value))
}

// ---------------------------------------------------------------------------
// Shared GCP auth (used by the store and the liveness registry).
// ---------------------------------------------------------------------------

/// Fetch a GCP OAuth token: the `FIRESTORE_ACCESS_TOKEN` env var (local runs) or the
/// GCE/Cloud Run metadata server (workload identity).
fn fetch_gcp_token(http: &reqwest::blocking::Client) -> Result<String, String> {
    if let Ok(t) = std::env::var("FIRESTORE_ACCESS_TOKEN") {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    // Ask the metadata server for a token scoped to Firestore. Without an explicit `scopes`,
    // the runtime SA token was rejected by Firestore with 401 (the presence/§28 backbone never
    // authenticated — failing silently since deploy). The SA has roles/datastore.user; this just
    // mints a token carrying the matching OAuth scope. `cloud-platform` covers every API the relay
    // touches (all of which are Firestore today) so we don't have to enumerate per-API scopes.
    let url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform";
    let resp = http
        .get(url)
        .header("Metadata-Flavor", "Google")
        .send()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    v["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "no access_token".into())
}

/// A token with a ~50-minute cache (tokens last 1h).
fn cached_token(
    cache: &Mutex<Option<(String, Instant)>>,
    http: &reqwest::blocking::Client,
) -> Result<String, String> {
    if let Some((tok, at)) = cache.lock().unwrap().clone() {
        if at.elapsed() < Duration::from_secs(3000) {
            return Ok(tok);
        }
    }
    let tok = fetch_gcp_token(http)?;
    *cache.lock().unwrap() = Some((tok.clone(), Instant::now()));
    Ok(tok)
}

// ---------------------------------------------------------------------------
// Liveness registry (DESIGN.md §28): the passive discovery plane for the backbone.
// ---------------------------------------------------------------------------

/// An online peer relay discovered via the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// base58 node address (the relay's identity).
    pub node: String,
    pub region: String,
    /// Connectable endpoint for node-to-node links (e.g. `wss://eu-west1.relay.hopme.sh/`).
    pub endpoint: String,
    pub heartbeat_ms: u64,
}

/// Is a heartbeat still fresh? (A read of a stale entry means the node is offline.)
fn is_fresh(heartbeat_ms: u64, now_ms: u64, ttl_ms: u64) -> bool {
    now_ms.saturating_sub(heartbeat_ms) <= ttl_ms
}

/// The passive liveness registry. Online relays heartbeat a doc keyed by their node
/// id into a top-level `registry` collection; readers filter by freshness. **Reading
/// never wakes a node** (it's a Firestore read), so a node is only ever woken by its
/// own clients — never by a peer (DESIGN.md §28).
pub struct Registry {
    http: reqwest::blocking::Client,
    collection_url: String, // .../documents/registry
    me: String,             // our node id (excluded from `online`)
    token: Mutex<Option<(String, Instant)>>,
}

impl Registry {
    pub fn new(project: &str, node_addr: &[u8]) -> Self {
        let me = bs58::encode(node_addr).into_string();
        let base = "https://firestore.googleapis.com/v1";
        let collection_url =
            format!("{base}/projects/{project}/databases/(default)/documents/registry");
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            collection_url,
            me,
            token: Mutex::new(None),
        }
    }

    fn token(&self) -> Result<String, String> {
        cached_token(&self.token, &self.http)
    }

    /// Announce we're online (call on wake, then periodically). Idempotent upsert.
    pub fn heartbeat(&self, region: &str, endpoint: &str, now_ms: u64) -> Result<(), String> {
        let url = format!("{}/{}", self.collection_url, self.me);
        let body = registry_doc_json(&self.me, region, endpoint, now_ms);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("heartbeat {}", resp.status()))
        }
    }

    /// Currently-online peers (fresh heartbeat within `ttl_ms`), excluding ourselves.
    /// A pure Firestore read — wakes no one.
    pub fn online(&self, now_ms: u64, ttl_ms: u64) -> Result<Vec<PeerInfo>, String> {
        let token = self.token()?;
        let resp = self
            .http
            .get(&self.collection_url)
            .query(&[("pageSize", "300")])
            .bearer_auth(&token)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() == 404 {
            return Ok(Vec::new()); // no registry yet
        }
        if !resp.status().is_success() {
            return Err(format!("online {}", resp.status()));
        }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        if let Some(docs) = v["documents"].as_array() {
            for d in docs {
                if let Some(p) = parse_registry_doc(d) {
                    if p.node != self.me && is_fresh(p.heartbeat_ms, now_ms, ttl_ms) {
                        out.push(p);
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Build a Firestore document body for a registry heartbeat.
fn registry_doc_json(
    node: &str,
    region: &str,
    endpoint: &str,
    heartbeat_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "fields": {
            "node": { "stringValue": node },
            "region": { "stringValue": region },
            "endpoint": { "stringValue": endpoint },
            "heartbeatAt": { "integerValue": heartbeat_ms.to_string() },
            // F-20: timestampValue the Firestore TTL policy sweeps on, so stale registry rows self-expire.
            "expireAt": { "timestampValue": rfc3339_utc(heartbeat_ms + PRESENCE_DOC_TTL_MS) },
        }
    })
}

/// Parse a Firestore registry document into a [`PeerInfo`].
fn parse_registry_doc(d: &serde_json::Value) -> Option<PeerInfo> {
    let f = d.get("fields")?;
    Some(PeerInfo {
        node: f["node"]["stringValue"].as_str()?.to_string(),
        region: f["region"]["stringValue"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        endpoint: f["endpoint"]["stringValue"].as_str()?.to_string(),
        heartbeat_ms: f["heartbeatAt"]["integerValue"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Cross-partition handoff (DESIGN.md §28): the offline-destination mailbox.
// ---------------------------------------------------------------------------

/// A device's last-known region, learned from where it checked in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevicePresence {
    /// base58 device address.
    pub device: String,
    pub region: String,
    pub heartbeat_ms: u64,
}

/// The presence index + cross-partition write plane.
///
/// When a relay holds a `Device`-addressed bundle it can't deliver locally, it looks
/// up where that device was last seen (`region_of`) and writes the bundle into *that
/// region's own partition* (`put_bundle_to`, deriving the region's node address the
/// same way every node does — shared seed + region name). The destination region then
/// delivers it on its next cold-start / device check-in by rehydrating its partition.
///
/// Presence is a passive Firestore write/read: looking up a device's region **wakes no
/// node** — only the destination region's own clients ever wake it (DESIGN.md §28).
pub struct Presence {
    http: reqwest::blocking::Client,
    project: String,
    /// The Firestore REST base (`https://firestore.googleapis.com/v1` in production). A field, not a
    /// per-method literal, so the cross-partition URL builders below share one origin and tests can
    /// point them at a loopback responder.
    base: String,
    presence_url: String, // .../documents/presence
    token: Mutex<Option<(String, Instant)>>,
}

impl Presence {
    pub fn new(project: &str) -> Self {
        let base = "https://firestore.googleapis.com/v1";
        let presence_url =
            format!("{base}/projects/{project}/databases/(default)/documents/presence");
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            project: project.to_string(),
            base: base.to_string(),
            presence_url,
            token: Mutex::new(None),
        }
    }

    fn token(&self) -> Result<String, String> {
        cached_token(&self.token, &self.http)
    }

    /// Record that `device` (base58) checked in from `region`. Idempotent upsert.
    pub fn set_presence(&self, device: &str, region: &str, now_ms: u64) -> Result<(), String> {
        let url = format!("{}/{}", self.presence_url, device);
        let body = presence_doc_json(device, region, now_ms);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("set_presence {}", resp.status()))
        }
    }

    /// Where was `device` (base58) last seen, if its check-in is still fresh within
    /// `ttl_ms`? A pure read — wakes no node. `Ok(None)` means unknown or stale.
    pub fn region_of(
        &self,
        device: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<Option<String>, String> {
        let url = format!("{}/{}", self.presence_url, device);
        let token = self.token()?;
        let resp = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("region_of {}", resp.status()));
        }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        match parse_presence_doc(&v) {
            Some(p) if is_fresh(p.heartbeat_ms, now_ms, ttl_ms) => Ok(Some(p.region)),
            _ => Ok(None),
        }
    }

    /// List the bundles held in `node`'s (base58) partition, as `(sealed bytes,
    /// expires_at)`. A warm node polls **its own** partition this way to ingest
    /// cross-partition handoffs that landed after it started (cold starts get them via
    /// the store's rehydrate instead).
    pub fn list_bundles_of(&self, node: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let base = &self.base;
        let collection_url = format!(
            "{base}/projects/{}/databases/(default)/documents/relays/{node}/bundles",
            self.project
        );
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{collection_url}?pageSize=300");
            if let Some(t) = &page_token {
                url.push_str(&format!("&pageToken={t}"));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 404 {
                return Ok(out);
            }
            if !resp.status().is_success() {
                return Err(format!("list_bundles_of {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                for d in docs {
                    if let Some(pair) = parse_doc(d) {
                        out.push(pair);
                    }
                }
            }
            match v["nextPageToken"].as_str() {
                Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Write a bundle into `node`'s (base58) partition — used to hand a bundle off into
    /// the destination region's mailbox. The owning node ingests it on its next
    /// partition reload (warm) or cold-start rehydrate.
    pub fn put_bundle_to(
        &self,
        node: &str,
        id: &BundleId,
        data: &[u8],
        expires_at: u64,
    ) -> Result<(), String> {
        let base = &self.base;
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/relays/{node}/bundles/{doc}",
            self.project
        );
        let body = doc_json(data, expires_at);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("put_bundle_to {}", resp.status()))
        }
    }

    /// §39 P5 blind spool: durably hold a PRIVATE bundle keyed by its **mailbox-tag** (base58 of the
    /// 16-byte tag) — a rotatable pseudonym, NOT an address — so an offline recipient can pull it on
    /// return. A separate collection from the device-address inbox (`relays/{node}`); the relay never
    /// opens the sealed envelope. The recipient is unlinkable here except by the mailbox-tag while it
    /// lives (the §39 cost of being pull-reachable offline). Swept at its own §8 lifetime by the
    /// `expireAt` TTL policy on the `bundles` collection group (zero compute) — same policy that
    /// reaps the handoff inbox, since both collections share the `bundles` id.
    pub fn spool_to_mailbox(
        &self,
        tag_b58: &str,
        id: &BundleId,
        data: &[u8],
        expires_at: u64,
    ) -> Result<(), String> {
        let base = &self.base;
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles/{doc}",
            self.project
        );
        let body = doc_json(data, expires_at);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("spool_to_mailbox {}", resp.status()))
        }
    }

    /// §39 P5: list a mailbox-tag's spooled private bundles, as `(sealed bytes, expires_at)`. Pulled
    /// when that recipient's want-beacon arrives (it then re-ingests them; P4's gradient steers each).
    pub fn list_mailbox(&self, tag_b58: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let base = &self.base;
        let collection_url = format!(
            "{base}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles",
            self.project
        );
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{collection_url}?pageSize=300");
            if let Some(t) = &page_token {
                url.push_str(&format!("&pageToken={t}"));
            }
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 404 {
                return Ok(out); // mailbox empty / never spooled
            }
            if !resp.status().is_success() {
                return Err(format!("list_mailbox {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                for d in docs {
                    if let Some(pair) = parse_doc(d) {
                        out.push(pair);
                    }
                }
            }
            match v["nextPageToken"].as_str() {
                Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// §39 P5: drop one spooled bundle after it's been pulled (the recipient is now reachable, so
    /// P4's live gradient delivers it). Idempotent — a 404 (already gone / TTL-swept) is fine.
    pub fn delete_mailbox_bundle(&self, tag_b58: &str, id: &BundleId) -> Result<(), String> {
        let base = &self.base;
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles/{doc}",
            self.project
        );
        let token = self.token()?;
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("delete_mailbox_bundle {}", resp.status()))
        }
    }
}

/// Build a Firestore document body for a device presence record.
/// How long after its last heartbeat a presence/registry doc is allowed to persist before the
/// Firestore TTL sweeps it (F-20). A small multiple of the ~90s read-side staleness filter: the read
/// path already ignores anything this old, so deletion cannot regress routing — it only stops the
/// collection being an indefinitely-retained per-address→region location log (DESIGN §33).
const PRESENCE_DOC_TTL_MS: u64 = 3_600_000; // 1h

fn presence_doc_json(device: &str, region: &str, heartbeat_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "fields": {
            "device": { "stringValue": device },
            "region": { "stringValue": region },
            "heartbeatAt": { "integerValue": heartbeat_ms.to_string() },
            // F-20: timestampValue the Firestore TTL policy sweeps on, so presence self-expires.
            "expireAt": { "timestampValue": rfc3339_utc(heartbeat_ms + PRESENCE_DOC_TTL_MS) },
        }
    })
}

/// Parse a Firestore presence document into a [`DevicePresence`].
fn parse_presence_doc(d: &serde_json::Value) -> Option<DevicePresence> {
    let f = d.get("fields")?;
    Some(DevicePresence {
        device: f["device"]["stringValue"].as_str()?.to_string(),
        region: f["region"]["stringValue"].as_str()?.to_string(),
        heartbeat_ms: f["heartbeatAt"]["integerValue"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

/// Build a Firestore document body for a bundle.
fn doc_json(data: &[u8], expires_at: u64) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    serde_json::json!({
        "fields": {
            "data": { "bytesValue": b64 },
            // Integer epoch-millis — what `parse_doc` reads back.
            "expiresAt": { "integerValue": expires_at.to_string() },
            // RFC3339 timestamp — the field the ACTIVE Firestore TTL policy sweeps on. TTL acts
            // ONLY on a `timestampValue` field (an integer is silently ignored), so this is what
            // actually garbage-collects expired handoff/spool bundles at their §8 lifetime.
            "expireAt": { "timestampValue": rfc3339_utc(expires_at) },
        }
    })
}

/// Format epoch-milliseconds as an RFC3339 UTC timestamp (e.g. `"2001-09-09T01:46:40Z"`) — the
/// shape Firestore stores as a `timestampValue`, the only field type its TTL feature acts on.
/// Pure integer math (no date crate): civil-from-days per Howard Hinnant's `chrono` algorithm.
fn rfc3339_utc(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // civil_from_days: days since 1970-01-01 → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parse a Firestore document into `(bundle bytes, expires_at)`.
fn parse_doc(d: &serde_json::Value) -> Option<(Vec<u8>, u64)> {
    let fields = d.get("fields")?;
    let b64 = fields["data"]["bytesValue"].as_str()?;
    let data = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let expires = fields["expiresAt"]["integerValue"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((data, expires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::prelude::*;
    use std::sync::Arc;

    /// stores-11: an in-memory [`BundleMirror`] fake. Records every mirrored op in order and serves
    /// a scripted `list_bundles`/`list_kv` for rehydrate, so the Store impl is testable without
    /// Firestore. It also keeps a durable `kv` map (stores-07) so a "restart" (drop + reopen over
    /// the same shared state) recovers what was written.
    #[derive(Clone, Default)]
    struct FakeMirror {
        /// What `list_bundles` returns on open (rehydrate source).
        listing: Vec<(Vec<u8>, u64)>,
        /// Every put/delete the worker performs, in FIFO order.
        ops: Arc<Mutex<Vec<MirrorOp>>>,
        /// stores-07: the durable kv state, shared across a simulated restart.
        kv: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum MirrorOp {
        Put { id: BundleId, expires_at: u64 },
        Delete { id: BundleId },
        KvPut { key: String },
        KvDelete { key: String },
    }

    impl BundleMirror for FakeMirror {
        fn list_bundles(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
            Ok(self.listing.clone())
        }
        fn put_bundle(
            &self,
            id: &BundleId,
            _data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.ops.lock().unwrap().push(MirrorOp::Put {
                id: *id,
                expires_at,
            });
            Ok(())
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.ops.lock().unwrap().push(MirrorOp::Delete { id: *id });
            Ok(())
        }
        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            Ok(self
                .kv
                .lock()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.ops
                .lock()
                .unwrap()
                .push(MirrorOp::KvPut { key: key.into() });
            self.kv
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.ops
                .lock()
                .unwrap()
                .push(MirrorOp::KvDelete { key: key.into() });
            self.kv.lock().unwrap().remove(key);
            Ok(())
        }
    }

    /// A mirror whose writes always fail (a degraded/offline Firestore), used for stores-09
    /// backpressure. Every put/delete errors, so the worker exhausts its retries and the op stays a
    /// long time in flight -- letting the bounded queue back up so drop-oldest kicks in.
    #[derive(Clone, Default)]
    struct FailingMirror {
        /// Bumped every time the worker actually attempts a bundle write (to prove it kept trying).
        attempts: Arc<AtomicU64>,
    }
    impl BundleMirror for FailingMirror {
        fn list_bundles(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
            Ok(Vec::new())
        }
        fn put_bundle(
            &self,
            _id: &BundleId,
            _data: &[u8],
            _e: u64,
        ) -> std::result::Result<(), String> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            // Block a beat so the queue fills faster than the worker drains it (simulates a slow,
            // failing backend), then fail so the op is retried.
            std::thread::sleep(Duration::from_millis(5));
            Err("backend down".into())
        }
        fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
            std::thread::sleep(Duration::from_millis(5));
            Err("backend down".into())
        }
    }

    fn sample(copies: u16) -> Bundle {
        let from = Identity::generate();
        let to = Identity::generate();
        Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"durable me".to_vec(),
            },
            BundleOpts {
                copies,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn rehydrate_preserves_the_stored_expiry_anchor() {
        // stores-02/stores-11: rehydrate must reinstate each bundle's REAL absolute deadline, not
        // re-anchor at now+lifetime. A far-future expiry survives; an already-past expiry (incl. 0,
        // see stores-r3-02) is skipped entirely.
        let live = sample(4);
        let live_id = live.id();
        let expired = sample(4);
        let expired_id = expired.id();
        let far_future = epoch_ms() + 60 * 60 * 1000;

        let mirror = FakeMirror {
            listing: vec![
                (live.to_bytes().unwrap(), far_future),
                (expired.to_bytes().unwrap(), 1), // epoch-ms 1: long past
            ],
            ..Default::default()
        };
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();

        assert!(store.contains(&live_id), "live bundle rehydrated");
        assert!(
            store.seen(&live_id),
            "dedup seen reinstated for live bundle"
        );
        assert!(
            !store.contains(&expired_id),
            "already-expired bundle must not be resurrected"
        );

        // The stored deadline (not now+lifetime) governs: a prune just before it keeps the bundle,
        // a prune just after it drops it. If rehydrate had re-anchored, this would misbehave.
        let mut store = store;
        store.prune(far_future - 1);
        assert!(store.contains(&live_id), "kept until its stored deadline");
        store.prune(far_future + 1);
        assert!(
            !store.contains(&live_id),
            "dropped past its stored deadline"
        );
    }

    #[test]
    fn rehydrate_does_not_resurrect_a_zero_expiry_bundle() {
        // stores-r3-02: the old code special-cased a stored `expires == 0` as a "never-expire"
        // sentinel and did put_with_expiry(_, 0). But MemoryStore::prune drops any id with
        // `exp <= now_ms`, and `0 <= now_ms` is ALWAYS true, so that bundle was wiped on the FIRST
        // real-clock prune (~1s after cold start): the sentinel was false. The contract is now
        // honest — a 0 (or any past) expiry is treated as already-expired and NOT resurrected, so
        // there is no phantom bundle that appears rehydrated only to vanish on the next prune.
        let zero = sample(4);
        let zero_id = zero.id();
        let live = sample(4);
        let live_id = live.id();
        let far_future = epoch_ms() + 60 * 60 * 1000;

        let mirror = FakeMirror {
            listing: vec![
                (zero.to_bytes().unwrap(), 0), // the (former) "never-expire" sentinel
                (live.to_bytes().unwrap(), far_future), // a normal live bundle for contrast
            ],
            ..Default::default()
        };
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        assert!(
            !store.contains(&zero_id),
            "a 0-expiry doc is treated as past and is NOT resurrected (no phantom bundle)"
        );
        assert!(
            !store.seen(&zero_id),
            "and it does not poison the dedup set with a doomed 0-expiry seen row"
        );
        assert!(
            store.contains(&live_id),
            "the live bundle is still rehydrated"
        );

        // A prune at real 'now' must not surprise anyone: nothing 0-related lingers to be reaped,
        // and the live bundle survives (it was never the 0 case).
        store.prune(epoch_ms());
        assert!(
            store.contains(&live_id),
            "the live future-dated bundle survives a real-clock prune"
        );
    }

    #[test]
    fn flush_drains_mirror_ops_in_fifo_order() {
        // F-21/stores-11: flush() must block until the FIFO writer has attempted every prior
        // put/delete, and the mirror must see them in submission order.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let a = sample(4);
        let a_id = a.id();
        let b = sample(4);
        let b_id = b.id();
        assert!(store.put(a, 1_000));
        assert!(store.put(b, 2_000));
        store.remove(&a_id);

        assert!(
            store.flush(std::time::Duration::from_secs(5)),
            "flush must drain within the timeout"
        );

        let recorded = ops.lock().unwrap().clone();
        // Assert FIFO order + ids: put(a), put(b), delete(a). (Only bundle ops here.)
        let shape: Vec<(&str, BundleId)> = recorded
            .iter()
            .filter_map(|op| match op {
                MirrorOp::Put { id, .. } => Some(("put", *id)),
                MirrorOp::Delete { id } => Some(("delete", *id)),
                MirrorOp::KvPut { .. } | MirrorOp::KvDelete { .. } => None,
            })
            .collect();
        assert_eq!(
            shape,
            vec![("put", a_id), ("put", b_id), ("delete", a_id)],
            "mirror sees put(a), put(b), delete(a) in FIFO order"
        );
        // Each put's expiry is anchored at its own now_ms (1000+lt vs 2000+lt), so they differ by
        // exactly the gap between the two put timestamps.
        let expiry = |id: &BundleId| -> u64 {
            recorded
                .iter()
                .find_map(|op| match op {
                    MirrorOp::Put { id: i, expires_at } if i == id => Some(*expires_at),
                    _ => None,
                })
                .expect("put recorded")
        };
        assert_eq!(
            expiry(&b_id) - expiry(&a_id),
            1_000,
            "each put's expiry is anchored at its own now_ms"
        );
    }

    /// stores-r2-01: build a bundle with an explicit `created_at`/`lifetime_ms` so a test can force
    /// the sender-clock skew that the re-anchor bug depended on.
    fn sample_with(copies: u16, created_at: u64, lifetime_ms: u32) -> Bundle {
        let from = Identity::generate();
        let to = Identity::generate();
        Bundle::create(
            &from,
            Destination::Device(to.address()),
            &to.address(),
            &Payload::PeerMessage {
                content_type: "t".into(),
                body: b"durable me".to_vec(),
            },
            BundleOpts {
                copies,
                created_at,
                lifetime_ms,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn split_copies_remirror_uses_receiver_anchored_expiry_not_created_at() {
        // stores-r2-01: a spray-and-wait split (or retransmit set_copies) on a RELAYED bundle whose
        // sender stamped created_at=0 (advisory, defaults to 0) must NOT re-anchor the durable doc's
        // expiry at created_at+lifetime (which lands ~1970 -> the Firestore TTL sweeps a still-live
        // spooled/handoff bundle early, silently dropping an offline recipient's message). The
        // re-mirror must reuse the receiver-anchored expiry recorded at put() time.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let lifetime_ms: u32 = 3_600_000; // 1h
        let now_ms: u64 = 10_000_000_000; // a real epoch-ms (well past 1970)
        let b = sample_with(4, /*created_at=*/ 0, lifetime_ms);
        let id = b.id();
        assert!(store.put(b, now_ms));

        // Force a spray-and-wait split, which re-mirrors the (now decremented) bundle.
        let gave = store.split_copies(&id);
        assert!(gave > 0, "split handed out at least one copy");
        assert!(store.flush(std::time::Duration::from_secs(5)));

        let recorded = ops.lock().unwrap().clone();
        // Two puts recorded for this id: the initial put and the split re-mirror. BOTH must carry the
        // receiver-anchored expiry (now + lifetime), never created_at(0) + lifetime.
        let put_expiries: Vec<u64> = recorded
            .iter()
            .filter_map(|op| match op {
                MirrorOp::Put { id: i, expires_at } if *i == id => Some(*expires_at),
                _ => None,
            })
            .collect();
        assert_eq!(put_expiries.len(), 2, "initial put + split re-mirror");
        let want = now_ms + lifetime_ms as u64;
        for e in &put_expiries {
            assert_eq!(
                *e, want,
                "re-mirror must reuse the receiver-anchored expiry (now+lifetime), \
                 not created_at(0)+lifetime={}",
                lifetime_ms
            );
            assert!(
                *e > now_ms,
                "expiry is in the FUTURE from the receiver clock, not ~1970"
            );
        }
    }

    #[test]
    fn set_copies_remirror_uses_receiver_anchored_expiry() {
        // stores-r2-01 twin: the retransmit set_copies path re-mirrors too, and must also carry the
        // receiver-anchored expiry rather than the sender's advisory created_at.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let lifetime_ms: u32 = 7_200_000; // 2h
        let now_ms: u64 = 12_000_000_000;
        let b = sample_with(4, /*created_at=*/ 0, lifetime_ms);
        let id = b.id();
        assert!(store.put(b, now_ms));
        store.set_copies(&id, 2);
        assert!(store.flush(std::time::Duration::from_secs(5)));

        let want = now_ms + lifetime_ms as u64;
        let recorded = ops.lock().unwrap().clone();
        let last_put = recorded
            .iter()
            .rev()
            .find_map(|op| match op {
                MirrorOp::Put { id: i, expires_at } if *i == id => Some(*expires_at),
                _ => None,
            })
            .expect("set_copies re-mirrored a put");
        assert_eq!(
            last_put, want,
            "set_copies re-mirror uses the receiver-anchored expiry"
        );
    }

    #[test]
    fn put_clamps_durable_expiry_and_rehydrate_bounds_a_hostile_window() {
        // stores-r2-03: a §39 bundle with a hostile ~49-day lifetime_ms must not write a 49-day
        // durable expiresAt (clamp on the write side to MAX_SEEN_LIFETIME_MS), AND a doc that
        // somehow carries a 49-day expiry (a pre-fix relay) must not reinstate a 49-day dedup window
        // on cold-start rehydrate.
        let now_ms: u64 = 20_000_000_000;
        let hostile_lifetime: u32 = u32::MAX; // ~49 days
        let clamp = hop_core::store::MAX_SEEN_LIFETIME_MS;

        // (a) write-side clamp: put() must mirror an expiry no larger than now + clamp.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        let b = sample_with(1, /*created_at=*/ now_ms, hostile_lifetime);
        let id = b.id();
        assert!(store.put(b, now_ms));
        assert!(store.flush(std::time::Duration::from_secs(5)));
        let mirrored = ops
            .lock()
            .unwrap()
            .iter()
            .find_map(|op| match op {
                MirrorOp::Put { id: i, expires_at } if *i == id => Some(*expires_at),
                _ => None,
            })
            .expect("put mirrored");
        assert_eq!(
            mirrored,
            now_ms + clamp,
            "durable expiry clamped to now + MAX_SEEN_LIFETIME_MS, not now + ~49 days"
        );

        // (b) rehydrate clamp: a durable doc carrying a raw ~49-day expiry must reinstate a dedup
        // window bounded to now + clamp, so a prune just past the clamp drops it (the hostile window
        // does NOT survive a scale cycle). Anchor against the REAL wall clock (open_with_mirror uses
        // epoch_ms), so the stored expiry is genuinely ~49 days in the future, not already past.
        let real_now = epoch_ms();
        let hostile_expiry = real_now + hostile_lifetime as u64; // ~49 days out from real now
        let held = sample_with(1, now_ms, hostile_lifetime);
        let held_id = held.id();
        let mirror2 = FakeMirror {
            listing: vec![(held.to_bytes().unwrap(), hostile_expiry)],
            ..Default::default()
        };
        // open_with_mirror anchors the clamp against the real wall clock (epoch_ms). The bundle is
        // rehydrated live, but its dedup deadline is bounded to ~now + one week, well before the
        // ~49-day hostile deadline.
        let mut store2 = FirestoreStore::open_with_mirror(mirror2).unwrap();
        assert!(store2.contains(&held_id), "live bundle still rehydrated");
        // A prune just past the clamped window drops it; if the raw 49-day expiry had been
        // reinstated, it would survive here.
        store2.prune(epoch_ms() + clamp + 1);
        assert!(
            !store2.contains(&held_id),
            "hostile 49-day dedup window was clamped to one week on rehydrate"
        );
    }

    #[test]
    fn drop_drains_pending_mirror_ops_without_explicit_flush() {
        // stores-r2-05: a store dropped WITHOUT a preceding flush() (panic / early return) must still
        // best-effort drain its enqueued ops to the durable mirror, not silently lose them.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();

        let put_id = {
            let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
            let b = sample(2);
            let id = b.id();
            assert!(store.put(b, 1_000));
            // Intentionally NO flush(): drop the store and rely on Drop's bounded join to drain.
            id
        }; // <- Drop runs here

        let recorded = ops.lock().unwrap().clone();
        assert!(
            recorded
                .iter()
                .any(|op| matches!(op, MirrorOp::Put { id, .. } if *id == put_id)),
            "Drop must drain the enqueued put to the durable mirror (no flush() called)"
        );
    }

    #[test]
    fn remove_mirrors_a_delete_only_when_present() {
        // stores-11: remove() must mirror a Delete when the bundle was actually held, and NOT emit a
        // spurious Delete for an id that was never there.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let b = sample(4);
        let id = b.id();
        let absent = sample(4).id();

        store.put(b, 0);
        assert!(store.remove(&id).is_some());
        assert!(store.remove(&absent).is_none(), "absent id removes nothing");

        assert!(store.flush(std::time::Duration::from_secs(5)));
        let recorded = ops.lock().unwrap().clone();
        let deletes: Vec<_> = recorded
            .iter()
            .filter(|op| matches!(op, MirrorOp::Delete { .. }))
            .collect();
        assert_eq!(
            deletes,
            vec![&MirrorOp::Delete { id }],
            "exactly one delete, for the held id only"
        );
    }

    #[test]
    fn kv_round_trips_and_survives_a_simulated_restart() {
        // stores-07: kv writes must mirror through the same seam as bundles, be readable in-process,
        // and survive a scale cycle (drop the store, reopen over the SAME durable mirror state).
        let mirror = FakeMirror::default();

        {
            let mut store = FirestoreStore::open_with_mirror(mirror.clone()).unwrap();
            store.put_kv("session/peerX", b"ratchet-state".to_vec());
            store.put_kv("prekey/secret", b"xk".to_vec());
            store.put_kv("doomed", b"bye".to_vec());
            store.remove_kv("doomed");
            // In-process reads are authoritative immediately (no Firestore round-trip needed).
            assert_eq!(
                store.get_kv("session/peerX"),
                Some(b"ratchet-state".to_vec())
            );
            assert_eq!(store.get_kv("doomed"), None);
            let mut sessions = store.list_kv("session/");
            sessions.sort();
            assert_eq!(
                sessions,
                vec![("session/peerX".to_string(), b"ratchet-state".to_vec())]
            );
            // Drain the mirror so every kv op has been applied to the durable fake before we drop.
            assert!(
                store.flush(Duration::from_secs(5)),
                "mirror drained before restart"
            );
        } // store dropped == relay scaled to zero

        // "Restart": a fresh store over the SAME durable mirror state must rehydrate kv (stores-07's
        // whole point: relay-hosted forward-secret sessions survive scale-to-zero, no re-secure churn).
        let restarted = FirestoreStore::open_with_mirror(mirror.clone()).unwrap();
        assert_eq!(
            restarted.get_kv("session/peerX"),
            Some(b"ratchet-state".to_vec()),
            "session survived the scale cycle"
        );
        assert_eq!(restarted.get_kv("prekey/secret"), Some(b"xk".to_vec()));
        assert_eq!(
            restarted.get_kv("doomed"),
            None,
            "a removed key must not resurrect on restart"
        );
    }

    #[test]
    fn kv_doc_round_trips_through_firestore_encoding() {
        // stores-07: a kv key that contains '/' (illegal in a Firestore doc id) and a value with
        // arbitrary bytes must round-trip: the original key is carried as a field and recovered.
        let json = kv_doc_json("session/peer\u{1f600}", b"\x00\x01\xff bytes");
        let doc = serde_json::json!({ "name": "x", "fields": json["fields"] });
        let (key, value) = parse_kv_doc(&doc).expect("parse");
        assert_eq!(key, "session/peer\u{1f600}");
        assert_eq!(value, b"\x00\x01\xff bytes");
    }

    #[test]
    fn mirror_queue_is_bounded_and_drops_oldest_under_a_failing_backend() {
        // stores-09: with a slow/failing Firestore the backlog must NOT grow without bound. We flood
        // far past the cap against a mirror whose writes fail (so ops linger in flight), and assert
        // (1) the queue never exceeds the cap, and (2) the shed ops are COUNTED (mirror_dropped),
        // rather than silently lost while put() keeps returning true.
        let mirror = FailingMirror::default();
        let attempts = mirror.attempts.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let flood = MIRROR_QUEUE_CAP + 5_000;
        for i in 0..flood {
            // Distinct ids so each is a real enqueue (put dedups on id).
            let b = sample(4);
            store.put(b, i as u64);
            // The queue length is an internal detail; assert the invariant via the public counter +
            // the fact that we never OOM. Peek the backlog directly to prove the bound holds.
            let qlen = store.tx.queue.0.lock().unwrap().ops.len();
            assert!(
                qlen <= MIRROR_QUEUE_CAP,
                "backlog {qlen} must never exceed the cap {MIRROR_QUEUE_CAP}"
            );
        }

        // We enqueued far more than the cap against a backend that can't keep up, so a large number
        // of ops must have been shed - and counted, not silently dropped.
        assert!(
            store.mirror_dropped() > 0,
            "sustained backpressure must shed (and count) oldest ops"
        );
        // Sanity: the worker really was attempting writes against the failing backend.
        assert!(
            attempts.load(Ordering::Relaxed) > 0,
            "the worker kept attempting writes against the degraded backend"
        );
    }

    #[test]
    fn a_flush_sentinel_is_never_dropped_even_at_the_cap() {
        // stores-09: drop-oldest must never discard a Flush ack (it carries the caller's channel), or
        // flush() could block forever. Fill PAST the cap (so drop-oldest is actively running) with a
        // fast mirror, then flush must still resolve - the sentinel rides through and is acked once
        // the backlog ahead of it clears. The invariant proven: shedding never touches a Flush.
        let mut store = FirestoreStore::open_with_mirror(FakeMirror::default()).unwrap();
        for i in 0..(MIRROR_QUEUE_CAP + 5_000) {
            store.put(sample(4), i as u64);
        }
        assert!(
            store.flush(Duration::from_secs(30)),
            "flush must complete; the sentinel is never drop-oldest'd"
        );
    }

    #[test]
    fn doc_round_trips_through_firestore_encoding() {
        let data = b"sealed bundle bytes \x00\x01\xff".to_vec();
        let json = doc_json(&data, 123_456);
        // Re-shape as a Firestore document (the API nests fields under "fields").
        let doc = serde_json::json!({ "name": "x", "fields": json["fields"] });
        let (got, expires) = parse_doc(&doc).expect("parse");
        assert_eq!(got, data);
        assert_eq!(expires, 123_456);
    }

    #[test]
    fn doc_carries_a_timestamp_for_ttl() {
        // The TTL policy is on `expireAt` and only acts on a `timestampValue`, so every doc
        // must carry one (an integer-only doc would never be swept — the bug this guards).
        let json = doc_json(b"x", 1_000_000_000_000); // 2001-09-09T01:46:40Z
        assert_eq!(
            json["fields"]["expireAt"]["timestampValue"],
            "2001-09-09T01:46:40Z"
        );
    }

    #[test]
    fn rfc3339_utc_matches_known_epochs() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000_000), "2001-09-09T01:46:40Z"); // Unix billennium
        assert_eq!(rfc3339_utc(1_700_000_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn parse_doc_rejects_garbage() {
        assert!(parse_doc(&serde_json::json!({"name": "x"})).is_none());
    }

    #[test]
    fn registry_doc_round_trips() {
        let json = registry_doc_json(
            "Node123",
            "eu-west1",
            "wss://eu-west1.relay.hopme.sh/",
            9000,
        );
        let doc = serde_json::json!({ "name": "x", "fields": json["fields"] });
        let p = parse_registry_doc(&doc).expect("parse");
        assert_eq!(p.node, "Node123");
        assert_eq!(p.region, "eu-west1");
        assert_eq!(p.endpoint, "wss://eu-west1.relay.hopme.sh/");
        assert_eq!(p.heartbeat_ms, 9000);
    }

    #[test]
    fn parse_registry_doc_rejects_garbage() {
        assert!(parse_registry_doc(&serde_json::json!({"name": "x"})).is_none());
    }

    #[test]
    fn presence_doc_round_trips() {
        let json = presence_doc_json("Dev9", "europe-north1", 4242);
        let doc = serde_json::json!({ "name": "x", "fields": json["fields"] });
        let p = parse_presence_doc(&doc).expect("parse");
        assert_eq!(p.device, "Dev9");
        assert_eq!(p.region, "europe-north1");
        assert_eq!(p.heartbeat_ms, 4242);
    }

    #[test]
    fn parse_presence_doc_rejects_garbage() {
        assert!(parse_presence_doc(&serde_json::json!({"name": "x"})).is_none());
    }

    #[test]
    fn freshness_is_a_ttl_window() {
        assert!(is_fresh(1_000, 1_000, 90_000), "same instant is fresh");
        assert!(is_fresh(1_000, 90_000, 90_000), "within ttl is fresh");
        assert!(
            !is_fresh(1_000, 200_000, 90_000),
            "past ttl is stale (offline)"
        );
    }

    #[test]
    fn freshness_never_underflows_with_a_future_heartbeat() {
        // is_fresh uses saturating_sub: a heartbeat clock AHEAD of the reader's `now` (clock skew
        // between regions) must read as fresh, not wrap around to a huge stale value. A raw
        // `now - heartbeat` would panic/underflow here.
        assert!(
            is_fresh(/*heartbeat*/ 5_000, /*now*/ 1_000, /*ttl*/ 90_000),
            "a heartbeat from a clock ahead of us is still fresh, not a wrapped-underflow stale"
        );
    }

    // ------------------------------------------------------------------------------------------
    // Store-trait passthroughs against the injected fake (stores-11 seam). These assert the
    // FirestoreStore forwards to its in-memory hot path AND mirrors the right durable op, which is
    // the whole contract: the relay reads memory, Firestore just has to agree.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn have_and_get_reflect_held_bundles_after_put_and_remove() {
        // have()/get()/contains() must track exactly what put()/remove() changed. A regression that
        // mirrored durably but forgot the in-memory hot path would fail here (the relay reads memory).
        let mut store = FirestoreStore::open_with_mirror(FakeMirror::default()).unwrap();
        let a = sample(4);
        let a_id = a.id();
        let b = sample(4);
        let b_id = b.id();

        assert!(store.get(&a_id).is_none(), "nothing held before put");
        assert!(store.have().ids.is_empty(), "have() empty before put");

        assert!(store.put(a, 1_000));
        assert!(store.put(b, 1_000));
        assert!(store.contains(&a_id) && store.contains(&b_id));
        assert!(store.get(&a_id).is_some(), "get returns the held bundle");
        let mut held = store.have().ids;
        held.sort();
        let mut want = vec![a_id, b_id];
        want.sort();
        assert_eq!(held, want, "have() lists exactly the two held ids");

        assert!(store.remove(&a_id).is_some());
        assert!(!store.contains(&a_id), "removed id no longer held");
        assert_eq!(store.have().ids, vec![b_id], "have() drops the removed id");
        // seen() outlives remove() (dedup window is retained past custody handoff).
        assert!(store.seen(&a_id), "removed bundle is still deduped (seen)");
    }

    #[test]
    fn seen_expiry_exposes_the_receiver_anchored_deadline() {
        // stores-r3-01: seen_expiry must surface the SAME clamped now+lifetime the durable put()
        // mirrored, so the handoff/spool path anchors Firestore's expireAt to the receiver clock.
        let mut store = FirestoreStore::open_with_mirror(FakeMirror::default()).unwrap();
        let lifetime_ms: u32 = 3_600_000;
        let now_ms: u64 = 50_000_000_000;
        let b = sample_with(4, /*created_at=*/ 0, lifetime_ms);
        let id = b.id();
        assert!(
            store.seen_expiry(&id).is_none(),
            "unknown id has no deadline"
        );
        assert!(store.put(b, now_ms));
        assert_eq!(
            store.seen_expiry(&id),
            Some(now_ms + lifetime_ms as u64),
            "seen_expiry is the receiver-anchored now+lifetime, the durable TTL anchor"
        );
    }

    #[test]
    fn put_returning_false_for_a_duplicate_does_not_mirror_twice() {
        // put() must mirror a durable Write only when the in-memory put actually stored the bundle.
        // A second put() of the same id inside the dedup window returns false and must NOT enqueue a
        // second mirror op (else a duplicate flood would re-write Firestore per copy).
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        // Build one bundle, keep its bytes so we can submit the identical id twice.
        let b = sample(4);
        let id = b.id();
        let again = Bundle::from_bytes(&b.to_bytes().unwrap()).unwrap();

        assert!(store.put(b, 1_000), "first put stores it");
        assert!(!store.put(again, 1_000), "second put is a dedup (false)");
        assert!(store.flush(Duration::from_secs(5)));

        let puts: Vec<_> = ops
            .lock()
            .unwrap()
            .iter()
            .filter(|op| matches!(op, MirrorOp::Put { id: i, .. } if *i == id))
            .cloned()
            .collect();
        assert_eq!(
            puts.len(),
            1,
            "a deduped put must mirror exactly once, not twice"
        );
    }

    #[test]
    fn split_copies_at_one_does_not_remirror() {
        // split_copies returns 0 when the budget is 1 (nothing to hand out). remirror() must be
        // skipped in that case -- a spurious re-mirror of an un-split bundle is wasted durable I/O.
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let b = sample(1); // single copy: split hands out floor(1/2) = 0
        let id = b.id();
        assert!(store.put(b, 1_000));
        assert!(store.flush(Duration::from_secs(5)));
        let puts_before = ops
            .lock()
            .unwrap()
            .iter()
            .filter(|op| matches!(op, MirrorOp::Put { .. }))
            .count();

        assert_eq!(store.split_copies(&id), 0, "a 1-copy bundle splits to 0");
        assert!(store.flush(Duration::from_secs(5)));
        let puts_after = ops
            .lock()
            .unwrap()
            .iter()
            .filter(|op| matches!(op, MirrorOp::Put { .. }))
            .count();
        assert_eq!(
            puts_before, puts_after,
            "split_copies==0 must NOT re-mirror the bundle"
        );
    }

    #[test]
    fn mirror_dropped_handle_shares_the_live_counter() {
        // The /healthz supervisor reads the dropped counter via a shared handle from ANOTHER thread
        // without owning the driver-owned store. The handle must observe the SAME atomic the store
        // bumps, not a detached snapshot.
        let store = FirestoreStore::open_with_mirror(FakeMirror::default()).unwrap();
        let handle = store.mirror_dropped_handle();
        assert_eq!(handle.load(Ordering::Relaxed), 0);
        // Bump the counter the same way backpressure does; the handle must see it live.
        store.dropped.fetch_add(3, Ordering::Relaxed);
        assert_eq!(
            handle.load(Ordering::Relaxed),
            3,
            "the handle aliases the store's live dropped counter"
        );
        assert_eq!(store.mirror_dropped(), 3, "and mirror_dropped() agrees");
    }

    /// A mirror that FAILS its first `fail_first` put attempts per op, then succeeds. Used to prove
    /// the worker's retry loop actually re-attempts and eventually persists (stores durability under
    /// a transient blip, not a permanent outage).
    #[derive(Clone)]
    struct FlakyMirror {
        fail_first: u64,
        attempts: Arc<AtomicU64>,
        succeeded: Arc<Mutex<Vec<BundleId>>>,
    }
    impl BundleMirror for FlakyMirror {
        fn list_bundles(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
            Ok(Vec::new())
        }
        fn put_bundle(
            &self,
            id: &BundleId,
            _data: &[u8],
            _e: u64,
        ) -> std::result::Result<(), String> {
            let n = self.attempts.fetch_add(1, Ordering::Relaxed);
            if n < self.fail_first {
                Err("transient".into())
            } else {
                self.succeeded.lock().unwrap().push(*id);
                Ok(())
            }
        }
        fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn worker_retries_a_transient_failure_and_eventually_persists() {
        // The background writer retries a failed mirror op (up to 3 attempts, backing off). A backend
        // that fails once then recovers must still get the durable write, not drop it after the first
        // error. This exercises the retry branch (attempt loop) end-to-end.
        let mirror = FlakyMirror {
            fail_first: 1, // fail the first attempt, succeed the second
            attempts: Arc::new(AtomicU64::new(0)),
            succeeded: Arc::new(Mutex::new(Vec::new())),
        };
        let attempts = mirror.attempts.clone();
        let succeeded = mirror.succeeded.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        let b = sample(4);
        let id = b.id();
        assert!(store.put(b, 1_000));
        assert!(
            store.flush(Duration::from_secs(5)),
            "flush drains after the retry succeeds"
        );

        assert!(
            attempts.load(Ordering::Relaxed) >= 2,
            "the worker re-attempted after the first failure"
        );
        assert_eq!(
            succeeded.lock().unwrap().as_slice(),
            &[id],
            "the op was persisted on the retry, not dropped after the first error"
        );
    }

    /// A mirror whose first put_bundle blocks until released, so the worker parks on that op and the
    /// FIFO behind it (including a Flush sentinel) can't drain. Used to prove flush() honors its
    /// timeout instead of hanging when the writer is stuck on a wedged backend.
    #[derive(Clone)]
    struct BlockingMirror {
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
    }
    impl BundleMirror for BlockingMirror {
        fn list_bundles(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
            Ok(Vec::new())
        }
        fn put_bundle(
            &self,
            _id: &BundleId,
            _d: &[u8],
            _e: u64,
        ) -> std::result::Result<(), String> {
            // Park here until the test releases the gate, wedging the single writer thread.
            let (lock, cvar) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cvar.wait(released).unwrap();
            }
            Ok(())
        }
        fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn flush_times_out_when_the_worker_is_wedged() {
        // flush() must return FALSE (not hang) when the writer can't drain in time. We wedge the
        // worker on a blocking put_bundle so the Flush sentinel behind it never gets acked; the
        // recv_timeout must expire and flush() reports failure. Then we release the gate and a second
        // flush must succeed, proving the store recovers once the backend un-wedges.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let mirror = BlockingMirror { gate: gate.clone() };
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        // Enqueue a put the worker will block on, so everything behind it (the flush sentinel) waits.
        assert!(store.put(sample(4), 1_000));

        let start = Instant::now();
        let ok = store.flush(Duration::from_millis(150));
        let elapsed = start.elapsed();
        assert!(!ok, "flush must report failure while the writer is wedged");
        assert!(
            elapsed >= Duration::from_millis(150),
            "flush waited out its timeout, not returned early"
        );

        // Release the wedged worker; the backlog drains and a fresh flush now succeeds.
        {
            let (lock, cvar) = &*gate;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        assert!(
            store.flush(Duration::from_secs(5)),
            "flush succeeds once the backend un-wedges and the backlog drains"
        );
    }

    #[test]
    fn default_bundle_mirror_kv_methods_are_noop_ok() {
        // A bundle-only backend (no kv surface) must compile AND behave: the default kv methods
        // return an empty listing and succeed silently, so a FirestoreStore over such a mirror still
        // opens and its kv writes never error out the worker.
        struct BundleOnly;
        impl BundleMirror for BundleOnly {
            fn list_bundles(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
                Ok(Vec::new())
            }
            fn put_bundle(
                &self,
                _id: &BundleId,
                _d: &[u8],
                _e: u64,
            ) -> std::result::Result<(), String> {
                Ok(())
            }
            fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
                Ok(())
            }
            // kv methods intentionally NOT overridden -> exercise the trait defaults.
        }
        let m = BundleOnly;
        assert!(m.list_kv().unwrap().is_empty(), "default list_kv is empty");
        assert!(m.put_kv("k", b"v").is_ok(), "default put_kv is ok");
        assert!(m.delete_kv("k").is_ok(), "default delete_kv is ok");

        // And a store over it opens (rehydrates zero kv) and mirrors a kv write without wedging.
        let mut store = FirestoreStore::open_with_mirror(BundleOnly).unwrap();
        store.put_kv("session/x", b"s".to_vec());
        assert_eq!(store.get_kv("session/x"), Some(b"s".to_vec()));
        assert!(
            store.flush(Duration::from_secs(5)),
            "kv write drains against a default (no-op) kv backend"
        );
    }

    #[test]
    fn open_rehydrates_both_bundles_and_kv_together() {
        // open() loads BOTH durable surfaces: a live bundle listing AND the kv side store, in one
        // pass. A cold-started relay must come back with its held mailbox and its forward-secret
        // sessions, so this asserts both are present after a fresh open over pre-populated state.
        let live = sample(4);
        let live_id = live.id();
        let far_future = epoch_ms() + 60 * 60 * 1000;
        let kv = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        kv.lock()
            .unwrap()
            .insert("session/peerZ".to_string(), b"ratchet".to_vec());
        let mirror = FakeMirror {
            listing: vec![(live.to_bytes().unwrap(), far_future)],
            ops: Arc::new(Mutex::new(Vec::new())),
            kv,
        };
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();
        assert!(store.contains(&live_id), "held bundle rehydrated on open");
        assert_eq!(
            store.get_kv("session/peerZ"),
            Some(b"ratchet".to_vec()),
            "kv session rehydrated on open in the same pass"
        );
    }

    #[test]
    fn registry_doc_carries_a_ttl_timestamp_and_survives_a_roundtrip() {
        // F-20: a registry heartbeat doc must carry an `expireAt` timestampValue (the ONLY field the
        // Firestore TTL policy sweeps) set to heartbeat + PRESENCE_DOC_TTL_MS, so stale registry rows
        // self-expire instead of retaining an indefinite node->region log. Also assert the integer
        // fields round-trip through parse.
        let hb: u64 = 1_700_000_000_000; // 2023-11-14T22:13:20Z
        let json = registry_doc_json("N1", "us-central1", "wss://x/", hb);
        assert_eq!(
            json["fields"]["expireAt"]["timestampValue"],
            rfc3339_utc(hb + PRESENCE_DOC_TTL_MS),
            "registry TTL timestamp is heartbeat + 1h"
        );
        let doc = serde_json::json!({ "name": "x", "fields": json["fields"] });
        let p = parse_registry_doc(&doc).unwrap();
        assert_eq!((p.node.as_str(), p.heartbeat_ms), ("N1", hb));
    }

    #[test]
    fn presence_doc_carries_a_ttl_timestamp() {
        // F-20 twin for presence: the location record must self-expire via an `expireAt`
        // timestampValue at heartbeat + PRESENCE_DOC_TTL_MS (DESIGN §33: no indefinite location log).
        let hb: u64 = 1_700_000_000_000;
        let json = presence_doc_json("Dev1", "eu-west1", hb);
        assert_eq!(
            json["fields"]["expireAt"]["timestampValue"],
            rfc3339_utc(hb + PRESENCE_DOC_TTL_MS),
            "presence TTL timestamp is heartbeat + 1h"
        );
    }

    #[test]
    fn parse_kv_doc_rejects_a_doc_missing_the_value() {
        // parse_kv_doc must reject a malformed doc (key present, value bytes missing) rather than
        // panic or invent an empty value -- a half-written kv row must be skipped on rehydrate.
        let doc = serde_json::json!({
            "name": "x",
            "fields": { "key": { "stringValue": "session/x" } }
        });
        assert!(
            parse_kv_doc(&doc).is_none(),
            "a kv doc with no value bytes is rejected"
        );
        // Non-base64 value bytes are also rejected (corrupt row, not a panic).
        let doc2 = serde_json::json!({
            "name": "x",
            "fields": {
                "key": { "stringValue": "session/x" },
                "value": { "bytesValue": "!!!not base64!!!" }
            }
        });
        assert!(
            parse_kv_doc(&doc2).is_none(),
            "corrupt value bytes rejected"
        );
    }

    #[test]
    fn rehydrate_skips_a_corrupt_bundle_but_keeps_the_good_one() {
        // A durable listing may contain a row whose bytes don't decode as a Bundle (corruption or a
        // future wire version). Rehydrate must skip it and still load the well-formed neighbours,
        // rather than aborting the whole open.
        let good = sample(4);
        let good_id = good.id();
        let far_future = epoch_ms() + 60 * 60 * 1000;
        let mirror = FakeMirror {
            listing: vec![
                (b"not a bundle at all".to_vec(), far_future),
                (good.to_bytes().unwrap(), far_future),
            ],
            ..Default::default()
        };
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();
        assert!(
            store.contains(&good_id),
            "the well-formed bundle rehydrated despite a corrupt sibling"
        );
        assert_eq!(store.have().ids, vec![good_id], "only the good one is held");
    }

    // ==========================================================================================
    // Loopback HTTP coverage (cov/firestore): the REST request-build + response-parse paths of
    // FirestoreClient / Registry / Presence run against a tiny std-only 127.0.0.1 responder. Each
    // client is built with its private URL fields pointed at the mock and a PRE-SEEDED token cache,
    // so no metadata-server or live-network call is ever made. This exercises the durability-mirror
    // wire code (methods/paths/bodies out, status/paging/parse back) without touching Firestore.
    // ==========================================================================================

    struct RecordedRequest {
        method: String,
        target: String, // request-target incl. query string
        body: String,
    }

    struct MockServer {
        base: String, // e.g. "http://127.0.0.1:54321"
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    /// Spawn a loopback HTTP responder that replies with `responses` (status, json body) in order,
    /// recording each request. Beyond the scripted list it replies `200 {}`. Each response closes the
    /// connection (`Connection: close`) so there is no keep-alive bookkeeping.
    fn spawn_mock(responses: Vec<(u16, String)>) -> MockServer {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let sink = requests.clone();
        std::thread::spawn(move || {
            let mut idx = 0usize;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let target = parts.next().unwrap_or("").to_string();
                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0
                        || header == "\r\n"
                        || header == "\n"
                    {
                        break;
                    }
                    if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body);
                }
                sink.lock().unwrap().push(RecordedRequest {
                    method,
                    target,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
                let (code, resp_body) = responses.get(idx).cloned().unwrap_or((200, "{}".into()));
                idx += 1;
                let resp = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{resp_body}",
                    resp_body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        MockServer { base, requests }
    }

    fn test_http() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn seeded_token() -> Mutex<Option<(String, Instant)>> {
        // A fresh cached token, so token() returns it without any metadata-server round-trip.
        Mutex::new(Some(("test-token".to_string(), Instant::now())))
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A Firestore document as the list REST endpoint returns it (fields parse_doc reads).
    fn firestore_doc(data: &[u8], expires_at: u64) -> serde_json::Value {
        serde_json::json!({
            "name": "projects/p/.../x",
            "fields": {
                "data": { "bytesValue": b64(data) },
                "expiresAt": { "integerValue": expires_at.to_string() },
            }
        })
    }

    fn firestore_client_at(base: &str) -> FirestoreClient {
        FirestoreClient {
            http: test_http(),
            collection_url: format!("{base}/documents/relays/NODE/bundles"),
            kv_url: format!("{base}/documents/relays/NODE/kv"),
            token: seeded_token(),
        }
    }

    fn registry_at(base: &str, me: &str) -> Registry {
        Registry {
            http: test_http(),
            collection_url: format!("{base}/documents/registry"),
            me: me.to_string(),
            token: seeded_token(),
        }
    }

    fn presence_at(base: &str) -> Presence {
        Presence {
            http: test_http(),
            project: "proj".to_string(),
            base: base.to_string(),
            presence_url: format!("{base}/documents/presence"),
            token: seeded_token(),
        }
    }

    #[test]
    fn firestore_put_bundle_patches_the_doc_and_maps_errors() {
        let id = sample(1).id();
        // Success: a 200 is Ok, and the request is a PATCH to /bundles/<bs58 id> carrying the doc body
        // (base64 data + integer expiresAt). Drive it through the trait to cover the delegation too.
        let srv = spawn_mock(vec![(200, "{}".into())]);
        let client = firestore_client_at(&srv.base);
        let mirror: &dyn BundleMirror = &client;
        assert!(mirror.put_bundle(&id, b"sealed", 4242).is_ok());
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs.len(), 1);
            assert_eq!(reqs[0].method, "PATCH");
            assert!(reqs[0]
                .target
                .contains(&format!("/bundles/{}", bs58::encode(id).into_string())));
            let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
            assert_eq!(body["fields"]["expiresAt"]["integerValue"], "4242");
            assert_eq!(
                body["fields"]["data"]["bytesValue"].as_str(),
                Some(b64(b"sealed").as_str())
            );
        }
        // Error: a 500 maps to Err (the write is not silently swallowed).
        let srv2 = spawn_mock(vec![(500, "boom".into())]);
        assert!(firestore_client_at(&srv2.base)
            .put_bundle(&id, b"x", 1)
            .is_err());
    }

    #[test]
    fn firestore_delete_bundle_treats_success_and_404_as_ok_but_errors_otherwise() {
        let id = sample(1).id();
        for code in [200u16, 404] {
            let srv = spawn_mock(vec![(code, "{}".into())]);
            let client = firestore_client_at(&srv.base);
            let mirror: &dyn BundleMirror = &client;
            assert!(mirror.delete_bundle(&id).is_ok(), "status {code} is ok");
            assert_eq!(srv.requests.lock().unwrap()[0].method, "DELETE");
        }
        let srv = spawn_mock(vec![(500, "no".into())]);
        assert!(
            firestore_client_at(&srv.base).delete_bundle(&id).is_err(),
            "a 500 delete maps to Err"
        );
    }

    #[test]
    fn firestore_list_bundles_pages_parses_and_handles_404() {
        // Two pages: the first carries a nextPageToken, the second ends the loop. Both docs parse.
        let page1 = serde_json::json!({
            "documents": [firestore_doc(b"one", 111)],
            "nextPageToken": "PAGE2"
        })
        .to_string();
        let page2 = serde_json::json!({ "documents": [firestore_doc(b"two", 222)] }).to_string();
        let srv = spawn_mock(vec![(200, page1), (200, page2)]);
        let client = firestore_client_at(&srv.base);
        let mirror: &dyn BundleMirror = &client;
        let out = mirror.list_bundles().unwrap();
        assert_eq!(out, vec![(b"one".to_vec(), 111), (b"two".to_vec(), 222)]);
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs.len(), 2, "followed the page token to a second request");
            assert!(reqs[1].target.contains("pageToken=PAGE2"));
        }
        // A 404 means the collection doesn't exist yet -> empty, not an error.
        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(firestore_client_at(&srv404.base)
            .list_bundles()
            .unwrap()
            .is_empty());
        // Any other non-success status is an error.
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srv500.base).list_bundles().is_err());
    }

    #[test]
    fn firestore_kv_put_and_delete_over_rest() {
        // put_kv PATCHes a doc whose id is bs58(key-bytes) and carries the ORIGINAL key + value.
        let srv = spawn_mock(vec![(200, "{}".into())]);
        let client = firestore_client_at(&srv.base);
        let mirror: &dyn BundleMirror = &client;
        assert!(mirror.put_kv("session/peerX", b"ratchet").is_ok());
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs[0].method, "PATCH");
            assert!(reqs[0].target.contains(&format!(
                "/kv/{}",
                bs58::encode("session/peerX".as_bytes()).into_string()
            )));
            let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
            assert_eq!(body["fields"]["key"]["stringValue"], "session/peerX");
        }
        // delete_kv: a 404 is fine (already gone); a 500 is an error; put_kv 500 is an error.
        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(firestore_client_at(&srv404.base).delete_kv("k").is_ok());
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srv500.base).delete_kv("k").is_err());
        let srvp = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srvp.base).put_kv("k", b"v").is_err());
    }

    #[test]
    fn firestore_list_kv_pages_parses_and_handles_404() {
        let kv_doc = |k: &str, v: &[u8]| {
            serde_json::json!({
                "name": "x",
                "fields": { "key": { "stringValue": k }, "value": { "bytesValue": b64(v) } }
            })
        };
        let page1 = serde_json::json!({
            "documents": [kv_doc("session/a", b"aa")],
            "nextPageToken": "P2"
        })
        .to_string();
        let page2 = serde_json::json!({ "documents": [kv_doc("prekey/b", b"bb")] }).to_string();
        let srv = spawn_mock(vec![(200, page1), (200, page2)]);
        let client = firestore_client_at(&srv.base);
        let mirror: &dyn BundleMirror = &client;
        let mut out = mirror.list_kv().unwrap();
        out.sort();
        assert_eq!(
            out,
            vec![
                ("prekey/b".to_string(), b"bb".to_vec()),
                ("session/a".to_string(), b"aa".to_vec()),
            ]
        );
        assert!(srv.requests.lock().unwrap()[1]
            .target
            .contains("pageToken=P2"));

        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(firestore_client_at(&srv404.base)
            .list_kv()
            .unwrap()
            .is_empty());
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srv500.base).list_kv().is_err());
    }

    #[test]
    fn firestore_client_new_builds_per_node_urls() {
        let addr = [1u8, 2, 3, 4];
        let node = bs58::encode(addr).into_string();
        let client = FirestoreClient::new("my-proj", &addr);
        assert!(client.collection_url.ends_with(&format!(
            "/projects/my-proj/databases/(default)/documents/relays/{node}/bundles"
        )));
        assert!(client.kv_url.ends_with(&format!("/relays/{node}/kv")));
    }

    #[test]
    fn gcp_token_env_var_and_cache_paths() {
        // This is the ONLY test touching FIRESTORE_ACCESS_TOKEN, and no other test triggers a fetch
        // (they all pre-seed a fresh token), so there is no cross-test env race.
        std::env::set_var("FIRESTORE_ACCESS_TOKEN", "env-tok");
        let http = test_http();
        // fetch_gcp_token short-circuits on the env var before any metadata call.
        assert_eq!(fetch_gcp_token(&http).unwrap(), "env-tok");
        // cached_token on an EMPTY cache fetches (via env), stores, and returns it.
        let empty: Mutex<Option<(String, Instant)>> = Mutex::new(None);
        assert_eq!(cached_token(&empty, &http).unwrap(), "env-tok");
        assert!(
            empty.lock().unwrap().is_some(),
            "token cached after the fetch"
        );
        // An EXPIRED cache entry forces a refetch (kept deterministic via the env var).
        std::env::set_var("FIRESTORE_ACCESS_TOKEN", "fresh-env");
        let expired: Mutex<Option<(String, Instant)>> = Mutex::new(Some((
            "old".into(),
            Instant::now() - Duration::from_secs(3001),
        )));
        assert_eq!(
            cached_token(&expired, &http).unwrap(),
            "fresh-env",
            "an expired cache re-fetches rather than returning the stale token"
        );
        std::env::remove_var("FIRESTORE_ACCESS_TOKEN");
        // A FRESH cache entry is returned without any fetch (env var now gone, yet this still works).
        let fresh: Mutex<Option<(String, Instant)>> =
            Mutex::new(Some(("cached".into(), Instant::now())));
        assert_eq!(cached_token(&fresh, &http).unwrap(), "cached");
    }

    #[test]
    fn registry_heartbeat_patches_and_maps_errors() {
        let srv = spawn_mock(vec![(200, "{}".into())]);
        let reg = registry_at(&srv.base, "MeNode");
        assert!(reg.heartbeat("eu-west1", "wss://eu/", 9_000).is_ok());
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs[0].method, "PATCH");
            assert!(reqs[0].target.contains("/registry/MeNode"));
            let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
            assert_eq!(body["fields"]["region"]["stringValue"], "eu-west1");
            assert_eq!(body["fields"]["endpoint"]["stringValue"], "wss://eu/");
        }
        let srv2 = spawn_mock(vec![(500, String::new())]);
        assert!(registry_at(&srv2.base, "MeNode")
            .heartbeat("r", "e", 1)
            .is_err());
    }

    #[test]
    fn registry_online_filters_self_and_stale_peers() {
        let now = 1_000_000u64;
        let ttl = 90_000u64;
        let reg_doc = |node: &str, region: &str, endpoint: &str, hb: u64| {
            serde_json::json!({
                "name": "x",
                "fields": {
                    "node": { "stringValue": node },
                    "region": { "stringValue": region },
                    "endpoint": { "stringValue": endpoint },
                    "heartbeatAt": { "integerValue": hb.to_string() },
                }
            })
        };
        let docs = serde_json::json!({
            "documents": [
                reg_doc("MeNode", "r0", "e0", now),                 // ourselves -> excluded
                reg_doc("StalePeer", "r1", "e1", now - ttl - 1),    // too old -> excluded
                reg_doc("FreshPeer", "eu", "wss://eu/", now - 1_000) // fresh non-self -> kept
            ]
        })
        .to_string();
        let srv = spawn_mock(vec![(200, docs)]);
        let online = registry_at(&srv.base, "MeNode").online(now, ttl).unwrap();
        assert_eq!(
            online.len(),
            1,
            "only the fresh non-self peer survives the filter"
        );
        assert_eq!(online[0].node, "FreshPeer");
        assert_eq!(online[0].region, "eu");
        assert_eq!(online[0].endpoint, "wss://eu/");

        // 404 -> empty (no registry yet); any other error -> Err.
        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(registry_at(&srv404.base, "Me")
            .online(now, ttl)
            .unwrap()
            .is_empty());
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(registry_at(&srv500.base, "Me").online(now, ttl).is_err());
    }

    #[test]
    fn registry_new_builds_registry_url() {
        let addr = [9u8, 9, 9];
        let reg = Registry::new("proj-x", &addr);
        assert!(reg
            .collection_url
            .ends_with("/projects/proj-x/databases/(default)/documents/registry"));
        assert_eq!(reg.me, bs58::encode(addr).into_string());
    }

    #[test]
    fn presence_set_presence_patches_and_maps_errors() {
        let srv = spawn_mock(vec![(200, "{}".into())]);
        let presence = presence_at(&srv.base);
        assert!(presence.set_presence("Dev1", "eu-west1", 5_000).is_ok());
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs[0].method, "PATCH");
            assert!(reqs[0].target.contains("/presence/Dev1"));
            let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
            assert_eq!(body["fields"]["region"]["stringValue"], "eu-west1");
        }
        let srv2 = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srv2.base).set_presence("D", "r", 1).is_err());
    }

    #[test]
    fn presence_region_of_returns_fresh_stale_and_missing() {
        let now = 2_000_000u64;
        let ttl = 90_000u64;
        let pdoc = |region: &str, hb: u64| {
            serde_json::json!({
                "name": "x",
                "fields": {
                    "device": { "stringValue": "Dev1" },
                    "region": { "stringValue": region },
                    "heartbeatAt": { "integerValue": hb.to_string() },
                }
            })
            .to_string()
        };
        // Fresh check-in -> Some(region).
        let srv = spawn_mock(vec![(200, pdoc("eu", now - 1_000))]);
        assert_eq!(
            presence_at(&srv.base).region_of("Dev1", now, ttl).unwrap(),
            Some("eu".to_string())
        );
        // Stale check-in -> None (offline, don't route there).
        let srv2 = spawn_mock(vec![(200, pdoc("eu", now - ttl - 1))]);
        assert_eq!(
            presence_at(&srv2.base).region_of("Dev1", now, ttl).unwrap(),
            None
        );
        // 404 -> None (unknown device); a 500 -> Err.
        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert_eq!(
            presence_at(&srv404.base)
                .region_of("Dev1", now, ttl)
                .unwrap(),
            None
        );
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srv500.base)
            .region_of("Dev1", now, ttl)
            .is_err());
    }

    #[test]
    fn presence_cross_partition_handoff_and_mailbox_paths() {
        let id = sample(1).id();
        let doc_id = bs58::encode(id).into_string();

        // put_bundle_to: PATCH into relays/{node}/bundles/{doc} of the destination partition.
        let srv = spawn_mock(vec![(200, "{}".into())]);
        assert!(presence_at(&srv.base)
            .put_bundle_to("NodeB", &id, b"data", 777)
            .is_ok());
        assert!(srv.requests.lock().unwrap()[0]
            .target
            .contains(&format!("/relays/NodeB/bundles/{doc_id}")));
        let srve = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srve.base)
            .put_bundle_to("NodeB", &id, b"x", 1)
            .is_err());

        // list_bundles_of: pages + parse, then 404 -> empty and 500 -> err.
        let page1 = serde_json::json!({
            "documents": [firestore_doc(b"h1", 10)],
            "nextPageToken": "N2"
        })
        .to_string();
        let page2 = serde_json::json!({ "documents": [firestore_doc(b"h2", 20)] }).to_string();
        let srvl = spawn_mock(vec![(200, page1), (200, page2)]);
        let got = presence_at(&srvl.base).list_bundles_of("NodeB").unwrap();
        assert_eq!(got, vec![(b"h1".to_vec(), 10), (b"h2".to_vec(), 20)]);
        assert!(srvl.requests.lock().unwrap()[1]
            .target
            .contains("pageToken=N2"));
        let srvl404 = spawn_mock(vec![(404, String::new())]);
        assert!(presence_at(&srvl404.base)
            .list_bundles_of("NodeB")
            .unwrap()
            .is_empty());
        let srvl500 = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srvl500.base).list_bundles_of("NodeB").is_err());

        // spool_to_mailbox: PATCH into mailboxes/{tag}/bundles/{doc}; error maps through.
        let srvs = spawn_mock(vec![(200, "{}".into())]);
        assert!(presence_at(&srvs.base)
            .spool_to_mailbox("TAG58", &id, b"m", 999)
            .is_ok());
        assert!(srvs.requests.lock().unwrap()[0]
            .target
            .contains(&format!("/mailboxes/TAG58/bundles/{doc_id}")));
        let srvse = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srvse.base)
            .spool_to_mailbox("TAG58", &id, b"m", 1)
            .is_err());

        // list_mailbox: pages + parse, then 404 -> empty and 500 -> err.
        let mp1 = serde_json::json!({
            "documents": [firestore_doc(b"s1", 5)],
            "nextPageToken": "M2"
        })
        .to_string();
        let mp2 = serde_json::json!({ "documents": [firestore_doc(b"s2", 6)] }).to_string();
        let srvm = spawn_mock(vec![(200, mp1), (200, mp2)]);
        let mailbox = presence_at(&srvm.base).list_mailbox("TAG58").unwrap();
        assert_eq!(mailbox, vec![(b"s1".to_vec(), 5), (b"s2".to_vec(), 6)]);
        let srvm404 = spawn_mock(vec![(404, String::new())]);
        assert!(presence_at(&srvm404.base)
            .list_mailbox("TAG58")
            .unwrap()
            .is_empty());
        let srvm500 = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srvm500.base).list_mailbox("TAG58").is_err());

        // delete_mailbox_bundle: success and 404 are both Ok (idempotent); 500 is an error.
        for code in [200u16, 404] {
            let srvd = spawn_mock(vec![(code, String::new())]);
            assert!(presence_at(&srvd.base)
                .delete_mailbox_bundle("TAG58", &id)
                .is_ok());
            assert_eq!(srvd.requests.lock().unwrap()[0].method, "DELETE");
        }
        let srvd500 = spawn_mock(vec![(500, String::new())]);
        assert!(presence_at(&srvd500.base)
            .delete_mailbox_bundle("TAG58", &id)
            .is_err());
    }

    #[test]
    fn presence_new_builds_presence_url_and_base() {
        let presence = Presence::new("proj-y");
        assert!(presence
            .presence_url
            .ends_with("/projects/proj-y/databases/(default)/documents/presence"));
        assert_eq!(presence.base, "https://firestore.googleapis.com/v1");
        assert_eq!(presence.project, "proj-y");
    }
}
