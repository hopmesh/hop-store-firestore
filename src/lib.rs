//! # hop-store-firestore
//!
//! A durable [`Store`](hop_core::store::Store) for a relay node, backed by Firestore
//! so the mailbox survives scale-to-zero (DESIGN.md §19/§21). **Per node**, not a
//! global store: each relay owns the subcollection
//! `relays/{node}/bundles`, so there's no cross-region contention.
//!
//! The relay's driver loop is synchronous and single-owner. A bounded FIFO worker performs Firestore
//! I/O, but every accepted mutation waits for its definitive acknowledgement before the in-memory hot
//! path changes. Security-critical batches can commit ratchet/KV state and exact bundle custody in one
//! Firestore commit. On startup we **load** the held bundles back from Firestore into memory; the node's
//! `rehydrate` then resumes them.
//!
//! Two durable surfaces are mirrored and write-through on mutation. Bundles and small KV state load
//! on open; attacker-influenced carrier chunks remain remote and rehydrate through bounded pages:
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
//! stores-09: the mirror channel is **bounded**. Capacity rejects a new mutation before it changes
//! memory; accepted custody is never dropped, coalesced away, or reported durable early. Rejections are
//! counted ([`FirestoreStore::mirror_dropped`]) so readiness can fail closed under backpressure.
//!
//! Durable cleanup of expired bundles is left to a **Firestore TTL policy** on the
//! `expireAt` timestamp field (a one-time setup; TTL only sweeps `timestampValue`
//! fields, so every doc carries one — see `doc_json`), keeping `prune` a fast
//! in-memory op. One policy on the `bundles` collection group covers both the
//! per-relay handoff inbox and the §39 mailbox spool.
//!
//! Auth: a Bearer token from the GCE/Cloud Run **metadata server** (workload
//! identity), or the `FIRESTORE_ACCESS_TOKEN` env var for local runs.

use std::io::Read as IoRead;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use hop_core::bundle::{Bundle, BundleId};
use hop_core::store::{
    DurabilityHandle, DurabilityReadiness, HaveSet, KvMutation, KvPage, KvPageRow, MemoryStore,
    Store,
};
use rand_core::{OsRng, RngCore};

/// A definitive batch rejection is safe to return with the old live state. `Unknown` means the
/// request may have committed and must quarantine admission unless marker reconciliation resolves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorBatchError {
    Definitive(String),
    Unknown(String),
}

impl MirrorBatchError {
    fn definitive(error: impl Into<String>) -> Self {
        Self::Definitive(error.into())
    }

    fn unknown(error: impl Into<String>) -> Self {
        Self::Unknown(error.into())
    }
}

impl std::fmt::Display for MirrorBatchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Definitive(error) => write!(formatter, "{error}"),
            Self::Unknown(error) => write!(formatter, "unknown commit outcome: {error}"),
        }
    }
}

/// stores-09: bound on the in-memory mirror backlog. A degraded Firestore backs writes up (each op
/// has a 15s reqwest timeout + 3 retries), so without a cap the queue grows with relay memory. Past
/// this a new operation is synchronously rejected before any hot-path state changes.
const MIRROR_QUEUE_CAP: usize = 4_096;

/// Carrier chunks are attacker-influenced and can be numerous. They stay in Firestore until the
/// node admits them one bounded page at a time instead of joining the small startup KV snapshot.
const LAZY_KV_PREFIX: &str = "strm/";
const LAZY_KV_PREFIX_END: &str = "strm0";
const FIRESTORE_KV_PAGE_SIZE: usize = 300;

/// Cold-open limits match relayd's 8,192-bundle custody ceiling and keep the complete durable hot
/// snapshot within the 2 GiB Cloud Run instance. Bundles and eager KV share one byte ceiling, so a
/// large security-state namespace cannot consume a second unaccounted pool beside bundle custody.
pub const FIRESTORE_STARTUP_MAX_BUNDLES: usize = 8_192;
pub const FIRESTORE_STARTUP_MAX_EAGER_KV_ROWS: usize = 32_768;
pub const FIRESTORE_STARTUP_MAX_BYTES: usize = 512 * 1024 * 1024;
/// One cold-open or readiness-maintenance pass may spend at most these scan and cleanup budgets.
/// Exhaustion preserves a cursor and keeps admission NotReady until a later bounded probe continues.
pub const FIRESTORE_STARTUP_MAX_SCANNED_ROWS: usize = 8_192;
pub const FIRESTORE_STARTUP_MAX_SCANNED_BYTES: usize = 128 * 1024 * 1024;
pub const FIRESTORE_STARTUP_MAX_PAGES: usize = 128;
pub const FIRESTORE_STARTUP_MAX_CLEANUP_OPERATIONS: usize = 256;
const FIRESTORE_STARTUP_PAGE_SIZE: usize = 64;
const FIRESTORE_KV_MAX_PAGE_RESPONSE_BYTES: usize = 24 * 1024 * 1024;

/// One remote bundle document. Invalid documents stay represented as `None` so startup accounting
/// and cleanup cannot silently lose them before the store sees the row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleMirrorRow {
    pub document_id: String,
    pub value: Option<(Vec<u8>, u64)>,
}

/// One ordered remote KV document. Firestore's ordered `key` field remains available even when the
/// value is malformed, allowing the cursor to advance while the rejected row is charged and cleaned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvMirrorRow {
    pub document_id: String,
    pub key: String,
    pub value: Option<Vec<u8>>,
}

/// One bounded remote page. The cursor is opaque to callers: Firestore bundle pages use its API
/// token, while ordered KV pages use the final key as an exclusive cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorPage<T> {
    pub rows: Vec<T>,
    pub next: Option<String>,
    /// Complete response bytes read across the remote requests represented by this page.
    pub scanned_bytes: usize,
    /// Actual remote requests represented by this page. Eager KV may cross its excluded lazy range
    /// and therefore consume two requests in one logical page.
    pub scanned_pages: usize,
}

impl<T> Default for MirrorPage<T> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            next: None,
            scanned_bytes: 0,
            scanned_pages: 0,
        }
    }
}

/// Cumulative startup admission and remote-work usage, exposed for aggregate accounting and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StartupUsage {
    pub bundles: usize,
    pub eager_kv_rows: usize,
    pub bytes: usize,
    pub scanned_rows: usize,
    pub scanned_bytes: usize,
    pub pages: usize,
    pub cleanup_operations: usize,
}

#[derive(Clone, Copy)]
struct StartupLimits {
    max_bundles: usize,
    max_eager_kv_rows: usize,
    max_bytes: usize,
    max_scanned_rows: usize,
    max_scanned_bytes: usize,
    max_pages: usize,
    max_cleanup_operations: usize,
    page_size: usize,
}

impl Default for StartupLimits {
    fn default() -> Self {
        Self {
            max_bundles: FIRESTORE_STARTUP_MAX_BUNDLES,
            max_eager_kv_rows: FIRESTORE_STARTUP_MAX_EAGER_KV_ROWS,
            max_bytes: FIRESTORE_STARTUP_MAX_BYTES,
            max_scanned_rows: FIRESTORE_STARTUP_MAX_SCANNED_ROWS,
            max_scanned_bytes: FIRESTORE_STARTUP_MAX_SCANNED_BYTES,
            max_pages: FIRESTORE_STARTUP_MAX_PAGES,
            max_cleanup_operations: FIRESTORE_STARTUP_MAX_CLEANUP_OPERATIONS,
            page_size: FIRESTORE_STARTUP_PAGE_SIZE,
        }
    }
}

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
        ack: mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>,
    },
    Delete {
        id: BundleId,
        ack: mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>,
    },
    /// stores-07: a kv upsert (`relays/{node}/kv/{key}`). `key` is a caller-chosen string
    /// (e.g. `session/<peer>`); `value` is opaque bytes.
    KvWrite {
        key: String,
        value: Vec<u8>,
        ack: mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>,
    },
    /// stores-07: a kv delete (idempotent).
    KvDelete {
        key: String,
        ack: mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>,
    },
    /// A security-critical store transaction. Firestore must commit every mutation together.
    KvBatch {
        mutations: Vec<KvMutation>,
        ack: mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>,
    },
    /// F-21: drain sentinel. The worker acks this AFTER processing every op ahead of it (mpsc is
    /// FIFO), so `flush()` blocking on the ack means all pending mirrors have been attempted.
    Flush(mpsc::SyncSender<bool>),
    /// Recovery drain ignores the pre-existing NotReady state. The generation check after this
    /// sentinel decides whether the probe may publish Ready.
    RecoveryDrain(mpsc::SyncSender<bool>),
}

/// The durable mirror seam behind [`FirestoreStore`] (stores-11). The real relay uses
/// [`FirestoreClient`] (a live REST endpoint); tests inject a fake so the Store impl's
/// durability-critical paths (rehydrate expiry anchoring, flush drain, mirror ordering) are
/// unit-testable without touching Firestore. Startup lists run during `open()` and bounded NotReady
/// maintenance probes; writes and deletes otherwise run on the background writer.
pub trait BundleMirror: Send + Sync + 'static {
    /// Load one bounded bundle page. A backend must paginate at its storage boundary; cold open never
    /// accepts an all-rows compatibility listing.
    fn list_bundle_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<BundleMirrorRow>, String>;
    /// Mirror a write (upsert).
    fn put_bundle(&self, id: &BundleId, data: &[u8], expires_at: u64) -> Result<(), String>;
    /// Mirror a delete (idempotent).
    fn delete_bundle(&self, id: &BundleId) -> Result<(), String>;
    /// Delete the exact listed document, including a malformed or identity-mismatched row.
    fn delete_bundle_document(&self, document_id: &str) -> Result<(), String> {
        let decoded = bs58::decode(document_id)
            .into_vec()
            .map_err(|error| format!("invalid Firestore bundle document id: {error}"))?;
        let id: BundleId = decoded
            .try_into()
            .map_err(|_| "invalid Firestore bundle document id length".to_string())?;
        self.delete_bundle(&id)
    }

    // --- kv surface (stores-07) -----------------------------------------------------------
    // A durable key -> bytes side store mirrored the same way bundles are: loaded on open,
    // write-through on mutation. Defaults keep bundle-only fakes compiling but report unsupported
    // writes, so the critical Store path can never mistake a no-op for durable acceptance.

    /// Load all persisted kv pairs as `(key, value)` for rehydrate. Default: none.
    fn list_kv(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        Ok(Vec::new())
    }
    /// Load one ordered, bounded eager-KV page. `after` is an exclusive original-key cursor.
    fn list_eager_kv_page(
        &self,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
        max_pages: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String>;
    /// Fetch one ordered, bounded KV page directly from the durable mirror.
    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, Vec<u8>)>, String>;
    /// Bounded form of [`BundleMirror::list_kv_page`] that retains malformed rows and reports the
    /// actual response bytes and requests. The default adapts in-memory test mirrors.
    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        if limit == 0 || max_bytes == 0 {
            return Ok(MirrorPage::default());
        }
        let rows: Vec<_> = self
            .list_kv_page(prefix, after, limit)?
            .into_iter()
            .map(|(key, value)| KvMirrorRow {
                document_id: bs58::encode(key.as_bytes()).into_string(),
                key,
                value: Some(value),
            })
            .collect();
        let scanned_bytes = rows.iter().fold(0usize, |total, row| {
            total
                .saturating_add(row.key.len())
                .saturating_add(row.value.as_ref().map_or(0, Vec::len))
        });
        if rows.len() > limit || scanned_bytes > max_bytes {
            return Err("Firestore mirror exceeded its bounded KV page request".into());
        }
        Ok(MirrorPage {
            rows,
            next: None,
            scanned_bytes,
            scanned_pages: 1,
        })
    }
    /// Mirror a kv upsert. Default: unsupported (bundle-only backend).
    fn put_kv(&self, _key: &str, _value: &[u8]) -> Result<(), String> {
        Err("Firestore mirror does not support kv persistence".into())
    }
    /// Mirror a kv delete (idempotent). Default: unsupported.
    fn delete_kv(&self, _key: &str) -> Result<(), String> {
        Err("Firestore mirror does not support kv persistence".into())
    }
    /// Delete the exact listed KV document rather than trusting its potentially hostile `key` field.
    fn delete_kv_document(&self, document_id: &str) -> Result<(), String> {
        let key = bs58::decode(document_id)
            .into_vec()
            .map_err(|error| format!("invalid Firestore KV document id: {error}"))?;
        let key = String::from_utf8(key)
            .map_err(|_| "invalid Firestore KV document id encoding".to_string())?;
        self.delete_kv(&key)
    }
    /// Atomically apply a critical store batch. Single mutations can use the existing definitive
    /// methods; a multi-operation default is rejected because sequential writes are not atomic.
    fn apply_kv_batch(&self, mutations: &[KvMutation]) -> Result<(), MirrorBatchError> {
        match mutations {
            [] => Ok(()),
            [KvMutation::Put { key, value }] => self
                .put_kv(key, value)
                .map_err(MirrorBatchError::definitive),
            [KvMutation::Remove { key }] => {
                self.delete_kv(key).map_err(MirrorBatchError::definitive)
            }
            [KvMutation::PutBundle { bundle, now_ms }] => {
                let lifetime =
                    (bundle.inner.lifetime_ms as u64).min(hop_core::store::MAX_SEEN_LIFETIME_MS);
                let data = bundle
                    .to_bytes()
                    .map_err(|error| MirrorBatchError::definitive(error.to_string()))?;
                self.put_bundle(&bundle.id(), &data, now_ms.saturating_add(lifetime))
                    .map_err(MirrorBatchError::definitive)
            }
            [KvMutation::RemoveBundle { id }] => {
                self.delete_bundle(id).map_err(MirrorBatchError::definitive)
            }
            _ => Err(MirrorBatchError::definitive(
                "Firestore mirror does not support atomic store batches",
            )),
        }
    }

    /// Definitive write/read/delete probe used before startup admission and during recovery.
    fn durability_probe(&self) -> Result<(), String> {
        Ok(())
    }

    /// Fence prior processes and reconcile every durable critical-operation journal before state
    /// is loaded. Backends without remote asynchronous commits have nothing to recover.
    fn recover_critical_operations(&self) -> Result<(), String> {
        Ok(())
    }

    /// Confirm that the startup fence still belongs to this process before publishing readiness.
    fn confirm_critical_operation_fence(&self) -> Result<(), String> {
        Ok(())
    }
}

impl BundleMirror for FirestoreClient {
    fn list_bundle_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<BundleMirrorRow>, String> {
        FirestoreClient::list_bundle_page(self, cursor, limit, max_bytes)
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
    fn list_eager_kv_page(
        &self,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
        max_pages: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        FirestoreClient::list_eager_kv_page(self, after, limit, max_bytes, max_pages)
    }
    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        FirestoreClient::list_kv_page(self, prefix, after, limit)
    }
    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        FirestoreClient::list_kv_page_bounded(self, prefix, after, limit, max_bytes)
    }
    fn put_kv(&self, key: &str, value: &[u8]) -> Result<(), String> {
        FirestoreClient::put_kv(self, key, value)
    }
    fn delete_kv(&self, key: &str) -> Result<(), String> {
        FirestoreClient::delete_kv(self, key)
    }
    fn delete_kv_document(&self, document_id: &str) -> Result<(), String> {
        FirestoreClient::delete_kv_document(self, document_id)
    }
    fn apply_kv_batch(&self, mutations: &[KvMutation]) -> Result<(), MirrorBatchError> {
        FirestoreClient::apply_kv_batch(self, mutations)
    }
    fn durability_probe(&self) -> Result<(), String> {
        FirestoreClient::durability_probe(self)
    }
    fn recover_critical_operations(&self) -> Result<(), String> {
        FirestoreClient::recover_critical_operations(self)
    }
    fn confirm_critical_operation_fence(&self) -> Result<(), String> {
        FirestoreClient::confirm_critical_operation_fence(self)
    }
}

/// Durable per-node store: in-memory hot path + Firestore mirror.
pub struct FirestoreStore {
    inner: MemoryStore,
    /// Shared with the writer so lazy namespaces can be read from Firestore without materializing
    /// them in the hot in-memory KV map during open.
    mirror: Arc<dyn BundleMirror>,
    /// The bounded mirror queue (stores-09). Capacity rejects before live state changes; the worker
    /// thread is the sole consumer.
    tx: MirrorTx,
    /// stores-09: count of durable ops shed because the mirror backlog was at [`MIRROR_QUEUE_CAP`].
    /// Non-zero means Firestore is degraded and this store is NOT durable right now; `/healthz`
    /// surfaces it. `Arc` so a boxed store's owner can read it without owning the store.
    dropped: Arc<AtomicU64>,
    /// Mirror operations that still failed after all retries. This is distinct from queue
    /// backpressure: either counter means the in-memory store is no longer durably mirrored.
    failed: Arc<AtomicU64>,
    /// Admission state shared with the writer and relay front door. Metrics above remain monotonic;
    /// readiness is recoverable after a definitive probe when no unknown commit is outstanding.
    durability: DurabilityHandle,
    startup_usage: StartupUsage,
    /// Nonzero while bounded startup scanning or rejected-row cleanup needs another maintenance pass.
    /// Admission remains NotReady until the continuation finishes and a generation-aware probe wins.
    startup_cleanup_pending: Arc<AtomicU64>,
    startup_maintenance: Option<StartupMaintenance>,
    startup_limits: StartupLimits,
    /// stores-r2-05: the background writer's join handle. Drop signals `closed` then best-effort
    /// joins (bounded wait) so ops enqueued-but-not-yet-flushed on an UNCLEAN teardown (panic, early
    /// return, a drop not preceded by `flush()`) still get drained rather than silently lost. `Option`
    /// so Drop can `take()` it and `join()`.
    writer: Option<std::thread::JoinHandle<()>>,
}

/// The bounded mirror queue's producer end (stores-09). No accepted operation is droppable.
#[derive(Clone)]
struct MirrorTx {
    queue: Arc<(Mutex<MirrorQueue>, std::sync::Condvar)>,
    dropped: Arc<AtomicU64>,
    durability: DurabilityHandle,
}

struct MirrorQueue {
    ops: std::collections::VecDeque<Op>,
    /// Set on drop of the store so the worker exits once drained (mirrors an mpsc hangup).
    closed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartupPhase {
    Bundles,
    EagerKv,
    Complete,
}

#[derive(Debug)]
enum StartupCleanupOp {
    Bundle(String),
    Kv(String),
}

struct StartupMaintenance {
    phase: StartupPhase,
    cursor: Option<String>,
    cleanup: std::collections::VecDeque<StartupCleanupOp>,
}

impl Default for StartupMaintenance {
    fn default() -> Self {
        Self {
            phase: StartupPhase::Bundles,
            cursor: None,
            cleanup: std::collections::VecDeque::new(),
        }
    }
}

impl StartupMaintenance {
    fn needed(&self) -> bool {
        self.phase != StartupPhase::Complete || !self.cleanup.is_empty()
    }
}

impl MirrorTx {
    /// Enqueue without shedding queued work. A full or closed queue is a synchronous failure, never
    /// an optimistic success followed by drop-oldest.
    fn send(&self, op: Op) -> std::result::Result<(), String> {
        let (lock, cvar) = &*self.queue;
        let mut q = lock
            .lock()
            .map_err(|_| "Firestore mirror queue lock poisoned".to_string())?;
        if q.closed {
            return Err("Firestore mirror queue is closed".into());
        }
        if q.ops.len() >= MIRROR_QUEUE_CAP {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.durability.mark_not_ready();
            return Err("Firestore mirror queue is full".into());
        }
        q.ops.push_back(op);
        cvar.notify_one();
        Ok(())
    }
}

impl FirestoreStore {
    /// Open the store for `node_addr` in `project`, loading held bundles and non-stream KV back into
    /// memory. Carrier chunks remain remote for bounded rehydrate. Spawns the writer thread.
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

    pub fn mirror_failed(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    pub fn mirror_failed_handle(&self) -> Arc<AtomicU64> {
        self.failed.clone()
    }

    pub fn durability_handle(&self) -> DurabilityHandle {
        self.durability.clone()
    }

    pub fn startup_usage(&self) -> StartupUsage {
        self.startup_usage
    }

    pub fn startup_cleanup_pending(&self) -> bool {
        self.startup_cleanup_pending.load(Ordering::Acquire) != 0
    }

    /// stores-r2-01: re-mirror an already-held bundle (after a spray-and-wait split or a retransmit
    /// set_copies) reusing the RECEIVER-anchored `expires_at` this store recorded at `put` time,
    /// NOT `created_at + lifetime_ms`. `created_at` is the SENDER's advisory clock (§8, defaults to
    /// 0): re-deriving from it can rewrite the durable doc's `expireAt` into the past (created_at=0
    /// -> ~1970), so the Firestore TTL policy would sweep a still-live spooled/handoff bundle early
    /// and silently drop an offline recipient's §39-spooled message. The stored `seen_expiry` is the
    /// same clamped `now + lifetime` `put()` mirrored, so every re-mirror carries the identical
    /// bound. Falls back to skipping the mirror if the id is no longer tracked (nothing to persist).
    fn commit_op(
        &self,
        build: impl FnOnce(mpsc::SyncSender<std::result::Result<(), MirrorBatchError>>) -> Op,
    ) -> std::result::Result<(), MirrorBatchError> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        if let Err(error) = self.tx.send(build(ack_tx)) {
            self.durability.mark_not_ready();
            return Err(MirrorBatchError::definitive(error));
        }
        match ack_rx.recv() {
            Ok(result) => result,
            Err(_) => {
                // The worker may have committed before it disappeared. With no acknowledgement the
                // outcome is unknown, so shared admission must quarantine immediately.
                self.durability.quarantine();
                Err(MirrorBatchError::unknown(
                    "Firestore mirror worker stopped before acknowledgement",
                ))
            }
        }
    }

    fn remirror(&self, id: &BundleId, bundle: &Bundle) -> std::result::Result<(), String> {
        let Some(expires_at) = self.inner.seen_expiry(id) else {
            return Err("bundle is no longer tracked for durable remirror".into());
        };
        let data = bundle.to_bytes().map_err(|e| e.to_string())?;
        self.commit_op(|ack| Op::Write {
            id: *id,
            data,
            expires_at,
            ack,
        })
        .map_err(|error| error.to_string())
    }

    fn drain_for_recovery(&self, timeout: Duration) -> bool {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        if self.tx.send(Op::RecoveryDrain(ack_tx)).is_err() {
            return false;
        }
        ack_rx.recv_timeout(timeout).unwrap_or(false)
    }

    /// Open over an arbitrary [`BundleMirror`] (stores-11 seam). `open()` is the production wiring
    /// (a live [`FirestoreClient`]); tests pass a fake mirror to exercise rehydrate/flush/mirror.
    pub fn open_with_mirror<M: BundleMirror>(mirror: M) -> Result<Self, String> {
        Self::open_with_mirror_limits(mirror, StartupLimits::default())
    }

    fn open_with_mirror_limits<M: BundleMirror>(
        mirror: M,
        limits: StartupLimits,
    ) -> Result<Self, String> {
        if limits.page_size == 0
            || limits.max_scanned_rows == 0
            || limits.max_scanned_bytes == 0
            || limits.max_pages == 0
            || limits.max_cleanup_operations == 0
        {
            return Err("Firestore startup maintenance limits must be nonzero".into());
        }
        let mirror: Arc<dyn BundleMirror> = Arc::new(mirror);
        let durability = DurabilityHandle::not_ready();
        let recovery_generation = durability.begin_recovery();
        mirror
            .recover_critical_operations()
            .map_err(|error| format!("Firestore critical-operation recovery failed: {error}"))?;
        mirror.durability_probe().map_err(|error| {
            format!("Firestore write/read/delete readiness probe failed: {error}")
        })?;
        let mut inner = MemoryStore::new();
        let mut startup_usage = StartupUsage::default();
        let mut startup_maintenance = StartupMaintenance::default();
        let startup_complete = run_startup_maintenance_round(
            &mut inner,
            mirror.as_ref(),
            &mut startup_usage,
            &mut startup_maintenance,
            limits,
        )?;

        if startup_complete {
            mirror.confirm_critical_operation_fence().map_err(|error| {
                format!("Firestore critical-operation startup fence was lost: {error}")
            })?;
        }

        let dropped = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let startup_cleanup_pending = Arc::new(AtomicU64::new(0));
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
            durability: durability.clone(),
        };
        let writer_failed = failed.clone();
        let writer_mirror = mirror.clone();
        let writer_durability = durability.clone();
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
                // F-21: sentinels ack after everything before them in the FIFO is done. Ordinary
                // flush also reports readiness; recovery drain leaves that decision to generation.
                match &op {
                    Op::Flush(ack) => {
                        let _ = ack.send(writer_durability.is_ready());
                        continue;
                    }
                    Op::RecoveryDrain(ack) => {
                        let _ = ack.send(true);
                        continue;
                    }
                    _ => {}
                }
                // Best-effort writes and synchronously-acknowledged critical writes share the same
                // bounded retry policy. Critical callers receive the final operation result below.
                let mut result = Err(MirrorBatchError::definitive(
                    "Firestore mirror operation was not attempted",
                ));
                for attempt in 0..3 {
                    let outcome = match &op {
                        Op::Write {
                            id,
                            data,
                            expires_at,
                            ..
                        } => writer_mirror
                            .put_bundle(id, data, *expires_at)
                            .map_err(MirrorBatchError::definitive),
                        Op::Delete { id, .. } => writer_mirror
                            .delete_bundle(id)
                            .map_err(MirrorBatchError::definitive),
                        Op::KvWrite { key, value, .. } => writer_mirror
                            .put_kv(key, value)
                            .map_err(MirrorBatchError::definitive),
                        Op::KvDelete { key, .. } => writer_mirror
                            .delete_kv(key)
                            .map_err(MirrorBatchError::definitive),
                        Op::KvBatch { mutations, .. } => writer_mirror.apply_kv_batch(mutations),
                        Op::Flush(_) | Op::RecoveryDrain(_) => break,
                    };
                    match outcome {
                        Ok(()) => {
                            result = Ok(());
                            break;
                        }
                        Err(e) => result = Err(e),
                    }
                    std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
                }
                if result.is_err() {
                    writer_failed.fetch_add(1, Ordering::Relaxed);
                    if matches!(&result, Err(MirrorBatchError::Unknown(_))) {
                        writer_durability.quarantine();
                    } else {
                        writer_durability.mark_not_ready();
                    }
                }
                match op {
                    Op::Write { ack, .. }
                    | Op::Delete { ack, .. }
                    | Op::KvWrite { ack, .. }
                    | Op::KvDelete { ack, .. } => {
                        let _ = ack.send(result);
                    }
                    Op::KvBatch { ack, .. } => {
                        let _ = ack.send(result);
                    }
                    _ => {}
                }
            }
        });

        if !startup_complete {
            startup_cleanup_pending.store(1, Ordering::Release);
            durability.mark_not_ready();
        } else if !durability.mark_ready_if_reconciled(recovery_generation) {
            return Err("Firestore readiness changed during cold open".into());
        }

        Ok(Self {
            inner,
            mirror,
            tx,
            dropped,
            failed,
            durability,
            startup_usage,
            startup_cleanup_pending,
            startup_maintenance: (!startup_complete).then_some(startup_maintenance),
            startup_limits: limits,
            writer: Some(writer),
        })
    }
}

fn run_startup_maintenance_round(
    inner: &mut MemoryStore,
    mirror: &dyn BundleMirror,
    usage: &mut StartupUsage,
    maintenance: &mut StartupMaintenance,
    limits: StartupLimits,
) -> Result<bool, String> {
    let mut cleanup_operations = 0usize;
    while let Some(operation) = maintenance.cleanup.front() {
        if cleanup_operations >= limits.max_cleanup_operations {
            return Ok(false);
        }
        cleanup_operations += 1;
        usage.cleanup_operations = usage.cleanup_operations.saturating_add(1);
        match operation {
            StartupCleanupOp::Bundle(document_id) => mirror.delete_bundle_document(document_id)?,
            StartupCleanupOp::Kv(document_id) => mirror.delete_kv_document(document_id)?,
        }
        maintenance.cleanup.pop_front();
    }
    if cleanup_operations == limits.max_cleanup_operations {
        return Ok(false);
    }

    let mut scanned_rows = 0usize;
    let mut scanned_bytes = 0usize;
    let mut scanned_pages = 0usize;
    let now_ms = epoch_ms();

    while maintenance.phase != StartupPhase::Complete {
        if scanned_rows >= limits.max_scanned_rows
            || scanned_bytes >= limits.max_scanned_bytes
            || scanned_pages >= limits.max_pages
        {
            return Ok(false);
        }
        let row_limit = limits.page_size.min(limits.max_scanned_rows - scanned_rows);
        let byte_limit = limits.max_scanned_bytes - scanned_bytes;
        let page_limit = limits.max_pages - scanned_pages;
        let prior_cursor = maintenance.cursor.clone();

        match maintenance.phase {
            StartupPhase::Bundles => {
                let page =
                    mirror.list_bundle_page(prior_cursor.as_deref(), row_limit, byte_limit)?;
                validate_startup_page(&page, row_limit, byte_limit, page_limit, "bundle")?;
                scanned_rows += page.rows.len();
                scanned_bytes += page.scanned_bytes;
                scanned_pages += page.scanned_pages;
                usage.scanned_rows = usage.scanned_rows.saturating_add(page.rows.len());
                usage.scanned_bytes = usage.scanned_bytes.saturating_add(page.scanned_bytes);
                usage.pages = usage.pages.saturating_add(page.scanned_pages);

                for row in page.rows {
                    let reject = |maintenance: &mut StartupMaintenance, document_id: String| {
                        maintenance
                            .cleanup
                            .push_back(StartupCleanupOp::Bundle(document_id));
                    };
                    let Some((data, stored_expires)) = row.value else {
                        reject(maintenance, row.document_id);
                        continue;
                    };
                    if stored_expires <= now_ms {
                        // Firestore TTL owns expired-row deletion. The row still consumes scan
                        // budgets, but readiness need not wait for a redundant application delete.
                        continue;
                    }
                    let Ok(bundle) = Bundle::from_bytes(&data) else {
                        reject(maintenance, row.document_id);
                        continue;
                    };
                    let id = bundle.id();
                    if row.document_id != bs58::encode(id).into_string()
                        || inner.seen(&id)
                        || usage.bundles >= limits.max_bundles
                        || usage.bytes.saturating_add(data.len()) > limits.max_bytes
                    {
                        reject(maintenance, row.document_id);
                        continue;
                    }
                    let expires = stored_expires
                        .min(now_ms.saturating_add(hop_core::store::MAX_SEEN_LIFETIME_MS));
                    if inner.put_with_expiry(bundle, expires) {
                        usage.bundles += 1;
                        usage.bytes += data.len();
                    } else {
                        reject(maintenance, row.document_id);
                    }
                }
                advance_startup_phase(
                    maintenance,
                    page.next,
                    prior_cursor.as_deref(),
                    StartupPhase::EagerKv,
                    "bundle",
                )?;
            }
            StartupPhase::EagerKv => {
                let page = mirror.list_eager_kv_page(
                    prior_cursor.as_deref(),
                    row_limit,
                    byte_limit,
                    page_limit,
                )?;
                validate_startup_page(&page, row_limit, byte_limit, page_limit, "eager-KV")?;
                scanned_rows += page.rows.len();
                scanned_bytes += page.scanned_bytes;
                scanned_pages += page.scanned_pages;
                usage.scanned_rows = usage.scanned_rows.saturating_add(page.rows.len());
                usage.scanned_bytes = usage.scanned_bytes.saturating_add(page.scanned_bytes);
                usage.pages = usage.pages.saturating_add(page.scanned_pages);

                for row in page.rows {
                    let expected_document = bs58::encode(row.key.as_bytes()).into_string();
                    let Some(value) = row.value else {
                        maintenance
                            .cleanup
                            .push_back(StartupCleanupOp::Kv(row.document_id));
                        continue;
                    };
                    let bytes = row.key.len().saturating_add(value.len());
                    if row.key.starts_with(LAZY_KV_PREFIX)
                        || row.document_id != expected_document
                        || inner.get_kv(&row.key).is_some()
                        || usage.eager_kv_rows >= limits.max_eager_kv_rows
                        || usage.bytes.saturating_add(bytes) > limits.max_bytes
                    {
                        maintenance
                            .cleanup
                            .push_back(StartupCleanupOp::Kv(row.document_id));
                        continue;
                    }
                    inner.put_kv(&row.key, value);
                    usage.eager_kv_rows += 1;
                    usage.bytes += bytes;
                }
                advance_startup_phase(
                    maintenance,
                    page.next,
                    prior_cursor.as_deref(),
                    StartupPhase::Complete,
                    "eager-KV",
                )?;
            }
            StartupPhase::Complete => unreachable!(),
        }
    }

    if scanned_rows == limits.max_scanned_rows
        || scanned_bytes == limits.max_scanned_bytes
        || scanned_pages == limits.max_pages
    {
        return Ok(false);
    }
    Ok(!maintenance.needed())
}

fn validate_startup_page<T>(
    page: &MirrorPage<T>,
    row_limit: usize,
    byte_limit: usize,
    page_limit: usize,
    label: &str,
) -> Result<(), String> {
    if page.rows.len() > row_limit {
        return Err(format!(
            "Firestore mirror exceeded the startup {label} row limit"
        ));
    }
    if page.scanned_bytes > byte_limit {
        return Err(format!(
            "Firestore mirror exceeded the startup {label} byte limit"
        ));
    }
    if page.scanned_pages == 0 || page.scanned_pages > page_limit {
        return Err(format!(
            "Firestore mirror exceeded the startup {label} page limit"
        ));
    }
    Ok(())
}

fn advance_startup_phase(
    maintenance: &mut StartupMaintenance,
    next: Option<String>,
    prior_cursor: Option<&str>,
    completed_phase: StartupPhase,
    label: &str,
) -> Result<(), String> {
    match next {
        Some(next) if Some(next.as_str()) != prior_cursor => maintenance.cursor = Some(next),
        Some(_) => return Err(format!("Firestore {label} startup cursor did not advance")),
        None => {
            maintenance.phase = completed_phase;
            maintenance.cursor = None;
        }
    }
    Ok(())
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
        let mut candidate = self.inner.clone();
        if !candidate.put(bundle, now_ms) || !candidate.contains(&id) {
            return false;
        }
        if self
            .commit_op(|ack| Op::Write {
                id,
                data,
                expires_at,
                ack,
            })
            .is_err()
        {
            return false;
        }
        self.inner = candidate;
        true
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
        let mut candidate = self.inner.clone();
        let held = candidate.rehydrate(bundle, now_ms) && candidate.contains(&id);
        if held
            && self
                .commit_op(|ack| Op::Write {
                    id,
                    data,
                    expires_at,
                    ack,
                })
                .is_ok()
        {
            self.inner = candidate;
            true
        } else {
            false
        }
    }

    fn get(&self, id: &BundleId) -> Option<Bundle> {
        self.inner.get(id)
    }

    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        let removed = self.inner.get(id)?;
        self.commit_op(|ack| Op::Delete { id: *id, ack }).ok()?;
        self.inner.remove(id);
        Some(removed)
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
        let Some(mut candidate) = self.inner.get(id) else {
            return 0;
        };
        let give = candidate.split_copies();
        if give > 0 && self.remirror(id, &candidate).is_ok() {
            self.inner.set_copies(id, candidate.env.copies);
            give
        } else {
            0
        }
    }

    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        let Some(mut candidate) = self.inner.get(id) else {
            return;
        };
        candidate.env.copies = copies;
        if self.remirror(id, &candidate).is_ok() {
            self.inner.set_copies(id, copies);
        }
    }

    fn seen_expiry(&self, id: &BundleId) -> Option<u64> {
        // stores-r3-01: expose the hot-path MemoryStore's receiver-anchored dedup deadline so the
        // relay's handoff/spool path anchors the durable Firestore `expireAt` to it (not to the
        // sender's advisory created_at, which can be 0 and would sweep a live message early).
        self.inner.seen_expiry(id)
    }

    // --- kv surface (stores-07): write-through to the durable `relays/{node}/kv` collection. ---

    fn put_kv(&mut self, key: &str, value: Vec<u8>) {
        let durable = value.clone();
        if self
            .commit_op(|ack| Op::KvWrite {
                key: key.to_string(),
                value: durable,
                ack,
            })
            .is_ok()
        {
            self.inner.put_kv(key, value);
        }
    }

    fn apply_kv_batch(&mut self, mutations: &[KvMutation]) -> std::result::Result<(), String> {
        if !self.durability.is_ready() {
            return Err(format!(
                "durable store is {:?} with {} unreconciled mutation(s)",
                self.durability.status(),
                self.durability.unreconciled()
            ));
        }
        if mutations.is_empty() {
            return Ok(());
        }
        serialize_critical_batch(mutations).map_err(|error| error.to_string())?;
        let mut candidate = self.inner.clone();
        candidate.apply_kv_batch(mutations)?;
        let durable = mutations.to_vec();
        self.commit_op(|ack| Op::KvBatch {
            mutations: durable,
            ack,
        })
        .map_err(|error| error.to_string())?;
        self.inner = candidate;
        Ok(())
    }

    fn put_kv_critical(&mut self, key: &str, value: Vec<u8>) -> std::result::Result<(), String> {
        self.apply_kv_batch(&[KvMutation::Put {
            key: key.to_string(),
            value,
        }])
    }

    fn get_kv(&self, key: &str) -> Option<Vec<u8>> {
        // The in-memory copy is authoritative in-process (loaded on open, kept in sync on write).
        self.inner.get_kv(key)
    }

    fn remove_kv(&mut self, key: &str) {
        if self
            .commit_op(|ack| Op::KvDelete {
                key: key.to_string(),
                ack,
            })
            .is_ok()
        {
            self.inner.remove_kv(key);
        }
    }

    fn remove_kv_critical(&mut self, key: &str) -> std::result::Result<(), String> {
        self.apply_kv_batch(&[KvMutation::Remove {
            key: key.to_string(),
        }])
    }

    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Vec<(String, Vec<u8>)> {
        if prefix.starts_with(LAZY_KV_PREFIX) {
            return match self.mirror.list_kv_page(prefix, after, limit) {
                Ok(page) => page,
                Err(_) => {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                    self.durability.mark_not_ready();
                    Vec::new()
                }
            };
        }
        self.inner.list_kv_page(prefix, after, limit)
    }

    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> std::result::Result<KvPage, String> {
        if !prefix.starts_with(LAZY_KV_PREFIX) {
            return self
                .inner
                .list_kv_page_bounded(prefix, after, limit, max_bytes);
        }
        match self
            .mirror
            .list_kv_page_bounded(prefix, after, limit, max_bytes)
        {
            Ok(page) => {
                let rows = page
                    .rows
                    .into_iter()
                    .map(|row| {
                        let expected_document = bs58::encode(row.key.as_bytes()).into_string();
                        let canonical = row.key.starts_with(prefix)
                            && row.key.len() <= CRITICAL_BATCH_MAX_KEY_BYTES
                            && row.document_id == expected_document
                            && row.value.is_some();
                        KvPageRow {
                            key: row.key,
                            value: row.value,
                            storage_id: Some(row.document_id),
                            canonical,
                        }
                    })
                    .collect();
                Ok(KvPage {
                    rows,
                    scanned_bytes: page.scanned_bytes,
                    scanned_pages: page.scanned_pages,
                })
            }
            Err(error) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.durability.mark_not_ready();
                Err(error)
            }
        }
    }

    fn remove_kv_rows_critical(&mut self, rows: &[KvPageRow]) -> std::result::Result<(), String> {
        if !self.durability.is_ready() {
            return Err(format!(
                "durable store is {:?} with {} unreconciled mutation(s)",
                self.durability.status(),
                self.durability.unreconciled()
            ));
        }
        let mut canonical = Vec::new();
        for row in rows {
            if !row.canonical {
                let document_id = row.storage_id.as_deref().ok_or_else(|| {
                    "malformed Firestore KV row has no durable document identity".to_string()
                })?;
                if let Err(error) = self.mirror.delete_kv_document(document_id) {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                    self.durability.mark_not_ready();
                    return Err(format!("Firestore listed-KV cleanup failed: {error}"));
                }
            } else {
                canonical.push(KvMutation::Remove {
                    key: row.key.clone(),
                });
            }
        }
        self.apply_kv_batch(&canonical)
    }

    /// F-21: block until the background writer has drained every pending mirror (or `timeout`
    /// elapses). The queue is FIFO, so an acked Flush means every prior Write/Delete/kv op was
    /// attempted. The Flush sentinel is never drop-oldest'd (stores-09), so this can't wedge.
    fn flush(&self, timeout: std::time::Duration) -> bool {
        let (ack_tx, ack_rx) = mpsc::sync_channel::<bool>(0);
        if self.tx.send(Op::Flush(ack_tx)).is_err() {
            return false;
        }
        ack_rx.recv_timeout(timeout).unwrap_or(false)
    }

    fn durability_status(&self) -> DurabilityReadiness {
        self.durability.status()
    }

    fn durability_handle(&self) -> Option<DurabilityHandle> {
        Some(self.durability.clone())
    }

    fn probe_durability(&mut self) -> std::result::Result<(), String> {
        let recovery_generation = self.durability.begin_recovery();
        if self.startup_cleanup_pending() {
            let mut maintenance = self
                .startup_maintenance
                .take()
                .ok_or_else(|| "Firestore startup maintenance state is missing".to_string())?;
            match run_startup_maintenance_round(
                &mut self.inner,
                self.mirror.as_ref(),
                &mut self.startup_usage,
                &mut maintenance,
                self.startup_limits,
            ) {
                Ok(true) => {
                    self.startup_cleanup_pending.store(0, Ordering::Release);
                }
                Ok(false) => {
                    self.startup_maintenance = Some(maintenance);
                    return Err(
                        "Firestore startup bounded-maintenance continuation is pending".into(),
                    );
                }
                Err(error) => {
                    self.startup_maintenance = Some(maintenance);
                    self.failed.fetch_add(1, Ordering::Relaxed);
                    self.durability.mark_not_ready();
                    return Err(format!("Firestore startup maintenance failed: {error}"));
                }
            }
        }
        self.mirror.durability_probe().map_err(|error| {
            self.durability.mark_not_ready();
            format!("Firestore write/read/delete readiness probe failed: {error}")
        })?;
        if self.durability.unreconciled() != 0 {
            return Err(format!(
                "{} ambiguous mutation(s) still require restart reconciliation",
                self.durability.unreconciled()
            ));
        }
        if !self.drain_for_recovery(Duration::from_secs(5)) {
            self.durability.mark_not_ready();
            return Err("Firestore mirror did not flush before readiness recovery".into());
        }
        self.mirror
            .confirm_critical_operation_fence()
            .map_err(|error| {
                self.durability.mark_not_ready();
                format!("Firestore critical-operation fence check failed: {error}")
            })?;
        if !self
            .durability
            .mark_ready_if_reconciled(recovery_generation)
        {
            return Err("Firestore durability failed during readiness recovery".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Firestore REST client (blocking; runs on the writer, cold open, and bounded maintenance probes).
// ---------------------------------------------------------------------------

/// Firestore commit requests time out in 15 seconds and the worker makes at most three attempts.
/// Keep journal evidence for a full day, far beyond that retry window, then let Firestore TTL bound
/// the operation collection without an application-side delete.
const OPERATION_MARKER_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const CRITICAL_BATCH_MAX_MUTATIONS: usize = 400;
const CRITICAL_BATCH_MAX_BYTES: usize = 512 * 1024;
const CRITICAL_BATCH_MAX_KEY_BYTES: usize = 1024;
const OPERATION_JOURNAL_PAGE_SIZE: usize = 32;
const OPERATION_JOURNAL_MAX_RECORDS: usize = 10_000;
const OPERATION_JOURNAL_MAX_PAGES: usize = 313;
const OPERATION_JOURNAL_MAX_SCAN_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const OPERATION_JOURNAL_MAX_PENDING: usize = 128;
const OPERATION_JOURNAL_MAX_SCAN_MUTATIONS: usize = 1_000_000;
const OPERATION_JOURNAL_MAX_SCAN_BYTES: usize = 256 * 1024 * 1024;
const OPERATION_JOURNAL_MAX_REPLAY_MUTATIONS: usize = 16_384;
const OPERATION_JOURNAL_MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
const OPERATION_JOURNAL_MAX_DOCUMENT_RESPONSE_BYTES: usize = 1024 * 1024;
const OPERATION_JOURNAL_MAX_PAGE_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
const OPERATION_FENCE_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const OPERATION_FENCE_ROTATION_ATTEMPTS: usize = 8;
const OPERATION_JOURNAL_MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
const OPERATION_JOURNAL_MAGIC: &[u8; 8] = b"HOPJNL01";

#[derive(Clone, Copy)]
struct OperationRecoveryLimits {
    page_size: usize,
    max_records: usize,
    max_pages: usize,
    max_response_bytes: usize,
}

impl Default for OperationRecoveryLimits {
    fn default() -> Self {
        Self {
            page_size: OPERATION_JOURNAL_PAGE_SIZE,
            max_records: OPERATION_JOURNAL_MAX_RECORDS,
            max_pages: OPERATION_JOURNAL_MAX_PAGES,
            max_response_bytes: OPERATION_JOURNAL_MAX_SCAN_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalState {
    Pending,
    Committed,
}

#[derive(Clone)]
struct JournalRecord {
    operation_id: String,
    identity: [u8; 32],
    serialized: Vec<u8>,
    mutations: Vec<KvMutation>,
    state: JournalState,
    created_at: u64,
    update_time: String,
}

enum OperationDocument {
    Journal(JournalRecord),
    LegacyCommitted {
        operation_id: String,
        identity: [u8; 32],
    },
}

enum JournalLookup {
    Absent,
    Pending(JournalRecord),
    Committed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OperationFence {
    generation: [u8; 32],
    update_time: String,
}

fn commit_status_is_ambiguous(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || matches!(status.as_u16(), 408 | 409 | 412 | 429)
}

fn bounded_response_json(
    response: reqwest::blocking::Response,
    max_bytes: usize,
    context: &str,
) -> Result<serde_json::Value, String> {
    bounded_response_json_with_size(response, max_bytes, context).map(|(value, _)| value)
}

fn bounded_response_json_with_size(
    response: reqwest::blocking::Response,
    max_bytes: usize,
    context: &str,
) -> Result<(serde_json::Value, usize), String> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    response
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{context} body read failed: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{context} body exceeds {max_bytes} bytes"));
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{context} decode failed: {error}"))?;
    Ok((value, bytes.len()))
}

fn firestore_documents<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> Result<&'a [serde_json::Value], String> {
    match value.get("documents") {
        None | Some(serde_json::Value::Null) => Ok(&[]),
        Some(serde_json::Value::Array(documents)) => Ok(documents),
        Some(_) => Err(format!("{context} documents field is not an array")),
    }
}

fn firestore_page_token(
    value: &serde_json::Value,
    context: &str,
) -> Result<Option<String>, String> {
    match value.get("nextPageToken") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(token)) if token.is_empty() => Ok(None),
        Some(serde_json::Value::String(token)) => Ok(Some(token.clone())),
        Some(_) => Err(format!("{context} nextPageToken is not a string")),
    }
}

fn serialize_critical_batch(mutations: &[KvMutation]) -> Result<Vec<u8>, MirrorBatchError> {
    if mutations.len() > CRITICAL_BATCH_MAX_MUTATIONS {
        return Err(MirrorBatchError::definitive(format!(
            "critical Firestore batch has {} mutations, limit is {CRITICAL_BATCH_MAX_MUTATIONS}",
            mutations.len()
        )));
    }

    fn append_bytes(
        output: &mut Vec<u8>,
        bytes: &[u8],
        label: &str,
    ) -> Result<(), MirrorBatchError> {
        let length = u32::try_from(bytes.len()).map_err(|_| {
            MirrorBatchError::definitive(format!("critical batch {label} is too large"))
        })?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(bytes);
        if output.len() > CRITICAL_BATCH_MAX_BYTES {
            return Err(MirrorBatchError::definitive(format!(
                "serialized critical Firestore batch exceeds {CRITICAL_BATCH_MAX_BYTES} bytes"
            )));
        }
        Ok(())
    }

    let mut targets = std::collections::BTreeSet::new();
    for mutation in mutations {
        let target = match mutation {
            KvMutation::Put { key, .. } | KvMutation::Remove { key } => {
                if key.is_empty() || key.len() > CRITICAL_BATCH_MAX_KEY_BYTES {
                    return Err(MirrorBatchError::definitive(format!(
                        "critical Firestore key length must be within 1..={CRITICAL_BATCH_MAX_KEY_BYTES} bytes"
                    )));
                }
                let mut target = Vec::with_capacity(key.len().saturating_add(1));
                target.push(0);
                target.extend_from_slice(key.as_bytes());
                target
            }
            KvMutation::PutBundle { bundle, .. } => {
                let mut target = Vec::with_capacity(33);
                target.push(1);
                target.extend_from_slice(&bundle.id());
                target
            }
            KvMutation::RemoveBundle { id } => {
                let mut target = Vec::with_capacity(33);
                target.push(1);
                target.extend_from_slice(id);
                target
            }
        };
        if !targets.insert(target) {
            return Err(MirrorBatchError::definitive(
                "critical Firestore batch writes the same document more than once",
            ));
        }
    }

    let count = u32::try_from(mutations.len())
        .map_err(|_| MirrorBatchError::definitive("critical batch mutation count overflow"))?;
    let mut output = Vec::new();
    output.extend_from_slice(OPERATION_JOURNAL_MAGIC);
    output.extend_from_slice(&count.to_be_bytes());
    for mutation in mutations {
        match mutation {
            KvMutation::Put { key, value } => {
                output.push(0);
                append_bytes(&mut output, key.as_bytes(), "key")?;
                append_bytes(&mut output, value, "value")?;
            }
            KvMutation::Remove { key } => {
                output.push(1);
                append_bytes(&mut output, key.as_bytes(), "key")?;
            }
            KvMutation::PutBundle { bundle, now_ms } => {
                output.push(2);
                output.extend_from_slice(&now_ms.to_be_bytes());
                let bytes = bundle
                    .to_bytes()
                    .map_err(|error| MirrorBatchError::definitive(error.to_string()))?;
                append_bytes(&mut output, &bytes, "bundle")?;
            }
            KvMutation::RemoveBundle { id } => {
                output.push(3);
                output.extend_from_slice(id);
            }
        }
        if output.len() > CRITICAL_BATCH_MAX_BYTES {
            return Err(MirrorBatchError::definitive(format!(
                "serialized critical Firestore batch exceeds {CRITICAL_BATCH_MAX_BYTES} bytes"
            )));
        }
    }
    Ok(output)
}

struct BatchDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BatchDecoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "critical-operation journal length overflow".to_string())?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated critical-operation journal".to_string())?;
        self.offset = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| "invalid critical-operation u32".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| "invalid critical-operation u64".to_string())?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn sized_bytes(&mut self) -> Result<&'a [u8], String> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| "critical-operation length does not fit usize".to_string())?;
        self.take(length)
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.sized_bytes()?.to_vec())
            .map_err(|_| "critical-operation journal key is not UTF-8".to_string())
    }
}

fn deserialize_critical_batch(serialized: &[u8]) -> Result<Vec<KvMutation>, String> {
    if serialized.len() > CRITICAL_BATCH_MAX_BYTES {
        return Err(format!(
            "serialized critical-operation journal exceeds {CRITICAL_BATCH_MAX_BYTES} bytes"
        ));
    }
    let mut decoder = BatchDecoder {
        bytes: serialized,
        offset: 0,
    };
    if decoder.take(OPERATION_JOURNAL_MAGIC.len())? != OPERATION_JOURNAL_MAGIC {
        return Err("critical-operation journal magic mismatch".into());
    }
    let count = usize::try_from(decoder.u32()?)
        .map_err(|_| "critical-operation mutation count does not fit usize".to_string())?;
    if count == 0 || count > CRITICAL_BATCH_MAX_MUTATIONS {
        return Err(format!(
            "critical-operation journal mutation count {count} is outside 1..={CRITICAL_BATCH_MAX_MUTATIONS}"
        ));
    }
    let mut mutations = Vec::with_capacity(count);
    for _ in 0..count {
        let mutation = match decoder.byte()? {
            0 => KvMutation::Put {
                key: decoder.string()?,
                value: decoder.sized_bytes()?.to_vec(),
            },
            1 => KvMutation::Remove {
                key: decoder.string()?,
            },
            2 => {
                let now_ms = decoder.u64()?;
                let bundle = Bundle::from_bytes(decoder.sized_bytes()?)
                    .map_err(|error| format!("invalid journaled bundle: {error}"))?;
                KvMutation::PutBundle {
                    bundle: Box::new(bundle),
                    now_ms,
                }
            }
            3 => {
                let id: BundleId = decoder
                    .take(32)?
                    .try_into()
                    .map_err(|_| "invalid journaled bundle id".to_string())?;
                KvMutation::RemoveBundle { id }
            }
            tag => return Err(format!("unknown critical-operation mutation tag {tag}")),
        };
        mutations.push(mutation);
    }
    if decoder.offset != serialized.len() {
        return Err("critical-operation journal has trailing bytes".into());
    }
    Ok(mutations)
}

fn critical_batch_identity(mutations: &[KvMutation]) -> Result<[u8; 32], MirrorBatchError> {
    serialize_critical_batch(mutations)?;

    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"hop.firestore.critical-batch.v1");
    hasher.update(&(mutations.len() as u64).to_be_bytes());
    for mutation in mutations {
        match mutation {
            KvMutation::Put { key, value } => {
                hasher.update(&[0]);
                field(&mut hasher, key.as_bytes());
                field(&mut hasher, value);
            }
            KvMutation::Remove { key } => {
                hasher.update(&[1]);
                field(&mut hasher, key.as_bytes());
            }
            KvMutation::PutBundle { bundle, now_ms } => {
                hasher.update(&[2]);
                hasher.update(&now_ms.to_be_bytes());
                field(
                    &mut hasher,
                    &bundle
                        .to_bytes()
                        .map_err(|error| MirrorBatchError::definitive(error.to_string()))?,
                );
            }
            KvMutation::RemoveBundle { id } => {
                hasher.update(&[3]);
                hasher.update(id);
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn operation_journal_json(
    operation_id: &str,
    identity: &[u8; 32],
    serialized: &[u8],
    mutation_count: usize,
    state: JournalState,
    created_at: u64,
    committed_at: Option<u64>,
) -> serde_json::Value {
    let mut fields = serde_json::json!({
        "journalVersion": { "integerValue": "1" },
        "operationId": { "stringValue": operation_id },
        "mutationId": {
            "bytesValue": base64::engine::general_purpose::STANDARD.encode(identity)
        },
        "mutationCount": { "integerValue": mutation_count.to_string() },
        "mutationBytes": { "integerValue": serialized.len().to_string() },
        "mutations": {
            "bytesValue": base64::engine::general_purpose::STANDARD.encode(serialized)
        },
        "state": {
            "stringValue": match state {
                JournalState::Pending => "pending",
                JournalState::Committed => "committed",
            }
        },
        "createdAt": { "integerValue": created_at.to_string() },
        "expireAt": {
            "timestampValue": rfc3339_utc(
                created_at.saturating_add(OPERATION_MARKER_RETENTION_MS)
            )
        }
    });
    if let Some(committed_at) = committed_at {
        fields["committedAt"] = serde_json::json!({ "integerValue": committed_at.to_string() });
    }
    serde_json::json!({ "fields": fields })
}

fn operation_fence_json(generation: &[u8; 32], document_name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": document_name,
        "fields": {
            "fenceVersion": { "integerValue": "1" },
            "generation": {
                "bytesValue": base64::engine::general_purpose::STANDARD.encode(generation)
            }
        }
    })
}

fn decode_identity(value: &serde_json::Value, field: &str) -> Result<[u8; 32], String> {
    let encoded = value["fields"][field]["bytesValue"]
        .as_str()
        .ok_or_else(|| format!("critical-operation {field} is missing"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| format!("critical-operation {field} is not base64"))?;
    decoded
        .try_into()
        .map_err(|_| format!("critical-operation {field} is not 32 bytes"))
}

fn integer_field(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value["fields"][field]["integerValue"]
        .as_str()
        .ok_or_else(|| format!("critical-operation {field} is missing"))?
        .parse()
        .map_err(|_| format!("critical-operation {field} is not an integer"))
}

fn parse_operation_document(value: &serde_json::Value) -> Result<OperationDocument, String> {
    let fields = value["fields"]
        .as_object()
        .ok_or_else(|| "critical-operation document has no fields".to_string())?;
    let document_name = value["name"]
        .as_str()
        .ok_or_else(|| "critical-operation document has no name".to_string())?;
    let document_id = document_name
        .rsplit('/')
        .next()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "critical-operation document has an invalid name".to_string())?;
    let update_time = value["updateTime"]
        .as_str()
        .filter(|time| !time.is_empty())
        .ok_or_else(|| "critical-operation document has no updateTime".to_string())?;
    let identity = decode_identity(value, "mutationId")?;
    let expire_at = value["fields"]["expireAt"]["timestampValue"]
        .as_str()
        .filter(|time| !time.is_empty())
        .ok_or_else(|| "critical-operation expireAt is missing".to_string())?;

    if !fields.contains_key("journalVersion") {
        if fields.contains_key("state")
            || fields.contains_key("mutations")
            || fields.contains_key("operationId")
            || fields.len() != 2
        {
            return Err("critical-operation journal version is missing".into());
        }
        if !document_id.starts_with("readiness-")
            && document_id != bs58::encode(identity).into_string()
        {
            return Err("legacy critical-operation marker id mismatch".into());
        }
        return Ok(OperationDocument::LegacyCommitted {
            operation_id: document_id.to_string(),
            identity,
        });
    }
    if integer_field(value, "journalVersion")? != 1 {
        return Err("unsupported critical-operation journal version".into());
    }
    let operation_id = value["fields"]["operationId"]["stringValue"]
        .as_str()
        .ok_or_else(|| "critical-operation operationId is missing".to_string())?;
    if operation_id != document_id || operation_id != bs58::encode(identity).into_string() {
        return Err(
            "critical-operation id does not match its document or mutation identity".into(),
        );
    }
    let encoded = value["fields"]["mutations"]["bytesValue"]
        .as_str()
        .ok_or_else(|| "critical-operation mutations are missing".to_string())?;
    let max_encoded = CRITICAL_BATCH_MAX_BYTES.div_ceil(3) * 4;
    if encoded.len() > max_encoded {
        return Err("critical-operation mutations exceed the encoded byte limit".into());
    }
    let serialized = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "critical-operation mutations are not base64".to_string())?;
    if serialized.len() != integer_field(value, "mutationBytes")? as usize {
        return Err("critical-operation mutation byte count mismatch".into());
    }
    let mutations = deserialize_critical_batch(&serialized)?;
    if serialize_critical_batch(&mutations).map_err(|error| error.to_string())? != serialized {
        return Err("critical-operation mutation encoding is not canonical".into());
    }
    if mutations.len() != integer_field(value, "mutationCount")? as usize {
        return Err("critical-operation mutation count mismatch".into());
    }
    if critical_batch_identity(&mutations).map_err(|error| error.to_string())? != identity {
        return Err("critical-operation mutation identity mismatch".into());
    }
    let created_at = integer_field(value, "createdAt")?;
    let now_ms = epoch_ms();
    if created_at > now_ms.saturating_add(OPERATION_JOURNAL_MAX_CLOCK_SKEW_MS) {
        return Err("critical-operation createdAt is too far in the future".into());
    }
    if expire_at != rfc3339_utc(created_at.saturating_add(OPERATION_MARKER_RETENTION_MS)).as_str() {
        return Err("critical-operation retention deadline mismatch".into());
    }
    let state = match value["fields"]["state"]["stringValue"].as_str() {
        Some("pending") if !fields.contains_key("committedAt") => JournalState::Pending,
        Some("committed") => {
            let committed_at = integer_field(value, "committedAt")?;
            if committed_at < created_at
                || committed_at > now_ms.saturating_add(OPERATION_JOURNAL_MAX_CLOCK_SKEW_MS)
            {
                return Err("critical-operation committedAt is outside its valid window".into());
            }
            JournalState::Committed
        }
        Some("pending") => return Err("pending critical-operation has committedAt".into()),
        _ => return Err("critical-operation state is invalid".into()),
    };
    Ok(OperationDocument::Journal(JournalRecord {
        operation_id: operation_id.to_string(),
        identity,
        serialized,
        mutations,
        state,
        created_at,
        update_time: update_time.to_string(),
    }))
}

fn parse_operation_fence(value: &serde_json::Value) -> Result<OperationFence, String> {
    if integer_field(value, "fenceVersion")? != 1 {
        return Err("unsupported critical-operation fence version".into());
    }
    let generation = decode_identity(value, "generation")?;
    let update_time = value["updateTime"]
        .as_str()
        .filter(|time| !time.is_empty())
        .ok_or_else(|| "critical-operation fence has no updateTime".to_string())?;
    Ok(OperationFence {
        generation,
        update_time: update_time.to_string(),
    })
}

fn operation_marker_json(identity: &[u8; 32], expires_at: u64) -> serde_json::Value {
    let mutation_id = base64::engine::general_purpose::STANDARD.encode(identity);
    serde_json::json!({
        "fields": {
            "mutationId": { "bytesValue": mutation_id },
            "expireAt": { "timestampValue": rfc3339_utc(expires_at) }
        }
    })
}

struct FirestoreClient {
    http: reqwest::blocking::Client,
    collection_url: String, // .../documents/relays/{node}/bundles
    kv_url: String,         // .../documents/relays/{node}/kv (stores-07)
    run_query_url: String,  // .../documents/relays/{node}:runQuery
    commit_url: String,     // .../documents:commit
    operation_url: String,  // .../documents/relays/{node}/operations
    operation_fence_url: String,
    bundle_document_prefix: String,
    kv_document_prefix: String,
    operation_document_prefix: String,
    operation_fence_document: String,
    operation_fence: Mutex<Option<OperationFence>>,
    operation_recovery: Mutex<()>,
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
        let run_query_url = format!(
            "{base}/projects/{project}/databases/(default)/documents/relays/{node}:runQuery"
        );
        let commit_url = format!("{base}/projects/{project}/databases/(default)/documents:commit");
        let operation_url = format!(
            "{base}/projects/{project}/databases/(default)/documents/relays/{node}/operations"
        );
        let operation_fence_url = format!(
            "{base}/projects/{project}/databases/(default)/documents/relays/{node}/control/critical-operation-fence"
        );
        let bundle_document_prefix =
            format!("projects/{project}/databases/(default)/documents/relays/{node}/bundles");
        let kv_document_prefix =
            format!("projects/{project}/databases/(default)/documents/relays/{node}/kv");
        let operation_document_prefix =
            format!("projects/{project}/databases/(default)/documents/relays/{node}/operations");
        let operation_fence_document = format!(
            "projects/{project}/databases/(default)/documents/relays/{node}/control/critical-operation-fence"
        );
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            collection_url,
            kv_url,
            run_query_url,
            commit_url,
            operation_url,
            operation_fence_url,
            bundle_document_prefix,
            kv_document_prefix,
            operation_document_prefix,
            operation_fence_document,
            operation_fence: Mutex::new(None),
            operation_recovery: Mutex::new(()),
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

    fn list_bundle_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<BundleMirrorRow>, String> {
        if limit == 0 || max_bytes == 0 {
            return Ok(MirrorPage::default());
        }
        let token = self.token()?;
        let page_size = limit.min(FIRESTORE_KV_PAGE_SIZE).to_string();
        let mut query = vec![("pageSize", page_size.as_str())];
        if let Some(cursor) = cursor {
            query.push(("pageToken", cursor));
        }
        let response = self
            .http
            .get(&self.collection_url)
            .query(&query)
            .bearer_auth(token)
            .send()
            .map_err(|error| error.to_string())?;
        if response.status().as_u16() == 404 {
            return Ok(MirrorPage {
                rows: Vec::new(),
                next: None,
                scanned_bytes: 0,
                scanned_pages: 1,
            });
        }
        if !response.status().is_success() {
            return Err(format!("list {}", response.status()));
        }
        let (value, scanned_bytes) =
            bounded_response_json_with_size(response, max_bytes, "Firestore bundle page")?;
        let documents = firestore_documents(&value, "Firestore bundle page")?;
        if documents.len() > limit {
            return Err("Firestore ignored the bounded bundle page size".into());
        }
        let mut rows = Vec::with_capacity(documents.len());
        for document in documents {
            rows.push(BundleMirrorRow {
                document_id: firestore_document_id(document)?,
                value: parse_doc(document),
            });
        }
        Ok(MirrorPage {
            rows,
            next: firestore_page_token(&value, "Firestore bundle page")?,
            scanned_bytes,
            scanned_pages: 1,
        })
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
        self.delete_kv_document(&doc)
    }

    fn delete_kv_document(&self, document_id: &str) -> Result<(), String> {
        let mut url = reqwest::Url::parse(&self.kv_url)
            .map_err(|error| format!("invalid Firestore KV URL: {error}"))?;
        url.path_segments_mut()
            .map_err(|_| "Firestore KV URL cannot accept a document id".to_string())?
            .push(document_id);
        let token = self.token()?;
        let resp = self
            .http
            .delete(url)
            .bearer_auth(token)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("delete_kv {}", resp.status()))
        }
    }

    fn apply_kv_batch(&self, mutations: &[KvMutation]) -> Result<(), MirrorBatchError> {
        if mutations.is_empty() {
            return Ok(());
        }
        let serialized = serialize_critical_batch(mutations)?;
        let identity = critical_batch_identity(mutations)?;
        let operation_id = bs58::encode(identity).into_string();
        let fence = self.active_operation_fence()?;
        let pending = match self.lookup_journal(&operation_id, &identity, &serialized)? {
            JournalLookup::Committed => return Ok(()),
            JournalLookup::Pending(record) => record,
            JournalLookup::Absent => {
                match self.create_pending_journal(
                    &operation_id,
                    &identity,
                    &serialized,
                    mutations.len(),
                    &fence,
                )? {
                    JournalLookup::Committed => return Ok(()),
                    JournalLookup::Pending(record) => record,
                    JournalLookup::Absent => {
                        return Err(MirrorBatchError::unknown(
                            "pending critical-operation journal was not confirmed",
                        ))
                    }
                }
            }
        };
        self.commit_pending_journal(&pending, &fence)
    }

    fn mutation_writes(
        &self,
        mutations: &[KvMutation],
    ) -> Result<Vec<serde_json::Value>, MirrorBatchError> {
        mutations
            .iter()
            .map(|mutation| -> Result<serde_json::Value, MirrorBatchError> {
                Ok(match mutation {
                    KvMutation::Put { key, value } => {
                        let doc_id = bs58::encode(key.as_bytes()).into_string();
                        let mut document = kv_doc_json(key, value);
                        document["name"] = serde_json::Value::String(format!(
                            "{}/{doc_id}",
                            self.kv_document_prefix
                        ));
                        serde_json::json!({ "update": document })
                    }
                    KvMutation::Remove { key } => {
                        let doc_id = bs58::encode(key.as_bytes()).into_string();
                        serde_json::json!({
                            "delete": format!("{}/{doc_id}", self.kv_document_prefix)
                        })
                    }
                    KvMutation::PutBundle { bundle, now_ms } => {
                        let doc_id = bs58::encode(bundle.id()).into_string();
                        let lifetime = (bundle.inner.lifetime_ms as u64)
                            .min(hop_core::store::MAX_SEEN_LIFETIME_MS);
                        let data = bundle
                            .to_bytes()
                            .map_err(|error| MirrorBatchError::definitive(error.to_string()))?;
                        let mut document = doc_json(&data, now_ms.saturating_add(lifetime));
                        document["name"] = serde_json::Value::String(format!(
                            "{}/{doc_id}",
                            self.bundle_document_prefix
                        ));
                        serde_json::json!({ "update": document })
                    }
                    KvMutation::RemoveBundle { id } => {
                        let doc_id = bs58::encode(id).into_string();
                        serde_json::json!({
                            "delete": format!("{}/{doc_id}", self.bundle_document_prefix)
                        })
                    }
                })
            })
            .collect()
    }

    fn active_operation_fence(&self) -> Result<OperationFence, MirrorBatchError> {
        self.operation_fence
            .lock()
            .map_err(|_| MirrorBatchError::unknown("critical-operation fence lock poisoned"))?
            .clone()
            .ok_or_else(|| MirrorBatchError::unknown("critical-operation fence is not initialized"))
    }

    fn read_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<OperationDocument>, MirrorBatchError> {
        let token = self.token().map_err(MirrorBatchError::unknown)?;
        let url = format!("{}/{operation_id}", self.operation_url);
        let response = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .map_err(|error| {
                MirrorBatchError::unknown(format!(
                    "critical-operation journal read failed: {error}"
                ))
            })?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(MirrorBatchError::unknown(format!(
                "critical-operation journal read returned {}",
                response.status()
            )));
        }
        let document = bounded_response_json(
            response,
            OPERATION_JOURNAL_MAX_DOCUMENT_RESPONSE_BYTES,
            "critical-operation journal",
        )
        .map_err(MirrorBatchError::unknown)?;
        parse_operation_document(&document)
            .map(Some)
            .map_err(MirrorBatchError::unknown)
    }

    fn lookup_journal(
        &self,
        operation_id: &str,
        identity: &[u8; 32],
        serialized: &[u8],
    ) -> Result<JournalLookup, MirrorBatchError> {
        match self.read_operation(operation_id)? {
            None => Ok(JournalLookup::Absent),
            Some(OperationDocument::LegacyCommitted {
                operation_id: observed_id,
                identity: observed_identity,
            }) if observed_id == operation_id && observed_identity == *identity => {
                Ok(JournalLookup::Committed)
            }
            Some(OperationDocument::LegacyCommitted { .. }) => Err(MirrorBatchError::unknown(
                "legacy critical-operation marker identity mismatch",
            )),
            Some(OperationDocument::Journal(record))
                if record.operation_id == operation_id
                    && record.identity == *identity
                    && record.serialized == serialized =>
            {
                match record.state {
                    JournalState::Pending => Ok(JournalLookup::Pending(record)),
                    JournalState::Committed => Ok(JournalLookup::Committed),
                }
            }
            Some(OperationDocument::Journal(_)) => Err(MirrorBatchError::unknown(
                "critical-operation journal does not match the submitted batch",
            )),
        }
    }

    fn create_pending_journal(
        &self,
        operation_id: &str,
        identity: &[u8; 32],
        serialized: &[u8],
        mutation_count: usize,
        fence: &OperationFence,
    ) -> Result<JournalLookup, MirrorBatchError> {
        let document_name = format!("{}/{operation_id}", self.operation_document_prefix);
        let mut document = operation_journal_json(
            operation_id,
            identity,
            serialized,
            mutation_count,
            JournalState::Pending,
            epoch_ms(),
            None,
        );
        document["name"] = serde_json::Value::String(document_name);
        let writes = serde_json::json!({
            "writes": [
                {
                    "update": document,
                    "currentDocument": { "exists": false }
                },
                {
                    "verify": self.operation_fence_document,
                    "currentDocument": { "updateTime": fence.update_time }
                }
            ]
        });
        let token = self.token().map_err(MirrorBatchError::definitive)?;
        let response = self
            .http
            .post(&self.commit_url)
            .bearer_auth(token)
            .json(&writes)
            .send();
        let cause = match response {
            Ok(response) if response.status().is_success() => {
                "pending journal create succeeded but confirmation failed".to_string()
            }
            Ok(response) if commit_status_is_ambiguous(response.status()) => {
                format!("pending journal create returned {}", response.status())
            }
            Ok(response) => {
                return Err(MirrorBatchError::definitive(format!(
                    "pending journal create returned {}",
                    response.status()
                )))
            }
            Err(error) => format!("pending journal create transport failed: {error}"),
        };
        match self.lookup_journal(operation_id, identity, serialized)? {
            JournalLookup::Absent => Err(MirrorBatchError::unknown(format!(
                "{cause}; journal is absent after confirmation read"
            ))),
            result => Ok(result),
        }
    }

    fn commit_pending_journal(
        &self,
        record: &JournalRecord,
        fence: &OperationFence,
    ) -> Result<(), MirrorBatchError> {
        if record.state != JournalState::Pending {
            return Err(MirrorBatchError::unknown(
                "attempted to replay a non-pending critical-operation journal",
            ));
        }
        let mut writes = self.mutation_writes(&record.mutations)?;
        let document_name = format!("{}/{}", self.operation_document_prefix, record.operation_id);
        let mut committed = operation_journal_json(
            &record.operation_id,
            &record.identity,
            &record.serialized,
            record.mutations.len(),
            JournalState::Committed,
            record.created_at,
            Some(epoch_ms()),
        );
        committed["name"] = serde_json::Value::String(document_name);
        writes.push(serde_json::json!({
            "update": committed,
            "currentDocument": { "updateTime": record.update_time }
        }));
        writes.push(serde_json::json!({
            "verify": self.operation_fence_document,
            "currentDocument": { "updateTime": fence.update_time }
        }));

        let token = self.token().map_err(|error| {
            MirrorBatchError::unknown(format!(
                "pending journal exists but commit token failed: {error}"
            ))
        })?;
        let response = self
            .http
            .post(&self.commit_url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "writes": writes }))
            .send();
        let cause = match response {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => format!("journaled mutation commit returned {}", response.status()),
            Err(error) => format!("journaled mutation commit transport failed: {error}"),
        };
        match self.lookup_journal(&record.operation_id, &record.identity, &record.serialized)? {
            JournalLookup::Committed => Ok(()),
            JournalLookup::Pending(_) => Err(MirrorBatchError::unknown(format!(
                "{cause}; journal remains pending"
            ))),
            JournalLookup::Absent => Err(MirrorBatchError::unknown(format!(
                "{cause}; journal disappeared before reconciliation"
            ))),
        }
    }

    fn read_operation_fence(&self) -> Result<Option<OperationFence>, String> {
        let token = self.token()?;
        let response = self
            .http
            .get(&self.operation_fence_url)
            .bearer_auth(token)
            .send()
            .map_err(|error| format!("critical-operation fence read failed: {error}"))?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(format!(
                "critical-operation fence read returned {}",
                response.status()
            ));
        }
        let document = bounded_response_json(
            response,
            OPERATION_FENCE_MAX_RESPONSE_BYTES,
            "critical-operation fence",
        )?;
        if document["name"].as_str() != Some(self.operation_fence_document.as_str()) {
            return Err("critical-operation fence document name mismatch".into());
        }
        parse_operation_fence(&document).map(Some)
    }

    fn rotate_operation_fence(&self, generation: [u8; 32]) -> Result<OperationFence, String> {
        *self
            .operation_fence
            .lock()
            .map_err(|_| "critical-operation fence lock poisoned".to_string())? = None;
        for _ in 0..OPERATION_FENCE_ROTATION_ATTEMPTS {
            let observed = self.read_operation_fence()?;
            if let Some(fence) = &observed {
                if fence.generation == generation {
                    *self
                        .operation_fence
                        .lock()
                        .map_err(|_| "critical-operation fence lock poisoned".to_string())? =
                        Some(fence.clone());
                    return Ok(fence.clone());
                }
            }
            let current_document = match observed {
                Some(fence) => serde_json::json!({ "updateTime": fence.update_time }),
                None => serde_json::json!({ "exists": false }),
            };
            let body = serde_json::json!({
                "writes": [{
                    "update": operation_fence_json(
                        &generation,
                        &self.operation_fence_document
                    ),
                    "currentDocument": current_document
                }]
            });
            let token = self.token()?;
            let response = self
                .http
                .post(&self.commit_url)
                .bearer_auth(token)
                .json(&body)
                .send();
            if let Ok(response) = &response {
                if !response.status().is_success() && !commit_status_is_ambiguous(response.status())
                {
                    return Err(format!(
                        "critical-operation fence rotation returned {}",
                        response.status()
                    ));
                }
            }
            let confirmed = self.read_operation_fence()?;
            if let Some(fence) = confirmed {
                if fence.generation == generation {
                    *self
                        .operation_fence
                        .lock()
                        .map_err(|_| "critical-operation fence lock poisoned".to_string())? =
                        Some(fence.clone());
                    return Ok(fence);
                }
            }
        }
        Err("critical-operation fence could not be established within its retry bound".into())
    }

    fn list_operation_page(
        &self,
        cursor: Option<&str>,
        page_size: usize,
        max_bytes: usize,
    ) -> Result<(Vec<serde_json::Value>, Option<String>, usize), String> {
        let requested_page_size = page_size;
        let page_size = requested_page_size.to_string();
        let mut query = vec![("pageSize", page_size.as_str())];
        if let Some(cursor) = cursor {
            query.push(("pageToken", cursor));
        }
        let token = self.token()?;
        let response = self
            .http
            .get(&self.operation_url)
            .query(&query)
            .bearer_auth(token)
            .send()
            .map_err(|error| format!("critical-operation journal page failed: {error}"))?;
        if response.status().as_u16() == 404 {
            return Ok((Vec::new(), None, 0));
        }
        if !response.status().is_success() {
            return Err(format!(
                "critical-operation journal page returned {}",
                response.status()
            ));
        }
        let (page, scanned_bytes) = bounded_response_json_with_size(
            response,
            max_bytes.min(OPERATION_JOURNAL_MAX_PAGE_RESPONSE_BYTES),
            "critical-operation journal page",
        )?;
        let documents = firestore_documents(&page, "critical-operation journal page")?;
        if documents.len() > requested_page_size {
            return Err("Firestore ignored the critical-operation journal page limit".into());
        }
        let documents = documents.to_vec();
        let next = firestore_page_token(&page, "critical-operation journal page")?;
        if documents.is_empty() && next.is_some() {
            return Err("critical-operation journal page advanced without records".into());
        }
        Ok((documents, next, scanned_bytes))
    }

    fn recover_critical_operations_with_generation(
        &self,
        generation: [u8; 32],
    ) -> Result<(), String> {
        self.recover_critical_operations_with_generation_and_limits(
            generation,
            OperationRecoveryLimits::default(),
        )
    }

    fn recover_critical_operations_with_generation_and_limits(
        &self,
        generation: [u8; 32],
        limits: OperationRecoveryLimits,
    ) -> Result<(), String> {
        if limits.page_size == 0
            || limits.max_records == 0
            || limits.max_pages == 0
            || limits.max_response_bytes == 0
        {
            return Err("critical-operation recovery limits must be nonzero".into());
        }
        let _recovery = self
            .operation_recovery
            .lock()
            .map_err(|_| "critical-operation recovery lock poisoned".to_string())?;
        let fence = self.rotate_operation_fence(generation)?;
        let mut cursor: Option<String> = None;
        let mut record_count = 0usize;
        let mut page_count = 0usize;
        let mut response_bytes = 0usize;
        let mut scan_mutations = 0usize;
        let mut scan_bytes = 0usize;
        let mut replay_mutations = 0usize;
        let mut replay_bytes = 0usize;
        let mut pending = Vec::new();
        loop {
            if record_count >= limits.max_records {
                return Err(format!(
                    "critical-operation journal exceeds {} records",
                    limits.max_records
                ));
            }
            if page_count >= limits.max_pages {
                return Err(format!(
                    "critical-operation journal exceeds {} pages",
                    limits.max_pages
                ));
            }
            if response_bytes >= limits.max_response_bytes {
                return Err("critical-operation journal response bytes exceed their bound".into());
            }
            let request_rows = limits.page_size.min(limits.max_records - record_count);
            let (documents, next, page_bytes) = self.list_operation_page(
                cursor.as_deref(),
                request_rows,
                limits.max_response_bytes - response_bytes,
            )?;
            page_count += 1;
            response_bytes = response_bytes
                .checked_add(page_bytes)
                .ok_or_else(|| "critical-operation response byte count overflow".to_string())?;
            record_count = record_count
                .checked_add(documents.len())
                .ok_or_else(|| "critical-operation journal record count overflow".to_string())?;
            if record_count > limits.max_records {
                return Err(format!(
                    "critical-operation journal exceeds {} records",
                    limits.max_records
                ));
            }
            for document in documents {
                let document = parse_operation_document(&document)?;
                if let OperationDocument::Journal(record) = document {
                    scan_mutations = scan_mutations
                        .checked_add(record.mutations.len())
                        .ok_or_else(|| {
                            "critical-operation scan mutation count overflow".to_string()
                        })?;
                    scan_bytes = scan_bytes
                        .checked_add(record.serialized.len())
                        .ok_or_else(|| "critical-operation scan byte count overflow".to_string())?;
                    if scan_mutations > OPERATION_JOURNAL_MAX_SCAN_MUTATIONS
                        || scan_bytes > OPERATION_JOURNAL_MAX_SCAN_BYTES
                    {
                        return Err("critical-operation journal scan work exceeds its bound".into());
                    }
                    if record.state == JournalState::Pending {
                        if pending.len() >= OPERATION_JOURNAL_MAX_PENDING {
                            return Err(format!(
                                "critical-operation journal exceeds {OPERATION_JOURNAL_MAX_PENDING} pending records"
                            ));
                        }
                        replay_mutations = replay_mutations
                            .checked_add(record.mutations.len())
                            .ok_or_else(|| {
                                "critical-operation replay mutation count overflow".to_string()
                            })?;
                        replay_bytes = replay_bytes
                            .checked_add(record.serialized.len())
                            .ok_or_else(|| {
                                "critical-operation replay byte count overflow".to_string()
                            })?;
                        if replay_mutations > OPERATION_JOURNAL_MAX_REPLAY_MUTATIONS
                            || replay_bytes > OPERATION_JOURNAL_MAX_REPLAY_BYTES
                        {
                            return Err("critical-operation replay work exceeds its bound".into());
                        }
                        pending.push(record);
                    }
                }
            }
            match next {
                Some(next) if Some(next.as_str()) != cursor.as_deref() => cursor = Some(next),
                Some(_) => {
                    return Err("critical-operation journal page cursor did not advance".into())
                }
                None => break,
            }
        }

        if record_count == limits.max_records
            || page_count == limits.max_pages
            || response_bytes == limits.max_response_bytes
        {
            return Err(
                "critical-operation journal reached a scan budget before reconciliation".into(),
            );
        }

        pending.sort_by(|left, right| {
            (left.created_at, left.operation_id.as_str())
                .cmp(&(right.created_at, right.operation_id.as_str()))
        });
        for record in pending {
            let mut result = Err(MirrorBatchError::unknown(
                "critical-operation replay was not attempted",
            ));
            for attempt in 0..3 {
                result = self.commit_pending_journal(&record, &fence);
                if result.is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
            }
            result.map_err(|error| {
                format!(
                    "critical-operation {} could not be reconciled: {error}",
                    record.operation_id
                )
            })?;
        }
        self.confirm_critical_operation_fence()
    }

    fn recover_critical_operations(&self) -> Result<(), String> {
        let mut generation = [0u8; 32];
        OsRng.fill_bytes(&mut generation);
        self.recover_critical_operations_with_generation(generation)
    }

    fn confirm_critical_operation_fence(&self) -> Result<(), String> {
        let expected = self
            .operation_fence
            .lock()
            .map_err(|_| "critical-operation fence lock poisoned".to_string())?
            .clone()
            .ok_or_else(|| "critical-operation fence is not initialized".to_string())?;
        let observed = self
            .read_operation_fence()?
            .ok_or_else(|| "critical-operation fence document is absent".to_string())?;
        if observed != expected {
            return Err("critical-operation fence ownership changed".into());
        }
        Ok(())
    }

    fn durability_probe(&self) -> Result<(), String> {
        static NEXT_PROBE: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
        let nonce = format!("{}-{}-{sequence}", std::process::id(), epoch_ms());
        let id = format!("readiness-{}", bs58::encode(nonce.as_bytes()).into_string());
        let identity = *blake3::hash(nonce.as_bytes()).as_bytes();
        self.durability_probe_document(&id, &identity)
    }

    fn durability_probe_document(&self, id: &str, identity: &[u8; 32]) -> Result<(), String> {
        let url = format!("{}/{id}", self.operation_url);
        let body = operation_marker_json(
            identity,
            epoch_ms().saturating_add(OPERATION_MARKER_RETENTION_MS),
        );
        let token = self.token()?;

        let write = self
            .http
            .patch(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .map_err(|error| format!("probe write transport failed: {error}"))?;
        if !write.status().is_success() {
            return Err(format!("probe write returned {}", write.status()));
        }
        let read = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .map_err(|error| format!("probe read transport failed: {error}"))?;
        if !read.status().is_success() {
            return Err(format!("probe read returned {}", read.status()));
        }
        let document: serde_json::Value = read
            .json()
            .map_err(|error| format!("probe read decode failed: {error}"))?;
        let observed = document["fields"]["mutationId"]["bytesValue"]
            .as_str()
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
            });
        if observed.as_deref() != Some(identity.as_slice()) {
            return Err("probe read did not return the value just written".into());
        }
        let delete = self
            .http
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .map_err(|error| format!("probe delete transport failed: {error}"))?;
        if !delete.status().is_success() && delete.status().as_u16() != 404 {
            return Err(format!("probe delete returned {}", delete.status()));
        }
        let confirm = self
            .http
            .get(&url)
            .bearer_auth(token)
            .send()
            .map_err(|error| format!("probe delete confirmation failed: {error}"))?;
        if confirm.status().as_u16() != 404 {
            return Err(format!(
                "probe delete confirmation returned {}",
                confirm.status()
            ));
        }
        Ok(())
    }

    /// Run one ordered Firestore query over the original `key` field. `start` carries the bound and
    /// whether it is inclusive; `end` is always exclusive. This is the primitive that keeps carrier
    /// rehydrate bounded at the remote storage boundary instead of paging an already-built local Vec.
    fn query_kv_page(
        &self,
        start: Option<(&str, bool)>,
        end: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        if limit == 0
            || max_bytes == 0
            || start.zip(end).is_some_and(|((start, _), end)| start >= end)
        {
            return Ok(MirrorPage::default());
        }

        let mut filters = Vec::new();
        if let Some((value, inclusive)) = start {
            filters.push(serde_json::json!({
                "fieldFilter": {
                    "field": { "fieldPath": "key" },
                    "op": if inclusive { "GREATER_THAN_OR_EQUAL" } else { "GREATER_THAN" },
                    "value": { "stringValue": value }
                }
            }));
        }
        if let Some(value) = end {
            filters.push(serde_json::json!({
                "fieldFilter": {
                    "field": { "fieldPath": "key" },
                    "op": "LESS_THAN",
                    "value": { "stringValue": value }
                }
            }));
        }

        let mut query = serde_json::json!({
            "from": [{ "collectionId": "kv" }],
            "orderBy": [{
                "field": { "fieldPath": "key" },
                "direction": "ASCENDING"
            }],
            "limit": limit.min(i32::MAX as usize)
        });
        if filters.len() == 1 {
            query["where"] = filters.pop().expect("one query filter");
        } else if !filters.is_empty() {
            query["where"] = serde_json::json!({
                "compositeFilter": { "op": "AND", "filters": filters }
            });
        }

        let token = self.token()?;
        let response = self
            .http
            .post(&self.run_query_url)
            .bearer_auth(token)
            .json(&serde_json::json!({ "structuredQuery": query }))
            .send()
            .map_err(|e| e.to_string())?;
        if response.status().as_u16() == 404 {
            return Ok(MirrorPage {
                rows: Vec::new(),
                next: None,
                scanned_bytes: 0,
                scanned_pages: 1,
            });
        }
        if !response.status().is_success() {
            return Err(format!("query_kv {}", response.status()));
        }
        let (response, scanned_bytes) =
            bounded_response_json_with_size(response, max_bytes, "Firestore KV query page")?;
        let response_rows = response
            .as_array()
            .ok_or_else(|| "query_kv response was not an array".to_string())?;
        let mut out = Vec::new();
        for row in response_rows {
            if let Some(document) = row.get("document") {
                let key = document["fields"]["key"]["stringValue"]
                    .as_str()
                    .ok_or_else(|| {
                        "query_kv returned a document without its ordered key".to_string()
                    })?
                    .to_string();
                out.push(KvMirrorRow {
                    document_id: firestore_document_id(document)?,
                    key,
                    value: parse_kv_doc(document).map(|(_, value)| value),
                });
            }
        }
        if out.len() > limit {
            return Err("Firestore ignored the bounded KV page size".into());
        }
        Ok(MirrorPage {
            rows: out,
            next: None,
            scanned_bytes,
            scanned_pages: 1,
        })
    }

    fn list_kv_range(
        &self,
        lower: Option<&str>,
        upper: Option<&str>,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut out = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let start = after
                .as_deref()
                .map(|cursor| (cursor, false))
                .or_else(|| lower.map(|bound| (bound, true)));
            let page = self.query_kv_page(
                start,
                upper,
                FIRESTORE_KV_PAGE_SIZE,
                FIRESTORE_KV_MAX_PAGE_RESPONSE_BYTES,
            )?;
            if page.rows.is_empty() {
                break;
            }
            let next = page.rows.last().map(|row| row.key.clone());
            let short = page.rows.len() < FIRESTORE_KV_PAGE_SIZE;
            for row in page.rows {
                let value = row
                    .value
                    .ok_or_else(|| "query_kv returned a malformed document".to_string())?;
                out.push((row.key, value));
            }
            if short || next == after {
                break;
            }
            after = next;
        }
        Ok(out)
    }

    fn list_kv(&self) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.list_kv_range(None, None)
    }

    fn list_eager_kv_page(
        &self,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
        max_pages: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        if limit == 0 || max_bytes == 0 || max_pages == 0 {
            return Ok(MirrorPage::default());
        }
        let mut rows = Vec::new();
        let mut scanned_bytes = 0usize;
        let mut scanned_pages = 0usize;
        let mut next = None;
        if after.is_none_or(|cursor| cursor < LAZY_KV_PREFIX) {
            let start = after.map(|cursor| (cursor, false));
            let page = self.query_kv_page(start, Some(LAZY_KV_PREFIX), limit, max_bytes)?;
            scanned_bytes += page.scanned_bytes;
            scanned_pages += page.scanned_pages;
            let first_range_complete = page.rows.len() < limit;
            rows.extend(page.rows);
            if rows.len() == limit {
                next = rows.last().map(|row| row.key.clone());
            } else if first_range_complete {
                // This cursor is outside both queried ranges. On continuation it skips the first
                // range and keeps the second range's lower bound inclusive, so a real `strm0` key
                // is not skipped merely because the remote-page budget ended at the range gap.
                next = Some(LAZY_KV_PREFIX.to_string());
            }
        }
        if rows.len() < limit && scanned_pages < max_pages && scanned_bytes < max_bytes {
            let start = match after {
                Some(cursor) if cursor >= LAZY_KV_PREFIX_END => Some((cursor, false)),
                _ => Some((LAZY_KV_PREFIX_END, true)),
            };
            let page =
                self.query_kv_page(start, None, limit - rows.len(), max_bytes - scanned_bytes)?;
            scanned_bytes += page.scanned_bytes;
            scanned_pages += page.scanned_pages;
            let second_range_complete = page.rows.len() < limit - rows.len();
            rows.extend(page.rows);
            next = if rows.len() == limit {
                rows.last().map(|row| row.key.clone())
            } else if second_range_complete {
                None
            } else {
                rows.last().map(|row| row.key.clone())
            };
        }
        Ok(MirrorPage {
            rows,
            next,
            scanned_bytes,
            scanned_pages,
        })
    }

    fn list_kv_page_bounded(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
        max_bytes: usize,
    ) -> Result<MirrorPage<KvMirrorRow>, String> {
        if limit == 0 || max_bytes == 0 {
            return Ok(MirrorPage::default());
        }
        let upper = prefix_upper_bound(prefix);
        if after
            .zip(upper.as_deref())
            .is_some_and(|(after, upper)| after >= upper)
        {
            return Ok(MirrorPage::default());
        }
        let start = match after {
            Some(cursor) if cursor >= prefix => Some((cursor, false)),
            _ if prefix.is_empty() => None,
            _ => Some((prefix, true)),
        };
        let page = self.query_kv_page(
            start,
            upper.as_deref(),
            limit,
            max_bytes.min(FIRESTORE_KV_MAX_PAGE_RESPONSE_BYTES),
        )?;
        let mut rows = Vec::new();
        for row in page.rows {
            if row.key.starts_with(prefix) {
                rows.push(row);
            }
        }
        rows.truncate(limit);
        let next =
            (rows.len() == limit).then(|| rows.last().expect("full bounded KV page").key.clone());
        Ok(MirrorPage {
            rows,
            next,
            scanned_bytes: page.scanned_bytes,
            scanned_pages: page.scanned_pages,
        })
    }

    fn list_kv_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        let page =
            self.list_kv_page_bounded(prefix, after, limit, FIRESTORE_KV_MAX_PAGE_RESPONSE_BYTES)?;
        page.rows
            .into_iter()
            .map(|row| {
                row.value
                    .map(|value| (row.key, value))
                    .ok_or_else(|| "query_kv returned a malformed document".to_string())
            })
            .collect()
    }
}

/// Smallest ASCII string strictly above every string with `prefix`. Persisted stream keys and their
/// cursors are ASCII, so incrementing the final non-DEL byte gives Firestore an exact prefix range.
fn prefix_upper_bound(prefix: &str) -> Option<String> {
    if !prefix.is_ascii() {
        return Some(format!("{prefix}\u{10ffff}"));
    }
    let mut bytes = prefix.as_bytes().to_vec();
    for index in (0..bytes.len()).rev() {
        if bytes[index] < 0x7f {
            bytes[index] += 1;
            bytes.truncate(index + 1);
            return String::from_utf8(bytes).ok();
        }
    }
    None
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

fn firestore_document_id(document: &serde_json::Value) -> Result<String, String> {
    document["name"]
        .as_str()
        .and_then(|name| name.rsplit('/').next())
        .filter(|document_id| !document_id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "Firestore document has no valid name".to_string())
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
// Tenant registry (§35): the account service WRITES it, the fleet READS it.
// ---------------------------------------------------------------------------

/// One tenant's fleet-facing record, projected from the account service's Postgres registry into
/// Firestore so relays and collectors can authorize carriage stamps and route telemetry without a
/// static operator file. Keyed by `tenant_hex` (32 lowercase-hex chars = a 16-byte TenantId).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantRecord {
    pub tenant_hex: String,
    /// The tenant's Ed25519 carriage-stamp PUBLIC key (64 lowercase-hex), or `None` before issuance.
    pub carriage_pubkey: Option<String>,
    /// The tenant's managed-OTLP forward endpoint, or `None`.
    pub otlp_endpoint: Option<String>,
    /// Whether the tenant is currently entitled. A suspended/closed tenant syncs as `active=false` so
    /// the fleet can drop it without the account service having to delete the row.
    pub active: bool,
}

/// The tenant registry the fleet reads and the account service writes: a top-level `tenants`
/// collection, one document per `tenant_hex`. Same workload-identity token path as the presence
/// [`Registry`]. Reads and writes are plain Firestore REST; a read wakes no node.
pub struct TenantRegistry {
    http: reqwest::blocking::Client,
    collection_url: String, // .../documents/tenants
    token: Mutex<Option<(String, Instant)>>,
}

impl TenantRegistry {
    pub fn new(project: &str) -> Self {
        let base = "https://firestore.googleapis.com/v1";
        let collection_url =
            format!("{base}/projects/{project}/databases/(default)/documents/tenants");
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            collection_url,
            token: Mutex::new(None),
        }
    }

    fn token(&self) -> Result<String, String> {
        cached_token(&self.token, &self.http)
    }

    /// Upsert one tenant's record (idempotent PATCH). Called by the account service on projection.
    /// `tenant_hex` must be validated (32 lowercase-hex) by the caller; it is refused here as a guard
    /// so a malformed id can never smuggle a path segment into the Firestore URL.
    pub fn upsert(&self, r: &TenantRecord) -> Result<(), String> {
        if !is_tenant_hex(&r.tenant_hex) {
            return Err("invalid tenant_hex".into());
        }
        let url = format!("{}/{}", self.collection_url, r.tenant_hex);
        let token = self.token()?;
        let resp = self
            .http
            .patch(&url)
            .bearer_auth(token)
            .json(&tenant_doc_json(r))
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("tenant upsert {}", resp.status()))
        }
    }

    /// Every tenant record (the fleet builds its KeyServer / OTLP map from this). Malformed documents
    /// are skipped rather than failing the whole read, so one odd row can't blank the fleet's view.
    pub fn all(&self) -> Result<Vec<TenantRecord>, String> {
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut req = self
                .http
                .get(&self.collection_url)
                .query(&[("pageSize", "300")])
                .bearer_auth(&token);
            if let Some(pt) = &page_token {
                req = req.query(&[("pageToken", pt.as_str())]);
            }
            let resp = req.send().map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 404 {
                return Ok(out); // no registry yet
            }
            if !resp.status().is_success() {
                return Err(format!("tenants list {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                out.extend(docs.iter().filter_map(parse_tenant_doc));
            }
            match v["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => return Ok(out),
            }
        }
    }
}

/// A `tenant_hex` is exactly 32 lowercase-hex chars (a 16-byte TenantId).
fn is_tenant_hex(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build a Firestore document body for a tenant record. Optional fields are omitted when `None` (a
/// missing field parses back to `None`), so an unissued key is never a bogus empty string.
fn tenant_doc_json(r: &TenantRecord) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "tenant".into(),
        serde_json::json!({ "stringValue": r.tenant_hex }),
    );
    fields.insert(
        "active".into(),
        serde_json::json!({ "booleanValue": r.active }),
    );
    if let Some(pk) = &r.carriage_pubkey {
        fields.insert(
            "carriagePubkey".into(),
            serde_json::json!({ "stringValue": pk }),
        );
    }
    if let Some(ep) = &r.otlp_endpoint {
        fields.insert(
            "otlpEndpoint".into(),
            serde_json::json!({ "stringValue": ep }),
        );
    }
    serde_json::json!({ "fields": fields })
}

/// Parse a Firestore tenant document into a [`TenantRecord`]. Requires a valid `tenant` field;
/// returns `None` for anything malformed so [`TenantRegistry::all`] can skip it.
fn parse_tenant_doc(d: &serde_json::Value) -> Option<TenantRecord> {
    let f = d.get("fields")?;
    let tenant_hex = f["tenant"]["stringValue"].as_str()?.to_string();
    if !is_tenant_hex(&tenant_hex) {
        return None;
    }
    Some(TenantRecord {
        tenant_hex,
        carriage_pubkey: f["carriagePubkey"]["stringValue"]
            .as_str()
            .map(str::to_string),
        otlp_endpoint: f["otlpEndpoint"]["stringValue"]
            .as_str()
            .map(str::to_string),
        // Absent `active` (an older/partial doc) is treated as inactive: fail closed.
        active: f["active"]["booleanValue"].as_bool().unwrap_or(false),
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

    /// Stream one Firestore document per page. `reserve` runs before the HTTP response body is read
    /// or decoded, and its guard is transferred to `visit` with the decoded bundle.
    pub fn visit_bundles_of<R>(
        &self,
        node: &str,
        reserve: impl FnMut() -> Result<R, String>,
        visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let collection_url = format!(
            "{}/projects/{}/databases/(default)/documents/relays/{node}/bundles",
            self.base, self.project
        );
        self.visit_bundle_collection(&collection_url, reserve, visit)
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

    pub fn visit_mailbox<R>(
        &self,
        tag_b58: &str,
        reserve: impl FnMut() -> Result<R, String>,
        visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let collection_url = format!(
            "{}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles",
            self.base, self.project
        );
        self.visit_bundle_collection(&collection_url, reserve, visit)
    }

    fn visit_bundle_collection<R>(
        &self,
        collection_url: &str,
        mut reserve: impl FnMut() -> Result<R, String>,
        mut visit: impl FnMut(R, Vec<u8>, u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let token = self.token()?;
        let mut page_token: Option<String> = None;
        loop {
            let reservation = reserve()?;
            let mut url = format!("{collection_url}?pageSize=1");
            if let Some(token) = &page_token {
                url.push_str(&format!("&pageToken={token}"));
            }
            let response = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .send()
                .map_err(|error| error.to_string())?;
            if response.status().as_u16() == 404 {
                return Ok(());
            }
            if !response.status().is_success() {
                return Err(format!("visit bundle collection {}", response.status()));
            }
            let page: serde_json::Value = response.json().map_err(|error| error.to_string())?;
            let documents = page["documents"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if documents.len() > 1 {
                return Err("Firestore ignored the one-document producer page limit".into());
            }
            if let Some(document) = documents.first() {
                let (data, expires_at) = parse_doc(document)
                    .ok_or_else(|| "Firestore returned a malformed bundle document".to_string())?;
                visit(reservation, data, expires_at)?;
            } else {
                drop(reservation);
            }
            match page["nextPageToken"].as_str() {
                Some(token) if !token.is_empty() => page_token = Some(token.to_string()),
                _ => break,
            }
        }
        Ok(())
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

/// A read-only view over every node partition's durable kv, for the §37 billing reconciler:
/// it enumerates the node partitions under `relays/` and lists each one's kv pairs so the
/// reconciler can collect the `usage/{hour}/{tenant}` and `telemetry_usage/{hour}/{tenant}`
/// ledger rows the relays and telemetry collectors merge off their hot paths.
///
/// Pure reads (`documents.list`), satisfied by `roles/datastore.viewer`; wakes no node. The
/// same auth scheme as every reader here: `FIRESTORE_ACCESS_TOKEN` env (local) or the
/// metadata server (Cloud Run), via the shared cached token.
pub struct KvReader {
    http: reqwest::blocking::Client,
    project: String,
    /// The Firestore REST base, a field so tests can point it at a loopback responder.
    base: String,
    token: Mutex<Option<(String, Instant)>>,
}

impl KvReader {
    pub fn new(project: &str) -> Self {
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            project: project.to_string(),
            base: "https://firestore.googleapis.com/v1".to_string(),
            token: Mutex::new(None),
        }
    }

    fn token(&self) -> Result<String, String> {
        cached_token(&self.token, &self.http)
    }

    /// Every node partition id (base58 address) under `relays/`. The parent docs are never
    /// created (only their subcollections are written), so they are Firestore "missing" docs;
    /// `showMissing=true` is what makes them enumerable. This sees EVERY partition that ever
    /// wrote durable state, including scaled-to-zero relays and telemetry collectors, which is
    /// exactly what billing needs (a partition with unreconciled rows must never be skipped
    /// just because its node is asleep).
    pub fn list_nodes(&self) -> Result<Vec<String>, String> {
        let collection_url = format!(
            "{}/projects/{}/databases/(default)/documents/relays",
            self.base, self.project
        );
        let token = self.token()?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{collection_url}?showMissing=true&pageSize=300");
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
                return Err(format!("list_nodes {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
            if let Some(docs) = v["documents"].as_array() {
                for d in docs {
                    // A missing doc carries only `name`; the partition id is its last segment.
                    if let Some(id) = d["name"].as_str().and_then(|n| n.rsplit('/').next()) {
                        if !id.is_empty() {
                            out.push(id.to_string());
                        }
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

    /// All kv pairs in `node`'s (base58) partition, `(original key, raw value bytes)`. The key
    /// comes from the doc's `key` field (doc ids are base58'd because kv keys contain `/`);
    /// callers filter by prefix client-side (there is no server-side prefix query here).
    pub fn list_kv_of(&self, node: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
        let collection_url = format!(
            "{}/projects/{}/databases/(default)/documents/relays/{node}/kv",
            self.base, self.project
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
                return Err(format!("list_kv_of {}", resp.status()));
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
        .and_then(|s| s.parse().ok())?;
    Some((data, expires))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::prelude::*;
    use std::sync::Arc;

    type MirroredBundles = Arc<Mutex<std::collections::BTreeMap<BundleId, (Vec<u8>, u64)>>>;

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
        bundles: MirroredBundles,
        /// Reject the batch before this zero-based mutation is applied to the candidate state.
        fail_batch_at: Option<usize>,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum MirrorOp {
        Put { id: BundleId, expires_at: u64 },
        Delete { id: BundleId },
        KvPut { key: String },
        KvDelete { key: String },
    }

    impl FakeMirror {
        fn bundle_page(
            &self,
            cursor: Option<&str>,
            limit: usize,
            max_bytes: usize,
        ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
            let offset = cursor
                .map(|value| {
                    value
                        .strip_prefix("test-offset:")
                        .ok_or_else(|| "invalid test bundle cursor".to_string())?
                        .parse::<usize>()
                        .map_err(|_| "invalid test bundle cursor".to_string())
                })
                .transpose()?
                .unwrap_or(0);
            let mut rows = self.listing.clone();
            rows.extend(self.bundles.lock().unwrap().values().cloned());
            let raw_page: Vec<_> = rows.iter().skip(offset).take(limit).cloned().collect();
            let scanned_bytes = raw_page
                .iter()
                .map(|(data, _)| data.len().saturating_add(std::mem::size_of::<u64>()))
                .sum();
            if scanned_bytes > max_bytes {
                return Err("test bundle page exceeded its byte budget".into());
            }
            let consumed = offset.saturating_add(raw_page.len());
            let page = raw_page
                .into_iter()
                .map(|(data, expires_at)| {
                    let document_id = Bundle::from_bytes(&data)
                        .map(|bundle| bs58::encode(bundle.id()).into_string())
                        .unwrap_or_else(|_| {
                            bs58::encode(blake3::hash(&data).as_bytes()).into_string()
                        });
                    BundleMirrorRow {
                        document_id,
                        value: Some((data, expires_at)),
                    }
                })
                .collect();
            Ok(MirrorPage {
                rows: page,
                next: (consumed < rows.len()).then(|| format!("test-offset:{consumed}")),
                scanned_bytes,
                scanned_pages: 1,
            })
        }

        fn eager_kv_page(
            &self,
            after: Option<&str>,
            limit: usize,
            max_bytes: usize,
        ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
            let mut rows: Vec<_> = self
                .kv
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    !key.starts_with(LAZY_KV_PREFIX)
                        && after.is_none_or(|cursor| key.as_str() > cursor)
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .take(limit.saturating_add(1))
                .collect();
            let has_more = rows.len() > limit;
            rows.truncate(limit);
            let next = has_more.then(|| rows.last().expect("full test eager page").0.clone());
            let scanned_bytes = rows
                .iter()
                .map(|(key, value)| key.len().saturating_add(value.len()))
                .sum();
            if scanned_bytes > max_bytes {
                return Err("test eager-KV page exceeded its byte budget".into());
            }
            Ok(MirrorPage {
                rows: rows
                    .into_iter()
                    .map(|(key, value)| KvMirrorRow {
                        document_id: bs58::encode(key.as_bytes()).into_string(),
                        key,
                        value: Some(value),
                    })
                    .collect(),
                next,
                scanned_bytes,
                scanned_pages: 1,
            })
        }

        fn kv_page(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> Vec<(String, Vec<u8>)> {
            self.kv
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| {
                    key.starts_with(prefix) && after.is_none_or(|cursor| key.as_str() > cursor)
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .take(limit)
                .collect()
        }
    }

    macro_rules! delegate_page_reads {
        () => {
            fn list_bundle_page(
                &self,
                cursor: Option<&str>,
                limit: usize,
                max_bytes: usize,
            ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
                self.inner.list_bundle_page(cursor, limit, max_bytes)
            }
            fn list_eager_kv_page(
                &self,
                after: Option<&str>,
                limit: usize,
                max_bytes: usize,
                max_pages: usize,
            ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
                self.inner
                    .list_eager_kv_page(after, limit, max_bytes, max_pages)
            }
            fn list_kv_page(
                &self,
                prefix: &str,
                after: Option<&str>,
                limit: usize,
            ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                self.inner.list_kv_page(prefix, after, limit)
            }
        };
    }

    macro_rules! empty_page_reads {
        () => {
            fn list_bundle_page(
                &self,
                _cursor: Option<&str>,
                _limit: usize,
                _max_bytes: usize,
            ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
                Ok(MirrorPage {
                    rows: Vec::new(),
                    next: None,
                    scanned_bytes: 0,
                    scanned_pages: 1,
                })
            }
            fn list_eager_kv_page(
                &self,
                _after: Option<&str>,
                _limit: usize,
                _max_bytes: usize,
                _max_pages: usize,
            ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
                Ok(MirrorPage {
                    rows: Vec::new(),
                    next: None,
                    scanned_bytes: 0,
                    scanned_pages: 1,
                })
            }
            fn list_kv_page(
                &self,
                _prefix: &str,
                _after: Option<&str>,
                _limit: usize,
            ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                Ok(Vec::new())
            }
        };
    }

    impl BundleMirror for FakeMirror {
        fn list_bundle_page(
            &self,
            cursor: Option<&str>,
            limit: usize,
            max_bytes: usize,
        ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
            self.bundle_page(cursor, limit, max_bytes)
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
            self.bundles
                .lock()
                .unwrap()
                .insert(*id, (_data.to_vec(), expires_at));
            Ok(())
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.ops.lock().unwrap().push(MirrorOp::Delete { id: *id });
            self.bundles.lock().unwrap().remove(id);
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
        fn list_eager_kv_page(
            &self,
            after: Option<&str>,
            limit: usize,
            max_bytes: usize,
            _max_pages: usize,
        ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
            self.eager_kv_page(after, limit, max_bytes)
        }
        fn list_kv_page(
            &self,
            prefix: &str,
            after: Option<&str>,
            limit: usize,
        ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            Ok(self.kv_page(prefix, after, limit))
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
        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            let mut candidate = self.kv.lock().unwrap().clone();
            let mut bundles = self.bundles.lock().unwrap().clone();
            let mut applied = Vec::new();
            for (index, mutation) in mutations.iter().enumerate() {
                if self.fail_batch_at == Some(index) {
                    return Err(MirrorBatchError::definitive(format!(
                        "injected Firestore batch failure at mutation {index}"
                    )));
                }
                match mutation {
                    KvMutation::Put { key, value } => {
                        candidate.insert(key.clone(), value.clone());
                        applied.push(MirrorOp::KvPut { key: key.clone() });
                    }
                    KvMutation::Remove { key } => {
                        candidate.remove(key);
                        applied.push(MirrorOp::KvDelete { key: key.clone() });
                    }
                    KvMutation::PutBundle { bundle, now_ms } => {
                        let id = bundle.id();
                        let lifetime = (bundle.inner.lifetime_ms as u64)
                            .min(hop_core::store::MAX_SEEN_LIFETIME_MS);
                        let expires_at = now_ms.saturating_add(lifetime);
                        bundles.insert(
                            id,
                            (
                                bundle.to_bytes().map_err(|error| {
                                    MirrorBatchError::definitive(error.to_string())
                                })?,
                                expires_at,
                            ),
                        );
                        applied.push(MirrorOp::Put { id, expires_at });
                    }
                    KvMutation::RemoveBundle { id } => {
                        bundles.remove(id);
                        applied.push(MirrorOp::Delete { id: *id });
                    }
                }
            }
            *self.kv.lock().unwrap() = candidate;
            *self.bundles.lock().unwrap() = bundles;
            self.ops.lock().unwrap().extend(applied);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FailingKvMirror;

    impl BundleMirror for FailingKvMirror {
        fn list_bundle_page(
            &self,
            _cursor: Option<&str>,
            _limit: usize,
            _max_bytes: usize,
        ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
            Ok(MirrorPage {
                rows: Vec::new(),
                next: None,
                scanned_bytes: 0,
                scanned_pages: 1,
            })
        }
        fn list_eager_kv_page(
            &self,
            _after: Option<&str>,
            _limit: usize,
            _max_bytes: usize,
            _max_pages: usize,
        ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
            Ok(MirrorPage {
                rows: Vec::new(),
                next: None,
                scanned_bytes: 0,
                scanned_pages: 1,
            })
        }
        fn list_kv_page(
            &self,
            _prefix: &str,
            _after: Option<&str>,
            _limit: usize,
        ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            Ok(Vec::new())
        }
        fn put_bundle(
            &self,
            _id: &BundleId,
            _data: &[u8],
            _expires_at: u64,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
            Ok(())
        }
        fn put_kv(&self, _key: &str, _value: &[u8]) -> std::result::Result<(), String> {
            Err("injected Firestore kv failure".into())
        }
        fn delete_kv(&self, _key: &str) -> std::result::Result<(), String> {
            Err("injected Firestore kv failure".into())
        }
    }

    #[derive(Clone)]
    struct ControlledBatchMirror {
        inner: FakeMirror,
        failure: Arc<Mutex<Option<MirrorBatchError>>>,
        probe_allowed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl BundleMirror for ControlledBatchMirror {
        delegate_page_reads!();
        fn put_bundle(
            &self,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.inner.put_bundle(id, data, expires_at)
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.inner.delete_bundle(id)
        }
        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            self.inner.list_kv()
        }
        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.inner.put_kv(key, value)
        }
        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.inner.delete_kv(key)
        }
        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            if let Some(error) = self.failure.lock().unwrap().clone() {
                return Err(error);
            }
            self.inner.apply_kv_batch(mutations)
        }
        fn durability_probe(&self) -> std::result::Result<(), String> {
            if self.probe_allowed.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err("injected write-denied readiness probe".into())
            }
        }
    }

    #[derive(Clone)]
    struct CommitThenDropMirror {
        inner: FakeMirror,
        drop_first_response: Arc<std::sync::atomic::AtomicBool>,
        applied: Arc<Mutex<std::collections::BTreeMap<[u8; 32], usize>>>,
        attempts: Arc<AtomicU64>,
    }

    #[derive(Clone)]
    struct RecoveryRaceMirror {
        inner: FakeMirror,
        probe_calls: Arc<AtomicU64>,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    }

    impl BundleMirror for RecoveryRaceMirror {
        delegate_page_reads!();
        fn put_bundle(
            &self,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.inner.put_bundle(id, data, expires_at)
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.inner.delete_bundle(id)
        }
        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            self.inner.list_kv()
        }
        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.inner.put_kv(key, value)
        }
        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.inner.delete_kv(key)
        }
        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            self.inner.apply_kv_batch(mutations)
        }
        fn durability_probe(&self) -> std::result::Result<(), String> {
            if self.probe_calls.fetch_add(1, Ordering::AcqRel) != 0 {
                self.entered.wait();
                self.release.wait();
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct DisconnectOnceMirror {
        inner: FakeMirror,
        disconnect_once: Arc<std::sync::atomic::AtomicBool>,
    }

    impl BundleMirror for DisconnectOnceMirror {
        delegate_page_reads!();
        fn put_bundle(
            &self,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.inner.put_bundle(id, data, expires_at)
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.inner.delete_bundle(id)
        }
        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            self.inner.list_kv()
        }
        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.inner.put_kv(key, value)
        }
        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.inner.delete_kv(key)
        }
        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            if self.disconnect_once.swap(false, Ordering::AcqRel) {
                panic!("injected worker disconnect before acknowledgement");
            }
            self.inner.apply_kv_batch(mutations)
        }
    }

    impl BundleMirror for CommitThenDropMirror {
        delegate_page_reads!();
        fn put_bundle(
            &self,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.inner.put_bundle(id, data, expires_at)
        }
        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.inner.delete_bundle(id)
        }
        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            self.inner.list_kv()
        }
        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.inner.put_kv(key, value)
        }
        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.inner.delete_kv(key)
        }
        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            let identity = critical_batch_identity(mutations)?;
            let already_applied = self.applied.lock().unwrap().contains_key(&identity);
            if !already_applied {
                self.inner.apply_kv_batch(mutations)?;
                self.applied.lock().unwrap().insert(identity, 1);
                if self.drop_first_response.swap(false, Ordering::AcqRel) {
                    return Err(MirrorBatchError::unknown(
                        "commit accepted, response transport dropped, reconciliation read failed",
                    ));
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum RestartWinner {
        Original,
        Replay,
        CrashBeforeCommit,
    }

    #[derive(Clone)]
    struct PendingTestBatch {
        identity: [u8; 32],
        mutations: Vec<KvMutation>,
    }

    struct RestartJournalState {
        pending: Option<PendingTestBatch>,
        committed: std::collections::BTreeSet<[u8; 32]>,
        applied: std::collections::BTreeMap<[u8; 32], usize>,
        armed: bool,
        recovery_started: bool,
        winner: RestartWinner,
    }

    #[derive(Clone)]
    struct RestartJournalMirror {
        inner: FakeMirror,
        state: Arc<(Mutex<RestartJournalState>, std::sync::Condvar)>,
    }

    impl RestartJournalMirror {
        fn new(winner: RestartWinner) -> Self {
            Self {
                inner: FakeMirror::default(),
                state: Arc::new((
                    Mutex::new(RestartJournalState {
                        pending: None,
                        committed: std::collections::BTreeSet::new(),
                        applied: std::collections::BTreeMap::new(),
                        armed: true,
                        recovery_started: false,
                        winner,
                    }),
                    std::sync::Condvar::new(),
                )),
            }
        }

        fn apply_once(
            &self,
            identity: [u8; 32],
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            {
                let state = self.state.0.lock().unwrap();
                if state.committed.contains(&identity) {
                    return Ok(());
                }
            }
            self.inner.apply_kv_batch(mutations)?;
            let (lock, cvar) = &*self.state;
            let mut state = lock.lock().unwrap();
            if state.committed.insert(identity) {
                *state.applied.entry(identity).or_insert(0) += 1;
            }
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.identity == identity)
            {
                state.pending = None;
            }
            state.armed = false;
            cvar.notify_all();
            Ok(())
        }

        fn wait_for_pending(&self) {
            let (lock, cvar) = &*self.state;
            let state = lock.lock().unwrap();
            let (state, timeout) = cvar
                .wait_timeout_while(state, Duration::from_secs(5), |state| {
                    state.pending.is_none()
                })
                .unwrap();
            assert!(!timeout.timed_out() && state.pending.is_some());
        }

        fn applied_counts(&self) -> Vec<usize> {
            self.state
                .0
                .lock()
                .unwrap()
                .applied
                .values()
                .copied()
                .collect()
        }
    }

    impl BundleMirror for RestartJournalMirror {
        delegate_page_reads!();

        fn put_bundle(
            &self,
            id: &BundleId,
            data: &[u8],
            expires_at: u64,
        ) -> std::result::Result<(), String> {
            self.inner.put_bundle(id, data, expires_at)
        }

        fn delete_bundle(&self, id: &BundleId) -> std::result::Result<(), String> {
            self.inner.delete_bundle(id)
        }

        fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
            self.inner.list_kv()
        }

        fn put_kv(&self, key: &str, value: &[u8]) -> std::result::Result<(), String> {
            self.inner.put_kv(key, value)
        }

        fn delete_kv(&self, key: &str) -> std::result::Result<(), String> {
            self.inner.delete_kv(key)
        }

        fn apply_kv_batch(
            &self,
            mutations: &[KvMutation],
        ) -> std::result::Result<(), MirrorBatchError> {
            let identity = critical_batch_identity(mutations)?;
            let (lock, cvar) = &*self.state;
            let mut state = lock.lock().unwrap();
            if state.committed.contains(&identity) {
                return Ok(());
            }
            if !state.armed {
                drop(state);
                return self.apply_once(identity, mutations);
            }
            match &state.pending {
                Some(pending) if pending.identity == identity && pending.mutations == mutations => {
                }
                Some(_) => {
                    return Err(MirrorBatchError::unknown(
                        "another test journal is still pending",
                    ))
                }
                None => {
                    state.pending = Some(PendingTestBatch {
                        identity,
                        mutations: mutations.to_vec(),
                    });
                    cvar.notify_all();
                }
            }
            match state.winner {
                RestartWinner::CrashBeforeCommit => Err(MirrorBatchError::unknown(
                    "crash after pending journal creation",
                )),
                RestartWinner::Original => {
                    while !state.recovery_started {
                        state = cvar.wait(state).unwrap();
                    }
                    drop(state);
                    self.apply_once(identity, mutations)
                }
                RestartWinner::Replay => {
                    while !state.committed.contains(&identity) {
                        state = cvar.wait(state).unwrap();
                    }
                    Ok(())
                }
            }
        }

        fn recover_critical_operations(&self) -> std::result::Result<(), String> {
            let (lock, cvar) = &*self.state;
            let mut state = lock.lock().unwrap();
            let Some(pending) = state.pending.clone() else {
                return Ok(());
            };
            state.recovery_started = true;
            cvar.notify_all();
            match state.winner {
                RestartWinner::Original => {
                    while !state.committed.contains(&pending.identity) {
                        state = cvar.wait(state).unwrap();
                    }
                    state.armed = false;
                    Ok(())
                }
                RestartWinner::Replay | RestartWinner::CrashBeforeCommit => {
                    state.armed = false;
                    drop(state);
                    self.apply_once(pending.identity, &pending.mutations)
                        .map_err(|error| error.to_string())
                }
            }
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

    #[test]
    fn critical_kv_waits_for_the_mirror_and_propagates_failure() {
        let mirror = FakeMirror::default();
        let durable = mirror.kv.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();

        store
            .put_kv_critical("session/alice", vec![1, 2, 3])
            .expect("critical write is acknowledged");
        assert_eq!(
            durable.lock().unwrap().get("session/alice").cloned(),
            Some(vec![1, 2, 3]),
            "success is returned only after the mirror contains the value"
        );
        store
            .remove_kv_critical("session/alice")
            .expect("critical delete is acknowledged");
        assert!(!durable.lock().unwrap().contains_key("session/alice"));

        let mut failing = FirestoreStore::open_with_mirror(FailingKvMirror).unwrap();
        let err = failing
            .put_kv_critical("session/alice", vec![9])
            .expect_err("failed mirror operation must reach the caller");
        assert!(err.contains("injected Firestore kv failure"));
        assert_eq!(failing.get_kv("session/alice"), None);
    }

    #[test]
    fn critical_kv_batch_is_mirrored_and_published_atomically() {
        let mirror = FakeMirror::default();
        let durable = mirror.kv.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        store
            .apply_kv_batch(&[
                KvMutation::Put {
                    key: "session/alice".into(),
                    value: vec![1],
                },
                KvMutation::Put {
                    key: "inbox/one".into(),
                    value: vec![2],
                },
                KvMutation::Put {
                    key: "inbox-seen/one".into(),
                    value: vec![3],
                },
            ])
            .unwrap();

        let durable = durable.lock().unwrap();
        assert_eq!(durable.get("session/alice"), Some(&vec![1]));
        assert_eq!(durable.get("inbox/one"), Some(&vec![2]));
        assert_eq!(durable.get("inbox-seen/one"), Some(&vec![3]));
        assert_eq!(store.get_kv("inbox/one"), Some(vec![2]));
    }

    #[test]
    fn startup_write_denied_probe_fails_before_store_open() {
        let mirror = ControlledBatchMirror {
            inner: FakeMirror::default(),
            failure: Arc::new(Mutex::new(None)),
            probe_allowed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let error = FirestoreStore::open_with_mirror(mirror)
            .err()
            .expect("write-denied backend must fail startup");
        assert!(error.contains("write/read/delete readiness probe failed"));
        assert!(error.contains("write-denied"));
    }

    #[test]
    fn definitive_not_committed_batch_degrades_then_recovers_after_probe() {
        let failure = Arc::new(Mutex::new(None));
        let probe_allowed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mirror = ControlledBatchMirror {
            inner: FakeMirror::default(),
            failure: failure.clone(),
            probe_allowed: probe_allowed.clone(),
        };
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        *failure.lock().unwrap() = Some(MirrorBatchError::definitive(
            "commit rejected before application",
        ));
        assert!(store
            .put_kv_critical("session/alice", b"old-state-must-remain".to_vec())
            .is_err());
        assert_eq!(store.get_kv("session/alice"), None);
        assert_eq!(store.durability_status(), DurabilityReadiness::NotReady);

        *failure.lock().unwrap() = None;
        store
            .probe_durability()
            .expect("definitive failure recovers after a successful probe and flush");
        assert_eq!(store.durability_status(), DurabilityReadiness::Ready);
        store
            .put_kv_critical("session/alice", b"new-state".to_vec())
            .unwrap();
        assert_eq!(store.get_kv("session/alice"), Some(b"new-state".to_vec()));
    }

    #[test]
    fn concurrent_failure_generation_prevents_probe_from_overwriting_not_ready() {
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let mirror = RecoveryRaceMirror {
            inner: FakeMirror::default(),
            probe_calls: Arc::new(AtomicU64::new(0)),
            entered: entered.clone(),
            release: release.clone(),
        };
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();
        let durability = store.durability_handle();
        let before = durability.failure_generation();
        let recovery = std::thread::spawn(move || {
            let mut store = store;
            let result = store.probe_durability();
            (store, result)
        });

        entered.wait();
        durability.mark_not_ready();
        assert!(durability.failure_generation() > before);
        release.wait();

        let (store, result) = recovery.join().unwrap();
        assert!(
            result.is_err(),
            "the stale probe generation must be rejected"
        );
        assert_eq!(store.durability_status(), DurabilityReadiness::NotReady);
    }

    #[test]
    fn worker_ack_disconnect_quarantines_and_a_restart_gets_a_fresh_recovery_epoch() {
        let mirror = DisconnectOnceMirror {
            inner: FakeMirror::default(),
            disconnect_once: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let mut store = FirestoreStore::open_with_mirror(mirror.clone()).unwrap();
        let error = store
            .put_kv_critical("session/alice", b"candidate".to_vec())
            .expect_err("worker disconnect is an unknown commit outcome");
        assert!(error.contains("worker stopped before acknowledgement"));
        assert_eq!(store.durability_status(), DurabilityReadiness::Quarantined);
        assert_eq!(store.durability_handle().unreconciled(), 1);
        drop(store);

        let mut restarted = FirestoreStore::open_with_mirror(mirror).unwrap();
        assert_eq!(restarted.durability_status(), DurabilityReadiness::Ready);
        restarted
            .put_kv_critical("session/alice", b"after-restart".to_vec())
            .unwrap();
        assert_eq!(
            restarted.get_kv("session/alice"),
            Some(b"after-restart".to_vec())
        );
    }

    #[test]
    fn reconciliation_read_failure_quarantines_and_refuses_probe_recovery() {
        let failure = Arc::new(Mutex::new(Some(MirrorBatchError::unknown(
            "marker and affected-document reads unavailable",
        ))));
        let mirror = ControlledBatchMirror {
            inner: FakeMirror::default(),
            failure: failure.clone(),
            probe_allowed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        };
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        assert!(store
            .put_kv_critical("session/alice", b"candidate".to_vec())
            .is_err());
        assert_eq!(store.get_kv("session/alice"), None);
        assert_eq!(store.durability_status(), DurabilityReadiness::Quarantined);
        assert_eq!(store.durability_handle().unreconciled(), 1);

        *failure.lock().unwrap() = None;
        let error = store
            .probe_durability()
            .expect_err("a generic probe cannot erase an unreconciled commit outcome");
        assert!(error.contains("ambiguous mutation"));
        assert_eq!(store.durability_status(), DurabilityReadiness::Quarantined);
        assert!(store
            .put_kv_critical("session/alice", b"different plaintext state".to_vec())
            .is_err());
    }

    #[test]
    fn commit_then_drop_response_retries_once_without_key_or_bundle_reuse_across_restart() {
        let inner = FakeMirror::default();
        let durable_bundles = inner.bundles.clone();
        let mirror = CommitThenDropMirror {
            inner,
            drop_first_response: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            applied: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            attempts: Arc::new(AtomicU64::new(0)),
        };
        let applied = mirror.applied.clone();
        let attempts = mirror.attempts.clone();
        let sender_identity = Identity::generate();
        let sender_secret = sender_identity.to_secret_bytes();
        let recipient = Identity::generate();
        let recipient_prekey = recipient.derive_prekey();
        let mut sender = Node::with_store(
            sender_identity,
            FirestoreStore::open_with_mirror(mirror.clone()).unwrap(),
        );
        sender.tick(1);
        let advert = Advert::publish(
            &recipient,
            AdvertKind::PreKey {
                spk_pub: recipient_prekey.public,
                spk_sig: recipient_prekey.sig.to_vec(),
            },
            1,
            60_000,
            1,
        )
        .unwrap();
        sender.directory.ingest(advert, 1).unwrap();

        let first_id = sender
            .send_message_traced(
                recipient.address(),
                "text/plain".into(),
                b"first plaintext".to_vec(),
                false,
            )
            .unwrap();
        let second_id = sender
            .send_message_traced(
                recipient.address(),
                "text/plain".into(),
                b"different plaintext".to_vec(),
                false,
            )
            .unwrap();
        assert_ne!(first_id, second_id);
        let first = sender.store.get(&first_id).unwrap();
        let second = sender.store.get(&second_id).unwrap();
        let ratchet = |bundle: &Bundle| match bundle.open(&recipient).unwrap() {
            Payload::SessionInit { msg, .. } | Payload::SessionMessage { msg } => msg,
            _ => panic!("expected ratcheted payload"),
        };
        let first_ratchet = ratchet(&first);
        let second_ratchet = ratchet(&second);
        assert_ne!(
            (first_ratchet.header.dh, first_ratchet.header.n),
            (second_ratchet.header.dh, second_ratchet.header.n),
            "a different plaintext after the dropped response must use the next message key"
        );
        assert_ne!(first_ratchet.ciphertext, second_ratchet.ciphertext);
        drop(sender);

        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&sender_secret),
            FirestoreStore::open_with_mirror(mirror.clone()).unwrap(),
        );
        restarted.tick(2);
        let third_id = restarted
            .send_message_traced(
                recipient.address(),
                "text/plain".into(),
                b"after restart".to_vec(),
                false,
            )
            .unwrap();
        let third = restarted.store.get(&third_id).unwrap();
        let third_ratchet = ratchet(&third);
        assert_ne!(
            (second_ratchet.header.dh, second_ratchet.header.n),
            (third_ratchet.header.dh, third_ratchet.header.n),
            "restart resumes after the reconciled send key"
        );
        assert_eq!(
            durable_bundles.lock().unwrap().len(),
            3,
            "three sends create three unique bundle documents, never a duplicate retry bundle"
        );
        assert!(
            attempts.load(Ordering::Acquire) >= 4,
            "first batch was retried"
        );
        assert!(
            applied.lock().unwrap().values().all(|count| *count == 1),
            "every deterministic mutation identity is applied at most once"
        );
    }

    #[test]
    fn restart_reconciliation_allows_original_or_replay_to_win_exactly_once() {
        for winner in [RestartWinner::Original, RestartWinner::Replay] {
            let mirror = RestartJournalMirror::new(winner);
            let bundle = sample(4);
            let id = bundle.id();
            let mutations = vec![
                KvMutation::PutBundle {
                    bundle: Box::new(bundle),
                    now_ms: epoch_ms(),
                },
                KvMutation::Put {
                    key: "session/race".into(),
                    value: b"advanced-ratchet".to_vec(),
                },
            ];
            let mut original = FirestoreStore::open_with_mirror(mirror.clone()).unwrap();
            let submitted = mutations.clone();
            let original_commit = std::thread::spawn(move || original.apply_kv_batch(&submitted));
            mirror.wait_for_pending();

            let restarted = FirestoreStore::open_with_mirror(mirror.clone())
                .expect("restart reconciliation must resolve the pending exact batch");
            original_commit
                .join()
                .unwrap()
                .expect("the losing request recognizes the committed journal");
            assert!(restarted.contains(&id));
            assert_eq!(
                restarted.get_kv("session/race"),
                Some(b"advanced-ratchet".to_vec())
            );
            assert!(
                mirror.applied_counts().iter().all(|count| *count == 1),
                "the original and replay race must apply each identity exactly once"
            );
        }
    }

    #[test]
    fn pending_journal_restart_advances_the_ratchet_without_plaintext_key_reuse() {
        let mirror = RestartJournalMirror::new(RestartWinner::CrashBeforeCommit);
        let sender_identity = Identity::generate();
        let sender_secret = sender_identity.to_secret_bytes();
        let recipient = Identity::generate();
        let recipient_prekey = recipient.derive_prekey();
        let now_ms = epoch_ms();
        let mut sender = Node::with_store(
            sender_identity,
            FirestoreStore::open_with_mirror(mirror.clone()).unwrap(),
        );
        sender.tick(now_ms);
        let advert = Advert::publish(
            &recipient,
            AdvertKind::PreKey {
                spk_pub: recipient_prekey.public,
                spk_sig: recipient_prekey.sig.to_vec(),
            },
            now_ms,
            60_000,
            1,
        )
        .unwrap();
        sender.directory.ingest(advert, now_ms).unwrap();
        sender
            .send_message_traced(
                recipient.address(),
                "text/plain".into(),
                b"first plaintext".to_vec(),
                false,
            )
            .expect_err("the process crashes after the pending journal is durable");
        assert_eq!(
            sender.store.durability_status(),
            DurabilityReadiness::Quarantined
        );
        drop(sender);

        let mut restarted = Node::with_store(
            Identity::from_secret_bytes(&sender_secret),
            FirestoreStore::open_with_mirror(mirror.clone())
                .expect("restart replays the pending send before loading ratchet state"),
        );
        restarted.tick(now_ms.saturating_add(1));
        let first_id = restarted.store.have().ids[0];
        let first = restarted.store.get(&first_id).unwrap();
        let advert = Advert::publish(
            &recipient,
            AdvertKind::PreKey {
                spk_pub: recipient_prekey.public,
                spk_sig: recipient_prekey.sig.to_vec(),
            },
            now_ms.saturating_add(1),
            60_000,
            1,
        )
        .unwrap();
        restarted
            .directory
            .ingest(advert, now_ms.saturating_add(1))
            .unwrap();
        let second_id = restarted
            .send_message_traced(
                recipient.address(),
                "text/plain".into(),
                b"different plaintext".to_vec(),
                false,
            )
            .unwrap();
        let second = restarted.store.get(&second_id).unwrap();
        let ratchet = |bundle: &Bundle| match bundle.open(&recipient).unwrap() {
            Payload::SessionInit { msg, .. } | Payload::SessionMessage { msg } => msg,
            _ => panic!("expected ratcheted payload"),
        };
        let first_ratchet = ratchet(&first);
        let second_ratchet = ratchet(&second);
        assert_ne!(first_id, second_id);
        assert_ne!(
            (first_ratchet.header.dh, first_ratchet.header.n),
            (second_ratchet.header.dh, second_ratchet.header.n),
            "restart must continue after the journaled message key"
        );
        assert_ne!(first_ratchet.ciphertext, second_ratchet.ciphertext);
        assert!(mirror.applied_counts().iter().all(|count| *count == 1));
    }

    #[test]
    fn mixed_bundle_and_session_batch_rolls_back_when_the_second_mutation_fails() {
        let mirror = FakeMirror {
            fail_batch_at: Some(1),
            ..Default::default()
        };
        let durable_kv = mirror.kv.clone();
        let durable_bundles = mirror.bundles.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        let bundle = sample(4);
        let id = bundle.id();

        let error = store
            .apply_kv_batch(&[
                KvMutation::PutBundle {
                    bundle: Box::new(bundle),
                    now_ms: 1_000,
                },
                KvMutation::Put {
                    key: "session/alice".into(),
                    value: vec![7],
                },
            ])
            .expect_err("the injected second mutation failure must surface");

        assert!(error.contains("mutation 1"));
        assert!(!store.contains(&id), "hot bundle custody was not published");
        assert!(!store.seen(&id), "hot dedup state was not published");
        assert_eq!(store.get_kv("session/alice"), None);
        assert!(durable_bundles.lock().unwrap().is_empty());
        assert!(durable_kv.lock().unwrap().is_empty());
    }

    #[test]
    fn critical_batch_limits_reject_before_mirror_submission() {
        let mirror = FakeMirror::default();
        let ops = mirror.ops.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        let too_many: Vec<_> = (0..=CRITICAL_BATCH_MAX_MUTATIONS)
            .map(|index| KvMutation::Remove {
                key: format!("session/{index}"),
            })
            .collect();
        let error = store
            .apply_kv_batch(&too_many)
            .expect_err("an over-count batch must be rejected synchronously");
        assert!(error.contains("limit"));

        let oversized = vec![KvMutation::Put {
            key: "session/oversized".into(),
            value: vec![0; CRITICAL_BATCH_MAX_BYTES],
        }];
        let error = store
            .apply_kv_batch(&oversized)
            .expect_err("an over-byte batch must be rejected synchronously");
        assert!(error.contains("exceeds"));
        assert!(ops.lock().unwrap().is_empty());
        assert_eq!(store.durability_status(), DurabilityReadiness::Ready);
    }

    #[test]
    fn accepted_mutations_refuse_a_full_queue_instead_of_shedding() {
        let dropped = Arc::new(AtomicU64::new(0));
        let queue = Arc::new((
            Mutex::new(MirrorQueue {
                ops: std::collections::VecDeque::new(),
                closed: false,
            }),
            std::sync::Condvar::new(),
        ));
        {
            let mut q = queue.0.lock().unwrap();
            for _ in 0..MIRROR_QUEUE_CAP {
                let (ack, _rx) = mpsc::sync_channel(0);
                q.ops.push_back(Op::Flush(ack));
            }
        }
        let tx = MirrorTx {
            queue,
            dropped: dropped.clone(),
            durability: DurabilityHandle::ready(),
        };
        let (ack, _rx) = mpsc::sync_channel(0);

        let err = tx
            .send(Op::KvDelete {
                key: "session/alice".into(),
                ack,
            })
            .expect_err("a full queue must synchronously reject critical work");
        assert!(err.contains("full"));
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "capacity rejection is counted without shedding an older operation"
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
    fn tenant_doc_round_trips_with_and_without_optional_fields() {
        let full = TenantRecord {
            tenant_hex: "a3f1c0d2e4b6a8091122334455667788".into(),
            carriage_pubkey: Some(
                "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44".into(),
            ),
            otlp_endpoint: Some("https://otlp.datadoghq.com/v1".into()),
            active: true,
        };
        let doc = serde_json::json!({ "name": "x", "fields": tenant_doc_json(&full)["fields"] });
        assert_eq!(parse_tenant_doc(&doc).unwrap(), full);

        // Unissued key / no OTLP: those fields are omitted and parse back to None.
        let bare = TenantRecord {
            tenant_hex: "00112233445566778899aabbccddeeff".into(),
            carriage_pubkey: None,
            otlp_endpoint: None,
            active: false,
        };
        let doc = serde_json::json!({ "name": "x", "fields": tenant_doc_json(&bare)["fields"] });
        assert_eq!(parse_tenant_doc(&doc).unwrap(), bare);
    }

    #[test]
    fn parse_tenant_doc_rejects_garbage_and_bad_hex() {
        assert!(parse_tenant_doc(&serde_json::json!({"name": "x"})).is_none());
        // a non-hex / wrong-length tenant id is refused
        let bad = serde_json::json!({ "fields": { "tenant": { "stringValue": "not-a-tenant" }, "active": { "booleanValue": true } } });
        assert!(parse_tenant_doc(&bad).is_none());
    }

    #[test]
    fn tenant_upsert_refuses_a_malformed_id_before_any_request() {
        let reg = TenantRegistry::new("proj");
        let r = TenantRecord {
            tenant_hex: "../secrets".into(),
            carriage_pubkey: None,
            otlp_endpoint: None,
            active: true,
        };
        assert!(reg.upsert(&r).is_err());
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
        empty_page_reads!();
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
        assert_eq!(store.mirror_failed(), 0);
    }

    #[test]
    fn exhausted_retries_make_health_and_flush_report_failure() {
        let mirror = FlakyMirror {
            fail_first: u64::MAX,
            attempts: Arc::new(AtomicU64::new(0)),
            succeeded: Arc::new(Mutex::new(Vec::new())),
        };
        let attempts = mirror.attempts.clone();
        let mut store = FirestoreStore::open_with_mirror(mirror).unwrap();
        let failed = store.mirror_failed_handle();

        let bundle = sample(91);
        let id = bundle.id();
        assert!(!store.put(bundle, 1_000));
        assert!(
            !store.contains(&id),
            "failed durability leaves hot custody unchanged"
        );
        assert!(!store.flush(Duration::from_secs(5)));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert_eq!(store.mirror_failed(), 1);
        assert_eq!(failed.load(Ordering::Relaxed), 1);
        assert!(
            !store.flush(Duration::from_secs(5)),
            "an earlier exhausted write must not be hidden by a later empty flush"
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
        empty_page_reads!();
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
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();

        // Enqueue directly so the test thread is not itself waiting for the definitive write ack.
        let bundle = sample(4);
        let (ack, rx) = mpsc::sync_channel(0);
        store
            .tx
            .send(Op::Write {
                id: bundle.id(),
                data: bundle.to_bytes().unwrap(),
                expires_at: 2_000,
                ack,
            })
            .unwrap();
        drop(rx);

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
    fn default_bundle_mirror_kv_writes_report_unsupported() {
        // A bundle-only backend still compiles and lists no kv, but it must not claim a no-op write
        // was durable. The worker records the failure and flush reports the degraded mirror.
        struct BundleOnly;
        impl BundleMirror for BundleOnly {
            empty_page_reads!();
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
        assert!(m.put_kv("k", b"v").is_err());
        assert!(m.delete_kv("k").is_err());

        // Even the legacy infallible API fails closed by leaving the hot copy untouched.
        let mut store = FirestoreStore::open_with_mirror(BundleOnly).unwrap();
        store.put_kv("session/x", b"s".to_vec());
        assert_eq!(store.get_kv("session/x"), None);
        assert!(
            !store.flush(Duration::from_secs(5)),
            "unsupported kv mirror is reported rather than accepted as durable"
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
            bundles: Arc::default(),
            fail_batch_at: None,
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
    fn cold_open_accounts_mixed_rejected_rows_and_resumes_at_exact_budgets() {
        #[derive(Clone)]
        struct AdversarialStartupMirror {
            bundle_pages: Arc<Vec<MirrorPage<BundleMirrorRow>>>,
            kv_pages: Arc<Vec<MirrorPage<KvMirrorRow>>>,
            bundle_calls: Arc<AtomicU64>,
            kv_calls: Arc<AtomicU64>,
            cleanup_calls: Arc<AtomicU64>,
            probe_calls: Arc<AtomicU64>,
            unbounded_calls: Arc<AtomicU64>,
            budgets: Arc<Mutex<Vec<(usize, usize, usize)>>>,
        }

        impl BundleMirror for AdversarialStartupMirror {
            fn list_bundle_page(
                &self,
                cursor: Option<&str>,
                limit: usize,
                max_bytes: usize,
            ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
                self.budgets.lock().unwrap().push((limit, max_bytes, 1));
                let index = match cursor {
                    None => 0,
                    Some("bundle-1") => 1,
                    Some(other) => return Err(format!("unexpected bundle cursor {other}")),
                };
                let page = self
                    .bundle_pages
                    .get(index)
                    .cloned()
                    .ok_or_else(|| "unexpected bundle page request".to_string())?;
                assert!(page.rows.len() <= limit);
                assert!(page.scanned_bytes <= max_bytes);
                self.bundle_calls.fetch_add(1, Ordering::AcqRel);
                Ok(page)
            }
            fn put_bundle(
                &self,
                _id: &BundleId,
                _data: &[u8],
                _expires_at: u64,
            ) -> std::result::Result<(), String> {
                Ok(())
            }
            fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
                self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                self.unbounded_calls.fetch_add(1, Ordering::Relaxed);
                Err("unbounded KV listing must not be used".into())
            }
            fn list_eager_kv_page(
                &self,
                after: Option<&str>,
                limit: usize,
                max_bytes: usize,
                max_pages: usize,
            ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
                self.budgets
                    .lock()
                    .unwrap()
                    .push((limit, max_bytes, max_pages));
                let index = match after {
                    None => 0,
                    Some(other) => return Err(format!("unexpected eager-KV cursor {other}")),
                };
                let page = self
                    .kv_pages
                    .get(index)
                    .cloned()
                    .ok_or_else(|| "unexpected eager-KV page request".to_string())?;
                assert!(page.rows.len() <= limit);
                assert!(page.scanned_bytes <= max_bytes);
                assert!(page.scanned_pages <= max_pages);
                self.kv_calls.fetch_add(1, Ordering::AcqRel);
                Ok(page)
            }
            fn list_kv_page(
                &self,
                _prefix: &str,
                _after: Option<&str>,
                _limit: usize,
            ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                Ok(Vec::new())
            }
            fn put_kv(&self, _key: &str, _value: &[u8]) -> std::result::Result<(), String> {
                Ok(())
            }
            fn delete_kv(&self, _key: &str) -> std::result::Result<(), String> {
                self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            fn durability_probe(&self) -> std::result::Result<(), String> {
                self.probe_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        let live_a = sample(4);
        let live_b = sample(4);
        let expired_a = sample(4);
        let expired_b = sample(4);
        let malformed_id = sample(4).id();
        let malformed_empty_id = sample(4).id();
        let rejected_id = sample(4).id();
        let duplicate_id = sample(4).id();
        let future = epoch_ms() + 60_000;
        let bundle_pages = vec![
            MirrorPage {
                rows: vec![
                    BundleMirrorRow {
                        document_id: bs58::encode(expired_a.id()).into_string(),
                        value: Some((expired_a.to_bytes().unwrap(), 1)),
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(malformed_id).into_string(),
                        value: Some((b"malformed bundle".to_vec(), future)),
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(live_a.id()).into_string(),
                        value: Some((live_a.to_bytes().unwrap(), future)),
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(duplicate_id).into_string(),
                        value: Some((live_a.to_bytes().unwrap(), future)),
                    },
                ],
                next: Some("bundle-1".into()),
                scanned_bytes: 32,
                scanned_pages: 1,
            },
            MirrorPage {
                rows: vec![
                    BundleMirrorRow {
                        document_id: bs58::encode(expired_b.id()).into_string(),
                        value: Some((expired_b.to_bytes().unwrap(), 1)),
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(malformed_empty_id).into_string(),
                        value: None,
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(rejected_id).into_string(),
                        value: Some((live_a.to_bytes().unwrap(), future)),
                    },
                    BundleMirrorRow {
                        document_id: bs58::encode(live_b.id()).into_string(),
                        value: Some((live_b.to_bytes().unwrap(), future)),
                    },
                ],
                next: None,
                scanned_bytes: 32,
                scanned_pages: 1,
            },
        ];
        let kv_pages = vec![MirrorPage {
            rows: vec![
                KvMirrorRow {
                    document_id: bs58::encode("session/a".as_bytes()).into_string(),
                    key: "session/a".into(),
                    value: Some(b"ratchet".to_vec()),
                },
                KvMirrorRow {
                    document_id: bs58::encode("session/bad".as_bytes()).into_string(),
                    key: "session/bad".into(),
                    value: None,
                },
                KvMirrorRow {
                    document_id: bs58::encode("session/duplicate".as_bytes()).into_string(),
                    key: "session/a".into(),
                    value: Some(b"duplicate".to_vec()),
                },
                KvMirrorRow {
                    document_id: bs58::encode("strm/rejected".as_bytes()).into_string(),
                    key: "strm/rejected".into(),
                    value: Some(vec![9]),
                },
            ],
            next: None,
            scanned_bytes: 32,
            scanned_pages: 1,
        }];
        let mirror = AdversarialStartupMirror {
            bundle_pages: Arc::new(bundle_pages),
            kv_pages: Arc::new(kv_pages),
            bundle_calls: Arc::new(AtomicU64::new(0)),
            kv_calls: Arc::new(AtomicU64::new(0)),
            cleanup_calls: Arc::new(AtomicU64::new(0)),
            probe_calls: Arc::new(AtomicU64::new(0)),
            unbounded_calls: Arc::new(AtomicU64::new(0)),
            budgets: Arc::new(Mutex::new(Vec::new())),
        };
        let observed = mirror.clone();
        let mut store = FirestoreStore::open_with_mirror_limits(
            mirror,
            StartupLimits {
                max_bundles: 2,
                max_eager_kv_rows: 2,
                max_bytes: 1024 * 1024,
                max_scanned_rows: 4,
                max_scanned_bytes: 32,
                max_pages: 1,
                max_cleanup_operations: 2,
                page_size: 4,
            },
        )
        .unwrap();

        assert_eq!(store.startup_usage().bundles, 1);
        assert_eq!(store.startup_usage().eager_kv_rows, 0);
        assert_eq!(store.startup_usage().scanned_rows, 4);
        assert_eq!(store.startup_usage().scanned_bytes, 32);
        assert_eq!(store.startup_usage().pages, 1);
        assert_eq!(store.durability_status(), DurabilityReadiness::NotReady);
        assert!(store.startup_cleanup_pending());
        assert_eq!(observed.bundle_calls.load(Ordering::Acquire), 1);
        assert_eq!(observed.kv_calls.load(Ordering::Acquire), 0);

        for (step, expected) in [
            (1, (1, 0, 2)),
            (2, (2, 0, 2)),
            (3, (2, 0, 4)),
            (4, (2, 1, 4)),
            (5, (2, 1, 6)),
        ] {
            let error = store
                .probe_durability()
                .expect_err("each exhausted maintenance budget keeps admission closed");
            assert!(error.contains("bounded-maintenance continuation"));
            assert_eq!(
                (
                    observed.bundle_calls.load(Ordering::Acquire),
                    observed.kv_calls.load(Ordering::Acquire),
                    observed.cleanup_calls.load(Ordering::Acquire),
                ),
                expected,
                "exact remote stop after maintenance step {step}"
            );
            assert_eq!(store.durability_status(), DurabilityReadiness::NotReady);
        }

        store
            .probe_durability()
            .expect("the final bounded cleanup and readiness probe complete");
        assert_eq!(store.durability_status(), DurabilityReadiness::Ready);
        assert!(!store.startup_cleanup_pending());
        assert_eq!(observed.cleanup_calls.load(Ordering::Acquire), 7);
        assert_eq!(observed.probe_calls.load(Ordering::Acquire), 2);
        assert_eq!(store.startup_usage().bundles, 2);
        assert_eq!(store.startup_usage().eager_kv_rows, 1);
        assert_eq!(store.startup_usage().scanned_rows, 12);
        assert_eq!(store.startup_usage().scanned_bytes, 96);
        assert_eq!(store.startup_usage().pages, 3);
        assert_eq!(store.startup_usage().cleanup_operations, 7);
        assert_eq!(observed.unbounded_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            observed.budgets.lock().unwrap().as_slice(),
            &[(4, 32, 1), (4, 32, 1), (4, 32, 1)],
            "every list request receives the exact remaining row, byte, and page budget"
        );
    }

    #[test]
    fn open_leaves_hostile_stream_rows_remote_and_pages_them_by_cursor() {
        type PageCalls = Arc<Mutex<Vec<(Option<String>, usize)>>>;

        #[derive(Clone, Default)]
        struct PagedMirror {
            unbounded_lists: Arc<AtomicU64>,
            eager_lists: Arc<AtomicU64>,
            fetched_stream_rows: Arc<AtomicU64>,
            page_calls: PageCalls,
        }

        impl BundleMirror for PagedMirror {
            fn list_bundle_page(
                &self,
                _cursor: Option<&str>,
                _limit: usize,
                _max_bytes: usize,
            ) -> std::result::Result<MirrorPage<BundleMirrorRow>, String> {
                Ok(MirrorPage {
                    rows: Vec::new(),
                    next: None,
                    scanned_bytes: 0,
                    scanned_pages: 1,
                })
            }
            fn put_bundle(
                &self,
                _id: &BundleId,
                _data: &[u8],
                _expires_at: u64,
            ) -> std::result::Result<(), String> {
                Ok(())
            }
            fn delete_bundle(&self, _id: &BundleId) -> std::result::Result<(), String> {
                Ok(())
            }
            fn list_kv(&self) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                self.unbounded_lists.fetch_add(1, Ordering::Relaxed);
                Err("unbounded KV listing must not be used".into())
            }
            fn list_eager_kv_page(
                &self,
                _after: Option<&str>,
                _limit: usize,
                _max_bytes: usize,
                _max_pages: usize,
            ) -> std::result::Result<MirrorPage<KvMirrorRow>, String> {
                self.eager_lists.fetch_add(1, Ordering::Relaxed);
                Ok(MirrorPage {
                    rows: vec![KvMirrorRow {
                        document_id: bs58::encode("session/alice".as_bytes()).into_string(),
                        key: "session/alice".into(),
                        value: Some(vec![9]),
                    }],
                    next: None,
                    scanned_bytes: "session/alice".len() + 1,
                    scanned_pages: 1,
                })
            }
            fn list_kv_page(
                &self,
                prefix: &str,
                after: Option<&str>,
                limit: usize,
            ) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
                assert_eq!(prefix, LAZY_KV_PREFIX);
                self.page_calls
                    .lock()
                    .unwrap()
                    .push((after.map(str::to_string), limit));
                let first = after
                    .and_then(|key| key.rsplit('/').next())
                    .and_then(|part| part.parse::<usize>().ok())
                    .map_or(0, |index| index + 1);
                let end = first.saturating_add(limit).min(100_000);
                let page: Vec<_> = (first..end)
                    .map(|index| (format!("strm/{index:06}"), vec![index as u8]))
                    .collect();
                self.fetched_stream_rows
                    .fetch_add(page.len() as u64, Ordering::Relaxed);
                Ok(page)
            }
        }

        let mirror = PagedMirror::default();
        let observed = mirror.clone();
        let store = FirestoreStore::open_with_mirror(mirror).unwrap();
        assert_eq!(store.get_kv("session/alice"), Some(vec![9]));
        assert_eq!(observed.eager_lists.load(Ordering::Relaxed), 1);
        assert_eq!(observed.unbounded_lists.load(Ordering::Relaxed), 0);
        assert_eq!(observed.fetched_stream_rows.load(Ordering::Relaxed), 0);

        let first = store.list_kv_page(LAZY_KV_PREFIX, None, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(observed.fetched_stream_rows.load(Ordering::Relaxed), 3);
        let cursor = first.last().unwrap().0.clone();
        let second = store.list_kv_page(LAZY_KV_PREFIX, Some(&cursor), 3);
        assert_eq!(second.first().unwrap().0, "strm/000003");
        assert_eq!(observed.fetched_stream_rows.load(Ordering::Relaxed), 6);
        assert_eq!(
            observed.page_calls.lock().unwrap().as_slice(),
            &[(None, 3), (Some("strm/000002".into()), 3)]
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

    fn journal_document(
        mutations: &[KvMutation],
        state: JournalState,
        update_time: &str,
    ) -> serde_json::Value {
        let serialized = serialize_critical_batch(mutations).unwrap();
        let identity = critical_batch_identity(mutations).unwrap();
        let operation_id = bs58::encode(identity).into_string();
        let name = format!(
            "projects/TEST/databases/(default)/documents/relays/NODE/operations/{operation_id}"
        );
        let created_at = epoch_ms();
        let mut document = operation_journal_json(
            &operation_id,
            &identity,
            &serialized,
            mutations.len(),
            state,
            created_at,
            (state == JournalState::Committed).then_some(created_at.saturating_add(1)),
        );
        document["name"] = serde_json::Value::String(name);
        document["updateTime"] = serde_json::Value::String(update_time.to_string());
        document
    }

    fn fence_document(generation: [u8; 32], update_time: &str) -> serde_json::Value {
        let mut document = operation_fence_json(
            &generation,
            "projects/TEST/databases/(default)/documents/relays/NODE/control/critical-operation-fence",
        );
        document["updateTime"] = serde_json::Value::String(update_time.to_string());
        document
    }

    fn firestore_client_at(base: &str) -> FirestoreClient {
        FirestoreClient {
            http: test_http(),
            collection_url: format!("{base}/documents/relays/NODE/bundles"),
            kv_url: format!("{base}/documents/relays/NODE/kv"),
            run_query_url: format!("{base}/documents/relays/NODE:runQuery"),
            commit_url: format!("{base}/documents:commit"),
            operation_url: format!("{base}/documents/relays/NODE/operations"),
            operation_fence_url: format!(
                "{base}/documents/relays/NODE/control/critical-operation-fence"
            ),
            bundle_document_prefix:
                "projects/TEST/databases/(default)/documents/relays/NODE/bundles".into(),
            kv_document_prefix: "projects/TEST/databases/(default)/documents/relays/NODE/kv".into(),
            operation_document_prefix:
                "projects/TEST/databases/(default)/documents/relays/NODE/operations".into(),
            operation_fence_document:
                "projects/TEST/databases/(default)/documents/relays/NODE/control/critical-operation-fence"
                    .into(),
            operation_fence: Mutex::new(Some(OperationFence {
                generation: [9; 32],
                update_time: "fence-update-time".into(),
            })),
            operation_recovery: Mutex::new(()),
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

    fn kv_reader_at(base: &str) -> KvReader {
        KvReader {
            http: test_http(),
            project: "proj".to_string(),
            base: base.to_string(),
            token: seeded_token(),
        }
    }

    #[test]
    fn kv_reader_lists_nodes_with_show_missing_and_paginates() {
        // Two pages; the docs are "missing" parents so they carry only `name`. The reader must
        // request showMissing (parents are never created directly) and follow nextPageToken.
        let page1 = serde_json::json!({
            "documents": [
                { "name": "projects/proj/databases/(default)/documents/relays/NodeA" },
                { "name": "projects/proj/databases/(default)/documents/relays/NodeB" },
            ],
            "nextPageToken": "tok1",
        });
        let page2 = serde_json::json!({
            "documents": [
                { "name": "projects/proj/databases/(default)/documents/relays/NodeC" },
            ],
        });
        let srv = spawn_mock(vec![(200, page1.to_string()), (200, page2.to_string())]);
        let reader = kv_reader_at(&srv.base);
        let nodes = reader.list_nodes().unwrap();
        assert_eq!(nodes, vec!["NodeA", "NodeB", "NodeC"]);
        let reqs = srv.requests.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0]
            .target
            .contains("/documents/relays?showMissing=true"));
        assert!(reqs[1].target.contains("pageToken=tok1"));
    }

    #[test]
    fn kv_reader_list_nodes_treats_404_as_empty() {
        let srv = spawn_mock(vec![(404, "{}".into())]);
        assert!(kv_reader_at(&srv.base).list_nodes().unwrap().is_empty());
    }

    #[test]
    fn kv_reader_lists_kv_pairs_recovering_the_original_key() {
        // kv docs carry the ORIGINAL key in a `key` field (doc ids are base58'd because keys
        // contain '/'); the reader must return that, plus the raw value bytes.
        let doc = kv_doc_json(
            "usage/402/00000000000000000000000000000000",
            &7u64.to_le_bytes(),
        );
        let page = serde_json::json!({ "documents": [doc] });
        let srv = spawn_mock(vec![(200, page.to_string())]);
        let pairs = kv_reader_at(&srv.base).list_kv_of("NodeA").unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "usage/402/00000000000000000000000000000000");
        assert_eq!(pairs[0].1, 7u64.to_le_bytes().to_vec());
        let reqs = srv.requests.lock().unwrap();
        assert!(reqs[0].target.contains("/documents/relays/NodeA/kv"));
    }

    #[test]
    fn kv_reader_list_kv_surfaces_server_errors() {
        let srv = spawn_mock(vec![(500, "{}".into())]);
        assert!(kv_reader_at(&srv.base).list_kv_of("NodeA").is_err());
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
    fn firestore_bundle_pages_parse_and_handle_404() {
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
        let first = mirror.list_bundle_page(None, 1, 1024).unwrap();
        assert_eq!(first.rows[0].value, Some((b"one".to_vec(), 111)));
        assert_eq!(first.scanned_pages, 1);
        assert!(first.scanned_bytes > 0);
        assert_eq!(first.next.as_deref(), Some("PAGE2"));
        let second = mirror
            .list_bundle_page(first.next.as_deref(), 1, 1024)
            .unwrap();
        assert_eq!(second.rows[0].value, Some((b"two".to_vec(), 222)));
        assert_eq!(second.next, None);
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs.len(), 2, "followed the page token to a second request");
            assert!(reqs[1].target.contains("pageToken=PAGE2"));
        }
        // A 404 means the collection doesn't exist yet -> empty, not an error.
        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(firestore_client_at(&srv404.base)
            .list_bundle_page(None, 1, 1024)
            .unwrap()
            .rows
            .is_empty());
        // Any other non-success status is an error.
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srv500.base)
            .list_bundle_page(None, 1, 1024)
            .is_err());
    }

    #[test]
    fn firestore_bundle_page_retains_malformed_documents_in_scan_accounting() {
        let malformed = serde_json::json!({
            "name": "projects/p/databases/(default)/documents/relays/n/bundles/bad",
            "fields": {
                "data": { "bytesValue": "not-base64" },
                "expiresAt": { "integerValue": "not-an-integer" }
            }
        });
        let body = serde_json::json!({
            "documents": [firestore_doc(b"valid", 123), malformed]
        })
        .to_string();
        let server = spawn_mock(vec![(200, body.clone())]);
        let page = firestore_client_at(&server.base)
            .list_bundle_page(None, 2, body.len())
            .unwrap();

        assert_eq!(page.rows.len(), 2);
        assert_eq!(page.rows[0].value, Some((b"valid".to_vec(), 123)));
        assert_eq!(page.rows[1].value, None);
        assert_eq!(page.scanned_bytes, body.len());
        assert_eq!(page.scanned_pages, 1);
        assert_eq!(server.requests.lock().unwrap().len(), 1);
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

        let malformed = spawn_mock(vec![(200, String::new())]);
        let client = firestore_client_at(&malformed.base);
        let mirror: &dyn BundleMirror = &client;
        mirror.delete_kv_document("not base58!").unwrap();
        let requests = malformed.requests.lock().unwrap();
        assert_eq!(requests[0].method, "DELETE");
        assert!(requests[0].target.ends_with("/kv/not%20base58!"));
    }

    #[test]
    fn firestore_kv_batch_creates_a_confirmed_journal_before_one_mutation_commit() {
        let mutations = vec![
            KvMutation::Put {
                key: "session/peerX".into(),
                value: b"ratchet".to_vec(),
            },
            KvMutation::Remove {
                key: "inbox/accepted".into(),
            },
        ];
        let pending = journal_document(&mutations, JournalState::Pending, "pending-update");
        let srv = spawn_mock(vec![
            (404, String::new()),
            (200, "{}".into()),
            (200, pending.to_string()),
            (200, "{}".into()),
        ]);
        let client = firestore_client_at(&srv.base);
        client.apply_kv_batch(&mutations).unwrap();

        let requests = srv.requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].target.contains("/operations/"));
        assert_eq!(requests[1].method, "POST");
        assert!(requests[1].target.ends_with("/documents:commit"));
        let create: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(
            create["writes"].as_array().unwrap().len(),
            2,
            "a create-only pending journal plus the startup fence verification"
        );
        assert_eq!(create["writes"][0]["currentDocument"]["exists"], false);
        assert_eq!(
            create["writes"][0]["update"]["fields"]["state"]["stringValue"],
            "pending"
        );
        assert_eq!(
            create["writes"][1]["currentDocument"]["updateTime"],
            "fence-update-time"
        );
        assert_eq!(requests[2].method, "GET", "pending journal is confirmed");

        let commit: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
        assert_eq!(commit["writes"].as_array().unwrap().len(), 4);
        assert_eq!(
            commit["writes"][0]["update"]["fields"]["key"]["stringValue"],
            "session/peerX"
        );
        assert!(commit["writes"][1]["delete"]
            .as_str()
            .unwrap()
            .ends_with(&bs58::encode("inbox/accepted".as_bytes()).into_string()));
        assert_eq!(
            commit["writes"][2]["update"]["fields"]["state"]["stringValue"],
            "committed"
        );
        assert_eq!(
            commit["writes"][2]["currentDocument"]["updateTime"],
            "pending-update"
        );
        assert_eq!(
            commit["writes"][3]["currentDocument"]["updateTime"],
            "fence-update-time"
        );
        drop(requests);

        let denied = spawn_mock(vec![(404, String::new()), (403, String::new())]);
        assert!(matches!(
            firestore_client_at(&denied.base)
                .apply_kv_batch(&[KvMutation::Remove { key: "k".into() }]),
            Err(MirrorBatchError::Definitive(error)) if error.contains("403")
        ));
    }

    #[test]
    fn firestore_ambiguous_commit_reconciles_the_atomic_committed_journal() {
        let mutations = vec![KvMutation::Put {
            key: "session/peerX".into(),
            value: b"ratchet-next".to_vec(),
        }];
        let pending = journal_document(&mutations, JournalState::Pending, "pending-update");
        let committed = journal_document(&mutations, JournalState::Committed, "committed-update");

        // The commit endpoint returns a server/transport-class failure after accepting the atomic
        // write. The committed journal transition proves the exact mutations landed atomically.
        let accepted = spawn_mock(vec![
            (200, pending.to_string()),
            (500, String::new()),
            (200, committed.to_string()),
        ]);
        firestore_client_at(&accepted.base)
            .apply_kv_batch(&mutations)
            .expect("the exact committed journal reconciles the accepted commit");
        let requests = accepted.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[2].method, "GET");
        drop(requests);

        let still_pending = spawn_mock(vec![
            (200, pending.to_string()),
            (500, String::new()),
            (200, pending.to_string()),
        ]);
        assert!(matches!(
            firestore_client_at(&still_pending.base).apply_kv_batch(&mutations),
            Err(MirrorBatchError::Unknown(error)) if error.contains("journal remains pending")
        ));

        let unknown = spawn_mock(vec![
            (200, pending.to_string()),
            (500, String::new()),
            (503, String::new()),
        ]);
        assert!(matches!(
            firestore_client_at(&unknown.base).apply_kv_batch(&mutations),
            Err(MirrorBatchError::Unknown(error)) if error.contains("journal read")
        ));

        // A retry sees the committed marker and never submits the mutations again.
        let retry = spawn_mock(vec![(200, committed.to_string())]);
        firestore_client_at(&retry.base)
            .apply_kv_batch(&mutations)
            .unwrap();
        assert!(retry
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.method == "GET"));
    }

    #[test]
    fn firestore_timeout_conflict_and_throttle_statuses_require_reconciliation() {
        let mutations = vec![KvMutation::Remove {
            key: "session/peerX".into(),
        }];
        let pending = journal_document(&mutations, JournalState::Pending, "pending-update");
        for status in [408, 409, 412, 429, 500, 503] {
            let server = spawn_mock(vec![
                (200, pending.to_string()),
                (status, String::new()),
                (200, pending.to_string()),
            ]);
            assert!(matches!(
                firestore_client_at(&server.base).apply_kv_batch(&mutations),
                Err(MirrorBatchError::Unknown(error))
                    if error.contains("journal remains pending")
            ));
            assert_eq!(server.requests.lock().unwrap().len(), 3, "status {status}");
        }

        let unknown_create = spawn_mock(vec![
            (404, String::new()),
            (500, String::new()),
            (404, String::new()),
        ]);
        assert!(matches!(
            firestore_client_at(&unknown_create.base).apply_kv_batch(&mutations),
            Err(MirrorBatchError::Unknown(error)) if error.contains("journal is absent")
        ));
    }

    #[test]
    fn restart_replays_a_pending_journal_under_the_new_fence() {
        let mutations = vec![KvMutation::Put {
            key: "session/peerX".into(),
            value: b"ratchet-after-crash".to_vec(),
        }];
        let pending = journal_document(&mutations, JournalState::Pending, "pending-update");
        let old_fence = fence_document([9; 32], "fence-update-time");
        let new_fence = fence_document([7; 32], "new-fence-update");
        let journal_page = serde_json::json!({ "documents": [pending] }).to_string();
        let server = spawn_mock(vec![
            (200, old_fence.to_string()),
            (200, "{}".into()),
            (200, new_fence.to_string()),
            (200, journal_page),
            (200, "{}".into()),
            (200, new_fence.to_string()),
        ]);
        let client = firestore_client_at(&server.base);
        client
            .recover_critical_operations_with_generation([7; 32])
            .expect("restart must replay the exact pending batch before readiness");

        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 6);
        let rotation: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(
            rotation["writes"][0]["currentDocument"]["updateTime"],
            "fence-update-time"
        );
        assert_eq!(requests[3].method, "GET");
        assert!(requests[3].target.contains("/operations?pageSize=32"));
        let replay: serde_json::Value = serde_json::from_str(&requests[4].body).unwrap();
        assert_eq!(
            replay["writes"][1]["update"]["fields"]["state"]["stringValue"],
            "committed"
        );
        assert_eq!(
            replay["writes"][2]["currentDocument"]["updateTime"],
            "new-fence-update"
        );
    }

    #[test]
    fn restart_accepts_the_original_commit_when_it_wins_during_reconciliation() {
        let mutations = vec![KvMutation::Remove {
            key: "session/peerX".into(),
        }];
        let committed = journal_document(&mutations, JournalState::Committed, "committed-update");
        let old_fence = fence_document([9; 32], "fence-update-time");
        let new_fence = fence_document([6; 32], "new-fence-update");
        let journal_page = serde_json::json!({ "documents": [committed] }).to_string();
        let server = spawn_mock(vec![
            (200, old_fence.to_string()),
            (200, "{}".into()),
            (200, new_fence.to_string()),
            // The old commit lands after recovery starts but before the fenced journal scan.
            (200, journal_page),
            (200, new_fence.to_string()),
        ]);
        firestore_client_at(&server.base)
            .recover_critical_operations_with_generation([6; 32])
            .expect("the committed marker lets the original request win without replay");

        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "POST")
                .count(),
            1,
            "only fence rotation is posted; committed mutations are not replayed"
        );
    }

    #[test]
    fn pending_reconciliation_stops_before_row_page_and_response_byte_overrun() {
        let committed = |index: usize| {
            journal_document(
                &[KvMutation::Remove {
                    key: format!("session/peer-{index}"),
                }],
                JournalState::Committed,
                &format!("committed-{index}"),
            )
        };
        let page_one = serde_json::json!({
            "documents": [committed(0), committed(1)],
            "nextPageToken": "PAGE2"
        })
        .to_string();
        let page_two = serde_json::json!({
            "documents": [committed(2), committed(3)],
            "nextPageToken": "PAGE3"
        })
        .to_string();

        for (label, limits, expected_pages, expected_error) in [
            (
                "rows",
                OperationRecoveryLimits {
                    page_size: 2,
                    max_records: 4,
                    max_pages: 8,
                    max_response_bytes: 1024 * 1024,
                },
                2,
                "exceeds 4 records",
            ),
            (
                "pages",
                OperationRecoveryLimits {
                    page_size: 2,
                    max_records: 8,
                    max_pages: 2,
                    max_response_bytes: 1024 * 1024,
                },
                2,
                "exceeds 2 pages",
            ),
            (
                "bytes",
                OperationRecoveryLimits {
                    page_size: 2,
                    max_records: 8,
                    max_pages: 8,
                    max_response_bytes: page_one.len(),
                },
                1,
                "response bytes exceed",
            ),
        ] {
            let old_fence = fence_document([9; 32], "fence-update-time");
            let new_fence = fence_document([3; 32], "new-fence-update");
            let server = spawn_mock(vec![
                (200, old_fence.to_string()),
                (200, "{}".into()),
                (200, new_fence.to_string()),
                (200, page_one.clone()),
                (200, page_two.clone()),
            ]);
            let error = firestore_client_at(&server.base)
                .recover_critical_operations_with_generation_and_limits([3; 32], limits)
                .expect_err("a continued journal must stop before another remote page");
            assert!(error.contains(expected_error), "{label}: {error}");

            let requests = server.requests.lock().unwrap();
            assert_eq!(requests.len(), 3 + expected_pages, "{label}");
            let pages: Vec<_> = requests
                .iter()
                .filter(|request| request.target.contains("/operations?pageSize="))
                .collect();
            assert_eq!(pages.len(), expected_pages, "{label}");
            assert!(pages
                .iter()
                .all(|request| request.target.contains("pageSize=2")));
        }
    }

    #[test]
    fn crash_after_pending_creation_is_replayed_by_restart() {
        let mutations = vec![KvMutation::Put {
            key: "session/peerX".into(),
            value: b"next-ratchet".to_vec(),
        }];
        let pending = journal_document(&mutations, JournalState::Pending, "pending-update");
        let old_fence = fence_document([9; 32], "fence-update-time");
        let new_fence = fence_document([5; 32], "restart-fence-update");
        let journal_page = serde_json::json!({ "documents": [pending.clone()] }).to_string();
        let server = spawn_mock(vec![
            (404, String::new()),
            (200, "{}".into()),
            (200, pending.to_string()),
            (500, String::new()),
            (200, pending.to_string()),
            (200, old_fence.to_string()),
            (200, "{}".into()),
            (200, new_fence.to_string()),
            (200, journal_page),
            (200, "{}".into()),
            (200, new_fence.to_string()),
        ]);
        let old_process = firestore_client_at(&server.base);
        assert!(matches!(
            old_process.apply_kv_batch(&mutations),
            Err(MirrorBatchError::Unknown(error)) if error.contains("journal remains pending")
        ));

        let restarted = firestore_client_at(&server.base);
        restarted
            .recover_critical_operations_with_generation([5; 32])
            .expect("restart reconciles the durable pending record");
        let requests = server.requests.lock().unwrap();
        let old_commit: serde_json::Value = serde_json::from_str(&requests[3].body).unwrap();
        let replay: serde_json::Value = serde_json::from_str(&requests[9].body).unwrap();
        assert_eq!(
            old_commit["writes"].as_array().unwrap().len(),
            replay["writes"].as_array().unwrap().len(),
            "replay carries the exact original mutation set"
        );
        assert_eq!(
            old_commit["writes"][1]["currentDocument"]["updateTime"],
            "pending-update"
        );
        assert_eq!(
            old_commit["writes"][2]["currentDocument"]["updateTime"],
            "fence-update-time"
        );
        assert_eq!(
            replay["writes"][2]["currentDocument"]["updateTime"],
            "restart-fence-update"
        );
    }

    #[test]
    fn malformed_and_oversized_journals_fail_restart_closed() {
        let mutations = vec![KvMutation::Remove {
            key: "session/peerX".into(),
        }];
        let mut malformed = journal_document(&mutations, JournalState::Pending, "pending-update");
        malformed["fields"]["state"]["stringValue"] = serde_json::Value::String("unknown".into());
        let mut oversized = journal_document(&mutations, JournalState::Pending, "pending-update");
        oversized["fields"]["mutations"]["bytesValue"] =
            serde_json::Value::String("A".repeat(CRITICAL_BATCH_MAX_BYTES.div_ceil(3) * 4 + 1));

        for (label, document, expected) in [
            ("malformed", malformed, "state is invalid"),
            ("oversized", oversized, "encoded byte limit"),
        ] {
            let old_fence = fence_document([9; 32], "fence-update-time");
            let new_fence = fence_document([4; 32], "new-fence-update");
            let documents = if label == "malformed" {
                vec![document; 16]
            } else {
                vec![document]
            };
            let page = serde_json::json!({
                "documents": documents,
                "nextPageToken": "must-not-be-read"
            })
            .to_string();
            let server = spawn_mock(vec![
                (200, old_fence.to_string()),
                (200, "{}".into()),
                (200, new_fence.to_string()),
                (200, page),
            ]);
            let error = firestore_client_at(&server.base)
                .recover_critical_operations_with_generation([4; 32])
                .expect_err("invalid journal evidence must prevent readiness");
            assert!(error.contains(expected), "{label}: {error}");
            assert_eq!(
                server.requests.lock().unwrap().len(),
                4,
                "{label}: malformed rows fail closed on their first bounded page"
            );
        }
    }

    #[test]
    fn firestore_readiness_probe_requires_write_read_delete_and_absence_confirmation() {
        let identity = [7u8; 32];
        let marker = serde_json::json!({
            "fields": {
                "mutationId": { "bytesValue": b64(&identity) },
                "expireAt": { "timestampValue": "2099-01-01T00:00:00Z" }
            }
        })
        .to_string();
        let healthy = spawn_mock(vec![
            (200, "{}".into()),
            (200, marker),
            (200, "{}".into()),
            (404, String::new()),
        ]);
        firestore_client_at(&healthy.base)
            .durability_probe_document("readiness-test", &identity)
            .unwrap();
        let methods: Vec<_> = healthy
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.method.clone())
            .collect();
        assert_eq!(methods, ["PATCH", "GET", "DELETE", "GET"]);

        let denied = spawn_mock(vec![(403, String::new())]);
        let error = firestore_client_at(&denied.base)
            .durability_probe_document("readiness-denied", &identity)
            .expect_err("write denial must fail readiness");
        assert!(error.contains("probe write returned 403"));
        assert_eq!(denied.requests.lock().unwrap().len(), 1);
        assert_eq!(denied.requests.lock().unwrap()[0].method, "PATCH");
    }

    #[test]
    fn firestore_list_kv_page_uses_key_ranges_and_an_exclusive_cursor() {
        let kv_doc = |k: &str, v: &[u8]| {
            serde_json::json!({
                "name": "x",
                "fields": { "key": { "stringValue": k }, "value": { "bytesValue": b64(v) } }
            })
        };
        let page1 = serde_json::json!([{ "document": kv_doc("strm/000001", b"aa") }]).to_string();
        let page2 = serde_json::json!([{ "document": kv_doc("strm/000002", b"bb") }]).to_string();
        let srv = spawn_mock(vec![(200, page1), (200, page2)]);
        let client = firestore_client_at(&srv.base);
        let mirror: &dyn BundleMirror = &client;
        let first = mirror.list_kv_page("strm/", None, 1).unwrap();
        let second = mirror.list_kv_page("strm/", Some(&first[0].0), 1).unwrap();
        assert_eq!(
            (first, second),
            (
                vec![("strm/000001".to_string(), b"aa".to_vec())],
                vec![("strm/000002".to_string(), b"bb".to_vec())]
            )
        );
        let requests = srv.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|request| request.method == "POST"));
        assert!(requests
            .iter()
            .all(|request| request.target.ends_with("/documents/relays/NODE:runQuery")));
        let first_body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        let second_body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(first_body["structuredQuery"]["limit"], 1);
        assert_eq!(
            first_body["structuredQuery"]["where"]["compositeFilter"]["filters"][0]["fieldFilter"]
                ["op"],
            "GREATER_THAN_OR_EQUAL"
        );
        assert_eq!(
            second_body["structuredQuery"]["where"]["compositeFilter"]["filters"][0]["fieldFilter"]
                ["op"],
            "GREATER_THAN"
        );
        assert_eq!(
            second_body["structuredQuery"]["where"]["compositeFilter"]["filters"][0]["fieldFilter"]
                ["value"]["stringValue"],
            "strm/000001"
        );
        drop(requests);

        let srv404 = spawn_mock(vec![(404, String::new())]);
        assert!(firestore_client_at(&srv404.base)
            .list_kv_page("strm/", None, 1)
            .unwrap()
            .is_empty());
        let srv500 = spawn_mock(vec![(500, String::new())]);
        assert!(firestore_client_at(&srv500.base)
            .list_kv_page("strm/", None, 1)
            .is_err());
        let malformed = serde_json::json!([{
            "document": { "fields": { "key": { "stringValue": "strm/bad" } } }
        }])
        .to_string();
        let malformed_server = spawn_mock(vec![(200, malformed)]);
        assert!(firestore_client_at(&malformed_server.base)
            .list_kv_page("strm/", None, 1)
            .is_err());

        let malformed_but_identifiable = serde_json::json!([{
            "document": {
                "name": "projects/p/databases/(default)/documents/relays/NODE/kv/malformed-doc",
                "fields": { "key": { "stringValue": "strm/bad" } }
            }
        }])
        .to_string();
        let bounded_server = spawn_mock(vec![(200, malformed_but_identifiable)]);
        let bounded = firestore_client_at(&bounded_server.base)
            .list_kv_page_bounded("strm/", None, 1, 4096)
            .unwrap();
        assert_eq!(bounded.rows.len(), 1);
        assert_eq!(bounded.rows[0].document_id, "malformed-doc");
        assert!(bounded.rows[0].value.is_none());
        assert_eq!(bounded.scanned_pages, 1);
    }

    #[test]
    fn firestore_eager_kv_queries_around_the_lazy_stream_range() {
        let kv_doc = |k: &str, v: &[u8]| {
            serde_json::json!({
                "name": "x",
                "fields": { "key": { "stringValue": k }, "value": { "bytesValue": b64(v) } }
            })
        };
        let before =
            serde_json::json!([{ "document": kv_doc("session/a", b"ratchet") }]).to_string();
        let after = serde_json::json!([{ "document": kv_doc("tx/a", b"pending") }]).to_string();
        let srv = spawn_mock(vec![(200, before), (200, after)]);
        let page = firestore_client_at(&srv.base)
            .list_eager_kv_page(None, 10, 4096, 2)
            .unwrap();
        assert_eq!(
            page.rows
                .iter()
                .map(|row| (row.key.clone(), row.value.clone().unwrap()))
                .collect::<Vec<_>>(),
            vec![
                ("session/a".to_string(), b"ratchet".to_vec()),
                ("tx/a".to_string(), b"pending".to_vec())
            ]
        );
        assert_eq!(page.next, None);

        let requests = srv.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "one query on each side of strm/");
        let before_body: serde_json::Value = serde_json::from_str(&requests[0].body).unwrap();
        let after_body: serde_json::Value = serde_json::from_str(&requests[1].body).unwrap();
        assert_eq!(
            before_body["structuredQuery"]["where"]["fieldFilter"]["op"],
            "LESS_THAN"
        );
        assert_eq!(
            before_body["structuredQuery"]["where"]["fieldFilter"]["value"]["stringValue"],
            LAZY_KV_PREFIX
        );
        assert_eq!(
            after_body["structuredQuery"]["where"]["fieldFilter"]["op"],
            "GREATER_THAN_OR_EQUAL"
        );
        assert_eq!(
            after_body["structuredQuery"]["where"]["fieldFilter"]["value"]["stringValue"],
            LAZY_KV_PREFIX_END
        );
    }

    #[test]
    fn eager_kv_page_budget_continues_across_the_lazy_range_without_skipping_boundary_key() {
        let boundary = serde_json::json!([{
            "document": {
                "name": "x",
                "fields": {
                    "key": { "stringValue": LAZY_KV_PREFIX_END },
                    "value": { "bytesValue": b64(b"boundary") }
                }
            }
        }])
        .to_string();
        let server = spawn_mock(vec![(200, "[]".into()), (200, boundary)]);
        let client = firestore_client_at(&server.base);

        let first = client.list_eager_kv_page(None, 10, 4096, 1).unwrap();
        assert!(first.rows.is_empty());
        assert_eq!(first.scanned_pages, 1);
        assert_eq!(first.next.as_deref(), Some(LAZY_KV_PREFIX));

        let second = client
            .list_eager_kv_page(first.next.as_deref(), 10, 4096, 1)
            .unwrap();
        assert_eq!(second.rows.len(), 1);
        assert_eq!(second.rows[0].key, LAZY_KV_PREFIX_END);
        assert_eq!(
            second.rows[0].value.as_deref(),
            Some(b"boundary".as_slice())
        );
        assert_eq!(server.requests.lock().unwrap().len(), 2);
    }

    #[test]
    fn eager_kv_page_retains_malformed_values_in_scan_accounting() {
        let key = "session/malformed";
        let body = serde_json::json!([{
            "document": {
                "name": format!(
                    "projects/p/databases/(default)/documents/relays/n/kv/{}",
                    bs58::encode(key.as_bytes()).into_string()
                ),
                "fields": {
                    "key": { "stringValue": key },
                    "value": { "bytesValue": "not-base64" }
                }
            }
        }])
        .to_string();
        let server = spawn_mock(vec![(200, body.clone())]);
        let page = firestore_client_at(&server.base)
            .list_eager_kv_page(None, 1, body.len(), 1)
            .unwrap();

        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].key, key);
        assert_eq!(page.rows[0].value, None);
        assert_eq!(page.scanned_bytes, body.len());
        assert_eq!(page.scanned_pages, 1);
        assert_eq!(server.requests.lock().unwrap().len(), 1);
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
        assert!(client
            .run_query_url
            .ends_with(&format!("/relays/{node}:runQuery")));
        assert!(client
            .operation_url
            .ends_with(&format!("/relays/{node}/operations")));
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
    fn presence_streaming_visitors_reserve_before_each_one_document_page() {
        let page1 = serde_json::json!({
            "documents": [firestore_doc(b"one", 10)],
            "nextPageToken": "NEXT"
        })
        .to_string();
        let page2 = serde_json::json!({ "documents": [firestore_doc(b"two", 20)] }).to_string();
        let server = spawn_mock(vec![(200, page1), (200, page2)]);
        let reservations = Arc::new(AtomicU64::new(0));
        let visits = Arc::new(AtomicU64::new(0));
        let reserve_count = reservations.clone();
        let visit_count = visits.clone();
        presence_at(&server.base)
            .visit_bundles_of(
                "NodeB",
                move || {
                    reserve_count.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
                move |(), data, expires| {
                    let visited = visit_count.fetch_add(1, Ordering::AcqRel);
                    assert!(
                        reservations.load(Ordering::Acquire) > visited,
                        "reservation is acquired before page decode reaches the producer"
                    );
                    let expected = if visited == 0 {
                        (b"one".to_vec(), 10)
                    } else {
                        (b"two".to_vec(), 20)
                    };
                    assert_eq!((data, expires), expected);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(visits.load(Ordering::Acquire), 2);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.target.contains("pageSize=1")));
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
