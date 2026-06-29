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
//! memory; the node's `rehydrate` then resumes them. Only *bundles* are persisted —
//! the dedup `seen` set is in-memory (losing it across a scale cycle costs at most
//! some re-flooding, which the receiver dedups; §7).
//!
//! Durable cleanup of expired bundles is left to a **Firestore TTL policy** on the
//! `expireAt` timestamp field (a one-time setup; TTL only sweeps `timestampValue`
//! fields, so every doc carries one — see `doc_json`), keeping `prune` a fast
//! in-memory op. One policy on the `bundles` collection group covers both the
//! per-relay handoff inbox and the §39 mailbox spool.
//!
//! Auth: a Bearer token from the GCE/Cloud Run **metadata server** (workload
//! identity), or the `FIRESTORE_ACCESS_TOKEN` env var for local runs.

use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use hop_core::bundle::{Bundle, BundleId};
use hop_core::store::{HaveSet, MemoryStore, Store};

/// A bundle write/delete to mirror to Firestore.
enum Op {
    Write { id: BundleId, data: Vec<u8>, expires_at: u64 },
    Delete { id: BundleId },
}

/// Durable per-node store: in-memory hot path + Firestore mirror.
pub struct FirestoreStore {
    inner: MemoryStore,
    tx: Sender<Op>,
}

impl FirestoreStore {
    /// Open the store for `node_addr` in `project`, loading any held bundles back
    /// into memory. Spawns the background writer thread.
    pub fn open(project: &str, node_addr: &[u8]) -> Result<Self, String> {
        let client = FirestoreClient::new(project, node_addr);
        let mut inner = MemoryStore::new();

        // Rehydrate held bundles from Firestore into memory (mark seen so dedup holds).
        for (data, _expires) in client.list_bundles()? {
            if let Ok(bundle) = Bundle::from_bytes(&data) {
                inner.put(bundle, 0);
            }
        }

        let (tx, rx) = mpsc::channel::<Op>();
        std::thread::spawn(move || {
            for op in rx {
                // Best-effort with a couple of retries; the hot path never blocks here.
                for attempt in 0..3 {
                    let ok = match &op {
                        Op::Write { id, data, expires_at } => client.put_bundle(id, data, *expires_at),
                        Op::Delete { id } => client.delete_bundle(id),
                    };
                    if ok.is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));
                }
            }
        });

        Ok(Self { inner, tx })
    }
}

impl Store for FirestoreStore {
    fn put(&mut self, bundle: Bundle, now_ms: u64) -> bool {
        let id = bundle.id();
        let expires_at = now_ms.saturating_add(bundle.inner.lifetime_ms as u64);
        let data = match bundle.to_bytes() {
            Ok(d) => d,
            Err(_) => return false,
        };
        if self.inner.put(bundle, now_ms) {
            let _ = self.tx.send(Op::Write { id, data, expires_at });
            true
        } else {
            false
        }
    }

    fn get(&self, id: &BundleId) -> Option<Bundle> {
        self.inner.get(id)
    }

    fn remove(&mut self, id: &BundleId) -> Option<Bundle> {
        let removed = self.inner.remove(id);
        if removed.is_some() {
            let _ = self.tx.send(Op::Delete { id: *id });
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
            if let Some(b) = self.inner.get(id) {
                if let Ok(data) = b.to_bytes() {
                    let expires_at = b.inner.created_at.saturating_add(b.inner.lifetime_ms as u64);
                    let _ = self.tx.send(Op::Write { id: *id, data, expires_at });
                }
            }
        }
        give
    }

    fn set_copies(&mut self, id: &BundleId, copies: u16) {
        self.inner.set_copies(id, copies);
        if let Some(b) = self.inner.get(id) {
            if let Ok(data) = b.to_bytes() {
                let expires_at = b.inner.created_at.saturating_add(b.inner.lifetime_ms as u64);
                let _ = self.tx.send(Op::Write { id: *id, data, expires_at });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Firestore REST client (blocking; runs only on the background thread + open()).
// ---------------------------------------------------------------------------

struct FirestoreClient {
    http: reqwest::blocking::Client,
    collection_url: String, // .../documents/relays/{node}/bundles
    token: Mutex<Option<(String, Instant)>>,
}

impl FirestoreClient {
    fn new(project: &str, node_addr: &[u8]) -> Self {
        let node = bs58::encode(node_addr).into_string();
        let base = "https://firestore.googleapis.com/v1";
        let collection_url =
            format!("{base}/projects/{project}/databases/(default)/documents/relays/{node}/bundles");
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
            collection_url,
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
        let resp = self.http.delete(&url).bearer_auth(token).send().map_err(|e| e.to_string())?;
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
    let resp =
        http.get(url).header("Metadata-Flavor", "Google").send().map_err(|e| e.to_string())?;
    let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
    v["access_token"].as_str().map(|s| s.to_string()).ok_or_else(|| "no access_token".into())
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
        let resp =
            self.http.patch(&url).bearer_auth(token).json(&body).send().map_err(|e| e.to_string())?;
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
fn registry_doc_json(node: &str, region: &str, endpoint: &str, heartbeat_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "fields": {
            "node": { "stringValue": node },
            "region": { "stringValue": region },
            "endpoint": { "stringValue": endpoint },
            "heartbeatAt": { "integerValue": heartbeat_ms.to_string() },
        }
    })
}

/// Parse a Firestore registry document into a [`PeerInfo`].
fn parse_registry_doc(d: &serde_json::Value) -> Option<PeerInfo> {
    let f = d.get("fields")?;
    Some(PeerInfo {
        node: f["node"]["stringValue"].as_str()?.to_string(),
        region: f["region"]["stringValue"].as_str().unwrap_or("").to_string(),
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
        let resp =
            self.http.patch(&url).bearer_auth(token).json(&body).send().map_err(|e| e.to_string())?;
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
        let resp = self.http.get(&url).bearer_auth(token).send().map_err(|e| e.to_string())?;
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
        let base = "https://firestore.googleapis.com/v1";
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
            let resp =
                self.http.get(&url).bearer_auth(&token).send().map_err(|e| e.to_string())?;
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
        let base = "https://firestore.googleapis.com/v1";
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/relays/{node}/bundles/{doc}",
            self.project
        );
        let body = doc_json(data, expires_at);
        let token = self.token()?;
        let resp =
            self.http.patch(&url).bearer_auth(token).json(&body).send().map_err(|e| e.to_string())?;
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
        let base = "https://firestore.googleapis.com/v1";
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles/{doc}",
            self.project
        );
        let body = doc_json(data, expires_at);
        let token = self.token()?;
        let resp =
            self.http.patch(&url).bearer_auth(token).json(&body).send().map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("spool_to_mailbox {}", resp.status()))
        }
    }

    /// §39 P5: list a mailbox-tag's spooled private bundles, as `(sealed bytes, expires_at)`. Pulled
    /// when that recipient's want-beacon arrives (it then re-ingests them; P4's gradient steers each).
    pub fn list_mailbox(&self, tag_b58: &str) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let base = "https://firestore.googleapis.com/v1";
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
            let resp =
                self.http.get(&url).bearer_auth(&token).send().map_err(|e| e.to_string())?;
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
        let base = "https://firestore.googleapis.com/v1";
        let doc = bs58::encode(id).into_string();
        let url = format!(
            "{base}/projects/{}/databases/(default)/documents/mailboxes/{tag_b58}/bundles/{doc}",
            self.project
        );
        let token = self.token()?;
        let resp = self.http.delete(&url).bearer_auth(token).send().map_err(|e| e.to_string())?;
        if resp.status().is_success() || resp.status().as_u16() == 404 {
            Ok(())
        } else {
            Err(format!("delete_mailbox_bundle {}", resp.status()))
        }
    }
}

/// Build a Firestore document body for a device presence record.
fn presence_doc_json(device: &str, region: &str, heartbeat_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "fields": {
            "device": { "stringValue": device },
            "region": { "stringValue": region },
            "heartbeatAt": { "integerValue": heartbeat_ms.to_string() },
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
    let expires = fields["expiresAt"]["integerValue"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((data, expires))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(json["fields"]["expireAt"]["timestampValue"], "2001-09-09T01:46:40Z");
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
        let json = registry_doc_json("Node123", "eu-west1", "wss://eu-west1.relay.hopme.sh/", 9000);
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
        assert!(!is_fresh(1_000, 200_000, 90_000), "past ttl is stale (offline)");
    }
}
