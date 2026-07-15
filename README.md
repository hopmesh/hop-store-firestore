<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop-store-firestore</h1>

<p align="center">
  <b>Durable persistence for a Hop relay, on Firestore.</b><br>
  A <code>Store</code> backend for <a href="https://hopme.sh">Hop</a> that survives scale-to-zero.
</p>

<p align="center">
  <a href="https://crates.io/crates/hop-store-firestore"><img src="https://img.shields.io/crates/v/hop-store-firestore?color=dea584&label=crates.io" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/license-FSL--1.1--ALv2-3ddc84" alt="license">
  <img src="https://img.shields.io/badge/rust-2021-dea584" alt="rust 2021">
</p>

---

Hop is a **delay-tolerant mesh**: end-to-end encrypted datagrams that hop device to device, over BLE,
Wi-Fi, and the internet, until they reach the person you meant. Held, never dropped.

`hop-store-firestore` is a `hop-core` `Store` for a cloud relay: the mailbox and forward-secret session
state, mirrored to Firestore so a relay's held bundles survive a scale-to-zero and come back when the
container spins up. It's the persistence layer under a serverless Hop relay, not something a device needs.

## Install

```toml
[dependencies]
hop-store-firestore = "0.0"
```

## Use it

Open a store scoped to this relay's node address and hand it to the node:

```rust
use hop_core::prelude::*;
use hop_store_firestore::FirestoreStore;

let node_addr = identity.address();
let store = FirestoreStore::open("hop-mesh", &node_addr)?; // GCP project + this node's 32-byte address
let mut node = Node::with_store(identity, store);
```

Auth is a Bearer token from the GCE/Cloud Run metadata server (workload identity), or the
`FIRESTORE_ACCESS_TOKEN` env var for local runs.

## Shape

- **Per node, not global.** Each relay owns `relays/{node}/bundles`, so regions don't contend on a
  shared collection.
- **Memory hot path, async mirror.** The relay's driver loop is synchronous and single-owner, so it's
  never blocked on a round-trip: a `MemoryStore` serves reads, and a background writer thread mirrors
  puts and deletes to Firestore (a FIFO channel preserves per-id order). On open, held bundles load back
  into memory and the node's `rehydrate` resumes them.
- **Bounded backpressure.** The mirror channel is capped (drop-oldest under sustained backpressure) and
  dropped ops are counted (`mirror_dropped`), so a degraded Firestore can't grow relay memory without
  bound, and `/healthz` can see a store that's silently shedding durable writes.
- **Sessions persist too.** A small kv side store (`relays/{node}/kv`) round-trips ratchet sessions,
  prekey secrets, and pending content, so a scale cycle doesn't force a re-secure churn against peers.
- **Durable cleanup is a TTL policy.** A Firestore TTL on the `expireAt` field sweeps expired bundles, so
  `prune` stays a fast in-memory op.

Beyond the `Store`, the crate carries the relay's `Registry` (per-region presence + online peers) and
`Presence` (device-to-region hints and mailbox spool) for cross-region routing.

## Status

Prototype. Production-shaped: this is the store the relay fleet runs on when relays are enabled. Covered
by `cargo test -p hop-store-firestore` against an in-process mirror fake (no live Firestore needed for
the store contract).

## The Hop family

`hop-store-firestore` is one backend behind [hop-core](https://github.com/hopmesh/hop-core)'s `Store`
trait; [hop-store-sqlite](https://crates.io/crates/hop-store-sqlite) is the on-device/self-host backend.
The C ABI over the core is [libhop](https://github.com/hopmesh/libhop); the browser build is
[hop-wasm](https://github.com/hopmesh/hop-wasm). The language SDKs:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir) ·
[apple](https://github.com/hopmesh/hop-sdk-apple) ·
[android](https://github.com/hopmesh/hop-sdk-android).

## License

[FSL-1.1-ALv2](./LICENSE.md): source-available, and converts to Apache-2.0 after two years. The SDKs
that bind this are Apache-2.0.
