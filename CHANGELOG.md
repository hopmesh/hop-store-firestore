# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- refresh the hop-store-firestore standalone lock for the base64 bump (e13d67a)
- rustfmt drift and two overstated lines in the sec-relay-p1 write-up (b25d258)
- per-mirror repository, and retryable release artifacts (bf04449)
- refresh standalone lock checksums for the published sibling (b123888)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)

### CI
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- bump the rust-dependencies group across 1 directory with 7 updates (ce964ad)
- invert the license tiers, FSL moves from core to services (14d7fec)
- purge em-dashes and en-dashes from source (d222435)
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Documentation
- regenerate from conventional commits (910695c)
- regenerate from conventional commits (7160289)
- record the relay link-identity gap, and what sec-relay-p1 did and did not close (951093a)
- regenerate from conventional commits (3b47a5f)
- regenerate from conventional commits (ffb2acb)
- regenerate from conventional commits (e19ed95)
- regenerate from conventional commits (7a81fb6)
- regenerate from conventional commits (e6b97f2)
- regenerate from conventional commits (2741000)
- regenerate from conventional commits (b96e019)
- regenerate from conventional commits (330c8c6)
- regenerate from conventional commits (096180b)
- regenerate from conventional commits (102ae67)
- stop describing a routing algorithm the code no longer runs (5433b6e)
- regenerate from conventional commits (1572ae2)
- regenerate from conventional commits (a355901)
- branded, marketable READMEs for every sub-repo (9c2a477)

### Features
- finish inbound (import), drop export_pr (41c095e)
- relays + collectors read tenant keys from the registry (5b-2, reader) (f80f5b3)
- project the tenant registry to Firestore (phase 5b, writer) (e73d8d9)
- auto-generate monorepo + per-library changelogs (git-cliff) (8c64c37)
- the ledger source, closing the reconcile chain end to end (ba6b6b8)

### Other
- close SVC-002, SVC-003 and SVC-004 (5081fc2)
- key the presence index, de-fingerprint the delivery vaccine (e25fff5)
- bump our crates in every standalone/vendored Cargo.lock (aad3ff7)
- make the writer-scoped ledger readable end to end, and stop overclaiming (5ee2555)
- delete the dead copy-budget API and stop the simulator lying (9ab3138)
- one-time prekeys for async first contact (wire v11) (d6ebce3)
- publish the Rust crates under the hop-mesh-* namespace (3bb9d0c)
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)

### Testing
- cover the REST layer to 96.7% (from 40.5%) (#58) (1222bf3)

