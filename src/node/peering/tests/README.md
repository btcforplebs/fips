# `src/node/peering/tests/`

Unit tests for the files in `src/node/peering/`, one file per source file,
each declared from its source file as a child module:

```rust
#[cfg(test)]
#[path = "tests/<file>.rs"]
mod <name>;
```

so it keeps access to the source file's private items.

- `reconcile.rs` (module `claim_tests`): tests for `../reconcile.rs`, on
  how the reconciler's layers treat dials made on a transport neighbour's
  key claim (`Observed::claims_in_flight_by_peer`).

`reconcile.rs` in the parent directory still has an older inline `mod tests`
block; it takes no new tests. New tests for the reconciler go in this
directory. The tests here are pure: they build `Observed`, `Budget`,
`Policy` and `DiscoveryPools` by hand and call the reconciler, with no node,
transport or clock. Node-level tests that drive real legs are in
`src/node/tests/`.
