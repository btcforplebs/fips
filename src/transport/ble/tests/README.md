# BLE transport tests

Unit tests for files in `src/transport/ble/` that have no inline test block.
Each file here is the test module of the source file of the same name one
level up, declared from that file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it stays a child
module of its source file and can reach that file's private items.

- `recall.rs`: tests for `recall.rs`, the probe loop's bounded memory of
  link addresses: the bound on non-live addresses, eviction order, the age
  limit, and that live addresses are never dropped.

`pool.rs` and `mod.rs` still carry inline `mod tests` blocks. Those blocks
predate the rule that unit tests live in this directory, and are due to move
here; a test written for either file once they have moved belongs here.
