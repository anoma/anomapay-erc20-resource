# `anomapay_emergency_migrating_erc20_witness`

The emergency-migrating witness crate for the **AnomaPay ERC20 transfer resource**. It mirrors
[`anomapay_erc20_witness`](../anomapay_erc20_witness) — same wrap/unwrap/transfer logic —
and adds **migration** support for moving a legacy resource to the new format.

It reuses the base building blocks directly (`EncryptionInfo`, `LabelInfo`,
`ValueInfo`, `PermitInfo`, `ResourceWithLabel`, and the `calculate_*` helpers),
so this crate only adds what changes: the forwarder shape and the migration call type.

## What's new relative to the base crate

### `EmergencyMigratingTokenTransferWitness`
Same fields as `TokenTransferWitness`, except `forwarder_info` is replaced by
`emergency_migrating_forwarder_info: Option<EmergencyMigratingForwarderInfo>`.

### `EmergencyMigratingForwarderInfo`
```rust
pub struct EmergencyMigratingForwarderInfo {
    pub call_type: EmergencyMigratingCallType,               // Wrap | Unwrap | Migrate
    pub ethereum_account_addr: Option<Vec<u8>>, // not needed for Migrate
    pub permit_info: Option<PermitInfo>,
    pub migrate_info: Option<MigrateInfo>,   // present only for Migrate
    pub ordering_info: Option<OrderingInfo>, // None is an unordered call
}
```

`ordering_info` is the base crate's `OrderingInfo` and works exactly as in its
`ForwarderInfo`; it is set with `EmergencyMigratingForwarderInfo::with_ordering` (or
`EmergencyMigratingTransferLogic::with_ordering` on the host side, which returns
`Result` and rejects a non-ephemeral resource or missing forwarder info, since
only an ephemeral resource emits a forwarder call for the tags to ride on).

### `MigrateInfo`
The extra data a `Migrate` call proves about the **batch of legacy resources being
migrated**: a non-empty `entries: Vec<MigrateEntry>`, plus a single `auth_sig` over
the action tree root that authorizes the whole batch.

Each `MigrateEntry` holds one legacy resource: its `Resource`, nullifier key, a
Merkle `path` from the legacy commitment tree (proving the resource existed), its
owner's `ValueInfo`, and the **legacy** forwarder address used in its label —
entries may come from different legacy forwarder deployments. Because one
signature covers the batch, every entry must share the same `auth_pk`.

### `EmergencyMigratingCallType` ([`call_type.rs`](src/call_type.rs))
Adds `Migrate` to `Wrap`/`Unwrap`, plus `encode_migrate_forwarder_input_batch`, which
ABI-encodes the batch calldata for the EVM forwarder: the token address, the total
migrated quantity, and one Solidity `MigrateEntry` per resource (nullifier, legacy
commitment-tree root, legacy logic ref, legacy forwarder address).

## The migration constraint

When `constrain()` runs on an ephemeral resource with `EmergencyMigratingCallType::Migrate`, it
enforces (in [`src/lib.rs`](src/lib.rs)):

- migration must be triggered by a **consumed** resource;
- the batch is **non-empty**;
- every migrated legacy resource is **non-ephemeral**;
- each entry's `value_ref` matches its `ValueInfo`, and all entries share the
  same `auth_pk`, under which the batch's single authorization signature over
  the action tree root verifies with
  `TokenTransferAuthorizationEmergencyMigrating`;
- each entry's `label_ref` matches `sha2(legacy_forwarder_addr, erc20_token_addr)`;
- the entries' quantities sum (without overflow) to the trigger resource's quantity;

then it derives each migrated resource's nullifier and Merkle root and emits the
batched `Migrate` forwarder calldata as the external payload.

`Wrap` and `Unwrap` behave as in the base crate.

## Where it's used

- [`anomapay_emergency_migrating_erc20_library`](../anomapay_emergency_migrating_erc20_library) wraps this witness behind
  `EmergencyMigratingTransferLogic` and builds the migration transaction.
- [`anomapay_emergency_migrating_erc20_circuit`](../anomapay_emergency_migrating_erc20_circuit) reads an
  `EmergencyMigratingTokenTransferWitness` in the guest and calls `constrain()`.

## Testing

```bash
cargo test -p anomapay_emergency_migrating_erc20_witness
```

See the [workspace README](../README.md) for the full picture.
