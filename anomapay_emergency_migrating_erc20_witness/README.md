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
`new_forwarder_info: Option<NewForwarderInfo>`.

### `NewForwarderInfo`
```rust
pub struct NewForwarderInfo {
    pub call_type: EmergencyMigratingCallType,               // Wrap | Unwrap | Migrate
    pub ethereum_account_addr: Option<Vec<u8>>, // not needed for Migrate
    pub permit_info: Option<PermitInfo>,
    pub migrate_info: Option<MigrateInfo>,   // present only for Migrate
}
```

### `MigrateInfo`
The extra data a `Migrate` call proves about the **legacy resource being migrated**:
its `Resource`, nullifier key, a Merkle `path` from the legacy commitment tree
(proving the resource existed), the owner's authorization signature and
`ValueInfo`, and the **legacy** forwarder address used in its label.

### `EmergencyMigratingCallType` ([`call_type.rs`](src/call_type.rs))
Adds `Migrate` to `Wrap`/`Unwrap`, plus `encode_migrate_forwarder_input`, which
ABI-encodes the `MigrateEntry` calldata (nullifier, legacy commitment-tree root, legacy
logic ref, legacy forwarder address) for the EVM forwarder.

## The migration constraint

When `constrain()` runs on an ephemeral resource with `EmergencyMigratingCallType::Migrate`, it
enforces (in [`src/lib.rs`](src/lib.rs)):

- migration must be triggered by a **consumed** resource;
- the migrated legacy resource is **non-ephemeral**;
- its `value_ref` matches its `ValueInfo`, and the owner's authorization
  signature over the action tree root verifies under
  `TokenTransferAuthorizationEmergencyMigrating`;
- its quantity equals the trigger resource's quantity;
- its `label_ref` matches `sha2(legacy_forwarder_addr, erc20_token_addr)`;

then it derives the migrated resource's nullifier and Merkle root and emits the
`Migrate` forwarder calldata as the external payload.

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
