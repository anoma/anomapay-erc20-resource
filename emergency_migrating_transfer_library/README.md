# `emergency_migrating_transfer_library`

The emergency-migrating host-side proving API for the **AnomaPay ERC20 transfer resource**. It is
the migration-capable counterpart of [`transfer_library`](../transfer_library):
same wrap/unwrap/transfer constructors, plus everything needed to **migrate a v1
resource** — including a ready-made transaction builder.

It wraps [`emergency_migrating_transfer_witness`](../emergency_migrating_transfer_witness) (and reuses v1 witness
types) behind the ARM `LogicProver` trait.

## What it provides

### `EmergencyMigratingTransferLogic`
A wrapper around an `EmergencyMigratingTokenTransferWitness` implementing `LogicProver`. It
mirrors `TransferLogic`'s constructors —
`consume_persistent_resource_logic`, `create_persistent_resource_logic`,
`mint_resource_logic_with_permit`, `burn_resource_logic` — and adds:

- **`migrate_resource_logic`** — builds the consumed-side logic for a migration:
  the emergency-migrating (ephemeral) resource being consumed plus the `MigrateInfo` describing
  the v1 resource being migrated (its resource, nullifier key, Merkle path, auth
  signature/keys, and the v1 forwarder address).

### `migrate_tx::construct_migrate_tx` ([`src/migrate_tx.rs`](src/migrate_tx.rs))
Assembles a complete, balanced ARM `Transaction` that migrates a v1 resource.
Given the consumed, migrated, and created resource parameters it:

1. builds the action tree from the consumed nullifier and created commitment,
2. creates the compliance unit (Groth16),
3. proves the consumed-side (`migrate_resource_logic`) and created-side
   (`create_persistent_resource_logic`) resource logics,
4. assembles the action and generates the delta proof,

returning a verifiable `Transaction`.

### Embedded guest + image id
- `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ELF` — the guest binary, embedded via `include_bytes!`
  from [`elf/emergency-migrating-token-transfer-guest.bin`](elf/emergency-migrating-token-transfer-guest.bin).
- `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` — the guest `ImageID` (a `Digest`,
  `5482722fcc17653be77d112484e8d6a7737eb75b60379efe7ce0b78843908132`) used to
  verify proofs on- and off-chain.

> [!IMPORTANT]
> `EMERGENCY_MIGRATING_TOKEN_TRANSFER_ID` pins a **specific committed build** of the guest, not
> whatever `cargo risczero build` produces at HEAD. It is consumed by deployed
> contracts, so it is rotated only when the proof semantics change. See
> [`emergency_migrating_transfer_circuit/README.md`](../emergency_migrating_transfer_circuit/README.md) for how to
> reproduce it and when/how to update it.

## Testing

```bash
cargo test -p emergency_migrating_transfer_library
```

`simple_migrate_test` in [`src/migrate_tx.rs`](src/migrate_tx.rs) builds and
verifies a migration transaction end to end. It is gated off on macOS and does
real proving — run it with `RISC0_DEV_MODE=1` for a fast (non-verifiable) pass.

See the [workspace README](../README.md) for the full picture.
