# `anomapay_emergency_migrating_erc20_library`

The emergency-migrating host-side proving API for the **AnomaPay ERC20 transfer resource**. It is
the migration-capable counterpart of [`anomapay_erc20_library`](../anomapay_erc20_library):
same wrap/unwrap/transfer constructors, plus everything needed to **migrate a legacy
resource** — including a ready-made transaction builder.

It wraps [`anomapay_emergency_migrating_erc20_witness`](../anomapay_emergency_migrating_erc20_witness) (and reuses base witness
types) behind the ARM `LogicProver` trait.

## What it provides

### `EmergencyMigratingTransferLogic`
A wrapper around an `EmergencyMigratingTokenTransferWitness` implementing `LogicProver`. It
mirrors `TransferLogic`'s constructors —
`consume_persistent_resource_logic`, `create_persistent_resource_logic`,
`mint_resource_logic_with_permit`, `burn_resource_logic` — and adds:

- **`migrate_resource_logic`** — builds the consumed-side logic for a migration:
  the emergency-migrating (ephemeral) trigger resource being consumed plus the
  `MigrateInfo` describing the **batch** of legacy resources being migrated — one
  `MigrateEntryParams` per resource (its resource, nullifier key, Merkle path, auth
  and encryption keys, and the legacy forwarder address, which may differ per entry)
  and a single authorization signature over the `auth_pk` they all share.

### `migrate_tx::construct_migrate_tx` ([`src/migrate_tx.rs`](src/migrate_tx.rs))
Assembles a complete, balanced ARM `Transaction` that migrates a batch of legacy
resources. Given the consumed (trigger), migrated, and created resource parameters
it:

1. builds the action tree from the consumed nullifier and created commitment,
2. creates the compliance unit (Groth16),
3. proves the consumed-side (`migrate_resource_logic`) and created-side
   (`create_persistent_resource_logic`) resource logics,
4. assembles the action and generates the delta proof,

returning a verifiable `Transaction`.

### Embedded guest + image id
- `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ELF` — the guest binary, embedded via `include_bytes!`
  from [`elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`](elf/anomapay-emergency-migrating-erc20-circuit-guest.bin).
- `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` — the guest `ImageID` (a `Digest`,
  `1742014631fc2c0bf1433d1ae909358af682df1e7c98d38ef15fb8c8f58709a2`) used to
  verify proofs on- and off-chain.

> [!IMPORTANT]
> `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` pins a **specific committed build** of the guest, not
> whatever `cargo risczero build` produces at HEAD. It is consumed by deployed
> contracts, so it is rotated only when the proof semantics change. See
> [`anomapay_emergency_migrating_erc20_circuit/README.md`](../anomapay_emergency_migrating_erc20_circuit/README.md) for how to
> reproduce it and when/how to update it.

## Testing

```bash
cargo test -p anomapay_emergency_migrating_erc20_library
```

`simple_migrate_test` in [`src/migrate_tx.rs`](src/migrate_tx.rs) builds and
verifies a migration transaction end to end. It is gated off on macOS and does
real proving — run it with `RISC0_DEV_MODE=1` for a fast (non-verifiable) pass.

See the [workspace README](../README.md) for the full picture.
