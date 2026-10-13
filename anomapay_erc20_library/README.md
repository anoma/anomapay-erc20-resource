# `anomapay_erc20_library`

The base host-side proving API for the **AnomaPay ERC20 transfer resource**. It
wraps [`anomapay_erc20_witness`](../anomapay_erc20_witness) behind the ARM `LogicProver`
trait and ships the prebuilt guest so hosts can prove and verify without
rebuilding the circuit.

## What it provides

### `TransferLogic`
A thin wrapper around a `TokenTransferWitness` that implements
`LogicProver` (`proving_key`, `verifying_key`, `witness`), so calling
`.prove(...)` produces a resource-logic proof. Besides the generic `new(...)`,
it offers constructors for each operation, so callers don't have to assemble the
witness fields by hand:

| constructor | resource produced |
| --- | --- |
| `consume_persistent_resource_logic` | consume an existing persistent resource (verifies the owner's auth signature) |
| `create_persistent_resource_logic` | create a persistent resource (encrypts payload for the recipient) |
| `mint_resource_logic_with_permit` | ephemeral **wrap** (mint) leg, carrying the Permit2 signature |
| `burn_resource_logic` | ephemeral **unwrap** (burn) leg |

### Embedded guest + image id
- `ANOMAPAY_ERC20_CIRCUIT_ELF` — the guest binary, embedded via `include_bytes!` from
  [`elf/anomapay-erc20-circuit-guest.bin`](elf/anomapay-erc20-circuit-guest.bin).
- `ANOMAPAY_ERC20_CIRCUIT_ID` — the guest `ImageID` (a `Digest`,
  `004d51ca4ae38a47cd340543a8b277f48702b675a0508fe13e69d3576702a9c7`) used to
  verify proofs on- and off-chain.

> [!IMPORTANT]
> `ANOMAPAY_ERC20_CIRCUIT_ID` pins a **specific committed build** of the guest, not
> whatever `cargo risczero build` produces at HEAD. It is consumed by deployed
> contracts, so it is rotated only when the proof semantics change — not on
> incidental dependency or toolchain bumps. See
> [`anomapay_erc20_circuit/README.md`](../anomapay_erc20_circuit/README.md) for how to
> reproduce it and when/how to update it.

Unlike the witness crate, this crate builds `anoma-rm-risc0` with the
`transaction` and `prove` features — it is a **host** dependency, not part of
the guest.

## Testing

```bash
cargo test -p anomapay_erc20_library
```

See the [workspace README](../README.md) for the full picture and
[`anomapay_emergency_migrating_erc20_library`](../anomapay_emergency_migrating_erc20_library) for the migration-capable
version.
