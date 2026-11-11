# Reproducibly generate proving and verifying keys (ELF and ImageID)

```bash
cargo risczero build --manifest-path anomapay_emergency_migrating_erc20_circuit/methods/guest/Cargo.toml
```

which reproduces the `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` committed in
[`anomapay_emergency_migrating_erc20_library/src/lib.rs`](../anomapay_emergency_migrating_erc20_library/src/lib.rs):

```bash
ELFs ready at:
ImageID: e4310e9ef42dd77c63aac61a26eef6fce38df6f3217d0468d6d46854fb00da1a
anomapay_emergency_migrating_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-emergency-migrating-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at
`anomapay_emergency_migrating_erc20_library/elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`
in this repo. See [`anomapay_erc20_circuit/README.md`](../anomapay_erc20_circuit/README.md) for why
and when this `ImageID` can drift from a fresh build, and how to rotate it.

It was last rotated for the `2.0.0-rc.5` release: the `anoma-rm-risc0` /
`anoma-rm-risc0-gadgets` bump to `2.0.0-rc.9` moved RISC Zero to `3.1.0`
(`risc0-zkvm` `3.1.0`, `risc0-build` `3.0.7`). The resource logic is unchanged,
but the toolchain and ARM upgrade re-link the guest, so the `ImageID` moves.
RISC Zero `3.1.0` also changes the proof circuits and control root, so receipts
produced by earlier versions must be regenerated, and the deployed verifiers
updated. ARM `2.0.0-rc.9` rotated its own verifying keys too, which the protocol
adapter has to be redeployed against alongside this `ImageID`.

The rotation before that came when the `Migrate` constraint started binding the
trigger resource's `value_ref` to the hash of the migrated nullifiers. That
changed the guest's logic, so the protocol adapter has to be redeployed against
the new value.

Before that, the `2.0.0-rc.4` release bumped `anoma-rm-risc0` /
`anoma-rm-risc0-gadgets` to `2.0.0-rc.8.1`, which renamed `LogicInstance::root`
to `action_tree_root` and re-linked the guest without changing its journal.
