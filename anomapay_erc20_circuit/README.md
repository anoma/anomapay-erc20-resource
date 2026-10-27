# Reproducibly generate proving and verifying keys (ELF and ImageID)

You may generate different ELFs and ImageIDs on different machines and environments. To reproduce the same output and publicly verify that the ELF and ImageID correspond to the circuit source code, use the tool and command below.

## Reproducing the `ANOMAPAY_ERC20_CIRCUIT_ID` committed in `anomapay_erc20_library`

The `ANOMAPAY_ERC20_CIRCUIT_ID` constant in [`anomapay_erc20_library/src/lib.rs`](../anomapay_erc20_library/src/lib.rs) is the `ImageID` of the guest ELF built from this repo at the commit it was last rotated at. To reproduce it, run:

```bash
cargo risczero build --manifest-path anomapay_erc20_circuit/methods/guest/Cargo.toml
```

which reproduces:

```bash
ELFs ready at:
ImageID: 9c7f5feab5f4dc239b5caf180f633e4eac94b5ba6504029abee8d49541f4e026
anomapay_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at `anomapay_erc20_library/elf/anomapay-erc20-circuit-guest.bin` in this repo.

It was last rotated for the `2.0.0-rc.4` release: the `anoma-rm-risc0` /
`anoma-rm-risc0-gadgets` bump to `2.0.0-rc.8.1` renamed `LogicInstance::root` to
`action_tree_root`. That rename does not change the journal the guest commits —
the field order and encoding are identical — but the ARM upgrade re-links the
guest, so the `ImageID` moves regardless. The same release also rotated ARM's own
verifying keys (`COMPLIANCE_VK`, `PADDING_LOGIC_VK`, `BATCH_AGGREGATION_VK`,
`BATCH_AGGREGATION_EVM_VK`), which the protocol adapter has to be redeployed
against alongside this `ImageID`.

## ImageID drift after future changes

Running `cargo risczero build` against a later commit may produce an `ImageID` that no longer matches the committed `ANOMAPAY_ERC20_CIRCUIT_ID`. That's expected whenever a transitive dependency changes without the committed ID being rotated — see below.

### Why the values drift

The `ImageID` is a digest over the entire compiled guest binary, which transitively pins:

- the circuit source in this crate (`anomapay_erc20_circuit`),
- `anomapay_erc20_witness` (the resource-logic/constraint code the guest actually links against — this is a guest dependency; `anomapay_erc20_library` is host-only and is **not** compiled into the guest),
- the ARM libraries (`anoma_rm_risc0`, `anoma_rm_risc0_gadgets`),
- the toolchain and any other transitive dependency.

*Any* change to `anomapay_erc20_witness` — including a version bump that does not touch resource-logic behavior — re-links the guest and produces a new `ImageID`. The same is true for ARM library upgrades. The circuit's own source code can be byte-for-byte identical and the `ImageID` will still change.

### Why we do not bump `ANOMAPAY_ERC20_CIRCUIT_ID` on every rebuild

`ANOMAPAY_ERC20_CIRCUIT_ID` is consumed off-chain (app-level checks) and on-chain (the deployed protocol adapter / verifier contracts). Rotating it requires:

1. redeploying the protocol-adapter contracts on every supported chain, and
2. updating the `ID in PA` reference used by downstream integrations.

We only pay that cost when the **circuit logic itself** changes — i.e., when the proof semantics change. Dependency or toolchain bumps that leave the logic unchanged are intentionally allowed to leave `ANOMAPAY_ERC20_CIRCUIT_ID` and the committed `anomapay-erc20-circuit-guest.bin` on the older build, even though `cargo risczero build` would now produce a different `ImageID`.

If you need the two values to agree (e.g., before a release that does change circuit logic), update both together:

1. Rebuild with the command above.
2. Replace `anomapay_erc20_library/elf/anomapay-erc20-circuit-guest.bin` with the freshly built ELF.
3. Update `ANOMAPAY_ERC20_CIRCUIT_ID` in `anomapay_erc20_library/src/lib.rs` to the new `ImageID`.
4. Coordinate the corresponding protocol-adapter redeployment and PA update.


Note: The unstable feature of risc0-zkvm currently causes issues in circuits. This can be temporarily fixed by manually updating the tool. The problem will be fully resolved in the next release of RISC Zero.

```bash
cargo install --force --git https://github.com/risc0/risc0 --tag v3.0.3 -Fexperimental cargo-risczero
```
