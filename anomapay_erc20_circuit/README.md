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
ImageID: 51c2403f4e1de40c3c3ecef69385f8772ee99b4a610e88f1ad2b1b85b481a7f2
anomapay_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at `anomapay_erc20_library/elf/anomapay-erc20-circuit-guest.bin` in this repo.

## ImageID drift after future changes

Running `cargo risczero build` against a later commit may produce an `ImageID` that no longer matches the committed `ANOMAPAY_ERC20_CIRCUIT_ID`. That's expected whenever a transitive dependency changes without the committed ID being rotated — see below.

### Why the values drift

The `ImageID` is a digest over the entire compiled guest binary, which transitively pins:

- the circuit source in this crate (`anomapay_erc20_circuit`),
- `anomapay_erc20_library` (the resource-logic definitions shared with the host/backend),
- the ARM libraries (`anoma_rm_risc0`, `anoma_rm_risc0_gadgets`, `anomapay_erc20_witness`, …),
- the toolchain and any other transitive dependency.

Because `anomapay_erc20_library` is shared by both the guest circuit and the host/backend, *any* change to it — including a version bump that does not touch resource-logic behavior — re-links the guest and produces a new `ImageID`. The same is true for ARM library upgrades. The circuit's own source code can be byte-for-byte identical and the `ImageID` will still change.

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
