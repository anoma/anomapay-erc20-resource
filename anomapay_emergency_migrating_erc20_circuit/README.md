# Reproducibly generate proving and verifying keys (ELF and ImageID)

```bash
cargo risczero build --manifest-path anomapay_emergency_migrating_erc20_circuit/methods/guest/Cargo.toml
```

which reproduces the `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` committed in
[`anomapay_emergency_migrating_erc20_library/src/lib.rs`](../anomapay_emergency_migrating_erc20_library/src/lib.rs):

```bash
ELFs ready at:
ImageID: 47ab0d901b35909c87c6c08463393205ae42f11ca4af3dd48416606bb02fbcc2
anomapay_emergency_migrating_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-emergency-migrating-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at
`anomapay_emergency_migrating_erc20_library/elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`
in this repo. See [`anomapay_erc20_circuit/README.md`](../anomapay_erc20_circuit/README.md) for why
and when this `ImageID` can drift from a fresh build, and how to rotate it.
