# Reproducibly generate proving and verifying keys (ELF and ImageID)

```bash
cargo risczero build --manifest-path anomapay_emergency_migrating_erc20_circuit/methods/guest/Cargo.toml
```

which reproduces the `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` committed in
[`anomapay_emergency_migrating_erc20_library/src/lib.rs`](../anomapay_emergency_migrating_erc20_library/src/lib.rs):

```bash
ELFs ready at:
ImageID: 1742014631fc2c0bf1433d1ae909358af682df1e7c98d38ef15fb8c8f58709a2
anomapay_emergency_migrating_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-emergency-migrating-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at
`anomapay_emergency_migrating_erc20_library/elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`
in this repo. See [`anomapay_erc20_circuit/README.md`](../anomapay_erc20_circuit/README.md) for why
and when this `ImageID` can drift from a fresh build, and how to rotate it.

It was last rotated for the `2.0.0-rc.3` release: the `anoma-rm-risc0` /
`anoma-rm-risc0-gadgets` bump to `2.0.0-rc.8` reverted the `afterTags` /
`beforeTags` ordering fields on `ForwarderCalldata`, dropping the witness-side
`OrderingInfo` with them — both change the ABI-encoded forwarder calldata the
guest commits to, and the witness layout the guest deserializes.
