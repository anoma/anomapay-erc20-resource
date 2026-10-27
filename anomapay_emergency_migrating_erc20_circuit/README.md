# Reproducibly generate proving and verifying keys (ELF and ImageID)

```bash
cargo risczero build --manifest-path anomapay_emergency_migrating_erc20_circuit/methods/guest/Cargo.toml
```

which reproduces the `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` committed in
[`anomapay_emergency_migrating_erc20_library/src/lib.rs`](../anomapay_emergency_migrating_erc20_library/src/lib.rs):

```bash
ELFs ready at:
ImageID: 60931f86d307c92ac22b710fd943811378ff12f249d068028c54d8faf00677c6
anomapay_emergency_migrating_erc20_circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/anomapay-emergency-migrating-erc20-circuit-guest.bin
```

The same value is also embedded as the committed guest binary at
`anomapay_emergency_migrating_erc20_library/elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`
in this repo. See [`anomapay_erc20_circuit/README.md`](../anomapay_erc20_circuit/README.md) for why
and when this `ImageID` can drift from a fresh build, and how to rotate it.

It was last rotated for the `2.0.0-rc.4` release: the `anoma-rm-risc0` /
`anoma-rm-risc0-gadgets` bump to `2.0.0-rc.8.1` renamed `LogicInstance::root` to
`action_tree_root`. That rename does not change the journal the guest commits —
the field order and encoding are identical — but the ARM upgrade re-links the
guest, so the `ImageID` moves regardless. The same release also rotated ARM's own
verifying keys (`COMPLIANCE_VK`, `PADDING_LOGIC_VK`, `BATCH_AGGREGATION_VK`,
`BATCH_AGGREGATION_EVM_VK`), which the protocol adapter has to be redeployed
against alongside this `ImageID`.
