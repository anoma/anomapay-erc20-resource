# Legacy Version

This document specifies the legacy version of the ERC20 resource logic, which the legacy ERC20 forwarder accepts. The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. The legacy version

The legacy ERC20 forwarder accepts the logic ref `bc12323668c37c3d381ca798f11116f35fb1639d12239b29da7810df3985e7ad`. The circuit binary with this logic ref is `transfer_library/elf/token-transfer-guest.bin` at the tag `2.0.0` of this repository. At that tag, the crate `transfer_witness` holds the source of its checks, and the circuit source depends on arm-risc0 `1.1.1`.

## 2. Differences

| Part                      | Legacy version                                                                                                                                                                                  | ERC20 resource logic                                                            |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Checks                    | The checks of [`01-resource-logic.md`](./01-resource-logic.md). The source differs only in the name of one field of the logic instance, `root`, which arm-risc0 later named `action_tree_root`. | [`01-resource-logic.md`](./01-resource-logic.md)                                |
| Crates                    | `transfer_witness`, `transfer_library` and `transfer_circuit`                                                                                                                                   | `anomapay_erc20_witness`, `anomapay_erc20_library` and `anomapay_erc20_circuit` |
| arm-risc0                 | `1.1.1`                                                                                                                                                                                         | `2.0.0-rc.9`                                                                    |
| Logic ref                 | `bc123236…`                                                                                                                                                                                     | `ANOMAPAY_ERC20_CIRCUIT_ID`                                                     |
| Forwarder that accepts it | The legacy ERC20 forwarder                                                                                                                                                                      | The ERC20 forwarder                                                             |

The witness of the ERC20 resource logic also fits the legacy binary. So a prover proves a legacy-forwarder resource with the witness of the ERC20 resource logic and the legacy binary.

## 3. Use after the Galileo upgrade

The owner of the protocol adapter deprecates the legacy logic ref, so no transaction creates resources with it. Transactions can still consume legacy-forwarder resources. A soft migration consumes them with the legacy binary and creates ERC20 resources of the ERC20 resource logic, which a kind tree makes aliases of them.
