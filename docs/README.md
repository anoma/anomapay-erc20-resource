# AnomaPay ERC20 Resource

This folder specifies the resource logics of AnomaPay ERC20 resources. The glossary of this repository, [`CONTEXT.md`](../CONTEXT.md#language), defines the terms.

## 1. Summary

ERC20 tokens in the ERC20 forwarder back each ERC20 resource. The ERC20 resource logic decides when a transaction can create or consume an ERC20 resource:

- A **wrap** consumes an ephemeral ERC20 resource. Its call has the forwarder take tokens from their owner through Permit2.
- A **transfer** consumes persistent ERC20 resources with the signature of their owner, and it creates persistent ERC20 resources for their new owners.
- An **unwrap** creates an ephemeral ERC20 resource. Its call has the forwarder send tokens to a receiver.

The emergency-migrating ERC20 resource logic, a draft, adds the migrate call of a hard migration. The legacy ERC20 forwarder accepts the legacy version of the ERC20 resource logic.

## 2. Documents

| Document                                                                                 | Content                                                                                                             |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| [`01-resource-logic.md`](./01-resource-logic.md)                                         | What the ERC20 resource logic checks for wraps, unwraps and persistent resources, what it leaves unchecked, and why |
| [`02-emergency-migrating-resource-logic.md`](./02-emergency-migrating-resource-logic.md) | The migrate call of the emergency-migrating ERC20 resource logic, a draft                                           |
| [`03-legacy-version.md`](./03-legacy-version.md)                                         | The legacy version, which the legacy ERC20 forwarder accepts                                                        |

Document 03 covers the legacy stack.

## 3. Crates

- `anomapay_erc20_witness` holds the witness `TokenTransferWitness` and its checks, which the circuit runs, and the ABI encoding of the forwarder calls.
- `anomapay_erc20_library` holds the prover `TransferLogic`, the circuit binary, and its image ID `ANOMAPAY_ERC20_CIRCUIT_ID`, which is the logic ref.
- `anomapay_erc20_circuit` holds the source of the circuit binary and the tests of the circuit.
- `anomapay_emergency_migrating_erc20_witness`, `anomapay_emergency_migrating_erc20_library` and `anomapay_emergency_migrating_erc20_circuit` hold the same for the emergency-migrating logic. The library also builds hard migration transactions (`migrate_tx::construct_migrate_tx`).
