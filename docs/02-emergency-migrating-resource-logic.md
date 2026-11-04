# Emergency-Migrating Resource Logic (Draft)

**Status: draft.** No deployed forwarder accepts its logic ref.

This document specifies the emergency-migrating ERC20 resource logic, which a hard migration uses. The code is in [`anomapay_emergency_migrating_erc20_witness/src/lib.rs`](../anomapay_emergency_migrating_erc20_witness/src/lib.rs) and [`anomapay_emergency_migrating_erc20_witness/src/call_type.rs`](../anomapay_emergency_migrating_erc20_witness/src/call_type.rs). The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. Differences to the ERC20 resource logic

The logic makes the checks of [`01-resource-logic.md`](./01-resource-logic.md) for wraps, unwraps and persistent resources, with these differences:

- Its authorization signatures use the domain `TokenTransferAuthorizationEmergencyMigrating`.
- A consumed ephemeral resource can also have a third call type, `Migrate`. Such a resource is the **trigger** of a hard migration.

The call type decides the side: a wrap and a trigger must be consumed, and an unwrap must be created.

## 2. The trigger

The witness of a trigger holds a batch of old resources, and for each one its nullifier key, the Merkle path of its commitment, the keys of its owner and the address of its forwarder. In-circuit checks:

- The label ref of the trigger is the SHA-256 hash of the forwarder address and the token address.
- The batch is not empty.
- Each old resource is persistent, and its value ref is the SHA-256 hash of its authorization key and its encryption key.
- Each old resource has the authorization key of the first old resource.
- The label ref of each old resource is the SHA-256 hash of the forwarder address of its entry and the token address of the trigger.
- The circuit calculates the commitment of each old resource, its commitment tree root from the Merkle path, and its nullifier from the nullifier key, which must match the commitment to the nullifier key.
- The quantities of the old resources add up to the quantity of the trigger, without overflow.
- One authorization signature over the action tree root verifies with the authorization key of the batch.
- The external payload has one blob: a call to the forwarder with the call type `Migrate`, the token, the total quantity and one `MigrateEntry` for each old resource, and an empty expected output, with the deletion criterion `Immediately`. Each entry holds the nullifier, the commitment tree root, the logic ref and the forwarder address of one old resource.

So the proof shows that the owner knows the keys of the old resources and signs the action. The action tree root covers the resources that the action creates, so the signature also selects who receives the new resources.

| Not checked                                                                            | Reason                                                                                                                                                              |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Whether the commitment tree root is a historical root                                  | The circuit has no state. The forwarder makes this out-of-circuit check against the protocol adapter.                                                               |
| Whether a transaction consumed an old resource, or a hard migration replaced it before | The forwarder checks the nullifier against the nullifier set of the protocol adapter and against its own set, and it stores the nullifier.                          |
| The logic ref of each old resource                                                     | The forwarder accepts only the logic refs that it lists as vulnerable.                                                                                              |
| The forwarder address of each old resource                                             | The forwarder accepts only its own address and the address of the legacy ERC20 forwarder.                                                                           |
| Several owners in one batch                                                            | One signature authorizes the whole batch, so all old resources must have one authorization key. A user with resources of several keys makes one batch for each key. |

A flaw can forge old resources, and the state cannot show the difference between forged and correct ones. So forged old resources can also migrate.

## 3. Trust assumptions

- **The forwarder makes the state checks.** Without them, a prover could migrate a resource that does not exist, or one that a transaction consumed.

## 4. Parameters

| Name                                        | Value                                                                                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN` | `"TokenTransferAuthorizationEmergencyMigrating"`                                                                                                                       |
| Logic ref                                   | `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` in [`anomapay_emergency_migrating_erc20_library/src/lib.rs`](../anomapay_emergency_migrating_erc20_library/src/lib.rs) |
