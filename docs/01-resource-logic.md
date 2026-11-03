# Resource Logic

This document specifies what the ERC20 resource logic checks, what it leaves unchecked, and the reason for each. The code is in [`anomapay_erc20_witness/src/lib.rs`](../anomapay_erc20_witness/src/lib.rs) and [`anomapay_erc20_witness/src/call_type.rs`](../anomapay_erc20_witness/src/call_type.rs). The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. The proof of a resource

`TokenTransferWitness::constrain` proves one ERC20 resource. Its logic instance holds the tag, the side, the action tree root and the app data. The tag is the nullifier of a consumed resource, which needs its nullifier key, or the commitment of a created resource. The application payload is always empty.

The logic has four cases:

| Resource   | Consumed                | Created              |
| ---------- | ----------------------- | -------------------- |
| Ephemeral  | Wrap (section 2)        | Unwrap (section 3)   |
| Persistent | Consumption (section 4) | Creation (section 5) |

## 2. Wrap

In-circuit checks:

- The label ref is the SHA-256 hash of the forwarder address and the token address of the witness.
- The call type of the witness is `Wrap`.
- The external payload has one blob: a call to the forwarder with the input `(Wrap, token, quantity, WrapData)` and an empty expected output, with the deletion criterion `Immediately`. `WrapData` holds the Permit2 nonce and deadline, the owner address, the action tree root of the action, and a signature of 65 bytes.
- The resource payload and the discovery payload are empty.

| Not checked                                                      | Reason                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The Permit2 signature, nonce and deadline, and the owner address | Permit2 checks them on chain when the forwarder calls it, and a wrong value makes the transaction revert. The circuit puts the action tree root of the action into the Permit2 witness, so the signature authorizes the transfer only for this action and for the resources that it creates. |
| An authorization of the ephemeral resource                       | Only the Permit2 signature of the owner can move the tokens.                                                                                                                                                                                                                                 |
| The nullifier key                                                | The ephemeral resource does not exist before the transaction, so the prover chooses all its fields.                                                                                                                                                                                          |

## 3. Unwrap

In-circuit checks:

- The label ref is the SHA-256 hash of the forwarder address and the token address.
- The call type of the witness is `Unwrap`.
- The value ref is the address of the receiver, in the first 20 of its 32 bytes.
- The external payload has one blob: a call to the forwarder with the input `(Unwrap, token, quantity, receiver)` and an empty expected output, with the deletion criterion `Immediately`.
- The resource payload and the discovery payload are empty.

| Not checked                      | Reason                                                                                                                                                                                                                   |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| An authorization of the receiver | The owner of each consumed persistent ERC20 resource signs the action tree root. The root covers the commitment of the ephemeral resource, whose value ref holds the receiver. So the signature authorizes the receiver. |

## 4. Consumption of a persistent resource

In-circuit checks:

- The value ref is the SHA-256 hash of the authorization key and the encryption key of the witness.
- The authorization signature over the action tree root verifies with this authorization key, with the domain `TokenTransferAuthorization`.
- The app data is empty.

| Not checked                           | Reason                                                                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| The label ref                         | The logic checked it when a transaction created the resource, and the commitment fixes it.                                                 |
| The resources that the action creates | The signature covers the action tree root, which covers the tags of all resources of the action. So the owner authorizes the whole action. |

## 5. Creation of a persistent resource

In-circuit checks:

- The label ref is the SHA-256 hash of the forwarder address and the token address.
- The value ref is the SHA-256 hash of the authorization key and the encryption key of the new owner.
- The resource payload is the encryption of the resource, the forwarder address and the token address to the encryption key of the new owner. The circuit encrypts it with the sender key and the nonce of the witness. Its deletion criterion is `Never`.
- The discovery payload is the discovery ciphertext of the witness, with the deletion criterion `Never`.
- The external payload is empty.

| Not checked                             | Reason                                                                                                                                                                                       |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The discovery payload                   | It only lets the owner find the resource faster. A wrong one cannot move tokens or change a resource. The resource payload, which the circuit encrypts itself, carries what the owner needs. |
| The sender key and the encryption nonce | They change only the ciphertext. The circuit encrypts to the encryption key that the value ref commits to.                                                                                   |
| Who the new owner is                    | The owners of the consumed resources sign the action tree root, and a wrap needs the Permit2 signature over it. Both cover the commitment of each created resource.                          |

**Discovery.** The protocol adapter emits the resource payload and the discovery payload of each created persistent ERC20 resource as events, because their deletion criterion is `Never`. The discovery payload is a ciphertext for the discovery key of the owner, which the value ref does not include. The anoma-envio indexer collects these events. With fuzzy message detection, the galileo-indexer returns to a user the resources whose discovery payload fits the key of the user. The user then decrypts their resource payloads with its encryption key. A wrong discovery payload only hides the resource from this search: the owner can still find it by trying to decrypt all resource payloads.

## 6. Checks outside the logic

The logic checks no quantity, and no address beyond the label ref and the receiver of an unwrap. These checks cover the rest:

- **The compliance proof** calculates the commitment, the nullifier and the delta of each resource, and it checks the nonces of the created resources. The delta proof shows that the quantities balance for each kind point.
- **The kind** follows from the logic ref and the label ref. So ERC20 resources of another forwarder or another token have another kind, and they balance with these resources only through an alias of a kind tree.
- **The protocol adapter** rejects a repeated nullifier and a root that is not historical, and it makes the external calls.
- **The ERC20 forwarder** accepts calls only from its protocol adapter and only with its logic ref. Its balance check requires that exactly the quantity moves.
- **Permit2** checks the signature, the nonce and the deadline of a wrap.

## 7. Trust assumptions

- **The owner keeps its keys secret.** A transaction that consumes a persistent ERC20 resource needs its nullifier key and a signature with its authorization key.
- **Only resources of the ERC20 forwarder are backed.** The logic accepts any forwarder address. A contract that acts as a forwarder can accept a wrap without taking tokens. Its resources have their own kind, so they cannot unwrap tokens of the ERC20 forwarder unless a kind tree makes their kinds aliases.

## 8. Parameters

| Name                               | Value                                                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `AUTH_SIGNATURE_DOMAIN`            | `"TokenTransferAuthorization"`                                                                             |
| Label ref                          | `SHA-256(forwarder address ‖ token address)`                                                               |
| Value ref of a persistent resource | `SHA-256(authorization key ‖ encryption key)`                                                              |
| Value ref of an unwrap             | The receiver address, padded with zeros to 32 bytes                                                        |
| Logic ref                          | `ANOMAPAY_ERC20_CIRCUIT_ID` in [`anomapay_erc20_library/src/lib.rs`](../anomapay_erc20_library/src/lib.rs) |
