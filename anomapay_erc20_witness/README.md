# `anomapay_erc20_witness`

The base witness crate for the **AnomaPay ERC20 transfer resource**. It defines
the data a prover feeds into the RISC Zero guest and the resource-logic
constraint function the guest runs over it. This is the leaf crate of the
workspace — `anomapay_erc20_library` and the circuits all build on it.

It is `no_std`-friendly (depends on `anoma-rm-risc0` with `default-features =
false`) so the same constraint code compiles for both the host and the guest.

## What it provides

### `TokenTransferWitness`
The full set of inputs needed to prove the resource logic of a **single**
consumed or created resource:

| field | purpose |
| --- | --- |
| `resource` | the ARM `Resource` this witness is about |
| `is_consumed` | whether the resource is consumed (nullified) or created (committed) |
| `action_tree_root` | the action tree root that authorization signs over |
| `nf_key` | nullifier key (required for consumed resources) |
| `auth_sig` | authorization signature (required for consumed persistent resources) |
| `encryption_info` | keys/nonce for the resource + discovery ciphertexts |
| `forwarder_info` | EVM forwarder call data (`Wrap`/`Unwrap` + permit + call-ordering tags) |
| `label_info` | forwarder address + ERC20 token address (defines the label) |
| `value_info` | authorization + encryption public keys (defines the value) |

### `LogicCircuit` implementation
`TokenTransferWitness::constrain()` is the function the guest executes. It
branches on the resource kind and enforces the corresponding rules:

- **Ephemeral resource** → validates the label, builds the EVM forwarder
  `Wrap` (consumed) or `Unwrap` (created) calldata, and emits it as the
  `external_payload`.
- **Consumed persistent resource** → verifies the authorization signature over
  the action tree root under the `TokenTransferAuthorization` domain.
- **Created persistent resource** → validates the label, encrypts the resource
  payload for the recipient, and emits the resource + discovery ciphertexts.

It returns the `LogicInstance` (tag, `is_consumed`, root, app data) the guest
commits.

### Solidity ABI encoding ([`call_type.rs`](src/call_type.rs))
`CallType` (`Wrap`/`Unwrap`) plus `encode_wrap_forwarder_input` /
`encode_unwrap_forwarder_input`, which `alloy-sol-types`–encode the EVM
forwarder calldata (including the Permit2 `WrapData`) that the ARM places in the
action's external payload, and `encode_ordering_tags`, which encodes the
`after_tags` / `before_tags` of `OrderingInfo` as the `bytes32` tags
`ForwarderCalldata` carries.

### Call ordering
`ForwarderInfo` carries an optional `OrderingInfo`:

```rust
pub struct OrderingInfo {
    pub after_tags: Vec<Digest>,  // calls that must run before this one
    pub before_tags: Vec<Digest>, // calls that must not run before this one
}
```

A tag in `after_tags` names a resource whose forwarder calls must have run
before this call, one in `before_tags` a resource whose calls must not have.
`ordering_info: None` — the default for every constructor — is an unordered
call, and `ForwarderInfo::with_ordering` (or `TransferLogic::with_ordering` on
the host side) sets it.

Only an ephemeral resource emits a forwarder call: `constrain` builds the
calldata on that path alone, so ordering tags on any other shape would be
dropped. `TransferLogic::with_ordering` therefore returns `Result` and rejects a
non-ephemeral resource or missing forwarder info rather than silently ignoring
the constraint.

## Where it's used

- [`anomapay_erc20_library`](../anomapay_erc20_library) wraps this witness behind
  `TransferLogic` to build proofs on the host.
- [`anomapay_erc20_circuit`](../anomapay_erc20_circuit) reads a `TokenTransferWitness` in
  the guest and calls `constrain()`.

## Testing

```bash
cargo test -p anomapay_erc20_witness
```

The unit tests in [`src/call_type.rs`](src/call_type.rs) exercise the forwarder
calldata encoding.

See the [workspace README](../README.md) for the full picture.
