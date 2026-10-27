//! The AnomaPay link witness crate holds the witness and the resource-logic constraints of a
//! link: an ephemeral resource whose label commits to the terms of an order.
//!
//! The user's action creates the link. The delta is summed over all actions of a transaction,
//! so the transaction balances only if some action consumes it. When a link is consumed, its
//! logic requires the resource created at the link's own position in that action to pay the
//! terms: a persistent resource of the output kind, owned by the recipient, with at least the
//! minimum quantity.
//!
//! The position pairing keeps one output from paying two links. The logic reads the link's
//! position from its leaf in the action tree and compares the output's nonce with
//! `Resource::derive_nonce(position, H(nullifiers))`. Compliance enforces that nonce for the
//! resource created at that index among the created resources, so no other resource of the
//! action can carry it. Distinct links sit at distinct leaves, so they need distinct outputs.
//! This holds for any order of the consumed and created resources in the action's list.
//!
//! A link expires at the deadline in its terms. When a link is created, its logic emits one
//! forwarder call to a `BlockTimeForwarder` and expects the answer that the deadline is still
//! ahead. The protocol adapter reverts when a call's output differs from the expected one, so
//! from the deadline on, every transaction with the user's action reverts.
//!
//! A link is identified by its kind, not by the resource the user created. Consuming an
//! ephemeral resource needs no membership proof, so a filler can discharge the link with any
//! resource of its kind and any nullifier key. Balance ties the two: each created link forces
//! one consumption of its kind, and each consumption must pay.

pub use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0::{
    Digest,
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
    utils::{bytes_to_words, hash_bytes},
};
use anoma_rm_risc0_gadgets::evm::ForwarderCalldata;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Domain separator of the label hash.
pub const LABEL_DOMAIN: &[u8] = b"AnomaPayLinkTermsV1";

/// `TimeComparison.GT`, the answer of `BlockTimeForwarder` while the deadline is ahead.
pub const DEADLINE_AHEAD: u8 = 2;

/// What a link commits to in its label.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// Logic reference of the output kind.
    pub output_logic_ref: Digest,
    /// Label reference of the output kind.
    pub output_label_ref: Digest,
    /// Value reference of the recipient, for a token `H(auth_pk, encryption_pk)`.
    pub recipient_value_ref: Digest,
    /// Nullifier key commitment of the recipient.
    pub recipient_nk_commitment: NullifierKeyCommitment,
    /// Least quantity the output must have.
    pub minimum: u128,
    /// Unix time from which the order can no longer be filled. It must fit in `uint48`.
    pub deadline: u64,
    /// Address of the `BlockTimeForwarder` that checks the deadline.
    pub time_forwarder: [u8; 20],
    /// Keeps the label of one order apart from another's with equal terms.
    pub nonce: [u8; 32],
}

impl Terms {
    /// The label reference of a link with these terms. Every field has a fixed width, so the
    /// encoding is injective and the hash binds the terms.
    pub fn label_ref(&self) -> Digest {
        hash_bytes(
            &[
                LABEL_DOMAIN,
                self.output_logic_ref.as_bytes(),
                self.output_label_ref.as_bytes(),
                self.recipient_value_ref.as_bytes(),
                self.recipient_nk_commitment.as_bytes(),
                &self.minimum.to_be_bytes(),
                &self.deadline.to_be_bytes(),
                &self.time_forwarder,
                &self.nonce,
            ]
            .concat(),
        )
    }

    /// The forwarder call that keeps the order open until its deadline: `BlockTimeForwarder`
    /// decodes `abi.encode(uint48 deadline)` and must answer `abi.encode(TimeComparison.GT)`,
    /// which holds while `block.timestamp < deadline`.
    pub fn deadline_call(&self) -> ExpirableBlob {
        let mut input = [0u8; 32];
        input[24..].copy_from_slice(&self.deadline.to_be_bytes());
        let mut output = [0u8; 32];
        output[31] = DEADLINE_AHEAD;
        let call =
            ForwarderCalldata::from_bytes(&self.time_forwarder, input.to_vec(), output.to_vec());
        ExpirableBlob {
            blob: bytes_to_words(&call.encode()),
            // Deleted immediately: the blob is only needed to make the call.
            deletion_criterion: 0,
        }
    }

    /// Checks that `output` pays the terms. Consuming a persistent token takes a signature by
    /// the key behind its value reference and the nullifier key behind its commitment, so both
    /// are checked: an output that matches only one of them can be one nobody can spend.
    pub fn check_pays(&self, output: &Resource) -> Result<(), ArmError> {
        if output.is_ephemeral {
            return Err(failed("Link output is ephemeral"));
        }
        if output.logic_ref != self.output_logic_ref || output.label_ref != self.output_label_ref {
            return Err(failed("Link output has another kind"));
        }
        if output.value_ref != self.recipient_value_ref {
            return Err(failed("Link output has another value_ref"));
        }
        if output.nk_commitment != self.recipient_nk_commitment {
            return Err(failed("Link output has another nk_commitment"));
        }
        if output.quantity < self.minimum {
            return Err(failed("Link output is below the minimum"));
        }
        Ok(())
    }
}

/// What the action that consumes a link shows about the output that pays it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fill {
    /// Path of the link's nullifier to the action tree root. Its leaf position is the index of
    /// the created resource that pays the link.
    pub link_path: MerklePath,
    /// The created resource that pays the terms.
    pub output: Resource,
    /// Path of the output's commitment to the action tree root.
    pub output_path: MerklePath,
    /// `H(nullifiers)` of the action's consumed resources, in order.
    pub nullifiers_digest: Digest,
}

/// The witness of a link's logic proof.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LinkWitness {
    /// The link.
    pub resource: Resource,
    /// Whether the link is consumed or created.
    pub is_consumed: bool,
    /// Root of the link's action tree.
    pub action_tree_root: Digest,
    /// Nullifier key of the link. It carries no authority: any resource of the link's kind
    /// discharges the link, with whatever key the filler chooses.
    pub nf_key: NullifierKey,
    /// The terms the label opens to.
    pub terms: Terms,
    /// Present when the link is consumed.
    pub fill: Option<Fill>,
}

impl LogicCircuit for LinkWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        let tag = self.resource.tag(self.is_consumed, &self.nf_key)?;

        // Quantity 1 makes "the delta forces a consumption" hold: a link of quantity 0 would
        // balance without one.
        if !self.resource.is_ephemeral || self.resource.quantity != 1 {
            return Err(failed("A link is ephemeral with quantity 1"));
        }
        if self.resource.label_ref != self.terms.label_ref() {
            return Err(failed("Link label does not open to the terms"));
        }
        // A minimum of 0 would let a quantity-0 output discharge the link.
        if self.terms.minimum == 0 {
            return Err(failed("Link minimum is zero"));
        }
        // `BlockTimeForwarder` would revert on a wider deadline, and the order could never be
        // filled.
        if self.terms.deadline >= 1 << 48 {
            return Err(failed("Link deadline does not fit in uint48"));
        }

        let mut app_data = AppData::default();
        if self.is_consumed {
            let fill = self.fill.as_ref().ok_or(ArmError::MissingField("Fill"))?;
            if fill.link_path.root(&tag) != self.action_tree_root {
                return Err(failed("Link path does not reach the action tree root"));
            }
            if fill.output_path.root(&fill.output.commitment()) != self.action_tree_root {
                return Err(failed("Link output is not in the action"));
            }
            let position = position(&fill.link_path)?;
            if fill.output.nonce != Resource::derive_nonce(position, fill.nullifiers_digest) {
                return Err(failed("Link output is not created at the link's position"));
            }
            self.terms.check_pays(&fill.output)?;
        } else {
            // The created link sits in the user's action, so every transaction with that
            // action makes the call.
            app_data.external_payload.push(self.terms.deadline_call());
        }

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed,
            root: self.action_tree_root,
            app_data,
        })
    }
}

/// The leaf position a path opens. A step's flag is set when the sibling is on the left, that is
/// when the node is a right child.
pub fn position(path: &MerklePath) -> Result<u32, ArmError> {
    if path.len() > 32 {
        return Err(failed("Link path is too long"));
    }
    Ok(path
        .0
        .iter()
        .enumerate()
        .fold(0, |position, (depth, (_, right))| {
            position | (u32::from(*right) << depth)
        }))
}

fn failed(reason: &str) -> ArmError {
    ArmError::ProveFailed(reason.to_string())
}
