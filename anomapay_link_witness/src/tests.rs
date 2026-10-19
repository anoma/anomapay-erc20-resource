//! Native checks of the link constraints. Actions go through the real compliance constraints,
//! so a change to nonce derivation or to the order of the action tree leaves fails here.

use super::*;
use anoma_rm_risc0::{
    action_tree::ActionTree,
    compliance::{self, ComplianceWitness, INITIAL_ROOT},
    resource::ConsumedResourceWitness,
};

fn digest(byte: u8) -> Digest {
    Digest::from_bytes([byte; 32])
}

fn recipient_nk() -> NullifierKeyCommitment {
    NullifierKey::new([41; 32]).commit()
}

/// An order for at least 7 WETH to the recipient.
fn terms(nonce: u8) -> Terms {
    Terms {
        output_logic_ref: digest(2),
        output_label_ref: digest(30),
        recipient_value_ref: digest(40),
        recipient_nk_commitment: recipient_nk(),
        minimum: 7,
        nonce: [nonce; 32],
    }
}

fn link(terms: &Terms) -> Resource {
    Resource {
        logic_ref: digest(1),
        label_ref: terms.label_ref(),
        quantity: 1,
        value_ref: Digest::default(),
        is_ephemeral: true,
        nonce: [0; 32],
        nk_commitment: NullifierKey::default().commit(),
        rand_seed: [0; 32],
    }
}

/// The ephemeral wrap of `quantity` WETH from the generic forwarder.
fn wrap(quantity: u128) -> Resource {
    Resource {
        logic_ref: digest(2),
        label_ref: digest(30),
        quantity,
        value_ref: digest(99),
        is_ephemeral: true,
        nonce: [9; 32],
        nk_commitment: NullifierKey::default().commit(),
        rand_seed: [0; 32],
    }
}

/// `quantity` WETH for the recipient. Its nonce is set when the action is built.
fn output(quantity: u128) -> Resource {
    Resource {
        logic_ref: digest(2),
        label_ref: digest(30),
        quantity,
        value_ref: digest(40),
        is_ephemeral: false,
        nonce: [0; 32],
        nk_commitment: recipient_nk(),
        rand_seed: [5; 32],
    }
}

/// An action whose tree comes from the compliance instance: created nonces are derived as
/// compliance requires, and `compliance::constrain` must accept the unit.
struct Action {
    consumed: Vec<(Resource, NullifierKey)>,
    created: Vec<Resource>,
    nullifiers: Vec<Digest>,
    tree: ActionTree,
}

fn action_with_keys(consumed: Vec<(Resource, NullifierKey)>, created: Vec<Resource>) -> Action {
    let nullifiers: Vec<Digest> = consumed
        .iter()
        .map(|(resource, key)| resource.nullifier(key).unwrap())
        .collect();
    let created: Vec<Resource> = created
        .into_iter()
        .enumerate()
        .map(|(index, resource)| Resource {
            nonce: Resource::derive_nonce_from_nullifiers(index as u32, &nullifiers).unwrap(),
            ..resource
        })
        .collect();
    let witness = ComplianceWitness::from_parts(
        consumed
            .iter()
            .map(|(resource, key)| ConsumedResourceWitness::from_resource(*resource, key.clone()))
            .collect(),
        created.clone(),
        INITIAL_ROOT,
        &[1; 32],
        vec![None; consumed.len() + created.len()],
    );
    let instance = compliance::constrain(&witness).expect("compliance accepts the action");
    Action {
        consumed,
        created,
        nullifiers,
        tree: ActionTree::new(instance.tags().collect()),
    }
}

fn action(consumed: Vec<Resource>, created: Vec<Resource>) -> Action {
    action_with_keys(
        consumed
            .into_iter()
            .map(|resource| (resource, NullifierKey::default()))
            .collect(),
        created,
    )
}

impl Action {
    /// The witness of the link consumed at `link`, claiming the output created at `output`.
    fn fill(&self, link: usize, output: usize, terms: Terms) -> LinkWitness {
        let created = self.created[output];
        let (resource, nf_key) = self.consumed[link].clone();
        LinkWitness {
            resource,
            is_consumed: true,
            action_tree_root: self.tree.root().unwrap(),
            nf_key,
            terms,
            fill: Some(Fill {
                link_path: self.tree.generate_path(&self.nullifiers[link]).unwrap(),
                output: created,
                output_path: self.tree.generate_path(&created.commitment()).unwrap(),
                nullifiers_digest: Resource::hash_nullifiers(&self.nullifiers).unwrap(),
            }),
        }
    }
}

fn rejected(witness: &LinkWitness, reason: &str) {
    assert_eq!(witness.constrain(), Err(failed(reason)));
}

/// The link at leaf 0 is paid by created resource 0.
#[test]
fn fill_at_link_position_passes() {
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![output(7)]);
    let instance = fill.fill(0, 0, terms(11)).constrain().unwrap();
    assert_eq!(instance.tag, fill.nullifiers[0]);
    assert!(instance.is_consumed);
    assert_eq!(instance.root, fill.tree.root().unwrap());
}

#[test]
fn created_link_passes() {
    let witness = LinkWitness {
        resource: link(&terms(11)),
        terms: terms(11),
        ..LinkWitness::default()
    };
    assert!(witness.constrain().is_ok());
}

#[test]
fn link_of_quantity_zero_or_persistent_rejected() {
    for resource in [
        Resource {
            quantity: 0,
            ..link(&terms(11))
        },
        Resource {
            is_ephemeral: false,
            ..link(&terms(11))
        },
    ] {
        let witness = LinkWitness {
            resource,
            terms: terms(11),
            ..LinkWitness::default()
        };
        rejected(&witness, "A link is ephemeral with quantity 1");
    }
}

/// A minimum of 0 would let a quantity-0 output discharge the link.
#[test]
fn zero_minimum_rejected() {
    let free = Terms {
        minimum: 0,
        ..terms(11)
    };
    let witness = LinkWitness {
        resource: link(&free),
        terms: free,
        ..LinkWitness::default()
    };
    rejected(&witness, "Link minimum is zero");
    let fill = action(vec![link(&free), wrap(0)], vec![output(0)]);
    rejected(&fill.fill(0, 0, free), "Link minimum is zero");
}

#[test]
fn other_terms_rejected() {
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![output(7)]);
    rejected(
        &fill.fill(0, 0, terms(12)),
        "Link label does not open to the terms",
    );
}

/// An output to another recipient does not pay.
#[test]
fn other_value_ref_rejected() {
    let paid = Resource {
        value_ref: digest(50),
        ..output(7)
    };
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![paid]);
    rejected(
        &fill.fill(0, 0, terms(11)),
        "Link output has another value_ref",
    );
}

/// The recipient's value_ref with another nullifier key commitment does not pay: nobody could
/// spend it.
#[test]
fn other_nk_commitment_rejected() {
    let paid = Resource {
        nk_commitment: NullifierKey::new([42; 32]).commit(),
        ..output(7)
    };
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![paid]);
    rejected(
        &fill.fill(0, 0, terms(11)),
        "Link output has another nk_commitment",
    );
}

#[test]
fn ephemeral_output_rejected() {
    let paid = Resource {
        is_ephemeral: true,
        ..output(7)
    };
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![paid]);
    rejected(&fill.fill(0, 0, terms(11)), "Link output is ephemeral");
}

#[test]
fn output_below_minimum_rejected() {
    let fill = action(vec![link(&terms(11)), wrap(6)], vec![output(6)]);
    rejected(
        &fill.fill(0, 0, terms(11)),
        "Link output is below the minimum",
    );
}

/// Two links, one output. The link at position 0 is paid; the link at position 1 cannot claim
/// the same output.
#[test]
fn shared_output_rejected() {
    let fill = action(
        vec![link(&terms(11)), link(&terms(12)), wrap(7)],
        vec![output(7)],
    );
    assert!(fill.fill(0, 0, terms(11)).constrain().is_ok());
    rejected(
        &fill.fill(1, 0, terms(12)),
        "Link output is not created at the link's position",
    );
}

#[test]
fn two_outputs_pay_two_links() {
    let fill = action(
        vec![link(&terms(11)), link(&terms(12)), wrap(14)],
        vec![output(7), output(7)],
    );
    assert!(fill.fill(0, 0, terms(11)).constrain().is_ok());
    assert!(fill.fill(1, 1, terms(12)).constrain().is_ok());
}

#[test]
fn crossed_pairing_rejected() {
    let fill = action(
        vec![link(&terms(11)), link(&terms(12)), wrap(14)],
        vec![output(7), output(7)],
    );
    for (link, output, terms) in [(0, 1, terms(11)), (1, 0, terms(12))] {
        rejected(
            &fill.fill(link, output, terms),
            "Link output is not created at the link's position",
        );
    }
}

/// A link is identified by its kind, not by the resource the user created: an ephemeral
/// resource of the same kind, never created and with a key the filler chose, discharges it.
/// Balance still forces one paid consumption per created link.
#[test]
fn any_resource_of_the_kind_discharges_a_link() {
    let filler_key = NullifierKey::new([77; 32]);
    let forged = Resource {
        nonce: [3; 32],
        rand_seed: [4; 32],
        nk_commitment: filler_key.commit(),
        ..link(&terms(11))
    };
    let fill = action_with_keys(
        vec![(forged, filler_key), (wrap(7), NullifierKey::default())],
        vec![output(7)],
    );
    assert!(fill.fill(0, 0, terms(11)).constrain().is_ok());
}

#[test]
fn output_outside_the_action_rejected() {
    let fill = action(vec![link(&terms(11)), wrap(7)], vec![output(7)]);
    let mut witness = fill.fill(0, 0, terms(11));
    if let Some(claim) = witness.fill.as_mut() {
        claim.output.rand_seed = [6; 32];
    }
    rejected(&witness, "Link output is not in the action");
}

#[test]
fn position_reads_the_path() {
    let leaves: Vec<Digest> = (1..=5).map(digest).collect();
    let tree = ActionTree::new(leaves.clone());
    for (index, leaf) in leaves.iter().enumerate() {
        assert_eq!(
            position(&tree.generate_path(leaf).unwrap()),
            Ok(index as u32)
        );
    }
}
