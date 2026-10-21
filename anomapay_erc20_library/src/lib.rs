//! The AnomaPay ERC20 library crate contains the host-side proving API for the simple transfer
//! resource logic.
//!
//! Of particular interest are the TransferLogic struct, and the TokenTransferWitness structs.

use anoma_rm_risc0::{
    Digest, error::ArmError, logic_proof::LogicProver, nullifier_key::NullifierKey,
    resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use hex::FromHex;
use k256::AffinePoint;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use anomapay_erc20_witness::{
    EncryptionInfo, ForwarderInfo, LabelInfo, PermitInfo, TokenTransferWitness, ValueInfo,
    call_type::CallType,
};

/// The binary program that is executed in the zkvm to generate proofs.
/// This program takes in a witness as argument and runs the constraint function on it.
pub const ANOMAPAY_ERC20_CIRCUIT_ELF: &[u8] =
    include_bytes!("../elf/anomapay-erc20-circuit-guest.bin");

lazy_static! {
    /// The identity of the binary that executes the proofs in the zkvm.
    pub static ref ANOMAPAY_ERC20_CIRCUIT_ID: Digest =
        Digest::from_hex("533868e294fc632d1809edb4875d6a084746817b230e95351845d175449f2404")
            .unwrap();
}

/// Holds the transfer resource logic.
/// The witness is the input to create a proof. So a TransferLogic can be used to generate proof
/// that the resource logics held within it are actually correct.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogic {
    pub witness: TokenTransferWitness,
}

impl TransferLogic {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<NullifierKey>,
        auth_sig: Option<AuthoritySignature>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfo>,
        label_info: Option<LabelInfo>,
        value_info: Option<ValueInfo>,
    ) -> Self {
        Self {
            witness: TokenTransferWitness::new(
                resource,
                is_consumed,
                action_tree_root,
                nf_key,
                auth_sig,
                encryption_info,
                forwarder_info,
                label_info,
                value_info,
            ),
        }
    }

    /// Creates resource logic for a created resource.
    pub fn consume_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        auth_pk: AuthorityVerifyingKey,
        encryption_pk: AffinePoint,
        auth_sig: AuthoritySignature,
    ) -> Self {
        let value_info = ValueInfo {
            auth_pk,
            encryption_pk,
        };
        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            Some(auth_sig),
            None,
            None,
            None,
            Some(value_info),
        )
    }
    /// Creates a resource logic for a resource that is created during minting, transfer, etc.
    pub fn create_persistent_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        discovery_pk: &AffinePoint,
        auth_pk: AuthorityVerifyingKey,
        encryption_pk: AffinePoint,
        forwarder_address: Vec<u8>,
        erc20_token_addr: Vec<u8>,
    ) -> Self {
        let encryption_info = EncryptionInfo::new(discovery_pk);
        let label_info = LabelInfo {
            forwarder_addr: forwarder_address,
            erc20_token_addr,
        };
        let value_info = ValueInfo {
            auth_pk,
            encryption_pk,
        };
        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            Some(encryption_info),
            None,
            Some(label_info),
            Some(value_info),
        )
    }

    /// Creates a resource logic for an ephemeral resource created during minting.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_resource_logic_with_permit(
        resource: Resource,
        action_tree_root: Digest,
        nf_key: NullifierKey,
        forwarder_addr: Vec<u8>,
        erc20_token_addr: Vec<u8>,
        ethereum_account_addr: Vec<u8>,
        permit_nonce: Vec<u8>,
        permit_deadline: Vec<u8>,
        permit_sig: Vec<u8>,
    ) -> Self {
        let permit_info = PermitInfo {
            permit_nonce,
            permit_deadline,
            permit_sig,
        };
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Wrap,
            ethereum_account_addr,
            permit_info: Some(permit_info),
            ordering_info: None,
        };
        let label_info = LabelInfo {
            forwarder_addr,
            erc20_token_addr,
        };

        Self::new(
            resource,
            true,
            action_tree_root,
            Some(nf_key),
            None,
            None,
            Some(forwarder_info),
            Some(label_info),
            None,
        )
    }

    /// Creates a resource logic for a resource that is created when burning a resource.
    pub fn burn_resource_logic(
        resource: Resource,
        action_tree_root: Digest,
        forwarder_addr: Vec<u8>,
        erc20_token_addr: Vec<u8>,
        ethereum_account_addr: Vec<u8>,
    ) -> Self {
        let forwarder_info = ForwarderInfo {
            call_type: CallType::Unwrap,
            ethereum_account_addr,
            permit_info: None,
            ordering_info: None,
        };
        let label_info = LabelInfo {
            forwarder_addr,
            erc20_token_addr,
        };

        Self::new(
            resource,
            false,
            action_tree_root,
            None,
            None,
            None,
            Some(forwarder_info),
            Some(label_info),
            None,
        )
    }

    /// Constrains when this resource's forwarder call runs relative to the calls of other
    /// resources: a tag in `after_tags` names a resource whose calls must have run already,
    /// a tag in `before_tags` one whose calls must not have.
    ///
    /// Only the ephemeral wrap/unwrap legs carry a forwarder call: `constrain` emits an
    /// external payload for an ephemeral resource only, and reads the forwarder info solely
    /// on that path. Ordering a logic that will emit no forwarder call is a mistake with no
    /// safe reading — the constraint could only be dropped — so both a non-ephemeral resource
    /// and missing forwarder info are rejected rather than ignored.
    pub fn with_ordering(
        mut self,
        after_tags: Vec<Digest>,
        before_tags: Vec<Digest>,
    ) -> Result<Self, ArmError> {
        if !self.witness.resource.is_ephemeral {
            return Err(ArmError::ProveFailed(
                "Only an ephemeral resource carries a forwarder call to order".to_string(),
            ));
        }
        let forwarder_info = self
            .witness
            .forwarder_info
            .take()
            .ok_or(ArmError::MissingField("Forwarder info"))?;
        self.witness.forwarder_info = Some(forwarder_info.with_ordering(after_tags, before_tags));
        Ok(self)
    }
}

impl LogicProver for TransferLogic {
    type Witness = TokenTransferWitness;
    fn proving_key() -> &'static [u8] {
        ANOMAPAY_ERC20_CIRCUIT_ELF
    }

    fn verifying_key() -> Digest {
        *ANOMAPAY_ERC20_CIRCUIT_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ephemeral_resource() -> Resource {
        Resource {
            is_ephemeral: true,
            ..Resource::default()
        }
    }

    // Note `Resource::default()` is ephemeral, so a persistent resource must say so.
    fn persistent_resource() -> Resource {
        Resource {
            is_ephemeral: false,
            ..Resource::default()
        }
    }

    /// The ephemeral unwrap (burn) leg: the only shape whose `constrain` emits a
    /// forwarder call for the ordering tags to ride on.
    fn burn_logic(resource: Resource) -> TransferLogic {
        TransferLogic::burn_resource_logic(
            resource,
            Digest::default(),
            vec![0u8; 20],
            vec![1u8; 20],
            vec![2u8; 20],
        )
    }

    #[test]
    fn with_ordering_sets_the_tags_on_an_ephemeral_forwarder_leg() {
        let after = Digest::new([1u32; 8]);
        let before = Digest::new([2u32; 8]);

        let logic = burn_logic(ephemeral_resource())
            .with_ordering(vec![after], vec![before])
            .unwrap();

        let forwarder_info = logic.witness.forwarder_info.as_ref().unwrap();
        let ordering_info = forwarder_info.ordering_info.as_ref().unwrap();
        assert_eq!(ordering_info.after_tags, vec![after]);
        assert_eq!(ordering_info.before_tags, vec![before]);
    }

    #[test]
    fn with_ordering_is_rejected_on_a_persistent_resource_with_forwarder_info() {
        // Forwarder info alone does not mean a forwarder call: `constrain` emits an
        // external payload only for an ephemeral resource, so the tags would be dropped.
        let logic = burn_logic(persistent_resource());
        assert!(logic.witness.forwarder_info.is_some());

        assert!(matches!(
            logic.with_ordering(vec![Digest::new([1u32; 8])], vec![]),
            Err(ArmError::ProveFailed(_))
        ));
    }

    #[test]
    fn with_ordering_is_rejected_without_forwarder_info() {
        // An ephemeral resource, so only the missing forwarder info can reject it.
        let logic = TransferLogic::new(
            ephemeral_resource(),
            false,
            Digest::default(),
            None,
            None,
            None,
            None,
            None,
            None,
        );

        assert!(matches!(
            logic.with_ordering(vec![Digest::new([1u32; 8])], vec![]),
            Err(ArmError::MissingField("Forwarder info"))
        ));
    }
}
