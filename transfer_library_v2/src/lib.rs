//! the transfer library contains the definition of the resource logics for the simple transfer
//! application.
//!
//! Of particular interest are the TransferLogicV2 struct, and the TokenTransferWitnessV2 structs.

pub mod migrate_tx;

use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, merkle_path::MerklePath, nullifier_key::NullifierKey,
    resource::Resource,
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use hex::FromHex;
use k256::AffinePoint;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use transfer_witness_v2::{
    ForwarderInfoV2, MigrateEntry, MigrateInfo, TokenTransferWitnessV2, call_type_v2::CallTypeV2,
};

use transfer_witness::{EncryptionInfo, LabelInfo, PermitInfo, ValueInfo};

/// The binary program that is executed in the zkvm to generate proofs.
/// This program takes in a witness as argument and runs the constraint function on it.
pub const TOKEN_TRANSFER_V2_ELF: &[u8] = include_bytes!("../elf/token-transfer-guest-v2.bin");

lazy_static! {
    /// The identity of the binary that executes the proofs in the zkvm.
    pub static ref TOKEN_TRANSFER_V2_ID: Digest =
        Digest::from_hex("5482722fcc17653be77d112484e8d6a7737eb75b60379efe7ce0b78843908132")
            .unwrap();
}

/// Parameters describing one V1 resource being migrated as part of a batch.
/// All entries in a batch must share the same `auth_pk`, since the batch is
/// authorized by a single signature over that key.
pub struct MigrateEntryParams {
    pub resource: Resource,
    pub nf_key: NullifierKey,
    // Merkle path from cm-tree to prove existence of the resource
    pub path: MerklePath,
    pub auth_pk: AuthorityVerifyingKey,
    pub encryption_pk: AffinePoint,
    // forwarder address of the migrated resource
    pub forwarder_addr: Vec<u8>,
}

/// Holds the transfer resource logic.
/// The witness is the input to create a proof. So a TransferLogicV2 can be used to generate proof
/// that the resource logics held within it are actually correct.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct TransferLogicV2 {
    pub witness: TokenTransferWitnessV2,
}

impl TransferLogicV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resource: Resource,
        is_consumed: bool,
        action_tree_root: Digest,
        nf_key: Option<NullifierKey>,
        auth_sig: Option<AuthoritySignature>,
        encryption_info: Option<EncryptionInfo>,
        forwarder_info: Option<ForwarderInfoV2>,
        label_info: Option<LabelInfo>,
        value_info: Option<ValueInfo>,
    ) -> Self {
        Self {
            witness: TokenTransferWitnessV2::new(
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
        let forwarder_info = ForwarderInfoV2 {
            call_type: CallTypeV2::Wrap,
            ethereum_account_addr: Some(ethereum_account_addr),
            permit_info: Some(permit_info),
            migrate_info: None,
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
        let forwarder_info = ForwarderInfoV2 {
            call_type: CallTypeV2::Unwrap,
            ethereum_account_addr: Some(ethereum_account_addr),
            permit_info: None,
            migrate_info: None,
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

    pub fn migrate_resource_logic(
        self_resource: Resource,
        action_tree_root: Digest,
        self_nf_key: NullifierKey,
        // forwarder address v2
        self_forwarder_addr: Vec<u8>,
        erc20_token_addr: Vec<u8>,
        // single signature authorizing the whole batch, over the shared auth_pk
        migrate_auth_sig: AuthoritySignature,
        migrate_entries: Vec<MigrateEntryParams>,
    ) -> Self {
        let label_info = LabelInfo {
            forwarder_addr: self_forwarder_addr,
            erc20_token_addr,
        };

        let entries = migrate_entries
            .into_iter()
            .map(|params| MigrateEntry {
                resource: params.resource,
                nf_key: params.nf_key,
                path: params.path,
                value_info: ValueInfo {
                    auth_pk: params.auth_pk,
                    encryption_pk: params.encryption_pk,
                },
                forwarder_addr: params.forwarder_addr,
            })
            .collect();

        let forwarder_info = ForwarderInfoV2 {
            call_type: CallTypeV2::Migrate,
            ethereum_account_addr: None,
            permit_info: None,
            migrate_info: Some(MigrateInfo {
                auth_sig: migrate_auth_sig,
                entries,
            }),
        };

        Self::new(
            self_resource,
            true,
            action_tree_root,
            Some(self_nf_key),
            None,
            None,
            Some(forwarder_info),
            Some(label_info),
            None,
        )
    }
}

impl LogicProver for TransferLogicV2 {
    type Witness = TokenTransferWitnessV2;
    fn proving_key() -> &'static [u8] {
        TOKEN_TRANSFER_V2_ELF
    }

    fn verifying_key() -> Digest {
        *TOKEN_TRANSFER_V2_ID
    }

    fn witness(&self) -> &Self::Witness {
        &self.witness
    }
}
