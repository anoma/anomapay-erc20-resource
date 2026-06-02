use crate::TransferLogicV2;
use anoma_rm_risc0::{
    Digest,
    action::Action,
    action_tree::MerkleTree,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::LogicProver,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::Resource,
    transaction::{Delta, Transaction},
};
use anoma_rm_risc0_gadgets::authority::{AuthoritySignature, AuthorityVerifyingKey};
use k256::AffinePoint;

#[allow(clippy::too_many_arguments)]
pub fn construct_migrate_tx(
    // Parameters for the consumed resource
    consumed_resource: Resource,
    latest_cm_tree_root: Digest,
    consumed_nf_key: NullifierKey,
    forwarder_addr: Vec<u8>,
    erc20_token_addr: Vec<u8>,

    // Parameters for migrated resource via forwarder
    migrated_resource: Resource,
    migrated_nf_key: NullifierKey,
    migrated_resource_path: MerklePath,
    migrated_auth_pk: AuthorityVerifyingKey,
    migrated_encryption_pk: AffinePoint,
    migrated_auth_sig: AuthoritySignature,
    migrated_forwarder_addr: Vec<u8>,

    // Parameters for the created resource
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_auth_pk: AuthorityVerifyingKey,
    created_encryption_pk: AffinePoint,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree_root = MerkleTree::new(vec![consumed_nf, created_cm]).root()?;

    // Generate compliance units
    let compliance_witness = ComplianceWitness::from_resources(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key.clone(),
        created_resource,
    );
    let compliance_unit = ComplianceUnit::create(&compliance_witness, ProofType::Groth16)?;

    // Generate logic proofs
    let consumed_resource_logic = TransferLogicV2::migrate_resource_logic(
        consumed_resource,
        action_tree_root,
        consumed_nf_key,
        forwarder_addr.clone(),
        erc20_token_addr.clone(),
        migrated_resource,
        migrated_nf_key,
        migrated_resource_path,
        migrated_auth_pk,
        migrated_encryption_pk,
        migrated_auth_sig,
        migrated_forwarder_addr,
    );
    let consumed_logic_proof = consumed_resource_logic.prove(ProofType::Groth16)?;

    let created_resource_logic = TransferLogicV2::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        created_auth_pk,
        created_encryption_pk,
        forwarder_addr,
        erc20_token_addr,
    );
    let created_logic_proof = created_resource_logic.prove(ProofType::Groth16)?;

    // Construct the action
    let action = Action::new(
        vec![compliance_unit],
        vec![consumed_logic_proof, created_logic_proof],
    )?;

    // Construct the transaction
    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv)?;
    let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    let balanced_tx = tx.generate_delta_proof().unwrap();
    Ok(balanced_tx)
}

#[test]
#[cfg(not(target_os = "macos"))]
fn simple_migrate_test() {
    use anoma_rm_risc0::{
        compliance::INITIAL_ROOT, nullifier_key::NullifierKey, resource::Resource,
    };
    use anoma_rm_risc0_gadgets::{
        authority::{AuthoritySigningKey, AuthorityVerifyingKey},
        encryption::random_keypair,
    };
    use transfer_witness::ValueInfo;
    use transfer_witness::{calculate_label_ref, calculate_persistent_value_ref};
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    // Common parameters
    let forwarder_addr_v1 = vec![0u8; 20];
    let logic_ref_v1 = Digest::default();
    let forwarder_addr_v2 = vec![1u8; 20];
    let erc20_token_addr = vec![2u8; 20];
    let quantity = 100;
    let label_ref = calculate_label_ref(&forwarder_addr_v1, &erc20_token_addr);
    let label_ref_v2 = calculate_label_ref(&forwarder_addr_v2, &erc20_token_addr);

    // Construct the migrated resource
    let migrated_auth_sk = AuthoritySigningKey::from_bytes(&[9u8; 32]).unwrap();
    let migrated_auth_pk = AuthorityVerifyingKey::from_signing_key(&migrated_auth_sk);
    let (_migrated_encryption_sk, migrated_encryption_pk) = random_keypair();
    let migrated_nf_key = NullifierKey::default();
    let migrated_nf_cm = migrated_nf_key.commit();
    let value_info = ValueInfo {
        auth_pk: migrated_auth_pk,
        encryption_pk: migrated_encryption_pk,
    };
    let migrated_value_ref = calculate_persistent_value_ref(&value_info);
    let migrated_resource = Resource {
        logic_ref: logic_ref_v1,
        nk_commitment: migrated_nf_cm,
        label_ref,
        value_ref: migrated_value_ref,
        quantity,
        is_ephemeral: false,
        ..Default::default()
    };

    let migrated_cm = migrated_resource.commitment();
    println!("Migrated resource cm: {:?}", migrated_cm);

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = NullifierKey::random_pair();
    let consumed_resource = Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        label_ref: label_ref_v2,
        nk_commitment: consumed_nf_cm,
        quantity,
        is_ephemeral: true,
        ..Default::default()
    };

    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = *INITIAL_ROOT;

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = NullifierKey::random_pair();
    let created_auth_sk = AuthoritySigningKey::new();
    let created_auth_pk = AuthorityVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let value_info = ValueInfo {
        auth_pk: created_auth_pk,
        encryption_pk: created_encryption_pk,
    };
    let created_resource = Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        nk_commitment: created_nf_cm,
        label_ref: label_ref_v2,
        value_ref: calculate_persistent_value_ref(&value_info),
        quantity,
        is_ephemeral: false,
        nonce: consumed_nf.as_bytes().try_into().unwrap(),
        ..Default::default()
    };

    let created_cm = created_resource.commitment();

    // Generate the authorization signature
    let action_tree = MerkleTree::new(vec![consumed_nf, created_cm]);
    let migrated_auth_sig = migrated_auth_sk.sign(
        AUTH_SIGNATURE_DOMAIN_V2,
        action_tree.root().unwrap().as_bytes(),
    );

    // Construct the migration transaction
    let tx_start_timer = std::time::Instant::now();
    let tx = construct_migrate_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        forwarder_addr_v2,
        erc20_token_addr,
        migrated_resource,
        migrated_nf_key,
        MerklePath::from_path(&[]), // dummy path
        migrated_auth_pk,
        migrated_encryption_pk,
        migrated_auth_sig,
        forwarder_addr_v1,
        created_resource,
        created_discovery_pk,
        created_auth_pk,
        created_encryption_pk,
    )
    .unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // Verify the transaction
    tx.verify().unwrap();
}
