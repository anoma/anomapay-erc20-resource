use crate::{EmergencyMigratingTransferLogic, MigrateEntryParams};
use anoma_rm_risc0::{
    Digest, action,
    action_tree::ActionTree,
    compliance, compliance_unit,
    delta_proof::DeltaWitness,
    error::ArmError,
    logic_proof::LogicProver,
    nullifier_key::NullifierKey,
    proving_system::ProofType,
    resource::{ConsumedResourceWitness, Resource},
    transaction::{self, Delta, Transaction},
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

    // Single signature authorizing the whole batch, over the auth_pk shared by
    // every entry below.
    migrate_auth_sig: AuthoritySignature,
    // Batch of resources being migrated by the consumed (trigger) resource.
    migrate_entries: Vec<MigrateEntryParams>,

    // Parameters for the created resource
    created_resource: Resource,
    created_discovery_pk: AffinePoint,
    created_auth_pk: AuthorityVerifyingKey,
    created_encryption_pk: AffinePoint,
) -> Result<Transaction, ArmError> {
    // Action tree
    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key)?;
    let created_cm = created_resource.commitment();
    let action_tree_root = ActionTree::new(vec![consumed_nf, created_cm]).root()?;

    // Generate compliance units
    let consumed_resource_witness =
        ConsumedResourceWitness::from_resource(consumed_resource, consumed_nf_key.clone());
    let compliance_witness = compliance::from_resources_with_ephemeral_root(
        vec![consumed_resource_witness],
        vec![created_resource],
        latest_cm_tree_root,
        vec![],
    );
    let compliance_unit = compliance_unit::create(&compliance_witness, ProofType::Groth16)?;

    // Generate logic proofs
    let consumed_resource_logic = EmergencyMigratingTransferLogic::migrate_resource_logic(
        consumed_resource,
        action_tree_root,
        consumed_nf_key,
        forwarder_addr.clone(),
        erc20_token_addr.clone(),
        migrate_auth_sig,
        migrate_entries,
    );
    let consumed_logic_proof = consumed_resource_logic.prove(ProofType::Groth16)?;

    let created_resource_logic = EmergencyMigratingTransferLogic::create_persistent_resource_logic(
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
    let action = action::new(
        compliance_unit,
        vec![consumed_logic_proof, created_logic_proof],
    )?;

    // Construct the transaction
    let delta_witness = DeltaWitness::from_bytes(&compliance_witness.rcv)?;
    let tx = Transaction::create(vec![action], Delta::Witness(delta_witness));
    let balanced_tx = transaction::generate_delta_proof(tx).unwrap();
    Ok(balanced_tx)
}

#[test]
#[cfg(not(target_os = "macos"))]
fn simple_migrate_test() {
    use anoma_rm_risc0::{
        compliance::INITIAL_ROOT,
        constants::{init_kind_table_from_file, kind_table_hash},
        merkle_path::MerklePath,
        nullifier_key::{self, NullifierKey},
        proving_system::JournalEncoding,
        resource::Resource,
        transaction,
    };
    use anoma_rm_risc0_gadgets::{
        authority::{AuthoritySigningKey, AuthorityVerifyingKey},
        encryption::random_keypair,
    };
    use emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN;
    use transfer_witness::ValueInfo;
    use transfer_witness::{calculate_label_ref, calculate_persistent_value_ref};

    // The transaction carries an empty kind table (no precomputed kind
    // points), so `Transaction::verify` needs the global table initialized
    // to the same empty set before it will accept the commitment.
    let kind_table_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("kind_table.json");
    init_kind_table_from_file(&kind_table_path).unwrap();

    // Common parameters. Two migrated resources, each from a different
    // forwarder deployment, but sharing one erc20 token address.
    let forwarder_addr_v1_a = vec![0u8; 20];
    let forwarder_addr_v1_b = vec![10u8; 20];
    let logic_ref_v1 = Digest::default();
    let forwarder_addr_v2 = vec![1u8; 20];
    let erc20_token_addr = vec![2u8; 20];
    let quantity_a = 60;
    let quantity_b = 40;
    let label_ref_v1_a = calculate_label_ref(&forwarder_addr_v1_a, &erc20_token_addr);
    let label_ref_v1_b = calculate_label_ref(&forwarder_addr_v1_b, &erc20_token_addr);
    let label_ref_v2 = calculate_label_ref(&forwarder_addr_v2, &erc20_token_addr);

    // Single authority shared by every entry in the batch: the batch is
    // authorized by one signature over this key.
    let migrated_auth_sk = AuthoritySigningKey::from_bytes(&[9u8; 32]).unwrap();
    let migrated_auth_pk = AuthorityVerifyingKey::from_signing_key(&migrated_auth_sk);

    // Construct the batch of migrated resources.
    let mut migrate_entries = Vec::new();
    for (forwarder_addr_v1, label_ref, quantity, seed) in [
        (forwarder_addr_v1_a.clone(), label_ref_v1_a, quantity_a, 9u8),
        (
            forwarder_addr_v1_b.clone(),
            label_ref_v1_b,
            quantity_b,
            19u8,
        ),
    ] {
        let (_migrated_encryption_sk, migrated_encryption_pk) = random_keypair();
        let migrated_nf_key = NullifierKey::from_bytes([seed; 32]);
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

        migrate_entries.push(MigrateEntryParams {
            resource: migrated_resource,
            nf_key: migrated_nf_key,
            path: MerklePath::from_path(&[]), // dummy path
            auth_pk: migrated_auth_pk,
            encryption_pk: migrated_encryption_pk,
            forwarder_addr: forwarder_addr_v1,
        });
    }
    let total_quantity = quantity_a + quantity_b;

    // Construct the consumed resource
    let (consumed_nf_key, consumed_nf_cm) = nullifier_key::random_pair();
    let consumed_resource = Resource {
        logic_ref: EmergencyMigratingTransferLogic::verifying_key(),
        label_ref: label_ref_v2,
        nk_commitment: consumed_nf_cm,
        quantity: total_quantity,
        is_ephemeral: true,
        ..Default::default()
    };

    let consumed_nf = consumed_resource.nullifier(&consumed_nf_key).unwrap();
    // Fetch the latest cm tree root from the chain
    let latest_cm_tree_root = INITIAL_ROOT;

    // Generate the created resource
    let (_created_nf_key, created_nf_cm) = nullifier_key::random_pair();
    let created_auth_sk = AuthoritySigningKey::new();
    let created_auth_pk = AuthorityVerifyingKey::from_signing_key(&created_auth_sk);
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let (_created_encryption_sk, created_encryption_pk) = random_keypair();
    let value_info = ValueInfo {
        auth_pk: created_auth_pk,
        encryption_pk: created_encryption_pk,
    };
    let created_resource = Resource {
        logic_ref: EmergencyMigratingTransferLogic::verifying_key(),
        nk_commitment: created_nf_cm,
        label_ref: label_ref_v2,
        value_ref: calculate_persistent_value_ref(&value_info),
        quantity: total_quantity,
        is_ephemeral: false,
        nonce: Resource::derive_nonce_from_nullifiers(0, &[consumed_nf]).unwrap(),
        ..Default::default()
    };

    let created_cm = created_resource.commitment();

    // Generate the authorization signature, now that the action tree root is known.
    let action_tree = ActionTree::new(vec![consumed_nf, created_cm]);
    let action_root = action_tree.root().unwrap();
    let migrate_auth_sig = migrated_auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        action_root.as_bytes(),
    );

    // Construct the migration transaction
    let tx_start_timer = std::time::Instant::now();
    let tx = construct_migrate_tx(
        consumed_resource,
        latest_cm_tree_root,
        consumed_nf_key,
        forwarder_addr_v2,
        erc20_token_addr,
        migrate_auth_sig,
        migrate_entries,
        created_resource,
        created_discovery_pk,
        created_auth_pk,
        created_encryption_pk,
    )
    .unwrap();
    println!("Tx build duration time: {:?}", tx_start_timer.elapsed());

    // Verify the transaction
    let kind_table_commitment = *kind_table_hash().unwrap();
    transaction::verify(&tx, kind_table_commitment, JournalEncoding::Risc0Serde).unwrap();
}
