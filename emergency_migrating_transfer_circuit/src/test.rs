// Add circuit tests here
use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, nullifier_key::NullifierKey, resource::Resource,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{SecretKey, generate_public_key},
};
use emergency_migrating_transfer_library::EmergencyMigratingTransferLogic;
use k256::Scalar;
use transfer_library::TransferLogic;
use transfer_witness::{
    ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_ethereum_account_addr,
};

const FORWARDER_ADDR_V1: [u8; 20] = [0u8; 20];
const EMERGENCY_MIGRATING_FORWARDER_ADDR: [u8; 20] = [10u8; 20];
const UNEXPECTED_FORWARDER_ADDR: [u8; 20] = [20u8; 20];
const ERC20_TOKEN_ADDR: [u8; 20] = [1u8; 20];
const ETHEREUM_ACCOUNT_ADDR: [u8; 20] = [2u8; 20];
const QUANTITY: u128 = 1000;
const UNEXPECTED_QUANTITY: u128 = 1001;
const NF_KEY_BYTES: [u8; 32] = [3u8; 32];
const UNEXPECTED_NF_KEY_BYTES: [u8; 32] = [33u8; 32];
const PERMIT_NONCE: [u8; 32] = [4u8; 32];
const PERMIT_DEADLINE: [u8; 32] = [5u8; 32];
const PERMIT_SIG: [u8; 65] = [6u8; 65];
const AUTH_SK: [u8; 32] = [7u8; 32];
const UNEXPECTED_AUTH_SK: [u8; 32] = [77u8; 32];
const ENCRYPTION_SK: u32 = 8u32;
const UNEXPECTED_ENCRYPTION_SK: u32 = 88u32;

// Create a sample persistent resource for testing
fn create_persistent_resource() -> Resource {
    let label_ref = calculate_label_ref(&EMERGENCY_MIGRATING_FORWARDER_ADDR, &ERC20_TOKEN_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());
    let value_info = ValueInfo {
        auth_pk,
        encryption_pk,
    };

    let value_ref = calculate_persistent_value_ref(&value_info);

    Resource {
        logic_ref: EmergencyMigratingTransferLogic::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

// Create a sample ephemeral resource for testing
fn create_ephemeral_resource() -> Resource {
    let label_ref = calculate_label_ref(&EMERGENCY_MIGRATING_FORWARDER_ADDR, &ERC20_TOKEN_ADDR);
    let value_ref = calculate_value_ref_from_ethereum_account_addr(&ETHEREUM_ACCOUNT_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: EmergencyMigratingTransferLogic::verifying_key(),
        nk_commitment,
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

// Create a sample persistent resource in v1 for testing
fn create_persistent_resource_v1() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_ADDR_V1, &ERC20_TOKEN_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());
    let value_info = ValueInfo {
        auth_pk,
        encryption_pk,
    };

    let value_ref = calculate_persistent_value_ref(&value_info);

    Resource {
        logic_ref: TransferLogic::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

// Create a valid migrate resource logic for testing, migrating a single-entry batch.
fn create_migrate_resource_logic() -> EmergencyMigratingTransferLogic {
    use anoma_rm_risc0::merkle_path::MerklePath;
    use emergency_migrating_transfer_library::MigrateEntryParams;
    use emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN;

    // mock a resource to be migrated in v1
    let resource_v1 = create_persistent_resource_v1();

    // create the ephemeral resource to migrate the resource_v1
    let self_resource = create_ephemeral_resource();

    // It should be the real root in practice
    let action_tree_root = Digest::default();

    let nf_key = NullifierKey::from_bytes(NF_KEY_BYTES);

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);

    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        action_tree_root.as_bytes(),
    );

    EmergencyMigratingTransferLogic::migrate_resource_logic(
        self_resource,
        action_tree_root,
        nf_key.clone(),
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        auth_sig,
        vec![MigrateEntryParams {
            resource: resource_v1,
            nf_key: nf_key.clone(), // using the same nf_key for simplicity
            path: MerklePath::default(), // using default path for simplicity, only a real tx/action needs a valid path
            auth_pk,
            encryption_pk,
            forwarder_addr: FORWARDER_ADDR_V1.to_vec(),
        }],
    )
}

#[test]
fn test_mint() {
    use anoma_rm_risc0::{logic_proof, proving_system::ProofType};

    let resource = create_ephemeral_resource();
    let mut resource_logic = EmergencyMigratingTransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    logic_proof::verify(&proof).unwrap();

    // Change the is_consumed flag to false
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn() {
    use anoma_rm_risc0::{logic_proof, proving_system::ProofType};

    let resource = create_ephemeral_resource();
    let mut resource_logic = EmergencyMigratingTransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    logic_proof::verify(&proof).unwrap();

    // Change the is_consumed flag to true
    resource_logic.witness.is_consumed = true;
    // Fill in the nf_key to avoid returning early
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer() {
    use anoma_rm_risc0::{logic_proof, proving_system::ProofType};
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN;
    use transfer_witness::ResourceWithLabel;

    let consumed_resource = create_persistent_resource();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        action_tree_root.as_bytes(),
    );

    let consumed_resource_logic =
        EmergencyMigratingTransferLogic::consume_persistent_resource_logic(
            consumed_resource,
            action_tree_root,
            NullifierKey::from_bytes(NF_KEY_BYTES),
            auth_pk,
            encryption_pk,
            auth_sig,
        );

    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    logic_proof::verify(&proof).unwrap();

    let created_resource = create_persistent_resource();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let created_resource_logic = EmergencyMigratingTransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
    );

    let proof = created_resource_logic.prove(ProofType::Succinct).unwrap();
    logic_proof::verify(&proof).unwrap();

    // check discovery ciphertext
    let discovery_ciphertext = Ciphertext::from_words(
        &logic_proof::get_instance(&proof)
            .unwrap()
            .app_data
            .discovery_payload[0]
            .blob,
    );
    discovery_ciphertext.decrypt(&created_discovery_sk).unwrap();

    // check encryption
    let encryption_ciphertext = Ciphertext::from_words(
        &logic_proof::get_instance(&proof)
            .unwrap()
            .app_data
            .resource_payload[0]
            .blob,
    );
    let plaintext = encryption_ciphertext.decrypt(&encryption_sk).unwrap();
    let expected_plaintext = bincode::serialize(&ResourceWithLabel {
        resource: created_resource,
        forwarder: EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        erc20_token_addr: ERC20_TOKEN_ADDR.to_vec(),
    })
    .unwrap();
    assert_eq!(plaintext.as_bytes(), expected_plaintext);

    // Deserialize to verify correctness
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(
        deserialized.forwarder,
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        "Forwarder address mismatch"
    );
    assert_eq!(
        deserialized.erc20_token_addr,
        ERC20_TOKEN_ADDR.to_vec(),
        "ERC20 address mismatch"
    );
    assert_eq!(deserialized.resource, created_resource, "Resource mismatch");
}

// Create a migrate resource logic migrating a batch of `count` V1 resources,
// each from its own forwarder address, sharing one erc20 token address, and each
// worth QUANTITY / count (so the total matches the trigger resource's quantity).
fn create_migrate_resource_logic_batch(count: u8) -> EmergencyMigratingTransferLogic {
    use anoma_rm_risc0::merkle_path::MerklePath;
    use emergency_migrating_transfer_library::MigrateEntryParams;
    use emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN;

    let action_tree_root = Digest::default();
    let per_entry_quantity = QUANTITY / count as u128;

    let self_resource = Resource {
        quantity: per_entry_quantity * count as u128,
        ..create_ephemeral_resource()
    };
    let self_nf_key = NullifierKey::from_bytes(NF_KEY_BYTES);

    // All entries share the same auth_pk, since the batch is authorized by a
    // single signature over that key.
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let auth_sig = auth_sk.sign(
        EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
        action_tree_root.as_bytes(),
    );

    let entries = (0..count)
        .map(|i| {
            let seed = i + 1; // avoid an all-zero seed, which is an invalid nullifier key
            let forwarder_addr_v1 = vec![i; 20];
            let label_ref = calculate_label_ref(&forwarder_addr_v1, &ERC20_TOKEN_ADDR);
            let nk_commitment = NullifierKey::from_bytes([seed; 32]).commit();
            let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
            let encryption_pk = generate_public_key(encryption_sk.inner());
            let value_info = ValueInfo {
                auth_pk,
                encryption_pk,
            };
            let value_ref = calculate_persistent_value_ref(&value_info);
            let resource = Resource {
                logic_ref: TransferLogic::verifying_key(),
                label_ref,
                value_ref,
                quantity: per_entry_quantity,
                is_ephemeral: false,
                nk_commitment,
                ..Default::default()
            };

            MigrateEntryParams {
                resource,
                nf_key: NullifierKey::from_bytes([seed; 32]),
                path: MerklePath::default(),
                auth_pk,
                encryption_pk,
                forwarder_addr: forwarder_addr_v1,
            }
        })
        .collect();

    EmergencyMigratingTransferLogic::migrate_resource_logic(
        self_resource,
        action_tree_root,
        self_nf_key,
        EMERGENCY_MIGRATING_FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        auth_sig,
        entries,
    )
}

#[test]
fn test_positive_migration() {
    use anoma_rm_risc0::{logic_proof, proving_system::ProofType};

    let resource_logic = create_migrate_resource_logic();

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    logic_proof::verify(&proof).unwrap();
}

#[test]
fn test_positive_batch_migration() {
    use anoma_rm_risc0::{logic_proof, proving_system::ProofType};

    // Migrate a batch of 3 resources, each from its own V1 forwarder address,
    // merging into the single created resource.
    let resource_logic = create_migrate_resource_logic_batch(3);

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    logic_proof::verify(&proof).unwrap();
}

#[test]
fn test_negative_migration_with_empty_batch() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
        .as_mut()
        .unwrap()
        .entries
        .clear();
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_is_consumed_in_self_resource() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the is_consumed flag to false
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_missing_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Remove the migrate_info to simulate missing migration data
    resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info = None;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_is_ephemeral_in_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the is_ephemeral flag to false in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.entries[0].resource.is_ephemeral = true; // should be false for persistent resource
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_auth_pk_in_value_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the auth_pk in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
        migrate_info.entries[0].value_info.auth_pk = wrong_auth_pk;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_encryption_pk_in_value_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the encryption_pk in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
        let wrong_encryption_pk = generate_public_key(wrong_encryption_sk.inner());
        migrate_info.entries[0].value_info.encryption_pk = wrong_encryption_pk;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_auth_sig() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the auth_sig in the migrate_info, using a wrong auth_sk
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_sig = wrong_auth_sk.sign(
            emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
            resource_logic.witness.action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Change the auth_sig in the migrate_info, using a wrong action_tree_root
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_action_tree_root = Digest::from([10u8; 32]);
        let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
        let wrong_auth_sig = auth_sk.sign(
            emergency_migrating_transfer_witness::EMERGENCY_MIGRATING_AUTH_SIGNATURE_DOMAIN,
            wrong_action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Change the auth_sig in the migrate_info, using a wrong domain
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
        let wrong_auth_sig = auth_sk.sign(
            b"WrongDomain",
            resource_logic.witness.action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_quantity() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the quantity in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.entries[0].resource.quantity = UNEXPECTED_QUANTITY;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_nf_key() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();
    // Change the nf_key in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.entries[0].nf_key = NullifierKey::from_bytes(UNEXPECTED_NF_KEY_BYTES);
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_negative_migration_with_wrong_forwarder_addr_in_migrate_info() {
    use anoma_rm_risc0::proving_system::ProofType;

    let mut resource_logic = create_migrate_resource_logic();

    // Change the forwarder_addr in the migrate_info
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .new_forwarder_info
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.entries[0].forwarder_addr = UNEXPECTED_FORWARDER_ADDR.to_vec();
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}
