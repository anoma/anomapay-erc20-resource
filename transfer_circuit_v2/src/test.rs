// Add circuit tests here
use anoma_rm_risc0::{
    Digest, logic_proof::LogicProver, nullifier_key::NullifierKey, resource::Resource,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{SecretKey, generate_public_key},
};
use k256::Scalar;
use transfer_library::TransferLogic;
use transfer_library_v2::TransferLogicV2;
use transfer_witness::{
    ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_ethereum_account_addr,
};

const FORWARDER_ADDR_V1: [u8; 20] = [0u8; 20];
const FORWARDER_ADDR_V2: [u8; 20] = [10u8; 20];
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

// Create a sample persistent resource in v2 for testing
fn create_persistent_resource_v2() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_ADDR_V2, &ERC20_TOKEN_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());
    let value_info = ValueInfo {
        auth_pk,
        encryption_pk,
    };

    let value_ref = calculate_persistent_value_ref(&value_info);

    Resource {
        logic_ref: TransferLogicV2::verifying_key(),
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: false,
        nk_commitment,
        ..Default::default()
    }
}

// Create a sample ephemeral resource in v2 for testing
fn create_ephemeral_resource_v2() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_ADDR_V2, &ERC20_TOKEN_ADDR);
    let value_ref = calculate_value_ref_from_ethereum_account_addr(&ETHEREUM_ACCOUNT_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: TransferLogicV2::verifying_key(),
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
    let encryption_pk = generate_public_key(&encryption_sk.inner());
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

// Create a valid migrate resource logic in v2 for testing
fn create_migrate_resource_logic() -> TransferLogicV2 {
    use anoma_rm_risc0::merkle_path::MerklePath;
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    // mock a resource to be migrated in v1
    let resource_v1 = create_persistent_resource_v1();

    // create the ephemeral resource in v2 to migrate the resource_v1
    let self_resource = create_ephemeral_resource_v2();

    // It should be the real root in practice
    let action_tree_root = Digest::default();

    let nf_key = NullifierKey::from_bytes(NF_KEY_BYTES);

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);

    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN_V2, action_tree_root.as_bytes());

    TransferLogicV2::migrate_resource_logic(
        self_resource,
        action_tree_root,
        nf_key.clone(),
        FORWARDER_ADDR_V2.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        resource_v1,
        nf_key,                // using the same nf_key for simplicity
        MerklePath::default(), // using default path for simplicity, only a real tx/action needs a valid path
        auth_pk,
        encryption_pk,
        auth_sig,
        FORWARDER_ADDR_V1.to_vec(),
    )
}

#[test]
fn test_mint_v2() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource = create_ephemeral_resource_v2();
    let mut resource_logic = TransferLogicV2::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR_V2.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();

    // Change the is_consumed flag to false
    resource_logic.witness.is_consumed = false;
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_burn_v2() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource = create_ephemeral_resource_v2();
    let mut resource_logic = TransferLogicV2::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_ADDR_V2.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();

    // Change the is_consumed flag to true
    resource_logic.witness.is_consumed = true;
    // Fill in the nf_key to avoid returning early
    resource_logic.witness.nf_key = Some(NullifierKey::from_bytes(NF_KEY_BYTES));
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_transfer_v2() {
    use anoma_rm_risc0::proving_system::ProofType;
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use transfer_witness::ResourceWithLabel;
    use transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2;

    let consumed_resource = create_persistent_resource_v2();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN_V2, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogicV2::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    let created_resource = create_persistent_resource_v2();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let created_resource_logic = TransferLogicV2::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_ADDR_V2.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
    );

    let proof = created_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    // check discovery ciphertext
    let discovery_ciphertext =
        Ciphertext::from_words(&proof.get_instance().unwrap().app_data.discovery_payload[0].blob);
    discovery_ciphertext.decrypt(&created_discovery_sk).unwrap();

    // check encryption
    let encryption_ciphertext =
        Ciphertext::from_words(&proof.get_instance().unwrap().app_data.resource_payload[0].blob);
    let plaintext = encryption_ciphertext.decrypt(&encryption_sk).unwrap();
    let expected_plaintext = bincode::serialize(&ResourceWithLabel {
        resource: created_resource,
        forwarder: FORWARDER_ADDR_V2.to_vec(),
        erc20_token_addr: ERC20_TOKEN_ADDR.to_vec(),
    })
    .unwrap();
    assert_eq!(plaintext.as_bytes(), expected_plaintext);

    // Deserialize to verify correctness
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(
        deserialized.forwarder,
        FORWARDER_ADDR_V2.to_vec(),
        "Forwarder address mismatch"
    );
    assert_eq!(
        deserialized.erc20_token_addr,
        ERC20_TOKEN_ADDR.to_vec(),
        "ERC20 address mismatch"
    );
    assert_eq!(deserialized.resource, created_resource, "Resource mismatch");
}

#[test]
fn test_positive_migration() {
    use anoma_rm_risc0::proving_system::ProofType;

    let resource_logic = create_migrate_resource_logic();

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();
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
        .forwarder_info_v2
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.resource.is_ephemeral = true; // should be false for persistent resource
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
        migrate_info.value_info.auth_pk = wrong_auth_pk;
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
        let wrong_encryption_pk = generate_public_key(&wrong_encryption_sk.inner());
        migrate_info.value_info.encryption_pk = wrong_encryption_pk;
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
        let wrong_auth_sig = wrong_auth_sk.sign(
            transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2,
            resource_logic.witness.action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Change the auth_sig in the migrate_info, using a wrong action_tree_root
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        let wrong_action_tree_root = Digest::from([10u8; 32]);
        let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
        let wrong_auth_sig = auth_sk.sign(
            transfer_witness_v2::AUTH_SIGNATURE_DOMAIN_V2,
            wrong_action_tree_root.as_bytes(),
        );
        migrate_info.auth_sig = wrong_auth_sig;
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Change the auth_sig in the migrate_info, using a wrong domain
    let mut resource_logic = create_migrate_resource_logic();
    if let Some(migrate_info) = &mut resource_logic
        .witness
        .forwarder_info_v2
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.resource.quantity = UNEXPECTED_QUANTITY;
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.nf_key = NullifierKey::from_bytes(UNEXPECTED_NF_KEY_BYTES);
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
        .forwarder_info_v2
        .as_mut()
        .unwrap()
        .migrate_info
    {
        migrate_info.forwarder_addr = UNEXPECTED_FORWARDER_ADDR.to_vec();
    }
    resource_logic.prove(ProofType::Succinct).unwrap_err();
}
