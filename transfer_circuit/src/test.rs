// Add circuit tests here
use anoma_rm_risc0::{
    logic_proof::LogicProver, nullifier_key::NullifierKey, proving_system::ProofType,
    resource::Resource,
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySigningKey, AuthorityVerifyingKey},
    encryption::{SecretKey, generate_public_key},
};
use k256::Scalar;
use transfer_library::TransferLogic;
use transfer_witness::{
    ValueInfo, calculate_label_ref, calculate_persistent_value_ref,
    calculate_value_ref_from_ethereum_account_addr,
};

const FORWARDER_ADDR: [u8; 20] = [0u8; 20];
const ERC20_TOKEN_ADDR: [u8; 20] = [1u8; 20];
const UNEXPECTED_ERC20_TOKEN_ADDR: [u8; 20] = [11u8; 20];
const INVALID_ERC20_TOKEN_ADDR: [u8; 21] = [1u8; 21];
const ETHEREUM_ACCOUNT_ADDR: [u8; 20] = [2u8; 20];
const UNEXPECTED_ETHEREUM_ACCOUNT_ADDR: [u8; 20] = [22u8; 20];
const INVALID_ETHEREUM_ACCOUNT_ADDR: [u8; 21] = [2u8; 21];
const QUANTITY: u128 = 1000;
const NF_KEY_BYTES: [u8; 32] = [3u8; 32];
const PERMIT_NONCE: [u8; 32] = [4u8; 32];
const PERMIT_DEADLINE: [u8; 32] = [5u8; 32];
const PERMIT_SIG: [u8; 65] = [6u8; 65];
const AUTH_SK: [u8; 32] = [7u8; 32];
const UNEXPECTED_AUTH_SK: [u8; 32] = [77u8; 32];
const ENCRYPTION_SK: u32 = 8;
const UNEXPECTED_ENCRYPTION_SK: u32 = 88;

// Create a sample ephemeral resource for testing
fn create_ephemeral_resource() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_ADDR, &ERC20_TOKEN_ADDR);
    let value_ref = calculate_value_ref_from_ethereum_account_addr(&ETHEREUM_ACCOUNT_ADDR);
    let nk_commitment = NullifierKey::from_bytes(NF_KEY_BYTES).commit();

    Resource {
        logic_ref: TransferLogic::verifying_key(),
        nk_commitment,
        label_ref,
        value_ref,
        quantity: QUANTITY,
        is_ephemeral: true,
        ..Default::default()
    }
}

// Create a sample persistent resource for testing
fn create_persistent_resource() -> Resource {
    let label_ref = calculate_label_ref(&FORWARDER_ADDR, &ERC20_TOKEN_ADDR);
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

#[test]
fn test_mint() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();
}

#[test]
fn test_burn() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
    );

    let proof = resource_logic.prove(ProofType::Succinct).unwrap();

    proof.verify().unwrap();
}

#[test]
fn test_transfer() {
    use anoma_rm_risc0::Digest;
    use anoma_rm_risc0_gadgets::encryption::{Ciphertext, random_keypair};
    use transfer_witness::{AUTH_SIGNATURE_DOMAIN, ResourceWithLabel};

    let consumed_resource = create_persistent_resource();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let consumed_resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    let proof = consumed_resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    let created_resource = create_persistent_resource();
    let (created_discovery_sk, created_discovery_pk) = random_keypair();
    let created_resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_ADDR.to_vec(),
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
        forwarder: FORWARDER_ADDR.to_vec(),
        erc20_token_addr: ERC20_TOKEN_ADDR.to_vec(),
    })
    .unwrap();
    assert_eq!(plaintext.as_bytes(), expected_plaintext);

    // Deserialize to verify correctness
    let deserialized: ResourceWithLabel = bincode::deserialize(plaintext.as_bytes()).unwrap();
    assert_eq!(
        deserialized.forwarder,
        FORWARDER_ADDR.to_vec(),
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
fn test_missing_nf_key() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    // Remove the nullifier key to simulate missing nf_key
    resource_logic.witness.nf_key = None;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_missing_forwarder_info() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    // Remove the permit info to simulate missing permit info
    let mut forwarder_info = resource_logic.witness.forwarder_info.unwrap();
    forwarder_info.permit_info = None;
    resource_logic.witness.forwarder_info = Some(forwarder_info);

    resource_logic.prove(ProofType::Succinct).unwrap_err();

    // Remove the forwarder info to simulate missing forwarder info
    resource_logic.witness.forwarder_info = None;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_missing_label_info() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    // Remove the label info to simulate missing label info
    resource_logic.witness.label_info = None;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_wrong_label_ref() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    // Tamper with the label_ref to simulate wrong label_ref
    resource_logic
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .erc20_token_addr[0] ^= 0xFF;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_wrong_call_type_for_wrap() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    // Change call type to Unwrap to simulate wrong call type for wrap
    resource_logic
        .witness
        .forwarder_info
        .as_mut()
        .unwrap()
        .call_type = transfer_witness::call_type::CallType::Unwrap;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_invalid_erc20_token_addr_for_wrap() {
    use anoma_rm_risc0::Digest;

    let mut resource = create_ephemeral_resource();
    resource.label_ref = calculate_label_ref(&FORWARDER_ADDR, &INVALID_ERC20_TOKEN_ADDR); // Invalid erc20_token_addr
    let resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        INVALID_ERC20_TOKEN_ADDR.to_vec(), // Invalid erc20_token_addr
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_invalid_ethereum_account_addr_for_wrap() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let resource_logic = TransferLogic::mint_resource_logic_with_permit(
        resource,
        Digest::default(), // dummy action_tree_root
        NullifierKey::from_bytes(NF_KEY_BYTES),
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        INVALID_ETHEREUM_ACCOUNT_ADDR.to_vec(), // Invalid ethereum_account_addr
        PERMIT_NONCE.to_vec(),
        PERMIT_DEADLINE.to_vec(),
        PERMIT_SIG.to_vec(),
    );

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_wrong_call_type_for_unwrap() {
    use anoma_rm_risc0::Digest;

    let resource = create_ephemeral_resource();
    let mut resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
    );

    // Change call type to Wrap to simulate wrong call type for unwrap
    resource_logic
        .witness
        .forwarder_info
        .as_mut()
        .unwrap()
        .call_type = transfer_witness::call_type::CallType::Wrap;

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

#[test]
fn test_invalid_value_ref_for_unwrap() {
    use anoma_rm_risc0::Digest;

    let mut resource = create_ephemeral_resource();
    let resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
        UNEXPECTED_ETHEREUM_ACCOUNT_ADDR.to_vec(), // Unexpected ethereum_account_addr
    );

    resource_logic.prove(ProofType::Succinct).unwrap_err();

    resource.label_ref = calculate_label_ref(&FORWARDER_ADDR, &[0u8; 21]); // Invalid erc20_token_addr
    let resource_logic = TransferLogic::burn_resource_logic(
        resource,
        Digest::default(), // dummy action_tree_root
        FORWARDER_ADDR.to_vec(),
        UNEXPECTED_ERC20_TOKEN_ADDR.to_vec(), // Unexpected erc20_token_addr
        ETHEREUM_ACCOUNT_ADDR.to_vec(),
    );

    resource_logic.prove(ProofType::Succinct).unwrap_err();
}

fn create_persistent_consumed_resource_logic() -> TransferLogic {
    use anoma_rm_risc0::Digest;
    use transfer_witness::AUTH_SIGNATURE_DOMAIN;

    let consumed_resource = create_persistent_resource();

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let auth_sig = auth_sk.sign(AUTH_SIGNATURE_DOMAIN, action_tree_root.as_bytes());

    let resource_logic = TransferLogic::consume_persistent_resource_logic(
        consumed_resource,
        action_tree_root,
        NullifierKey::from_bytes(NF_KEY_BYTES),
        auth_pk,
        encryption_pk,
        auth_sig,
    );

    // Positive test
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    resource_logic
}

#[test]
fn test_negative_persistent_resource_consumption_with_missing_info() {
    let resource_logic = create_persistent_consumed_resource_logic();

    // Remove the auth_sig to simulate missing auth_sig
    let mut resource_logic_with_missing_auth_sig = resource_logic.clone();
    resource_logic_with_missing_auth_sig.witness.auth_sig = None;

    resource_logic_with_missing_auth_sig
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();

    // Remove the value_info to simulate missing value_info
    let mut resource_logic_with_missing_value_info = resource_logic.clone();
    resource_logic_with_missing_value_info.witness.value_info = None;
    resource_logic_with_missing_value_info
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

#[test]
fn test_negative_persistent_resource_consumption_with_invalid_value_info() {
    let resource_logic = create_persistent_consumed_resource_logic();

    // Wrong auth_pk in value_info
    let mut resource_logic_with_wrong_auth_pk = resource_logic.clone();
    let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
    resource_logic_with_wrong_auth_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .auth_pk = wrong_auth_pk;

    // Wrong encryption_pk in value_info
    let mut resource_logic_with_wrong_encryption_pk = resource_logic.clone();
    let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
    let wrong_encryption_pk = generate_public_key(&wrong_encryption_sk.inner());
    resource_logic_with_wrong_encryption_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .encryption_pk = wrong_encryption_pk;

    resource_logic_with_wrong_auth_pk
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

#[test]
fn test_negative_persistent_resource_consumption_with_invalid_auth_sig() {
    use anoma_rm_risc0::Digest;

    let resource_logic = create_persistent_consumed_resource_logic();
    let action_tree_root = Digest::default(); // dummy action_tree_root

    // Wrong auth_sig
    let mut resource_logic_with_wrong_auth_sig = resource_logic.clone();
    let auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_sig = auth_sk.sign(
        transfer_witness::AUTH_SIGNATURE_DOMAIN,
        action_tree_root.as_bytes(),
    );
    resource_logic_with_wrong_auth_sig.witness.auth_sig = Some(wrong_auth_sig);
    resource_logic_with_wrong_auth_sig
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();

    // Wrong action_tree_root
    let mut resource_logic_with_wrong_action_tree_root = resource_logic.clone();
    let wrong_action_tree_root = Digest::from([1u8; 32]);
    resource_logic_with_wrong_action_tree_root
        .witness
        .action_tree_root = wrong_action_tree_root;
    resource_logic_with_wrong_action_tree_root
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();

    // Wrong AUTH_SIGNATURE_DOMAIN
    let mut resource_logic_with_wrong_auth_signature_domain = resource_logic.clone();
    let wrong_auth_signature_domain = b"wrong_domain";
    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let wrong_auth_sig = auth_sk.sign(wrong_auth_signature_domain, action_tree_root.as_bytes());
    resource_logic_with_wrong_auth_signature_domain
        .witness
        .auth_sig = Some(wrong_auth_sig);
    resource_logic_with_wrong_auth_signature_domain
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

fn create_persistent_created_resource_logic() -> TransferLogic {
    use anoma_rm_risc0::Digest;
    use anoma_rm_risc0_gadgets::encryption::random_keypair;

    let auth_sk = AuthoritySigningKey::from_bytes(&AUTH_SK).unwrap();
    let auth_pk = AuthorityVerifyingKey::from_signing_key(&auth_sk);
    let encryption_sk = SecretKey::new(Scalar::from(ENCRYPTION_SK));
    let encryption_pk = generate_public_key(&encryption_sk.inner());

    let action_tree_root = Digest::default(); // dummy action_tree_root

    let created_resource = create_persistent_resource();
    let (_created_discovery_sk, created_discovery_pk) = random_keypair();
    let resource_logic = TransferLogic::create_persistent_resource_logic(
        created_resource,
        action_tree_root,
        &created_discovery_pk,
        auth_pk,
        encryption_pk,
        FORWARDER_ADDR.to_vec(),
        ERC20_TOKEN_ADDR.to_vec(),
    );

    // Positive test
    let proof = resource_logic.prove(ProofType::Succinct).unwrap();
    proof.verify().unwrap();

    resource_logic
}

#[test]
fn test_negative_persistent_resource_creation_with_missing_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Remove the label_info to simulate missing label_info
    let mut resource_logic_with_missing_label_info = resource_logic.clone();
    resource_logic_with_missing_label_info.witness.label_info = None;

    resource_logic_with_missing_label_info
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();

    // Remove the value_info to simulate missing value_info
    let mut resource_logic_with_missing_value_info = resource_logic.clone();
    resource_logic_with_missing_value_info.witness.value_info = None;
    resource_logic_with_missing_value_info
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();

    // Remove the encryption_info to simulate missing encryption_info
    let mut resource_logic_with_missing_encryption_info = resource_logic.clone();
    resource_logic_with_missing_encryption_info
        .witness
        .encryption_info = None;

    resource_logic_with_missing_encryption_info
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_label_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Wrong forwarder address in label_info
    let mut resource_logic_with_wrong_forwarder_addr = resource_logic.clone();
    resource_logic_with_wrong_forwarder_addr
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .forwarder_addr[0] ^= 0xFF;

    // Wrong erc20_token_addr in label_info
    let mut resource_logic_with_wrong_erc20_token_addr = resource_logic.clone();
    resource_logic_with_wrong_erc20_token_addr
        .witness
        .label_info
        .as_mut()
        .unwrap()
        .erc20_token_addr[0] ^= 0xFF;

    resource_logic_with_wrong_forwarder_addr
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_value_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Wrong auth_pk in value_info
    let mut resource_logic_with_wrong_auth_pk = resource_logic.clone();
    let wrong_auth_sk = AuthoritySigningKey::from_bytes(&UNEXPECTED_AUTH_SK).unwrap();
    let wrong_auth_pk = AuthorityVerifyingKey::from_signing_key(&wrong_auth_sk);
    resource_logic_with_wrong_auth_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .auth_pk = wrong_auth_pk;

    // Wrong encryption_pk in value_info
    let mut resource_logic_with_wrong_encryption_pk = resource_logic.clone();
    let wrong_encryption_sk = SecretKey::new(Scalar::from(UNEXPECTED_ENCRYPTION_SK));
    let wrong_encryption_pk = generate_public_key(&wrong_encryption_sk.inner());
    resource_logic_with_wrong_encryption_pk
        .witness
        .value_info
        .as_mut()
        .unwrap()
        .encryption_pk = wrong_encryption_pk;

    resource_logic_with_wrong_auth_pk
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}

#[test]
fn test_negative_persistent_resource_creation_with_invalid_encryption_info() {
    let resource_logic = create_persistent_created_resource_logic();

    // Invalid encryption nonce in encryption_info
    let mut resource_logic_with_invalid_encryption_nonce = resource_logic.clone();
    resource_logic_with_invalid_encryption_nonce
        .witness
        .encryption_info
        .as_mut()
        .unwrap()
        .encryption_nonce = [0u8; 13].to_vec(); // should be 12 bytes

    resource_logic_with_invalid_encryption_nonce
        .prove(anoma_rm_risc0::proving_system::ProofType::Succinct)
        .unwrap_err();
}
