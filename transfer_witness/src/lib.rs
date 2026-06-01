//! The transfer witness library holds the struct to generate proofs over resource logics for
//! simple transfer resources in the Anoma Pay application.
//!
pub mod call_type;

use crate::call_type::{CallType, encode_unwrap_forwarder_input, encode_wrap_forwarder_input};
pub use anoma_rm_risc0::resource_logic::LogicCircuit;
use anoma_rm_risc0::{
    Digest,
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    nullifier_key::NullifierKey,
    resource::Resource,
    utils::{bytes_to_words, hash_bytes},
};
use anoma_rm_risc0_gadgets::{
    authority::{AuthoritySignature, AuthorityVerifyingKey},
    encryption::{Ciphertext, SecretKey},
    evm::ForwarderCalldata,
};
use k256::AffinePoint;
use k256::elliptic_curve::group::GroupEncoding;
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub enum DeletionCriterion {
    Immediately = 0,
    Never = 1,
}

pub const AUTH_SIGNATURE_DOMAIN: &[u8] = b"TokenTransferAuthorization";

/// The TokenTransferWitness holds all the information necessary to generate a proof of the
/// resource logic of a given resource.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TokenTransferWitness {
    /// Resource this witness is about.
    pub resource: Resource,
    /// Is this a consumed or created resource.
    pub is_consumed: bool,
    /// Action tree root
    pub action_tree_root: Digest,
    /// Nullifier key for the resource.
    pub nf_key: Option<NullifierKey>,
    /// A consumed persistent resource requires an authorization signature
    pub auth_sig: Option<AuthoritySignature>,
    /// See EncryptionInfo struct.
    pub encryption_info: Option<EncryptionInfo>,
    /// See ForwarderInfo struct.
    pub forwarder_info: Option<ForwarderInfo>,
    /// See LabelInfo struct.
    pub label_info: Option<LabelInfo>,
    /// See ValueInfo struct.
    pub value_info: Option<ValueInfo>,
}

/// The EncryptionInfo struct holds information about the encryption keys for the
/// recipient/sender of a resource in a transaction.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Secret key. randomly generated for persistent resource_ciphertext
    pub sender_sk: SecretKey,
    /// randomly generated for persistent resource_ciphertext(12 bytes)
    pub encryption_nonce: Vec<u8>,
    /// The discovery ciphertext for the resource
    pub discovery_ciphertext: Vec<u32>,
}

/// ForwarderInfo holds information about the forwarder contract being used by a transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwarderInfo {
    /// Wrapping/Unwrapping of a resource (i.e., mint/burn).
    pub call_type: CallType,
    /// Address of the ethereum account
    pub ethereum_account_addr: Vec<u8>,
    /// PermitInfo (see struct)
    pub permit_info: Option<PermitInfo>,
}

/// LabelInfo holds information about label plaintext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LabelInfo {
    /// Address of the forwarder contract for this resource.
    pub forwarder_addr: Vec<u8>,
    /// Address of the wrapped token within this resource (e.g. USDC).
    pub erc20_token_addr: Vec<u8>,
}

/// ValueInfo holds information about value plaintext
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueInfo {
    /// The authorization verifying key corresponds to the resource.value.owner
    pub auth_pk: AuthorityVerifyingKey,
    /// Public key. Obtain from the receiver for persistent resource_ciphertext
    pub encryption_pk: AffinePoint,
}

/// The PermitInfo contains information about the permit2 signature that is used to generate
/// logic proofs over resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermitInfo {
    /// Nonce of the permit2 signature.
    pub permit_nonce: Vec<u8>,
    /// Deadline of the permit2 signature (i.e., when does it expire)
    pub permit_deadline: Vec<u8>,
    /// Signature
    pub permit_sig: Vec<u8>,
}

/// The struct encoded in the resource payload for persistent created resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceWithLabel {
    pub resource: Resource,
    pub forwarder: Vec<u8>,
    pub erc20_token_addr: Vec<u8>,
}

impl TokenTransferWitness {
    // Compute the tag
    pub fn tag(&self) -> Result<Digest, ArmError> {
        if self.is_consumed {
            let nf_key = self
                .nf_key
                .as_ref()
                .ok_or(ArmError::MissingField("Nullifier key"))?;
            self.resource.nullifier(nf_key)
        } else {
            Ok(self.resource.commitment())
        }
    }

    // Check the value and return it unwrapped
    pub fn value(&self) -> Result<&ValueInfo, ArmError> {
        let value_info = self
            .value_info
            .as_ref()
            .ok_or(ArmError::MissingField("Value info"))?;

        if self.resource.value_ref != calculate_persistent_value_ref(value_info) {
            return Err(ArmError::InvalidResourceValueRef);
        }

        Ok(value_info)
    }

    // check on ephemeral resources and return external_payload
    pub fn ephemeral_resource_check(
        &self,
        action_root: &[u8],
    ) -> Result<Vec<ExpirableBlob>, ArmError> {
        let forwarder_info = self
            .forwarder_info
            .as_ref()
            .ok_or(ArmError::MissingField("Forwarder info"))?;

        let label_info = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("Label info"))?;

        // Check resource label: label = sha2(forwarder_addr, erc20_token_addr)
        let forwarder_addr = label_info.forwarder_addr.as_ref();
        let erc20_token_addr = label_info.erc20_token_addr.as_ref();
        let label_ref = calculate_label_ref(forwarder_addr, erc20_token_addr);
        if self.resource.label_ref != label_ref {
            return Err(ArmError::ProveFailed(
                "Invalid resource label_ref".to_string(),
            ));
        }

        let ethereum_account_addr = forwarder_info.ethereum_account_addr.as_ref();

        let inputs = if self.is_consumed {
            // Wrap
            if forwarder_info.call_type != CallType::Wrap {
                return Err(ArmError::ProveFailed(
                    "Wrong call type for Wrap".to_string(),
                ));
            }

            let permit_info = forwarder_info
                .permit_info
                .as_ref()
                .ok_or(ArmError::MissingField("Permit info"))?;

            encode_wrap_forwarder_input(
                erc20_token_addr,
                self.resource.quantity,
                permit_info.permit_nonce.as_ref(),
                permit_info.permit_deadline.as_ref(),
                ethereum_account_addr,
                action_root,
                permit_info.permit_sig.as_ref(),
            )?
        } else {
            // Unwrap
            if forwarder_info.call_type != CallType::Unwrap {
                return Err(ArmError::ProveFailed(
                    "Wrong call type for Unwrap".to_string(),
                ));
            }

            // Check resource value_ref: value_ref[0..20] =
            // ethereum_account_addr. We only need this for Unwrap to ensure
            // authorization signature of the consumed persistent resource over
            // the action tree root covers a resource containing
            // value_ref(ethereum_account_addr)
            let value_ref = calculate_value_ref_from_ethereum_account_addr(ethereum_account_addr);
            if self.resource.value_ref != value_ref {
                return Err(ArmError::ProveFailed(
                    "Invalid resource value_ref".to_string(),
                ));
            }

            encode_unwrap_forwarder_input(
                erc20_token_addr,
                ethereum_account_addr,
                self.resource.quantity,
            )?
        };

        let forwarder_call_data = ForwarderCalldata::from_bytes(forwarder_addr, inputs, vec![]);
        let call_data_expirable_blob = ExpirableBlob {
            blob: bytes_to_words(&forwarder_call_data.encode()),
            deletion_criterion: DeletionCriterion::Immediately as u32,
        };
        Ok(vec![call_data_expirable_blob])
    }

    // check persistent resource consumption
    pub fn persistent_resource_consumption(&self, action_root: &[u8]) -> Result<(), ArmError> {
        let auth_sig = self
            .auth_sig
            .as_ref()
            .ok_or(ArmError::MissingField("Auth signature"))?;

        let value_info = self.value()?;

        // Verify the authorization signature
        if value_info
            .auth_pk
            .verify(AUTH_SIGNATURE_DOMAIN, action_root, auth_sig)
            .is_err()
        {
            return Err(ArmError::InvalidSignature);
        }

        Ok(())
    }

    // check persistent resource creation and return discovery_payload and resource_payload
    pub fn persistent_resource_creation(
        &self,
    ) -> Result<(Vec<ExpirableBlob>, Vec<ExpirableBlob>), ArmError> {
        let label_info = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("Label info"))?;
        let label_ref = calculate_label_ref(
            label_info.forwarder_addr.as_ref(),
            label_info.erc20_token_addr.as_ref(),
        );

        if self.resource.label_ref != label_ref {
            return Err(ArmError::ProveFailed(
                "Invalid resource label_ref".to_string(),
            ));
        }

        let value_info = self.value()?;

        // Generate resource ciphertext
        let encryption_info = self
            .encryption_info
            .as_ref()
            .ok_or(ArmError::MissingField("Encryption info"))?;
        let payload_plaintext = bincode::serialize(&ResourceWithLabel {
            resource: self.resource,
            forwarder: label_info.forwarder_addr.clone(),
            erc20_token_addr: label_info.erc20_token_addr.clone(),
        })
        .map_err(|_| ArmError::InvalidResourceSerialization);
        let ciphertext = Ciphertext::encrypt_with_nonce(
            &payload_plaintext?,
            &value_info.encryption_pk,
            &encryption_info.sender_sk,
            encryption_info
                .encryption_nonce
                .clone()
                .try_into()
                .map_err(|_| ArmError::InvalidEncryptionNonce)?,
        )?;

        // Generate resource_payload
        let ciphertext_expirable_blob = ExpirableBlob {
            blob: ciphertext.as_words(),
            deletion_criterion: DeletionCriterion::Never as u32,
        };

        // Generate discovery_payload
        let ciphertext_discovery_blob = ExpirableBlob {
            blob: encryption_info.discovery_ciphertext.clone(),
            deletion_criterion: DeletionCriterion::Never as u32,
        };

        Ok((
            vec![ciphertext_discovery_blob],
            vec![ciphertext_expirable_blob],
        ))
    }
}

impl LogicCircuit for TokenTransferWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        // Load resources
        let tag = self.tag()?;

        let root_bytes = self.action_tree_root.as_bytes();

        // Generate payloads
        let (discovery_payload, resource_payload, external_payload) = if self.resource.is_ephemeral
        {
            // Generate external_payload for the ephemeral resource
            let external_payload = self.ephemeral_resource_check(root_bytes)?;

            // Empty discovery_payload and resource_payload
            (vec![], vec![], external_payload)
        } else if self.is_consumed {
            // Consume a persistent resource
            self.persistent_resource_consumption(root_bytes)?;

            // empty payloads for consumed persistent resource
            (vec![], vec![], vec![])
        } else {
            // Create a persistent resource
            let (discovery_payload, resource_payload) = self.persistent_resource_creation()?;

            // return discovery_payload and resource_payload
            (discovery_payload, resource_payload, vec![])
        };

        let app_data = AppData {
            resource_payload,
            discovery_payload,
            external_payload,
            application_payload: vec![], // Empty application payload
        };

        Ok(LogicInstance {
            tag,
            is_consumed: self.is_consumed,
            root: self.action_tree_root,
            app_data,
        })
    }
}

impl TokenTransferWitness {
    /// Create a new transfer witness.
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
            is_consumed,
            resource,
            action_tree_root,
            nf_key,
            auth_sig,
            encryption_info,
            forwarder_info,
            label_info,
            value_info,
        }
    }
}

/// Calculate the value ref based on an authorization key and an encryption key for a given user.
pub fn calculate_persistent_value_ref(value: &ValueInfo) -> Digest {
    hash_bytes(
        &[
            value.auth_pk.to_bytes(),
            value.encryption_pk.to_bytes().to_vec(),
        ]
        .concat(),
    )
}

/// Create the value_ref for the user's ethereum account address.
pub fn calculate_value_ref_from_ethereum_account_addr(ethereum_account_addr: &[u8]) -> Digest {
    let mut addr_padded = [0u8; 32];
    addr_padded[0..20].copy_from_slice(ethereum_account_addr);
    Digest::from_bytes(addr_padded)
}

/// Extract the ethereum_account_addr address from a value_ref.
pub fn get_ethereum_account_addr(value_ref: &Digest) -> [u8; 20] {
    let bytes = value_ref.as_bytes();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes[0..20]);
    addr
}

/// Calculate the label ref based on the forwarded and token address for resources.
pub fn calculate_label_ref(forwarder_add: &[u8], erc20_add: &[u8]) -> Digest {
    hash_bytes(&[forwarder_add, erc20_add].concat())
}

impl EncryptionInfo {
    /// Create new encryption info based on encryption and discovery public keys.
    pub fn new(discovery_pk: &AffinePoint) -> Self {
        let mut rng = OsRng;
        let discovery_nonce = {
            let mut nonce = [0u8; 12];
            rng.try_fill_bytes(&mut nonce)
                .expect("Failed to fill discovery nonce");
            nonce
        };
        let discovery_sk = SecretKey::random();
        let discovery_ciphertext = Ciphertext::encrypt_with_nonce(
            &vec![0u8],
            discovery_pk,
            &discovery_sk,
            discovery_nonce
                .as_slice()
                .try_into()
                .expect("Failed to convert discovery nonce, it cannot fail"),
        )
        .unwrap()
        .as_words();
        let sender_sk = SecretKey::random();
        let encryption_nonce = {
            let mut nonce = [0u8; 12];
            rng.try_fill_bytes(&mut nonce)
                .expect("Failed to fill encryption nonce");
            nonce
        };
        Self {
            sender_sk,
            encryption_nonce: encryption_nonce.to_vec(),
            discovery_ciphertext,
        }
    }
}

impl ResourceWithLabel {
    pub fn new(resource: Resource, forwarder: Vec<u8>, erc20_token_addr: Vec<u8>) -> Self {
        Self {
            resource,
            forwarder,
            erc20_token_addr,
        }
    }
}
