use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolValue, sol};
use anoma_rm_risc0::error::ArmError;

sol! {
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    enum CallType {
        Wrap,
        Unwrap
    }

   /// @notice A struct containing wrap specific inputs.
   /// @param nonce A unique value to prevent signature replays.
   /// @param deadline The deadline of the permit signature.
   /// @param owner The owner from which the funds a transferred from and signer of the Permit2 message.
   /// @param witness The action tree root that was signed over in addition to the permit data.
   /// @param signature The Permit2 signature.
    struct WrapData {
        uint256 nonce;
        uint256 deadline;
        address owner;
        bytes32 actionTreeRoot;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    /// @notice A struct containing unwrap specific inputs.
    /// @param receiver The receiving account address.
    struct UnwrapData {
        address receiver;
    }
}

pub fn encode_unwrap_forwarder_input(
    erc20_token_addr: &[u8],
    ethereum_account_addr: &[u8],
    quantity: u128,
) -> Result<Vec<u8>, ArmError> {
    // Encode as (CallType, erc20_token_addr, to, value)
    let token: Address = erc20_token_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid token address bytes".to_string()))
        .unwrap();
    let to: Address = ethereum_account_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid to address bytes".to_string()))
        .unwrap();

    Ok((
        CallType::Unwrap,
        token,
        quantity,
        UnwrapData { receiver: to },
    )
        .abi_encode_params())
}

pub fn encode_wrap_forwarder_input(
    erc20_token_addr: &[u8],
    quantity: u128,
    nonce: &[u8],
    deadline: &[u8],
    ethereum_account_addr: &[u8],
    action_tree_root: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ArmError> {
    let erc20_token: Address = erc20_token_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid from address bytes".to_string()))?;

    let owner: Address = ethereum_account_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid from address bytes".to_string()))?;

    if signature.len() != 65 {
        return Err(ArmError::ProveFailed(
            "Signature must be 65 bytes long".to_string(),
        ));
    }

    let wrap_data = WrapData {
        nonce: U256::from_be_slice(nonce),
        deadline: U256::from_be_slice(deadline),
        owner,
        actionTreeRoot: B256::from_slice(action_tree_root),
        r: B256::from_slice(&signature[0..32]),
        s: B256::from_slice(&signature[32..64]),
        v: signature[64],
    };

    Ok((CallType::Wrap, erc20_token, quantity, wrap_data).abi_encode_params())
}

#[test]
fn forward_call_data_test() {
    use anoma_rm_risc0_gadgets::evm::ForwarderCalldata;
    // Example data
    let addr = hex::decode("ffffffffffffffffffffffffffffffffffffffff").unwrap();
    let input = hex::decode("ab").unwrap();
    let output = hex::decode("cd").unwrap();

    // Create instance
    let data = ForwarderCalldata::from_bytes(&addr, input, output);

    // abi encode
    let encoded_data = data.encode();
    println!("encode: {:?}", hex::encode(&encoded_data));
    println!("len: {}", encoded_data.len());
    let decoded_data = ForwarderCalldata::decode(&encoded_data).unwrap();

    assert_eq!(data.untrustedForwarder, decoded_data.untrustedForwarder);
    assert_eq!(data.input, decoded_data.input);
    assert_eq!(data.output, decoded_data.output);
}

#[test]
fn encode_wrap_forwarder_input_test() {
    let token = hex::decode("2222222222222222222222222222222222222222").unwrap();
    let from = hex::decode("3333333333333333333333333333333333333333").unwrap();
    let quantity = 1000u128;

    let nonce = &[1u8; 32];
    let deadline = &[2u8; 32];
    let witness = vec![3u8; 32];
    let signature = vec![4u8; 65];

    let encoded = encode_wrap_forwarder_input(
        token.as_slice(),
        quantity,
        nonce,
        deadline,
        &from,
        &witness,
        &signature,
    )
    .unwrap();
    println!("encode: {:?}", hex::encode(&encoded));
    println!("len: {}", encoded.len());
}
