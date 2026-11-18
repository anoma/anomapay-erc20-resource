use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use anomapay_erc20_witness::call_type::{CallType, WrapData, encode_wrap_forwarder_input};

/// The words of `(Wrap, token, quantity, WrapData)` before the signature bytes: the three generic
/// words, the offset of `WrapData`, its four fixed words, and the offset and length of the signature.
const WRAP_HEADER_LENGTH: usize = 10 * 32;

#[test]
fn encode_wrap_forwarder_input_carries_the_signature_unchanged() {
    let token = Address::repeat_byte(0x22);
    let owner = Address::repeat_byte(0x33);
    let quantity = 1000u128;
    let nonce = [1u8; 32];
    let deadline = [2u8; 32];
    let action_tree_root = [3u8; 32];
    // Two Safe owner signatures; a length that is not a multiple of 32 needs padding.
    let signature = [4u8; 2 * 65];

    let input = encode_wrap_forwarder_input(
        token.as_slice(),
        quantity,
        &nonce,
        &deadline,
        owner.as_slice(),
        &action_tree_root,
        &signature,
    )
    .unwrap();

    assert_eq!(
        input.len(),
        WRAP_HEADER_LENGTH + signature.len().div_ceil(32) * 32,
        "the forwarder accepts only this length"
    );

    let (call_type, decoded_token, decoded_quantity, wrap_data) =
        <(CallType, Address, u128, WrapData)>::abi_decode_params(&input).unwrap();
    assert_eq!(call_type, CallType::Wrap);
    assert_eq!(decoded_token, token);
    assert_eq!(decoded_quantity, quantity);
    assert_eq!(wrap_data.nonce, U256::from_be_bytes(nonce));
    assert_eq!(wrap_data.deadline, U256::from_be_bytes(deadline));
    assert_eq!(wrap_data.owner, owner);
    assert_eq!(wrap_data.actionTreeRoot, B256::from(action_tree_root));
    assert_eq!(wrap_data.signature.as_ref(), signature.as_slice());
}
