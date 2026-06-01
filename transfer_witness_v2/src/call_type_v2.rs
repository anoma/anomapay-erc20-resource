use alloy_primitives::{Address, B256};
use alloy_sol_types::{SolValue, sol};
use anoma_rm_risc0::error::ArmError;

sol! {
    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    enum CallTypeV2 {
        Wrap,
        Unwrap,
        Migrate,
    }


    /// @notice A struct containing wrap specific inputs.
    /// @param nullifier The nullifier of the resource to be migrated.
    /// @param rootV1 The root of the commitment tree that must be the latest root of the stopped protocol adapter v1.
    /// @param logicRefV1 The logic reference that must match the ERC20 forwarder v1 contract.
    /// @param forwarderV1  The ERC20 forwarder v1 contract address that must match the one set in this contract.
    struct MigrateV1Data {
        bytes32 nullifier;
        bytes32 rootV1;
        bytes32 logicRefV1;
        address forwarderV1;
    }
}

pub fn encode_migrate_forwarder_input(
    erc20_token_addr: &[u8],
    quantity: u128,
    nullifier: &[u8],
    commitment_tree_root: &[u8],
    migrate_resource_logic_ref: &[u8],
    migrate_resource_forwarder_addr: &[u8],
) -> Result<Vec<u8>, ArmError> {
    let token: Address = erc20_token_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid address bytes".to_string()))?;

    let forwarder_addr_v1: Address = migrate_resource_forwarder_addr
        .try_into()
        .map_err(|_| ArmError::ProveFailed("Invalid address bytes".to_string()))?;

    let migrate_data = MigrateV1Data {
        nullifier: B256::from_slice(nullifier),
        rootV1: B256::from_slice(commitment_tree_root),
        logicRefV1: B256::from_slice(migrate_resource_logic_ref),
        forwarderV1: forwarder_addr_v1,
    };

    Ok((CallTypeV2::Migrate, token, quantity, migrate_data).abi_encode_params())
}
