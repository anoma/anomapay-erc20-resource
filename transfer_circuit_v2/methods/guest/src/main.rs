use transfer_witness_v2::LogicCircuit;
use transfer_witness_v2::TokenTransferWitnessV2;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TokenTransferWitnessV2 = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
