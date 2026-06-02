use transfer_witness::LogicCircuit;
use transfer_witness::TokenTransferWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TokenTransferWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
