use anomapay_erc20_witness::LogicCircuit;
use anomapay_erc20_witness::TokenTransferWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: TokenTransferWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
