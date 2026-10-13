use anomapay_emergency_migrating_erc20_witness::LogicCircuit;
use anomapay_emergency_migrating_erc20_witness::EmergencyMigratingTokenTransferWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: EmergencyMigratingTokenTransferWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
