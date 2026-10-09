use emergency_migrating_transfer_witness::LogicCircuit;
use emergency_migrating_transfer_witness::EmergencyMigratingTokenTransferWitness;
use risc0_zkvm::guest::env;

fn main() {
    let witness: EmergencyMigratingTokenTransferWitness = env::read();

    let instance = witness.constrain().unwrap();

    env::commit(&instance);
}
