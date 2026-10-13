# AnomaPay ERC20 Resource

Resource logics and zero-knowledge circuits for the **AnomaPay ERC20 transfer
resource**, targeting the [Anoma Resource Machine (ARM)](https://anoma.net) on
the [RISC Zero](https://dev.risczero.com) zkVM.

This repository packages the witness types, resource-logic library, and RISC
Zero guest programs that prove the validity of token-transfer resources. It was
extracted from the AnomaPay backend into a standalone workspace so the proving
artifacts (guest ELFs, `ImageID`s, and the Rust APIs around them) can be
versioned and reused independently of the backend services that consume them.

There are two variants of the resource:

- **base** — the original token-transfer resource (wrap / unwrap / transfer).
- **emergency-migrating** — adds **migration** support (migrating a legacy resource) on top of
  the base capabilities.

## Layout

Crates live at the repository root. The witness and library crates form one
Cargo workspace; each circuit is its own **excluded** workspace because RISC
Zero guests are cross-compiled to the `riscv32im-risc0-zkvm-elf` target and must
not share the host workspace's lockfile or profile.

```
.
├── anomapay_erc20_witness/                      # base witness data + resource-logic constraints
├── anomapay_emergency_migrating_erc20_witness/  # emergency-migrating witness data (depends on base)
├── anomapay_erc20_library/                      # base host API: TransferLogic, guest ELF + ImageID
├── anomapay_emergency_migrating_erc20_library/  # emergency-migrating host API + migration tx builder
├── anomapay_erc20_circuit/                      # base RISC Zero guest program  (excluded workspace)
└── anomapay_emergency_migrating_erc20_circuit/  # emergency-migrating RISC Zero guest program  (excluded workspace)
```

### Dependency graph

```
anomapay_erc20_witness ──────────────────────────────────────────────────────► anomapay_erc20_library ───► anomapay_erc20_circuit
        ▲                                                                         ▲                     │
        │                                                                         │                     │ (path deps,
        └── anomapay_emergency_migrating_erc20_witness ──► anomapay_emergency_migrating_erc20_library ──► anomapay_emergency_migrating_erc20_circuit
                                                                                              (guest embeds the library ELF)
```

- `anomapay_erc20_witness` is the leaf; everything else builds on it.
- The `*_library` crates **embed the prebuilt guest ELF** (`include_bytes!`) and
  expose the matching `ImageID`, so a host can verify proofs without rebuilding
  the guest.
- The `*_circuit` crates are the guest *sources* — used to (re)produce those
  ELFs — and depend on the witness/library crates by relative path.

## Crates

### `anomapay_erc20_witness`
Defines `TokenTransferWitness`: the full set of inputs needed to prove the
resource logic of a single consumed or created resource (the resource itself,
nullifier key, authorization signature, encryption info, forwarder/permit data,
label and value info). Implements the ARM `LogicCircuit` constraint function
that the guest executes, plus the Solidity-ABI (`alloy-sol-types`) encoding for
the EVM forwarder `Wrap`/`Unwrap` calldata. Authorization domain:
`TokenTransferAuthorization`.

### `anomapay_emergency_migrating_erc20_witness`
`EmergencyMigratingTokenTransferWitness` — the emergency-migrating witness, reusing the shared base building blocks
(`EncryptionInfo`, `LabelInfo`, `ValueInfo`, `PermitInfo`, …) and adding
`NewForwarderInfo` with `MigrateInfo` to support migrating a legacy resource.
Authorization domain: `TokenTransferAuthorizationEmergencyMigrating`.

### `anomapay_erc20_library`
Host-side API for base proving. `TransferLogic` wraps a witness and constructs
resource-logic proofs. Exposes:
- `ANOMAPAY_ERC20_CIRCUIT_ELF` — the embedded guest binary
  (`elf/anomapay-erc20-circuit-guest.bin`).
- `ANOMAPAY_ERC20_CIRCUIT_ID` — the guest `ImageID` (a `Digest`) used for verification
  on- and off-chain.

### `anomapay_emergency_migrating_erc20_library`
Emergency-migrating host-side API. `EmergencyMigratingTransferLogic` plus `migrate_tx::construct_migrate_tx`,
which assembles a complete ARM `Transaction` (compliance units, logic proofs,
delta proof) that migrates a legacy resource. Exposes `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ELF`
and `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID` (`elf/anomapay-emergency-migrating-erc20-circuit-guest.bin`).

### `anomapay_erc20_circuit` / `anomapay_emergency_migrating_erc20_circuit`
The RISC Zero guest programs (`anomapay-erc20-circuit` / `anomapay-emergency-migrating-erc20-circuit`). Each
`methods/guest` main simply reads a witness, runs `witness.constrain()`, and
commits the resulting `LogicInstance`:

```rust
let witness: TokenTransferWitness = env::read();
let instance = witness.constrain().unwrap();
env::commit(&instance);
```

Their integration tests (`src/test.rs`) exercise wrap/unwrap/transfer (and, for
the emergency-migrating circuit, migration) end to end. See each crate's `README.md` for how to reproducibly
build the ELF and `ImageID` with `cargo risczero build`.

## The guest ELF / `ImageID` model

`ANOMAPAY_ERC20_CIRCUIT_ID` (and `ANOMAPAY_EMERGENCY_MIGRATING_ERC20_CIRCUIT_ID`) is the `ImageID` of a **specific
committed build** of the guest ELF — not necessarily of a fresh
`cargo risczero build` at HEAD. The `ImageID` is a digest over the entire
compiled guest, so it changes whenever *any* transitive input changes — the
witness crate the guest actually links against (`anomapay_erc20_witness`, or
for the emergency-migrating guest, `anomapay_emergency_migrating_erc20_witness`
plus `anomapay_erc20_witness`), the ARM libraries (`anoma-rm-risc0`,
`anoma-rm-risc0-gadgets`), or the toolchain — even if the circuit logic is
byte-for-byte identical. `anomapay_erc20_library` is **not** a guest input: it
is host-only and only embeds the already-built ELF, so changes to it never
re-link the guest or affect its `ImageID`.

Because `ANOMAPAY_ERC20_CIRCUIT_ID` is consumed on-chain (verifier / protocol-adapter
contracts) and off-chain, it is rotated **only when the proof semantics
change** — not on incidental dependency or toolchain bumps. When you do need to
rotate it, rebuild the guest, replace the committed `elf/*.bin`, update the
`ImageID` constant in the library crate, and coordinate the corresponding
contract redeployment. Full details are in
[`anomapay_erc20_circuit/README.md`](anomapay_erc20_circuit/README.md).

## Building and testing

Requires the toolchain pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
(Rust **1.95**). Building the guests additionally needs the RISC Zero toolchain
(`cargo risczero`); see the circuit READMEs.

```bash
# Workspace crates (witness + library)
cargo build --workspace --all-targets
cargo test  --workspace

# Each circuit is a separate workspace — build/test from its own directory.
# RISC0_DEV_MODE=1 skips real proving so tests run fast (dev/CI only — it does
# NOT produce verifiable proofs).
cd anomapay_erc20_circuit                      && RISC0_DEV_MODE=1 cargo test -- --nocapture && cd ..
cd anomapay_emergency_migrating_erc20_circuit  && RISC0_DEV_MODE=1 cargo test -- --nocapture && cd ..
```

> The dev profile sets `opt-level = 3` for the whole workspace: running an
> unoptimized guest is dramatically slower.

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on pushes to `main`
and on pull requests:

- **Format** — `cargo fmt --all --check` for the workspace and each circuit
  (`rustfmt` `style_edition = "2024"`), plus `taplo fmt --check` for all
  `Cargo.toml`s.
- **Build & test** — `cargo build --workspace --all-targets`,
  `cargo test --workspace`, and a build + `RISC0_DEV_MODE=1` test of each
  circuit.

## Audits

Our software undergoes regular audits:

1. Informal Systems

   - Company Website: https://informal.systems
   - Commit ID: [03e60b64d9dc3845c55e34d1d0bef25392cb5b60](https://github.com/anoma/anomapay-erc20-forwarder/tree/03e60b64d9dc3845c55e34d1d0bef25392cb5b60)
   - Started: 2025-12-01
   - Finished: 2025-12-16
   - Last revised: 2025-12-19

   [📄 Audit Report (pdf)](./audits/2025-12-19_Informal_Systems_AnomaPay_Phase_I.pdf)

## Versioning

The workspace crates (`anomapay_erc20_witness`, `anomapay_emergency_migrating_erc20_witness`, `anomapay_erc20_library`, `anomapay_emergency_migrating_erc20_library`) share the
version in `[workspace.package]` (currently `2.0.0`). The circuit crates are
versioned independently (currently `2.0.0`).

## License

GPL-3.0.
