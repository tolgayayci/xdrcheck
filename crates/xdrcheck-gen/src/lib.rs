//! The generator. Node side: `core` (a standalone stellar-core), `upgrade` (protocol and settings upgrades)
//! and `soroban` (contract deploys and calls). Scenario side: `scenario` (the scenario file and its
//! interpreter) and `output` (blobs, sidecars, manifest variants and chain indexes).
pub mod core;
pub mod output;
pub mod scenario;
pub mod soroban;
pub mod upgrade;
