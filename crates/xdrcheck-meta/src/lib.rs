//! Meta analysis: stellar-core's golden-comparison normalisation (`normalise`), the metamorphic
//! rewrites that must not change any fact (`permute`), the structural skeleton (`skeleton`), the
//! reference extractor (`extract`) and the values a variant's bytes imply for its `requires` and
//! `derived.l1` fields (`derive`).
pub mod derive;
pub mod extract;
pub mod normalise;
pub mod permute;
pub mod skeleton;
