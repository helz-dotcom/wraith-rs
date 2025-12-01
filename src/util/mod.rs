//! Shared utilities

pub mod memory;
pub mod pattern;
pub mod hash;

pub use memory::{protect_memory, read_memory, write_memory, ProtectionGuard};
pub use pattern::PatternScanner;
pub use hash::{djb2_hash, djb2_hash_lowercase, fnv1a_hash};
