//! Shared utilities

pub mod memory;
pub mod pattern;
pub mod hash;
pub mod simd;

pub use memory::{protect_memory, read_memory, write_memory, ProtectionGuard};
pub use pattern::{Pattern, PatternScanner, ScanMatch, Scanner};
pub use hash::{djb2_hash, djb2_hash_lowercase, fnv1a_hash};
pub use simd::{SimdLevel, SimdScanner, simd_scan, simd_scan_first};

#[cfg(feature = "navigation")]
pub use pattern::{
    find_pattern_all_modules, find_pattern_executable, find_pattern_in_module,
    find_pattern_in_module_first, find_pattern_in_region,
};
