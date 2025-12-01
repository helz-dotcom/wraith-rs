#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)] // we document safety in SAFETY comments

//! wraith-rs: Safe abstractions for Windows PEB/TEB manipulation
//!
//! This library provides high-level, safe APIs for interacting with Windows
//! process internals, including:
//!
//! - PEB/TEB structure access with version-aware field offsets
//! - Module enumeration and querying
//! - Module unlinking from PEB lists
//! - Manual PE mapping (LoadLibrary bypass)
//! - Direct/indirect syscall invocation
//! - Hook detection and removal
//! - Anti-debug techniques

pub mod arch;
pub mod error;
#[cfg(any(
    feature = "manual-map",
    feature = "syscalls",
    feature = "hooks",
    feature = "antidebug",
    feature = "unlink"
))]
pub mod manipulation;
#[cfg(feature = "navigation")]
pub mod navigation;
pub mod structures;
pub mod util;
pub mod version;

// re-exports for convenience
pub use error::{Result, WraithError};
pub use structures::{Peb, Teb};
pub use version::{WindowsRelease, WindowsVersion};

/// library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
