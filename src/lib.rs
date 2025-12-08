#![cfg(windows)]
#![cfg_attr(not(feature = "std"), no_std)]
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
//!
//! # Feature Flags
//!
//! - `std` (default): Use the standard library. Disable for `no_std` environments.
//! - `alloc`: Enable heap allocation in `no_std` mode (requires an allocator).

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod arch;
pub mod error;
#[cfg(any(
    feature = "manual-map",
    feature = "syscalls",
    feature = "spoof",
    feature = "hooks",
    feature = "antidebug",
    feature = "unlink",
    feature = "remote"
))]
pub mod manipulation;
#[cfg(feature = "navigation")]
pub mod navigation;
pub mod structures;
pub mod util;
pub mod version;

#[cfg(feature = "kernel")]
pub mod km;

#[cfg(feature = "kernel-client")]
pub mod km_client;

// re-exports for convenience
pub use error::{Result, WraithError};
pub use structures::{Peb, Teb};
pub use version::{WindowsRelease, WindowsVersion};

/// library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
