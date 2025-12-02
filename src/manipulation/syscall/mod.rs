//! Direct and indirect syscall infrastructure
//!
//! This module provides the ability to invoke Windows syscalls directly,
//! bypassing usermode hooks placed by EDRs on ntdll functions.
//!
//! # Modes
//!
//! - **Direct**: Inline `syscall` instruction with SSN in eax
//! - **Indirect**: Jump to ntdll's syscall instruction for cleaner call stack
//! - **Native**: Fall back to normal API calls
//!
//! # Usage
//!
//! ```no_run
//! use wraith::manipulation::syscall::{get_syscall_table, DirectSyscall};
//!
//! let table = get_syscall_table().unwrap();
//! let syscall = DirectSyscall::from_table(&table, "NtClose").unwrap();
//! let status = unsafe { syscall.call1(handle) };
//! ```

mod direct;
mod enumerator;
mod indirect;
mod table;
mod wrappers;

pub use direct::DirectSyscall;
pub use enumerator::{enumerate_syscalls, EnumeratedSyscall, SyscallEnumerator};
pub use indirect::IndirectSyscall;
pub use table::{hashes, SyscallEntry, SyscallTable};
pub use wrappers::*;

use crate::error::Result;

#[cfg(feature = "std")]
use std::sync::OnceLock;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::format;

#[cfg(feature = "std")]
static SYSCALL_TABLE: OnceLock<Result<SyscallTable>> = OnceLock::new();

/// get or initialize the global syscall table
///
/// note: in no_std mode, this creates a new table each call since
/// global lazy initialization requires std. consider caching the
/// result yourself in no_std environments.
#[cfg(feature = "std")]
pub fn get_syscall_table() -> Result<&'static SyscallTable> {
    let result = SYSCALL_TABLE.get_or_init(SyscallTable::enumerate);
    match result {
        Ok(table) => Ok(table),
        Err(e) => Err(crate::error::WraithError::SyscallEnumerationFailed {
            reason: format!("{}", e),
        }),
    }
}

/// enumerate syscall table (no caching)
///
/// in no_std mode, you must cache the result yourself if needed.
#[cfg(not(feature = "std"))]
pub fn enumerate_syscall_table() -> Result<SyscallTable> {
    SyscallTable::enumerate()
}

/// syscall invocation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallMode {
    /// inline syscall instruction (mov eax, ssn; syscall)
    Direct,
    /// jump to syscall instruction in ntdll
    Indirect,
    /// use normal API call (fallback)
    Native,
}

impl Default for SyscallMode {
    fn default() -> Self {
        Self::Direct
    }
}

/// preferred syscall mode (can be changed at runtime)
static PREFERRED_MODE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// set preferred syscall mode
pub fn set_syscall_mode(mode: SyscallMode) {
    let value = match mode {
        SyscallMode::Direct => 0,
        SyscallMode::Indirect => 1,
        SyscallMode::Native => 2,
    };
    PREFERRED_MODE.store(value, core::sync::atomic::Ordering::Relaxed);
}

/// get current syscall mode
pub fn get_syscall_mode() -> SyscallMode {
    match PREFERRED_MODE.load(core::sync::atomic::Ordering::Relaxed) {
        0 => SyscallMode::Direct,
        1 => SyscallMode::Indirect,
        _ => SyscallMode::Native,
    }
}

/// check NTSTATUS for success
#[inline]
pub const fn nt_success(status: i32) -> bool {
    status >= 0
}

/// NTSTATUS codes
pub mod status {
    pub const STATUS_SUCCESS: i32 = 0;
    pub const STATUS_INVALID_HANDLE: i32 = 0xC0000008_u32 as i32;
    pub const STATUS_ACCESS_DENIED: i32 = 0xC0000022_u32 as i32;
    pub const STATUS_BUFFER_TOO_SMALL: i32 = 0xC0000023_u32 as i32;
    pub const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004_u32 as i32;
}
