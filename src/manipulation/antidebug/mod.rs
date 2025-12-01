//! Anti-debugging techniques
//!
//! This module provides functionality to detect and evade debugger
//! presence through various Windows anti-debug techniques.

mod heap_flags;
mod peb_flags;
mod thread_hide;

pub use heap_flags::{check_heap_flags, clear_heap_flags};
pub use peb_flags::{
    check_being_debugged, check_nt_global_flag, clear_being_debugged, clear_nt_global_flag,
    full_peb_cleanup,
};
pub use thread_hide::{get_hidden_threads, hide_current_thread, hide_thread, is_thread_hidden};

use crate::error::Result;

/// perform full anti-debug cleanup
///
/// clears all common debug indicators:
/// - PEB.BeingDebugged flag
/// - PEB.NtGlobalFlag debug bits
/// - Heap debug flags
pub fn full_cleanup() -> Result<()> {
    full_peb_cleanup()?;
    clear_heap_flags()?;
    Ok(())
}

/// check if any debug indicators are present
pub fn is_debugger_present() -> Result<bool> {
    // check PEB.BeingDebugged
    if check_being_debugged()? {
        return Ok(true);
    }

    // check NtGlobalFlag
    if check_nt_global_flag()? {
        return Ok(true);
    }

    // check heap flags
    if check_heap_flags()? {
        return Ok(true);
    }

    Ok(false)
}

/// debug indicator status
#[derive(Debug, Clone)]
pub struct DebugStatus {
    pub being_debugged: bool,
    pub nt_global_flag: bool,
    pub heap_flags: bool,
}

impl DebugStatus {
    /// check if any indicator is set
    pub fn any_detected(&self) -> bool {
        self.being_debugged || self.nt_global_flag || self.heap_flags
    }
}

impl std::fmt::Display for DebugStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Debug Status:")?;
        writeln!(
            f,
            "  BeingDebugged: {}",
            if self.being_debugged { "YES" } else { "no" }
        )?;
        writeln!(
            f,
            "  NtGlobalFlag: {}",
            if self.nt_global_flag { "YES" } else { "no" }
        )?;
        writeln!(
            f,
            "  HeapFlags: {}",
            if self.heap_flags { "YES" } else { "no" }
        )
    }
}

/// get detailed debug status
pub fn get_debug_status() -> Result<DebugStatus> {
    Ok(DebugStatus {
        being_debugged: check_being_debugged()?,
        nt_global_flag: check_nt_global_flag()?,
        heap_flags: check_heap_flags()?,
    })
}
