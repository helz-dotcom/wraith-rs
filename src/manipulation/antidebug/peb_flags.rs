//! PEB anti-debug flag manipulation
//!
//! Clears debug indicators in the Process Environment Block (PEB)
//! that are commonly checked by anti-debug code.

use crate::error::Result;
use crate::structures::Peb;

/// debug-related NtGlobalFlag bits set when debugger is attached
const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x10;
const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x20;
const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x40;

/// mask of all debug-related NtGlobalFlag bits
const DEBUG_FLAGS_MASK: u32 =
    FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;

/// clear BeingDebugged flag in PEB
pub fn clear_being_debugged() -> Result<()> {
    let mut peb = Peb::current()?;
    // SAFETY: we're intentionally modifying PEB to hide from debugger
    unsafe {
        peb.set_being_debugged(false);
    }
    Ok(())
}

/// check BeingDebugged flag
pub fn check_being_debugged() -> Result<bool> {
    let peb = Peb::current()?;
    Ok(peb.being_debugged())
}

/// clear debug-related bits from NtGlobalFlag
///
/// when a debugger attaches, these bits are typically set:
/// - FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
/// - FLG_HEAP_ENABLE_FREE_CHECK (0x20)
/// - FLG_HEAP_VALIDATE_PARAMETERS (0x40)
pub fn clear_nt_global_flag() -> Result<()> {
    let mut peb = Peb::current()?;

    let current = peb.nt_global_flag();
    let cleaned = current & !DEBUG_FLAGS_MASK;

    // SAFETY: we're intentionally modifying PEB to hide from debugger
    unsafe {
        peb.set_nt_global_flag(cleaned);
    }

    Ok(())
}

/// check if NtGlobalFlag has debug indicators
pub fn check_nt_global_flag() -> Result<bool> {
    let peb = Peb::current()?;
    let flags = peb.nt_global_flag();
    Ok(flags & DEBUG_FLAGS_MASK != 0)
}

/// get raw NtGlobalFlag value
pub fn get_nt_global_flag() -> Result<u32> {
    let peb = Peb::current()?;
    Ok(peb.nt_global_flag())
}

/// perform full PEB cleanup for anti-debug
pub fn full_peb_cleanup() -> Result<()> {
    clear_being_debugged()?;
    clear_nt_global_flag()?;
    Ok(())
}

/// detailed PEB debug state
#[derive(Debug, Clone)]
pub struct PebDebugState {
    pub being_debugged: bool,
    pub nt_global_flag: u32,
    pub has_debug_flags: bool,
}

impl PebDebugState {
    /// check if any debug indicators are present
    pub fn is_debugged(&self) -> bool {
        self.being_debugged || self.has_debug_flags
    }
}

impl std::fmt::Display for PebDebugState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PEB Debug State:")?;
        writeln!(
            f,
            "  BeingDebugged: {}",
            if self.being_debugged { "TRUE" } else { "FALSE" }
        )?;
        writeln!(f, "  NtGlobalFlag: {:#010x}", self.nt_global_flag)?;
        writeln!(
            f,
            "  Debug flags present: {}",
            if self.has_debug_flags { "YES" } else { "NO" }
        )?;

        if self.has_debug_flags {
            if self.nt_global_flag & FLG_HEAP_ENABLE_TAIL_CHECK != 0 {
                writeln!(f, "    - FLG_HEAP_ENABLE_TAIL_CHECK (0x10)")?;
            }
            if self.nt_global_flag & FLG_HEAP_ENABLE_FREE_CHECK != 0 {
                writeln!(f, "    - FLG_HEAP_ENABLE_FREE_CHECK (0x20)")?;
            }
            if self.nt_global_flag & FLG_HEAP_VALIDATE_PARAMETERS != 0 {
                writeln!(f, "    - FLG_HEAP_VALIDATE_PARAMETERS (0x40)")?;
            }
        }

        Ok(())
    }
}

/// get detailed PEB debug state
pub fn get_peb_debug_state() -> Result<PebDebugState> {
    let peb = Peb::current()?;
    let nt_global_flag = peb.nt_global_flag();

    Ok(PebDebugState {
        being_debugged: peb.being_debugged(),
        nt_global_flag,
        has_debug_flags: nt_global_flag & DEBUG_FLAGS_MASK != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_peb_flags() {
        let state = get_peb_debug_state();
        assert!(state.is_ok());
    }

    #[test]
    fn test_clear_being_debugged() {
        // this should work regardless of debugger presence
        let result = clear_being_debugged();
        assert!(result.is_ok());

        // verify it's cleared
        let debugged = check_being_debugged().unwrap();
        assert!(!debugged);
    }
}
