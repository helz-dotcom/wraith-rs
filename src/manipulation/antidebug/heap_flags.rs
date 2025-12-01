//! Heap debug flag manipulation
//!
//! Clears debug flags from the process heap that are set when
//! a debugger is attached.

use crate::error::{Result, WraithError};
use crate::structures::Peb;

/// heap structure offsets for Flags and ForceFlags fields
#[cfg(target_arch = "x86_64")]
mod offsets {
    pub const HEAP_FLAGS: usize = 0x70;
    pub const HEAP_FORCE_FLAGS: usize = 0x74;
}

#[cfg(target_arch = "x86")]
mod offsets {
    pub const HEAP_FLAGS: usize = 0x40;
    pub const HEAP_FORCE_FLAGS: usize = 0x44;
}

/// heap flag values
const HEAP_GROWABLE: u32 = 0x00000002;
const HEAP_TAIL_CHECKING_ENABLED: u32 = 0x00000020;
const HEAP_FREE_CHECKING_ENABLED: u32 = 0x00000040;
const HEAP_VALIDATE_PARAMETERS_ENABLED: u32 = 0x40000000;

/// mask of flags set by debugger
const DEBUG_FLAGS_MASK: u32 =
    HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_VALIDATE_PARAMETERS_ENABLED;

/// expected flags for non-debugged process (just HEAP_GROWABLE)
const CLEAN_FLAGS: u32 = HEAP_GROWABLE;

/// clear debug flags from process heap
pub fn clear_heap_flags() -> Result<()> {
    let peb = Peb::current()?;
    let process_heap = peb.process_heap() as usize;

    if process_heap == 0 {
        return Err(WraithError::NullPointer {
            context: "process heap",
        });
    }

    // read and clean Flags
    let flags_addr = process_heap + offsets::HEAP_FLAGS;
    // SAFETY: heap structure is valid for process heap
    let flags = unsafe { *(flags_addr as *const u32) };
    let clean_flags = flags & !DEBUG_FLAGS_MASK;
    unsafe {
        *(flags_addr as *mut u32) = clean_flags;
    }

    // read and clean ForceFlags
    let force_flags_addr = process_heap + offsets::HEAP_FORCE_FLAGS;
    let force_flags = unsafe { *(force_flags_addr as *const u32) };
    let clean_force = force_flags & !DEBUG_FLAGS_MASK;
    unsafe {
        *(force_flags_addr as *mut u32) = clean_force;
    }

    Ok(())
}

/// check if heap has debug flags set
pub fn check_heap_flags() -> Result<bool> {
    let peb = Peb::current()?;
    let process_heap = peb.process_heap() as usize;

    if process_heap == 0 {
        return Err(WraithError::NullPointer {
            context: "process heap",
        });
    }

    let flags_addr = process_heap + offsets::HEAP_FLAGS;
    // SAFETY: heap structure is valid for process heap
    let flags = unsafe { *(flags_addr as *const u32) };

    Ok(flags & DEBUG_FLAGS_MASK != 0)
}

/// get raw heap flags
pub fn get_heap_flags() -> Result<HeapFlags> {
    let peb = Peb::current()?;
    let process_heap = peb.process_heap() as usize;

    if process_heap == 0 {
        return Err(WraithError::NullPointer {
            context: "process heap",
        });
    }

    let flags_addr = process_heap + offsets::HEAP_FLAGS;
    let force_flags_addr = process_heap + offsets::HEAP_FORCE_FLAGS;

    // SAFETY: heap structure is valid
    let flags = unsafe { *(flags_addr as *const u32) };
    let force_flags = unsafe { *(force_flags_addr as *const u32) };

    Ok(HeapFlags { flags, force_flags })
}

/// heap flag values
#[derive(Debug, Clone, Copy)]
pub struct HeapFlags {
    pub flags: u32,
    pub force_flags: u32,
}

impl HeapFlags {
    /// check if debug flags are present
    pub fn has_debug_flags(&self) -> bool {
        (self.flags & DEBUG_FLAGS_MASK != 0) || (self.force_flags & DEBUG_FLAGS_MASK != 0)
    }

    /// check individual debug flags
    pub fn tail_checking_enabled(&self) -> bool {
        self.flags & HEAP_TAIL_CHECKING_ENABLED != 0
    }

    pub fn free_checking_enabled(&self) -> bool {
        self.flags & HEAP_FREE_CHECKING_ENABLED != 0
    }

    pub fn validate_parameters_enabled(&self) -> bool {
        self.flags & HEAP_VALIDATE_PARAMETERS_ENABLED != 0
    }
}

impl std::fmt::Display for HeapFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Heap Flags:")?;
        writeln!(f, "  Flags: {:#010x}", self.flags)?;
        writeln!(f, "  ForceFlags: {:#010x}", self.force_flags)?;
        writeln!(
            f,
            "  Debug flags present: {}",
            if self.has_debug_flags() { "YES" } else { "NO" }
        )?;

        if self.has_debug_flags() {
            if self.tail_checking_enabled() {
                writeln!(f, "    - HEAP_TAIL_CHECKING_ENABLED (0x20)")?;
            }
            if self.free_checking_enabled() {
                writeln!(f, "    - HEAP_FREE_CHECKING_ENABLED (0x40)")?;
            }
            if self.validate_parameters_enabled() {
                writeln!(f, "    - HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_heap_flags() {
        let flags = get_heap_flags();
        assert!(flags.is_ok());
    }

    #[test]
    fn test_clear_heap_flags() {
        let result = clear_heap_flags();
        assert!(result.is_ok());

        // verify debug flags are cleared
        let has_debug = check_heap_flags().unwrap();
        assert!(!has_debug);
    }
}
