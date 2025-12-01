//! DllMain / entry point invocation

use super::allocator::MappedMemory;
use super::parser::ParsedPe;
use crate::error::{Result, WraithError};

/// DllMain function signature
type DllMain = unsafe extern "system" fn(
    module: *mut core::ffi::c_void,
    reason: u32,
    reserved: *mut core::ffi::c_void,
) -> i32;

/// DLL call reasons
pub mod reason {
    pub const DLL_PROCESS_DETACH: u32 = 0;
    pub const DLL_PROCESS_ATTACH: u32 = 1;
    pub const DLL_THREAD_ATTACH: u32 = 2;
    pub const DLL_THREAD_DETACH: u32 = 3;
}

/// call PE entry point (DllMain)
pub fn call_entry_point(pe: &ParsedPe, memory: &MappedMemory, call_reason: u32) -> Result<bool> {
    let entry_rva = pe.entry_point_rva();

    // no entry point - some DLLs have none
    if entry_rva == 0 {
        return Ok(true);
    }

    let entry_va = memory.base() + entry_rva as usize;

    // verify entry point is within our mapped image
    if entry_va < memory.base() || entry_va >= memory.base() + memory.size() {
        return Err(WraithError::EntryPointFailed { status: -1 });
    }

    // SAFETY: entry_va points to valid code within our mapped image
    let entry_fn: DllMain = unsafe { core::mem::transmute(entry_va) };

    // SAFETY: calling DllMain with correct signature
    let result = unsafe { entry_fn(memory.base() as *mut _, call_reason, core::ptr::null_mut()) };

    // DllMain returns FALSE (0) on failure
    if result == 0 && call_reason == reason::DLL_PROCESS_ATTACH {
        Err(WraithError::EntryPointFailed { status: result })
    } else {
        Ok(result != 0)
    }
}

/// call entry point for DLL_PROCESS_ATTACH
pub fn call_dll_attach(pe: &ParsedPe, memory: &MappedMemory) -> Result<bool> {
    call_entry_point(pe, memory, reason::DLL_PROCESS_ATTACH)
}

/// call entry point for DLL_PROCESS_DETACH
pub fn call_dll_detach(pe: &ParsedPe, memory: &MappedMemory) -> Result<bool> {
    call_entry_point(pe, memory, reason::DLL_PROCESS_DETACH)
}

/// call entry point for DLL_THREAD_ATTACH
pub fn call_thread_attach(pe: &ParsedPe, memory: &MappedMemory) -> Result<bool> {
    call_entry_point(pe, memory, reason::DLL_THREAD_ATTACH)
}

/// call entry point for DLL_THREAD_DETACH
pub fn call_thread_detach(pe: &ParsedPe, memory: &MappedMemory) -> Result<bool> {
    call_entry_point(pe, memory, reason::DLL_THREAD_DETACH)
}

/// check if PE has an entry point
pub fn has_entry_point(pe: &ParsedPe) -> bool {
    pe.entry_point_rva() != 0
}

/// get entry point address for a mapped PE
pub fn get_entry_point_va(pe: &ParsedPe, memory: &MappedMemory) -> Option<usize> {
    let rva = pe.entry_point_rva();
    if rva == 0 {
        None
    } else {
        Some(memory.base() + rva as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_entry_point() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();
        let pe = ParsedPe::parse(&data).unwrap();

        // executable should have entry point
        assert!(has_entry_point(&pe));
    }
}
