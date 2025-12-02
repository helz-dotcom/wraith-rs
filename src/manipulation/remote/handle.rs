//! Handle duplication and stealing operations

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec, vec::Vec};

use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    get_syscall_table, nt_close, nt_success, DirectSyscall,
};

/// options for handle duplication
#[derive(Debug, Clone, Copy)]
pub struct HandleDuplicateOptions {
    /// desired access rights for the duplicated handle
    pub desired_access: u32,
    /// handle attributes (e.g., OBJ_INHERIT)
    pub attributes: u32,
    /// options (e.g., DUPLICATE_SAME_ACCESS, DUPLICATE_CLOSE_SOURCE)
    pub options: u32,
}

impl Default for HandleDuplicateOptions {
    fn default() -> Self {
        Self {
            desired_access: 0,
            attributes: 0,
            options: DUPLICATE_SAME_ACCESS,
        }
    }
}

impl HandleDuplicateOptions {
    /// duplicate with same access rights
    pub fn same_access() -> Self {
        Self::default()
    }

    /// duplicate and close the source handle
    pub fn close_source() -> Self {
        Self {
            desired_access: 0,
            attributes: 0,
            options: DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
        }
    }

    /// duplicate with specific access rights
    pub fn with_access(access: u32) -> Self {
        Self {
            desired_access: access,
            attributes: 0,
            options: 0,
        }
    }
}

/// information about a handle in a process
#[derive(Debug, Clone)]
pub struct HandleInfo {
    pub handle_value: usize,
    pub object_type: u32,
    pub granted_access: u32,
    pub object_name: Option<String>,
}

/// wrapper for a stolen/duplicated handle
pub struct StolenHandle {
    handle: usize,
    owns_handle: bool,
}

impl StolenHandle {
    /// get the raw handle value
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// release ownership of the handle (don't close on drop)
    pub fn leak(mut self) -> usize {
        self.owns_handle = false;
        self.handle
    }

    /// create from raw handle value
    ///
    /// # Safety
    /// caller must ensure handle is valid
    pub unsafe fn from_raw(handle: usize) -> Self {
        Self {
            handle,
            owns_handle: true,
        }
    }

    /// create without ownership
    ///
    /// # Safety
    /// caller must ensure handle is valid
    pub unsafe fn from_raw_borrowed(handle: usize) -> Self {
        Self {
            handle,
            owns_handle: false,
        }
    }
}

impl Drop for StolenHandle {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != 0 {
            let _ = nt_close(self.handle);
        }
    }
}

/// duplicate a handle from one process to another
pub fn duplicate_handle(
    source_process: usize,
    source_handle: usize,
    target_process: usize,
    options: HandleDuplicateOptions,
) -> Result<StolenHandle> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtDuplicateObject")?;

    let mut target_handle: usize = 0;

    // SAFETY: all handles are assumed valid by caller
    let status = unsafe {
        syscall.call_many(&[
            source_process,
            source_handle,
            target_process,
            &mut target_handle as *mut usize as usize,
            options.desired_access as usize,
            options.attributes as usize,
            options.options as usize,
        ])
    };

    if nt_success(status) {
        Ok(StolenHandle {
            handle: target_handle,
            owns_handle: true,
        })
    } else {
        Err(WraithError::HandleDuplicateFailed {
            reason: format!("NtDuplicateObject failed: {:#x}", status as u32),
        })
    }
}

/// steal a handle from a remote process to the current process
pub fn steal_handle(
    source_process: usize,
    remote_handle: usize,
    options: HandleDuplicateOptions,
) -> Result<StolenHandle> {
    let current_process: usize = usize::MAX; // pseudo handle
    duplicate_handle(source_process, remote_handle, current_process, options)
}

/// enumerate handles in the system
///
/// returns handles matching optional filter criteria
pub fn enumerate_system_handles(
    process_id_filter: Option<u32>,
    object_type_filter: Option<u32>,
) -> Result<Vec<SystemHandleEntry>> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQuerySystemInformation")?;

    const SYSTEM_HANDLE_INFORMATION: u32 = 16;
    const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;

    // start with 1MB buffer, grow if needed
    let mut buffer_size: usize = 1024 * 1024;
    let mut buffer: Vec<u8>;
    let mut return_length: u32 = 0;

    loop {
        buffer = vec![0u8; buffer_size];

        let status = unsafe {
            syscall.call4(
                SYSTEM_EXTENDED_HANDLE_INFORMATION as usize,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                &mut return_length as *mut u32 as usize,
            )
        };

        if nt_success(status) {
            break;
        }

        // STATUS_INFO_LENGTH_MISMATCH
        if status == 0xC0000004_u32 as i32 {
            buffer_size = return_length as usize + 0x10000;
            if buffer_size > 256 * 1024 * 1024 {
                return Err(WraithError::HandleDuplicateFailed {
                    reason: "buffer too large".into(),
                });
            }
            continue;
        }

        return Err(WraithError::HandleDuplicateFailed {
            reason: format!("NtQuerySystemInformation failed: {:#x}", status as u32),
        });
    }

    // parse the handle information
    parse_handle_info(&buffer, process_id_filter, object_type_filter)
}

#[repr(C)]
struct SystemHandleTableEntryInfoEx {
    object: usize,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

/// entry from system handle enumeration
#[derive(Debug, Clone)]
pub struct SystemHandleEntry {
    pub process_id: u32,
    pub handle_value: usize,
    pub object_type: u16,
    pub granted_access: u32,
    pub object_address: usize,
}

fn parse_handle_info(
    buffer: &[u8],
    process_id_filter: Option<u32>,
    object_type_filter: Option<u32>,
) -> Result<Vec<SystemHandleEntry>> {
    if buffer.len() < 16 {
        return Ok(Vec::new());
    }

    // first usize is number of handles
    let count = unsafe { *(buffer.as_ptr() as *const usize) };
    if count == 0 || count > 10_000_000 {
        return Ok(Vec::new());
    }

    let entry_size = core::mem::size_of::<SystemHandleTableEntryInfoEx>();
    let entries_start = 2 * core::mem::size_of::<usize>(); // skip count and reserved

    let mut handles = Vec::new();

    for i in 0..count {
        let offset = entries_start + i * entry_size;
        if offset + entry_size > buffer.len() {
            break;
        }

        let entry = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SystemHandleTableEntryInfoEx)
        };

        // apply filters
        if let Some(pid) = process_id_filter {
            if entry.unique_process_id != pid as usize {
                continue;
            }
        }

        if let Some(obj_type) = object_type_filter {
            if entry.object_type_index as u32 != obj_type {
                continue;
            }
        }

        handles.push(SystemHandleEntry {
            process_id: entry.unique_process_id as u32,
            handle_value: entry.handle_value,
            object_type: entry.object_type_index,
            granted_access: entry.granted_access,
            object_address: entry.object,
        });
    }

    Ok(handles)
}

/// find handles of a specific type in a target process
pub fn find_handles_in_process(
    target_pid: u32,
    object_type: Option<u32>,
) -> Result<Vec<SystemHandleEntry>> {
    enumerate_system_handles(Some(target_pid), object_type)
}

/// steal a process handle from another process
///
/// useful for bypassing process protection by duplicating an existing handle
pub fn steal_process_handle(
    source_process_handle: usize,
    remote_handle: usize,
) -> Result<StolenHandle> {
    steal_handle(source_process_handle, remote_handle, HandleDuplicateOptions::same_access())
}

/// object types for filtering
pub mod object_types {
    pub const PROCESS: u32 = 7;
    pub const THREAD: u32 = 8;
    pub const FILE: u32 = 31; // varies by Windows version
    pub const SECTION: u32 = 43; // varies by Windows version
    pub const KEY: u32 = 19; // registry key
}

// duplicate options
const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_duplicate_options() {
        let opts = HandleDuplicateOptions::same_access();
        assert!(opts.options & DUPLICATE_SAME_ACCESS != 0);

        let opts = HandleDuplicateOptions::close_source();
        assert!(opts.options & DUPLICATE_CLOSE_SOURCE != 0);
        assert!(opts.options & DUPLICATE_SAME_ACCESS != 0);
    }

    #[test]
    fn test_enumerate_own_handles() {
        let pid = std::process::id();
        let result = find_handles_in_process(pid, None);
        assert!(result.is_ok());

        let handles = result.unwrap();
        // we should have at least some handles
        assert!(!handles.is_empty(), "should have handles");
    }
}
