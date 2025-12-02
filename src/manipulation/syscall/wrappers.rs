//! Typed wrappers for common syscalls
//!
//! Provides safe-ish Rust interfaces for frequently used NT syscalls,
//! handling argument marshaling and error checking.
//!
//! Note: These wrappers require the `std` feature for the global syscall table.

#[cfg(feature = "std")]
use super::get_syscall_table;
use super::{nt_success, DirectSyscall};
use crate::error::{Result, WraithError};

// NT structures for syscall arguments

/// OBJECT_ATTRIBUTES structure
#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: usize,
    pub object_name: *const UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *const core::ffi::c_void,
    pub security_quality_of_service: *const core::ffi::c_void,
}

impl Default for ObjectAttributes {
    fn default() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            root_directory: 0,
            object_name: core::ptr::null(),
            attributes: 0,
            security_descriptor: core::ptr::null(),
            security_quality_of_service: core::ptr::null(),
        }
    }
}

impl ObjectAttributes {
    /// create empty OBJECT_ATTRIBUTES
    pub fn new() -> Self {
        Self::default()
    }

    /// create with OBJ_CASE_INSENSITIVE
    pub fn case_insensitive() -> Self {
        Self {
            attributes: OBJ_CASE_INSENSITIVE,
            ..Self::default()
        }
    }
}

/// CLIENT_ID structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

impl ClientId {
    /// create for a process ID
    pub fn for_process(pid: u32) -> Self {
        Self {
            unique_process: pid as usize,
            unique_thread: 0,
        }
    }

    /// create for a thread ID
    pub fn for_thread(tid: u32) -> Self {
        Self {
            unique_process: 0,
            unique_thread: tid as usize,
        }
    }
}

/// UNICODE_STRING structure
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *const u16,
}

// object attribute flags
pub const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
pub const OBJ_INHERIT: u32 = 0x00000002;

// process access rights
pub const PROCESS_ALL_ACCESS: u32 = 0x1F0FFF;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

// thread access rights
pub const THREAD_ALL_ACCESS: u32 = 0x1F03FF;
pub const THREAD_SET_INFORMATION: u32 = 0x0020;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;

// thread information classes
pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 17;

// allocation types
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_RELEASE: u32 = 0x8000;

// protection flags
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;

// pseudo handles
pub const CURRENT_PROCESS: usize = usize::MAX; // -1
pub const CURRENT_THREAD: usize = usize::MAX - 1; // -2

// NtClose - close a handle
pub fn nt_close(handle: usize) -> Result<()> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtClose")?;

    // SAFETY: NtClose is safe to call with any handle value
    let status = unsafe { syscall.call1(handle) };

    if nt_success(status) {
        Ok(())
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtClose".into(),
            status,
        })
    }
}

/// NtOpenProcess - open a process handle
pub fn nt_open_process(
    desired_access: u32,
    object_attributes: &ObjectAttributes,
    client_id: &ClientId,
) -> Result<usize> {
    let mut handle: usize = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtOpenProcess")?;

    // SAFETY: all pointers point to valid stack data
    let status = unsafe {
        syscall.call4(
            &mut handle as *mut usize as usize,
            desired_access as usize,
            object_attributes as *const _ as usize,
            client_id as *const _ as usize,
        )
    };

    if nt_success(status) {
        Ok(handle)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtOpenProcess".into(),
            status,
        })
    }
}

/// NtReadVirtualMemory - read memory from a process
pub fn nt_read_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut bytes_read: usize = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtReadVirtualMemory")?;

    // SAFETY: buffer is valid and properly sized
    let status = unsafe {
        syscall.call5(
            process_handle,
            base_address,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut bytes_read as *mut usize as usize,
        )
    };

    if nt_success(status) {
        Ok(bytes_read)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtReadVirtualMemory".into(),
            status,
        })
    }
}

/// NtWriteVirtualMemory - write memory to a process
pub fn nt_write_virtual_memory(
    process_handle: usize,
    base_address: usize,
    buffer: &[u8],
) -> Result<usize> {
    let mut bytes_written: usize = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtWriteVirtualMemory")?;

    // SAFETY: buffer is valid and properly sized
    let status = unsafe {
        syscall.call5(
            process_handle,
            base_address,
            buffer.as_ptr() as usize,
            buffer.len(),
            &mut bytes_written as *mut usize as usize,
        )
    };

    if nt_success(status) {
        Ok(bytes_written)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtWriteVirtualMemory".into(),
            status,
        })
    }
}

/// NtAllocateVirtualMemory - allocate memory in a process
pub fn nt_allocate_virtual_memory(
    process_handle: usize,
    preferred_base: usize,
    size: usize,
    allocation_type: u32,
    protect: u32,
) -> Result<(usize, usize)> {
    let mut base_address = preferred_base;
    let mut region_size = size;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtAllocateVirtualMemory")?;

    // SAFETY: pointers are valid stack addresses
    let status = unsafe {
        syscall.call6(
            process_handle,
            &mut base_address as *mut usize as usize,
            0, // zero_bits
            &mut region_size as *mut usize as usize,
            allocation_type as usize,
            protect as usize,
        )
    };

    if nt_success(status) {
        Ok((base_address, region_size))
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtAllocateVirtualMemory".into(),
            status,
        })
    }
}

/// NtFreeVirtualMemory - free memory in a process
pub fn nt_free_virtual_memory(
    process_handle: usize,
    base_address: usize,
    free_type: u32,
) -> Result<()> {
    let mut base = base_address;
    let mut size: usize = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtFreeVirtualMemory")?;

    // SAFETY: pointers are valid stack addresses
    let status = unsafe {
        syscall.call4(
            process_handle,
            &mut base as *mut usize as usize,
            &mut size as *mut usize as usize,
            free_type as usize,
        )
    };

    if nt_success(status) {
        Ok(())
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtFreeVirtualMemory".into(),
            status,
        })
    }
}

/// NtProtectVirtualMemory - change memory protection
pub fn nt_protect_virtual_memory(
    process_handle: usize,
    base_address: usize,
    size: usize,
    new_protect: u32,
) -> Result<u32> {
    let mut base = base_address;
    let mut region_size = size;
    let mut old_protect: u32 = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtProtectVirtualMemory")?;

    // SAFETY: pointers are valid stack addresses
    let status = unsafe {
        syscall.call5(
            process_handle,
            &mut base as *mut usize as usize,
            &mut region_size as *mut usize as usize,
            new_protect as usize,
            &mut old_protect as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        Ok(old_protect)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtProtectVirtualMemory".into(),
            status,
        })
    }
}

/// NtSetInformationThread - set thread information
///
/// commonly used with ThreadHideFromDebugger (17) to hide threads from debuggers
pub fn nt_set_information_thread(
    thread_handle: usize,
    information_class: u32,
    thread_information: *const core::ffi::c_void,
    thread_information_length: u32,
) -> Result<()> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtSetInformationThread")?;

    // SAFETY: caller is responsible for valid thread_information pointer
    let status = unsafe {
        syscall.call4(
            thread_handle,
            information_class as usize,
            thread_information as usize,
            thread_information_length as usize,
        )
    };

    if nt_success(status) {
        Ok(())
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtSetInformationThread".into(),
            status,
        })
    }
}

/// hide current thread from debugger
pub fn hide_thread_from_debugger() -> Result<()> {
    nt_set_information_thread(
        CURRENT_THREAD,
        THREAD_HIDE_FROM_DEBUGGER,
        core::ptr::null(),
        0,
    )
}

/// NtQuerySystemInformation - query system information
pub fn nt_query_system_information(
    information_class: u32,
    buffer: &mut [u8],
) -> Result<u32> {
    let mut return_length: u32 = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQuerySystemInformation")?;

    // SAFETY: buffer is valid and properly sized
    let status = unsafe {
        syscall.call4(
            information_class as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut return_length as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        Ok(return_length)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtQuerySystemInformation".into(),
            status,
        })
    }
}

/// NtQueryInformationProcess - query process information
pub fn nt_query_information_process(
    process_handle: usize,
    information_class: u32,
    buffer: &mut [u8],
) -> Result<u32> {
    let mut return_length: u32 = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQueryInformationProcess")?;

    // SAFETY: buffer is valid and properly sized
    let status = unsafe {
        syscall.call5(
            process_handle,
            information_class as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut return_length as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        Ok(return_length)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtQueryInformationProcess".into(),
            status,
        })
    }
}

/// NtQueryVirtualMemory - query virtual memory information
pub fn nt_query_virtual_memory(
    process_handle: usize,
    base_address: usize,
    information_class: u32,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut return_length: usize = 0;

    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQueryVirtualMemory")?;

    // SAFETY: buffer is valid and properly sized
    let status = unsafe {
        syscall.call6(
            process_handle,
            base_address,
            information_class as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut return_length as *mut usize as usize,
        )
    };

    if nt_success(status) {
        Ok(return_length)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtQueryVirtualMemory".into(),
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_close_invalid() {
        let result = nt_close(0xDEADBEEF);
        assert!(result.is_err());
    }

    #[test]
    fn test_allocate_and_free() {
        // allocate some memory in current process
        let result = nt_allocate_virtual_memory(
            CURRENT_PROCESS,
            0, // let OS choose address
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if let Ok((base, _size)) = result {
            assert!(base != 0, "should have allocated memory");

            // free it
            let free_result = nt_free_virtual_memory(CURRENT_PROCESS, base, MEM_RELEASE);
            assert!(free_result.is_ok(), "should free memory");
        }
    }

    #[test]
    fn test_protect_memory() {
        // allocate memory
        let (base, _) = nt_allocate_virtual_memory(
            CURRENT_PROCESS,
            0,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
        .expect("should allocate");

        // change protection
        let old = nt_protect_virtual_memory(CURRENT_PROCESS, base, 4096, PAGE_READONLY)
            .expect("should change protection");

        assert_eq!(old, PAGE_READWRITE);

        // cleanup
        let _ = nt_free_virtual_memory(CURRENT_PROCESS, base, MEM_RELEASE);
    }
}
