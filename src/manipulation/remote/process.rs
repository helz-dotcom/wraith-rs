//! Remote process wrapper for cross-process operations

use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    nt_allocate_virtual_memory, nt_close, nt_free_virtual_memory, nt_open_process,
    nt_protect_virtual_memory, nt_read_virtual_memory, nt_write_virtual_memory,
    ClientId, ObjectAttributes, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// process access rights configuration
#[derive(Debug, Clone, Copy)]
pub struct ProcessAccess {
    pub rights: u32,
}

impl ProcessAccess {
    pub const fn all() -> Self {
        Self { rights: PROCESS_ALL_ACCESS }
    }

    pub const fn read_write() -> Self {
        Self {
            rights: PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        }
    }

    pub const fn read_only() -> Self {
        Self {
            rights: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        }
    }

    pub const fn query() -> Self {
        Self {
            rights: PROCESS_QUERY_INFORMATION,
        }
    }

    pub const fn custom(rights: u32) -> Self {
        Self { rights }
    }
}

impl Default for ProcessAccess {
    fn default() -> Self {
        Self::all()
    }
}

/// wrapper for a remote process handle with memory operations
pub struct RemoteProcess {
    handle: usize,
    pid: u32,
    owns_handle: bool,
}

impl RemoteProcess {
    /// open a process by PID with specified access rights
    pub fn open(pid: u32, access: ProcessAccess) -> Result<Self> {
        let obj_attr = ObjectAttributes::new();
        let client_id = ClientId::for_process(pid);

        let handle = nt_open_process(access.rights, &obj_attr, &client_id).map_err(|e| {
            WraithError::ProcessOpenFailed {
                pid,
                reason: format!("{}", e),
            }
        })?;

        Ok(Self {
            handle,
            pid,
            owns_handle: true,
        })
    }

    /// open a process with all access rights
    pub fn open_all_access(pid: u32) -> Result<Self> {
        Self::open(pid, ProcessAccess::all())
    }

    /// create from an existing handle (does not take ownership)
    ///
    /// # Safety
    /// caller must ensure handle is valid and has appropriate access rights
    pub unsafe fn from_handle(handle: usize, pid: u32) -> Self {
        Self {
            handle,
            pid,
            owns_handle: false,
        }
    }

    /// create from an existing handle (takes ownership)
    ///
    /// # Safety
    /// caller must ensure handle is valid and has appropriate access rights
    pub unsafe fn from_handle_owned(handle: usize, pid: u32) -> Self {
        Self {
            handle,
            pid,
            owns_handle: true,
        }
    }

    /// get the raw process handle
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// get the process ID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// read memory from the remote process
    pub fn read(&self, address: usize, buffer: &mut [u8]) -> Result<usize> {
        nt_read_virtual_memory(self.handle, address, buffer).map_err(|e| {
            WraithError::ReadFailed {
                address: address as u64,
                size: buffer.len(),
            }
        })
    }

    /// read a typed value from the remote process
    pub fn read_value<T: Copy>(&self, address: usize) -> Result<T> {
        let mut buffer = vec![0u8; core::mem::size_of::<T>()];
        self.read(address, &mut buffer)?;
        // SAFETY: buffer is correctly sized and we just read the bytes
        Ok(unsafe { (buffer.as_ptr() as *const T).read_unaligned() })
    }

    /// read a null-terminated string from the remote process
    pub fn read_string(&self, address: usize, max_len: usize) -> Result<String> {
        let mut buffer = vec![0u8; max_len];
        let bytes_read = self.read(address, &mut buffer)?;

        let end = buffer.iter()
            .take(bytes_read)
            .position(|&b| b == 0)
            .unwrap_or(bytes_read);

        String::from_utf8_lossy(&buffer[..end]).into_owned();
        Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
    }

    /// read a wide string from the remote process
    pub fn read_wstring(&self, address: usize, max_chars: usize) -> Result<String> {
        let mut buffer = vec![0u16; max_chars];
        let byte_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                buffer.as_mut_ptr() as *mut u8,
                max_chars * 2,
            )
        };

        let bytes_read = self.read(address, byte_buffer)?;
        let chars_read = bytes_read / 2;

        let end = buffer.iter()
            .take(chars_read)
            .position(|&c| c == 0)
            .unwrap_or(chars_read);

        Ok(String::from_utf16_lossy(&buffer[..end]))
    }

    /// write memory to the remote process
    pub fn write(&self, address: usize, buffer: &[u8]) -> Result<usize> {
        nt_write_virtual_memory(self.handle, address, buffer).map_err(|_| {
            WraithError::WriteFailed {
                address: address as u64,
                size: buffer.len(),
            }
        })
    }

    /// write a typed value to the remote process
    pub fn write_value<T: Copy>(&self, address: usize, value: &T) -> Result<usize> {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                value as *const T as *const u8,
                core::mem::size_of::<T>(),
            )
        };
        self.write(address, bytes)
    }

    /// allocate memory in the remote process
    pub fn allocate(
        &self,
        size: usize,
        protection: u32,
    ) -> Result<RemoteAllocation> {
        self.allocate_at(0, size, protection)
    }

    /// allocate memory at a preferred address
    pub fn allocate_at(
        &self,
        preferred_base: usize,
        size: usize,
        protection: u32,
    ) -> Result<RemoteAllocation> {
        let (base, actual_size) = nt_allocate_virtual_memory(
            self.handle,
            preferred_base,
            size,
            MEM_COMMIT | MEM_RESERVE,
            protection,
        )
        .map_err(|e| WraithError::AllocationFailed {
            size,
            protection,
        })?;

        Ok(RemoteAllocation {
            process_handle: self.handle,
            base,
            size: actual_size,
            owns_memory: true,
        })
    }

    /// allocate RW memory
    pub fn allocate_rw(&self, size: usize) -> Result<RemoteAllocation> {
        self.allocate(size, PAGE_READWRITE)
    }

    /// allocate RWX memory
    pub fn allocate_rwx(&self, size: usize) -> Result<RemoteAllocation> {
        self.allocate(size, PAGE_EXECUTE_READWRITE)
    }

    /// allocate RX memory
    pub fn allocate_rx(&self, size: usize) -> Result<RemoteAllocation> {
        self.allocate(size, PAGE_EXECUTE_READ)
    }

    /// change memory protection in the remote process
    pub fn protect(&self, address: usize, size: usize, protection: u32) -> Result<u32> {
        nt_protect_virtual_memory(self.handle, address, size, protection).map_err(|_| {
            WraithError::ProtectionChangeFailed {
                address: address as u64,
                size,
            }
        })
    }

    /// change protection with RAII guard that restores on drop
    pub fn protect_guard(
        &self,
        address: usize,
        size: usize,
        new_protection: u32,
    ) -> Result<RemoteProtectionGuard> {
        let old_protection = self.protect(address, size, new_protection)?;
        Ok(RemoteProtectionGuard {
            process_handle: self.handle,
            address,
            size,
            old_protection,
        })
    }

    /// free allocated memory in the remote process
    pub fn free(&self, address: usize) -> Result<()> {
        nt_free_virtual_memory(self.handle, address, MEM_RELEASE).map_err(|_| {
            WraithError::AllocationFailed {
                size: 0,
                protection: 0,
            }
        })
    }

    /// write shellcode and allocate executable memory
    pub fn write_shellcode(&self, shellcode: &[u8]) -> Result<RemoteAllocation> {
        let alloc = self.allocate_rw(shellcode.len())?;
        self.write(alloc.base, shellcode)?;
        self.protect(alloc.base, alloc.size, PAGE_EXECUTE_READ)?;
        Ok(alloc)
    }

    /// write and execute shellcode via remote thread
    pub fn execute_shellcode(&self, shellcode: &[u8]) -> Result<u32> {
        let alloc = self.write_shellcode(shellcode)?;
        let thread = super::create_remote_thread(
            self,
            alloc.base,
            0,
            super::RemoteThreadOptions::default(),
        )?;
        Ok(thread.id())
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != 0 {
            let _ = nt_close(self.handle);
        }
    }
}

// SAFETY: handle is process-specific and can be sent between threads
unsafe impl Send for RemoteProcess {}
unsafe impl Sync for RemoteProcess {}

/// RAII wrapper for remote memory allocation
pub struct RemoteAllocation {
    process_handle: usize,
    base: usize,
    size: usize,
    owns_memory: bool,
}

impl RemoteAllocation {
    /// get the base address
    pub fn base(&self) -> usize {
        self.base
    }

    /// get the allocation size
    pub fn size(&self) -> usize {
        self.size
    }

    /// leak the allocation (don't free on drop)
    pub fn leak(mut self) -> usize {
        self.owns_memory = false;
        self.base
    }

    /// create from raw values without ownership
    ///
    /// # Safety
    /// caller must ensure the memory region is valid
    pub unsafe fn from_raw(process_handle: usize, base: usize, size: usize) -> Self {
        Self {
            process_handle,
            base,
            size,
            owns_memory: false,
        }
    }
}

impl Drop for RemoteAllocation {
    fn drop(&mut self) {
        if self.owns_memory && self.base != 0 {
            let _ = nt_free_virtual_memory(self.process_handle, self.base, MEM_RELEASE);
        }
    }
}

/// RAII guard for remote memory protection changes
pub struct RemoteProtectionGuard {
    process_handle: usize,
    address: usize,
    size: usize,
    old_protection: u32,
}

impl RemoteProtectionGuard {
    /// get the old protection that will be restored
    pub fn old_protection(&self) -> u32 {
        self.old_protection
    }
}

impl Drop for RemoteProtectionGuard {
    fn drop(&mut self) {
        let _ = nt_protect_virtual_memory(
            self.process_handle,
            self.address,
            self.size,
            self.old_protection,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_access_constants() {
        let all = ProcessAccess::all();
        assert_eq!(all.rights, PROCESS_ALL_ACCESS);

        let rw = ProcessAccess::read_write();
        assert!(rw.rights & PROCESS_VM_READ != 0);
        assert!(rw.rights & PROCESS_VM_WRITE != 0);
    }

    #[test]
    fn test_open_current_process() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only());
        assert!(proc.is_ok(), "should open current process");

        let proc = proc.unwrap();
        assert_eq!(proc.pid(), pid);
        assert!(proc.handle() != 0);
    }
}
