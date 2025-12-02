//! Executable memory allocation for trampolines
//!
//! Provides RAII-managed executable memory regions for storing
//! hook trampolines and stub code.

use crate::error::{Result, WraithError};

// memory allocation constants
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// executable memory region for trampolines
///
/// automatically freed when dropped
pub struct ExecutableMemory {
    base: *mut u8,
    size: usize,
    used: usize,
}

impl ExecutableMemory {
    /// allocate executable memory near a target address
    ///
    /// tries to allocate within ±2GB of target for relative jumps.
    /// falls back to any available address if near allocation fails.
    pub fn allocate_near(target: usize, size: usize) -> Result<Self> {
        // round size up to page boundary
        let size = (size + 0xFFF) & !0xFFF;

        // on x64, try to allocate within ±2GB for rel32 jumps
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(mem) = try_allocate_near_x64(target, size) {
                return Ok(mem);
            }
        }

        // fall back to allocation anywhere
        Self::allocate(size)
    }

    /// allocate executable memory at any available address
    pub fn allocate(size: usize) -> Result<Self> {
        let size = (size + 0xFFF) & !0xFFF;

        let base = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if base.is_null() {
            return Err(WraithError::AllocationFailed {
                size,
                protection: PAGE_EXECUTE_READWRITE,
            });
        }

        // zero the memory
        // SAFETY: base is valid for size bytes
        unsafe {
            core::ptr::write_bytes(base, 0xCC, size); // fill with INT3
        }

        Ok(Self {
            base: base as *mut u8,
            size,
            used: 0,
        })
    }

    /// get base address
    pub fn base(&self) -> usize {
        self.base as usize
    }

    /// get total allocated size
    pub fn size(&self) -> usize {
        self.size
    }

    /// get used bytes
    pub fn used(&self) -> usize {
        self.used
    }

    /// get available bytes
    pub fn available(&self) -> usize {
        self.size - self.used
    }

    /// write code to the memory region
    ///
    /// returns the address where the code was written
    pub fn write(&mut self, code: &[u8]) -> Result<usize> {
        if code.len() > self.available() {
            return Err(WraithError::WriteFailed {
                address: self.base as u64,
                size: code.len(),
            });
        }

        let write_addr = self.base as usize + self.used;

        // SAFETY: bounds checked, we own the memory
        unsafe {
            core::ptr::copy_nonoverlapping(code.as_ptr(), write_addr as *mut u8, code.len());
        }

        self.used += code.len();

        Ok(write_addr)
    }

    /// get pointer at offset
    pub fn ptr_at(&self, offset: usize) -> *mut u8 {
        // SAFETY: caller responsible for bounds checking
        unsafe { self.base.add(offset) }
    }

    /// read bytes from offset
    pub fn read_at(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.size {
            return Err(WraithError::ReadFailed {
                address: (self.base as usize + offset) as u64,
                size: len,
            });
        }

        // SAFETY: bounds checked
        Ok(unsafe { core::slice::from_raw_parts(self.base.add(offset), len) })
    }

    /// check if an address is within this memory region
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base as usize && addr < (self.base as usize + self.size)
    }

    /// check if this memory is within rel32 range of target
    pub fn is_near(&self, target: usize) -> bool {
        let base = self.base as usize;
        let distance = if base > target {
            base - target
        } else {
            target - base
        };
        distance <= i32::MAX as usize
    }

    /// flush instruction cache for this region
    pub fn flush_icache(&self) -> Result<()> {
        let result = unsafe {
            FlushInstructionCache(
                GetCurrentProcess(),
                self.base as *const _,
                self.size,
            )
        };

        if result == 0 {
            Err(WraithError::from_last_error("FlushInstructionCache"))
        } else {
            Ok(())
        }
    }

    /// take ownership without freeing
    pub fn leak(self) -> *mut u8 {
        let ptr = self.base;
        core::mem::forget(self);
        ptr
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        // SAFETY: self.base was allocated with VirtualAlloc
        unsafe {
            VirtualFree(self.base as *mut _, 0, MEM_RELEASE);
        }
    }
}

// SAFETY: we own the memory, safe to move between threads
unsafe impl Send for ExecutableMemory {}
unsafe impl Sync for ExecutableMemory {}

/// try to allocate near target on x64
#[cfg(target_arch = "x86_64")]
fn try_allocate_near_x64(target: usize, size: usize) -> Option<ExecutableMemory> {
    // try addresses within ±2GB of target
    // search in 64KB increments (allocation granularity)
    const GRANULARITY: usize = 0x10000;
    const SEARCH_RANGE: i64 = 0x7FFF0000; // slightly less than 2GB

    let target_i64 = target as i64;

    // try below target first (often has more free space)
    let mut addr = (target_i64 - SEARCH_RANGE).max(0x10000) as usize;
    addr = addr & !(GRANULARITY - 1); // align down

    while (addr as i64) < target_i64 {
        let ptr = unsafe {
            VirtualAlloc(
                addr as *mut _,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if !ptr.is_null() {
            // verify it's actually within range
            let distance = (target as i64 - ptr as i64).abs();
            if distance <= i32::MAX as i64 {
                unsafe {
                    core::ptr::write_bytes(ptr, 0xCC, size);
                }
                return Some(ExecutableMemory {
                    base: ptr as *mut u8,
                    size,
                    used: 0,
                });
            }
            // wrong location, free and try next
            unsafe {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
        addr += GRANULARITY;
    }

    // try above target
    addr = ((target_i64 + 0x10000) & !(GRANULARITY as i64 - 1)) as usize;
    let max_addr = (target_i64 + SEARCH_RANGE) as usize;

    while addr < max_addr {
        let ptr = unsafe {
            VirtualAlloc(
                addr as *mut _,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if !ptr.is_null() {
            let distance = (target as i64 - ptr as i64).abs();
            if distance <= i32::MAX as i64 {
                unsafe {
                    core::ptr::write_bytes(ptr, 0xCC, size);
                }
                return Some(ExecutableMemory {
                    base: ptr as *mut u8,
                    size,
                    used: 0,
                });
            }
            unsafe {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
        addr += GRANULARITY;
    }

    None
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut core::ffi::c_void;

    fn VirtualFree(lpAddress: *mut core::ffi::c_void, dwSize: usize, dwFreeType: u32) -> i32;

    fn FlushInstructionCache(
        hProcess: *mut core::ffi::c_void,
        lpBaseAddress: *const core::ffi::c_void,
        dwSize: usize,
    ) -> i32;

    fn GetCurrentProcess() -> *mut core::ffi::c_void;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate() {
        let mem = ExecutableMemory::allocate(0x1000).unwrap();
        assert!(mem.base() != 0);
        assert!(mem.size() >= 0x1000);
        assert_eq!(mem.used(), 0);
    }

    #[test]
    fn test_write() {
        let mut mem = ExecutableMemory::allocate(0x1000).unwrap();
        let code = [0x90, 0x90, 0x90, 0xC3]; // nop; nop; nop; ret

        let addr = mem.write(&code).unwrap();
        assert_eq!(addr, mem.base());
        assert_eq!(mem.used(), 4);

        let read = mem.read_at(0, 4).unwrap();
        assert_eq!(read, &code);
    }

    #[test]
    fn test_contains() {
        let mem = ExecutableMemory::allocate(0x1000).unwrap();
        assert!(mem.contains(mem.base()));
        assert!(mem.contains(mem.base() + 0x500));
        assert!(!mem.contains(mem.base() + 0x2000));
    }
}
