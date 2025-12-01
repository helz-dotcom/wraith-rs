//! Memory allocation for manual mapping

use crate::error::{Result, WraithError};

// memory allocation constants
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 0x04;

/// allocated memory region for PE image
pub struct MappedMemory {
    base: *mut u8,
    size: usize,
}

impl MappedMemory {
    /// get base address
    pub fn base(&self) -> usize {
        self.base as usize
    }

    /// get allocated size
    pub fn size(&self) -> usize {
        self.size
    }

    /// get mutable slice to entire region
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: base is valid for size bytes, we own the memory
        unsafe { core::slice::from_raw_parts_mut(self.base, self.size) }
    }

    /// get immutable slice to entire region
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: base is valid for size bytes, we own the memory
        unsafe { core::slice::from_raw_parts(self.base, self.size) }
    }

    /// write data at offset
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.size {
            return Err(WraithError::WriteFailed {
                address: (self.base as usize + offset) as u64,
                size: data.len(),
            });
        }

        // SAFETY: bounds checked, we own the memory
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(offset), data.len());
        }
        Ok(())
    }

    /// read value at offset
    pub fn read_at<T: Copy>(&self, offset: usize) -> Result<T> {
        if offset + core::mem::size_of::<T>() > self.size {
            return Err(WraithError::ReadFailed {
                address: (self.base as usize + offset) as u64,
                size: core::mem::size_of::<T>(),
            });
        }

        // SAFETY: bounds checked, read_unaligned handles alignment
        Ok(unsafe { (self.base.add(offset) as *const T).read_unaligned() })
    }

    /// write value at offset
    pub fn write_value_at<T>(&mut self, offset: usize, value: T) -> Result<()> {
        if offset + core::mem::size_of::<T>() > self.size {
            return Err(WraithError::WriteFailed {
                address: (self.base as usize + offset) as u64,
                size: core::mem::size_of::<T>(),
            });
        }

        // SAFETY: bounds checked, write_unaligned handles alignment
        unsafe {
            (self.base.add(offset) as *mut T).write_unaligned(value);
        }
        Ok(())
    }

    /// set memory protection for a region
    pub fn protect(&self, offset: usize, size: usize, protection: u32) -> Result<u32> {
        if offset + size > self.size {
            return Err(WraithError::ProtectionChangeFailed {
                address: (self.base as usize + offset) as u64,
                size,
            });
        }

        let mut old_protect: u32 = 0;

        // SAFETY: address is within our allocated range
        let result = unsafe {
            VirtualProtect(
                self.base.add(offset) as *mut _,
                size,
                protection,
                &mut old_protect,
            )
        };

        if result == 0 {
            return Err(WraithError::ProtectionChangeFailed {
                address: (self.base as usize + offset) as u64,
                size,
            });
        }

        Ok(old_protect)
    }

    /// free the allocated memory
    pub fn free(self) -> Result<()> {
        // SAFETY: self.base was allocated with VirtualAlloc
        let result = unsafe { VirtualFree(self.base as *mut _, 0, MEM_RELEASE) };

        if result == 0 {
            return Err(WraithError::from_last_error("VirtualFree"));
        }

        // prevent Drop from double-freeing
        core::mem::forget(self);
        Ok(())
    }

    /// get pointer at offset
    pub fn ptr_at(&self, offset: usize) -> *mut u8 {
        // SAFETY: caller responsible for bounds
        unsafe { self.base.add(offset) }
    }
}

impl Drop for MappedMemory {
    fn drop(&mut self) {
        // SAFETY: self.base was allocated with VirtualAlloc
        unsafe {
            VirtualFree(self.base as *mut _, 0, MEM_RELEASE);
        }
    }
}

// SAFETY: we own the memory, safe to move between threads
unsafe impl Send for MappedMemory {}
unsafe impl Sync for MappedMemory {}

/// allocate memory for PE image, trying preferred base first
pub fn allocate_image(size: usize, preferred_base: usize) -> Result<MappedMemory> {
    // try preferred base first
    let mut base = unsafe {
        VirtualAlloc(
            preferred_base as *mut _,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    // fall back to any available address
    if base.is_null() {
        base = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
    }

    if base.is_null() {
        return Err(WraithError::AllocationFailed {
            size,
            protection: PAGE_READWRITE,
        });
    }

    // zero the memory
    // SAFETY: base is valid for size bytes
    unsafe {
        core::ptr::write_bytes(base, 0, size);
    }

    Ok(MappedMemory {
        base: base as *mut u8,
        size,
    })
}

/// allocate memory at specific address (fails if not available)
pub fn allocate_at(base: usize, size: usize) -> Result<MappedMemory> {
    let ptr = unsafe {
        VirtualAlloc(
            base as *mut _,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    // must get exact address requested
    if ptr.is_null() || ptr as usize != base {
        if !ptr.is_null() {
            // got wrong address, free it
            unsafe {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
        return Err(WraithError::AllocationFailed {
            size,
            protection: PAGE_READWRITE,
        });
    }

    // zero the memory
    // SAFETY: ptr is valid for size bytes
    unsafe {
        core::ptr::write_bytes(ptr, 0, size);
    }

    Ok(MappedMemory {
        base: ptr as *mut u8,
        size,
    })
}

/// allocate memory anywhere (no preference)
pub fn allocate_anywhere(size: usize) -> Result<MappedMemory> {
    let base = unsafe {
        VirtualAlloc(
            core::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if base.is_null() {
        return Err(WraithError::AllocationFailed {
            size,
            protection: PAGE_READWRITE,
        });
    }

    // zero the memory
    // SAFETY: base is valid for size bytes
    unsafe {
        core::ptr::write_bytes(base, 0, size);
    }

    Ok(MappedMemory {
        base: base as *mut u8,
        size,
    })
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        address: *mut core::ffi::c_void,
        size: usize,
        allocation_type: u32,
        protection: u32,
    ) -> *mut core::ffi::c_void;

    fn VirtualFree(address: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;

    fn VirtualProtect(
        address: *mut core::ffi::c_void,
        size: usize,
        protection: u32,
        old_protection: *mut u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_anywhere() {
        let mem = allocate_anywhere(0x1000).expect("should allocate");
        assert!(mem.base() != 0);
        assert_eq!(mem.size(), 0x1000);
        mem.free().expect("should free");
    }

    #[test]
    fn test_read_write() {
        let mut mem = allocate_anywhere(0x1000).expect("should allocate");

        mem.write_value_at(0, 0xDEADBEEFu32).expect("should write");
        let val: u32 = mem.read_at(0).expect("should read");
        assert_eq!(val, 0xDEADBEEF);

        let data = [1u8, 2, 3, 4];
        mem.write_at(0x100, &data).expect("should write bytes");
        let slice = mem.as_slice();
        assert_eq!(&slice[0x100..0x104], &data);
    }

    #[test]
    fn test_protect() {
        let mem = allocate_anywhere(0x1000).expect("should allocate");

        const PAGE_READONLY: u32 = 0x02;
        let old = mem.protect(0, 0x1000, PAGE_READONLY).expect("should protect");
        assert_eq!(old, PAGE_READWRITE);
    }
}
