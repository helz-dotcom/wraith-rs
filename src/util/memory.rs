//! Memory read/write utilities

use crate::error::{Result, WraithError};

/// read memory at address into value
///
/// # Safety
/// address must be valid and readable
pub unsafe fn read_memory<T: Copy>(address: usize) -> Result<T> {
    if address == 0 {
        return Err(WraithError::NullPointer {
            context: "read_memory",
        });
    }

    // SAFETY: caller ensures address validity
    Ok(unsafe { (address as *const T).read_unaligned() })
}

/// write value to memory at address
///
/// # Safety
/// address must be valid and writable
pub unsafe fn write_memory<T: Copy>(address: usize, value: &T) -> Result<()> {
    if address == 0 {
        return Err(WraithError::NullPointer {
            context: "write_memory",
        });
    }

    // SAFETY: caller ensures address validity
    unsafe {
        (address as *mut T).write_unaligned(*value);
    }
    Ok(())
}

/// change memory protection
pub fn protect_memory(address: usize, size: usize, protection: u32) -> Result<u32> {
    let mut old_protect: u32 = 0;

    let result = unsafe {
        VirtualProtect(
            address as *mut _,
            size,
            protection,
            &mut old_protect,
        )
    };

    if result == 0 {
        Err(WraithError::ProtectionChangeFailed {
            address: u64::try_from(address).unwrap_or(u64::MAX),
            size,
        })
    } else {
        Ok(old_protect)
    }
}

/// RAII guard for memory protection changes
pub struct ProtectionGuard {
    address: usize,
    size: usize,
    old_protection: u32,
}

impl ProtectionGuard {
    /// change protection, returning guard that restores on drop
    pub fn new(address: usize, size: usize, new_protection: u32) -> Result<Self> {
        let old_protection = protect_memory(address, size, new_protection)?;
        Ok(Self {
            address,
            size,
            old_protection,
        })
    }
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        let _ = protect_memory(self.address, self.size, self.old_protection);
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualProtect(
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
}
