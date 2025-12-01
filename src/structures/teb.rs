//! TEB (Thread Environment Block) structure

use super::offsets::TebOffsets;
use crate::arch::segment;
use crate::error::{Result, WraithError};
use crate::version::WindowsVersion;
use core::ptr::NonNull;

/// safe wrapper around TEB access
pub struct Teb {
    ptr: NonNull<u8>,
    offsets: &'static TebOffsets,
}

impl Teb {
    /// get TEB for current thread
    pub fn current() -> Result<Self> {
        let ptr = unsafe { segment::get_teb() };
        let ptr = NonNull::new(ptr).ok_or(WraithError::InvalidTebAccess)?;

        let version = WindowsVersion::current()?;
        let offsets = TebOffsets::for_version(&version)?;

        Ok(Self { ptr, offsets })
    }

    /// raw TEB pointer
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// get process ID
    pub fn process_id(&self) -> u32 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.client_id);
            // ClientId.UniqueProcess is first field
            #[cfg(target_arch = "x86_64")]
            {
                *(addr as *const u64) as u32
            }
            #[cfg(target_arch = "x86")]
            {
                *(addr as *const u32)
            }
        }
    }

    /// get thread ID
    pub fn thread_id(&self) -> u32 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.client_id);
            // ClientId.UniqueThread is second field
            #[cfg(target_arch = "x86_64")]
            {
                let tid_addr = addr.add(8);
                *(tid_addr as *const u64) as u32
            }
            #[cfg(target_arch = "x86")]
            {
                let tid_addr = addr.add(4);
                *(tid_addr as *const u32)
            }
        }
    }

    /// get PEB pointer from TEB
    pub fn peb(&self) -> *mut u8 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.peb);
            #[cfg(target_arch = "x86_64")]
            {
                *(addr as *const u64) as *mut u8
            }
            #[cfg(target_arch = "x86")]
            {
                *(addr as *const u32) as *mut u8
            }
        }
    }

    /// get last error value
    pub fn last_error(&self) -> u32 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.last_error);
            *(addr as *const u32)
        }
    }

    /// set last error value
    pub fn set_last_error(&mut self, value: u32) {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.last_error);
            *(addr as *mut u32) = value;
        }
    }

    /// get stack base
    pub fn stack_base(&self) -> usize {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.stack_base);
            #[cfg(target_arch = "x86_64")]
            {
                *(addr as *const u64) as usize
            }
            #[cfg(target_arch = "x86")]
            {
                *(addr as *const u32) as usize
            }
        }
    }

    /// get stack limit
    pub fn stack_limit(&self) -> usize {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.stack_limit);
            #[cfg(target_arch = "x86_64")]
            {
                *(addr as *const u64) as usize
            }
            #[cfg(target_arch = "x86")]
            {
                *(addr as *const u32) as usize
            }
        }
    }
}
