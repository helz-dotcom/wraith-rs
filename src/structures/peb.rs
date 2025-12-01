//! PEB (Process Environment Block) structure

use super::ldr::PebLdrData;
use super::offsets::PebOffsets;
use crate::arch::{segment, NativePtr};
use crate::error::{Result, WraithError};
use crate::version::WindowsVersion;
use core::ptr::NonNull;

/// safe wrapper around PEB access
pub struct Peb {
    ptr: NonNull<u8>,
    offsets: &'static PebOffsets,
}

impl Peb {
    /// get PEB for current process
    pub fn current() -> Result<Self> {
        // SAFETY: segment::get_peb always returns valid PEB for current process
        let ptr = unsafe { segment::get_peb() };
        let ptr = NonNull::new(ptr).ok_or(WraithError::InvalidPebAccess)?;

        let version = WindowsVersion::current()?;
        let offsets = PebOffsets::for_version(&version)?;

        Ok(Self { ptr, offsets })
    }

    /// raw PEB pointer
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// check BeingDebugged flag
    pub fn being_debugged(&self) -> bool {
        // SAFETY: ptr is valid, offset is correct for this version
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.being_debugged);
            *(addr as *const u8) != 0
        }
    }

    /// set BeingDebugged flag
    ///
    /// # Safety
    /// modifies process state
    pub unsafe fn set_being_debugged(&mut self, value: bool) {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.being_debugged);
            *(addr as *mut u8) = if value { 1 } else { 0 };
        }
    }

    /// get NtGlobalFlag value
    pub fn nt_global_flag(&self) -> u32 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.nt_global_flag);
            *(addr as *const u32)
        }
    }

    /// set NtGlobalFlag value
    ///
    /// # Safety
    /// modifies process state
    pub unsafe fn set_nt_global_flag(&mut self, value: u32) {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.nt_global_flag);
            *(addr as *mut u32) = value;
        }
    }

    /// get pointer to PEB_LDR_DATA
    pub fn ldr(&self) -> Option<&PebLdrData> {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.ldr);
            let ldr_ptr = *(addr as *const *const PebLdrData);
            if ldr_ptr.is_null() {
                None
            } else {
                Some(&*ldr_ptr)
            }
        }
    }

    /// get mutable pointer to PEB_LDR_DATA
    ///
    /// # Safety
    /// caller must ensure exclusive access
    pub unsafe fn ldr_mut(&mut self) -> Option<&mut PebLdrData> {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.ldr);
            let ldr_ptr = *(addr as *mut *mut PebLdrData);
            if ldr_ptr.is_null() {
                None
            } else {
                Some(&mut *ldr_ptr)
            }
        }
    }

    /// get image base address
    pub fn image_base(&self) -> NativePtr {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.image_base);
            *(addr as *const NativePtr)
        }
    }

    /// get process heap pointer
    pub fn process_heap(&self) -> NativePtr {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.process_heap);
            *(addr as *const NativePtr)
        }
    }

    /// get number of processors
    pub fn number_of_processors(&self) -> u32 {
        unsafe {
            let addr = self.ptr.as_ptr().add(self.offsets.number_of_processors);
            *(addr as *const u32)
        }
    }
}

// manual Send/Sync - PEB is process-wide but our wrapper is safe
unsafe impl Send for Peb {}
unsafe impl Sync for Peb {}
