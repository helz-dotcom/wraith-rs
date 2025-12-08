//! Kernel-mode string types (UNICODE_STRING, ANSI_STRING)

use core::ffi::c_void;
use core::ptr::NonNull;
use alloc::vec::Vec;

use super::allocator::{PoolAllocator, PoolTag, PoolType};
use super::error::{KmError, KmResult};

/// Windows UNICODE_STRING structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnicodeStringRaw {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

impl Default for UnicodeStringRaw {
    fn default() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        }
    }
}

/// safe wrapper around UNICODE_STRING
pub struct UnicodeString {
    inner: UnicodeStringRaw,
    owned: bool,
}

impl UnicodeString {
    /// create empty unicode string
    pub const fn empty() -> Self {
        Self {
            inner: UnicodeStringRaw {
                length: 0,
                maximum_length: 0,
                buffer: core::ptr::null_mut(),
            },
            owned: false,
        }
    }

    /// create from static wide string (null-terminated)
    ///
    /// # Safety
    /// s must be a valid null-terminated wide string that outlives this struct
    pub const unsafe fn from_static(s: &'static [u16]) -> Self {
        let len = (s.len() - 1) * 2; // exclude null terminator
        Self {
            inner: UnicodeStringRaw {
                length: len as u16,
                maximum_length: (s.len() * 2) as u16,
                buffer: s.as_ptr() as *mut u16,
            },
            owned: false,
        }
    }

    /// create owned copy from &str
    pub fn from_str(s: &str) -> KmResult<Self> {
        let wide: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
        Self::from_wide_owned(wide)
    }

    /// create from wide string (takes ownership)
    pub fn from_wide_owned(mut wide: Vec<u16>) -> KmResult<Self> {
        let len_bytes = (wide.len() - 1) * 2; // exclude null terminator
        let max_bytes = wide.len() * 2;

        // ensure null terminator
        if wide.last() != Some(&0) {
            wide.push(0);
        }

        let ptr = wide.as_mut_ptr();
        core::mem::forget(wide); // we now own this memory

        Ok(Self {
            inner: UnicodeStringRaw {
                length: len_bytes as u16,
                maximum_length: max_bytes as u16,
                buffer: ptr,
            },
            owned: true,
        })
    }

    /// get raw structure for FFI
    pub fn as_raw(&self) -> &UnicodeStringRaw {
        &self.inner
    }

    /// get mutable raw structure for FFI
    pub fn as_raw_mut(&mut self) -> &mut UnicodeStringRaw {
        &mut self.inner
    }

    /// get pointer to raw structure
    pub fn as_ptr(&self) -> *const UnicodeStringRaw {
        &self.inner
    }

    /// get mutable pointer to raw structure
    pub fn as_mut_ptr(&mut self) -> *mut UnicodeStringRaw {
        &mut self.inner
    }

    /// get string length in bytes
    pub fn len(&self) -> usize {
        self.inner.length as usize
    }

    /// check if string is empty
    pub fn is_empty(&self) -> bool {
        self.inner.length == 0
    }

    /// get as wide string slice (without null terminator)
    pub fn as_wide(&self) -> &[u16] {
        if self.inner.buffer.is_null() || self.inner.length == 0 {
            return &[];
        }
        // SAFETY: buffer is valid for length bytes
        unsafe {
            core::slice::from_raw_parts(
                self.inner.buffer,
                (self.inner.length / 2) as usize,
            )
        }
    }
}

impl Drop for UnicodeString {
    fn drop(&mut self) {
        if self.owned && !self.inner.buffer.is_null() {
            // reconstruct Vec to deallocate
            let cap = (self.inner.maximum_length / 2) as usize;
            let len = cap; // we allocated this many
            // SAFETY: we allocated this buffer via Vec
            unsafe {
                let _ = Vec::from_raw_parts(self.inner.buffer, len, cap);
            }
        }
    }
}

/// Windows ANSI_STRING structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AnsiStringRaw {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u8,
}

impl Default for AnsiStringRaw {
    fn default() -> Self {
        Self {
            length: 0,
            maximum_length: 0,
            buffer: core::ptr::null_mut(),
        }
    }
}

/// safe wrapper around ANSI_STRING
pub struct AnsiString {
    inner: AnsiStringRaw,
    owned: bool,
}

impl AnsiString {
    /// create empty ansi string
    pub const fn empty() -> Self {
        Self {
            inner: AnsiStringRaw {
                length: 0,
                maximum_length: 0,
                buffer: core::ptr::null_mut(),
            },
            owned: false,
        }
    }

    /// create from static byte string
    ///
    /// # Safety
    /// s must be a valid null-terminated string that outlives this struct
    pub const unsafe fn from_static(s: &'static [u8]) -> Self {
        let len = s.len() - 1; // exclude null terminator
        Self {
            inner: AnsiStringRaw {
                length: len as u16,
                maximum_length: s.len() as u16,
                buffer: s.as_ptr() as *mut u8,
            },
            owned: false,
        }
    }

    /// create owned copy from &str
    pub fn from_str(s: &str) -> KmResult<Self> {
        let mut bytes: Vec<u8> = s.as_bytes().to_vec();
        bytes.push(0); // null terminator

        let len = s.len();
        let max_len = bytes.len();
        let ptr = bytes.as_mut_ptr();
        core::mem::forget(bytes);

        Ok(Self {
            inner: AnsiStringRaw {
                length: len as u16,
                maximum_length: max_len as u16,
                buffer: ptr,
            },
            owned: true,
        })
    }

    /// get raw structure for FFI
    pub fn as_raw(&self) -> &AnsiStringRaw {
        &self.inner
    }

    /// get as byte slice (without null terminator)
    pub fn as_bytes(&self) -> &[u8] {
        if self.inner.buffer.is_null() || self.inner.length == 0 {
            return &[];
        }
        // SAFETY: buffer is valid for length bytes
        unsafe {
            core::slice::from_raw_parts(self.inner.buffer, self.inner.length as usize)
        }
    }
}

impl Drop for AnsiString {
    fn drop(&mut self) {
        if self.owned && !self.inner.buffer.is_null() {
            let cap = self.inner.maximum_length as usize;
            // SAFETY: we allocated this buffer via Vec
            unsafe {
                let _ = Vec::from_raw_parts(self.inner.buffer, cap, cap);
            }
        }
    }
}

/// helper macro to create static unicode strings
#[macro_export]
macro_rules! unicode_str {
    ($s:literal) => {{
        const WIDE: &[u16] = &$crate::km::string::encode_wide_const($s);
        // SAFETY: static lifetime
        unsafe { $crate::km::string::UnicodeString::from_static(WIDE) }
    }};
}

/// compile-time wide string encoding (limited to ASCII)
pub const fn encode_wide_const<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    let mut result = [0u16; N];
    let mut i = 0;
    while i < bytes.len() && i < N - 1 {
        result[i] = bytes[i] as u16;
        i += 1;
    }
    result
}
