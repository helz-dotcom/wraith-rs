//! UNICODE_STRING structure with safe access

use core::slice;

/// raw UNICODE_STRING structure matching Windows definition
#[repr(C)]
#[derive(Debug)]
pub struct UnicodeString {
    pub length: u16,         // length in bytes (not chars), not including null
    pub maximum_length: u16, // total buffer size in bytes
    pub buffer: *mut u16,    // wide string pointer
}

impl UnicodeString {
    /// check if string is empty or null
    pub fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer.is_null()
    }

    /// get string as wide char slice (without null terminator)
    ///
    /// # Safety
    /// buffer must be valid for length bytes
    pub unsafe fn as_slice(&self) -> &[u16] {
        if self.is_empty() {
            return &[];
        }
        let char_count = (self.length / 2) as usize;
        // SAFETY: caller guarantees buffer validity
        unsafe { slice::from_raw_parts(self.buffer, char_count) }
    }

    /// convert to Rust String
    ///
    /// # Safety
    /// buffer must be valid
    pub unsafe fn to_string(&self) -> String {
        let slice = unsafe { self.as_slice() };
        String::from_utf16_lossy(slice)
    }

    /// convert to lowercase String for comparison
    ///
    /// # Safety
    /// buffer must be valid
    pub unsafe fn to_string_lowercase(&self) -> String {
        unsafe { self.to_string() }.to_lowercase()
    }

    /// case-insensitive comparison with str
    ///
    /// # Safety
    /// buffer must be valid
    pub unsafe fn eq_ignore_case(&self, other: &str) -> bool {
        let self_str = unsafe { self.to_string_lowercase() };
        self_str == other.to_lowercase()
    }

    /// case-insensitive comparison with wide string
    ///
    /// # Safety
    /// buffer must be valid
    pub unsafe fn eq_wide_ignore_case(&self, other: &[u16]) -> bool {
        let slice = unsafe { self.as_slice() };
        if slice.len() != other.len() {
            return false;
        }
        slice.iter().zip(other.iter()).all(|(&a, &b)| {
            // simple ASCII case-insensitive comparison
            let a_lower = if a >= 'A' as u16 && a <= 'Z' as u16 {
                a + 32
            } else {
                a
            };
            let b_lower = if b >= 'A' as u16 && b <= 'Z' as u16 {
                b + 32
            } else {
                b
            };
            a_lower == b_lower
        })
    }
}

/// helper to convert &str to wide string for comparison
pub fn str_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}
