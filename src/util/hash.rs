//! String hashing utilities for API hashing

/// DJB2 hash algorithm
pub const fn djb2_hash(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        hash = hash.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    hash
}

/// FNV-1a hash algorithm
pub const fn fnv1a_hash(s: &[u8]) -> u32 {
    const FNV_OFFSET: u32 = 2166136261;
    const FNV_PRIME: u32 = 16777619;

    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// hash string with lowercase conversion (for case-insensitive matching)
pub const fn djb2_hash_lowercase(s: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        let c = if s[i] >= b'A' && s[i] <= b'Z' {
            s[i] + 32
        } else {
            s[i]
        };
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
        i += 1;
    }
    hash
}

/// compile-time hash macro
#[macro_export]
macro_rules! hash {
    ($s:expr) => {
        $crate::util::hash::djb2_hash($s.as_bytes())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_djb2() {
        assert_eq!(djb2_hash(b"ntdll.dll"), djb2_hash(b"ntdll.dll"));
        assert_ne!(djb2_hash(b"ntdll.dll"), djb2_hash(b"kernel32.dll"));
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(
            djb2_hash_lowercase(b"NtDll.Dll"),
            djb2_hash_lowercase(b"ntdll.dll")
        );
    }
}
