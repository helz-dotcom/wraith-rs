//! SIMD-accelerated pattern matching
//!
//! Uses SSE2/AVX2 for fast pattern scanning when available.
//! Falls back to scalar implementation on unsupported platforms.
//!
//! In `no_std` mode, runtime SIMD detection is disabled and defaults to
//! scalar implementation. Use target features to enable SIMD at compile time.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;

/// SIMD implementation selector
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdLevel {
    /// No SIMD available, use scalar
    None,
    /// SSE2 available (128-bit)
    Sse2,
    /// AVX2 available (256-bit)
    Avx2,
}

impl SimdLevel {
    /// detect the best available SIMD level at runtime
    ///
    /// in `no_std` mode, this uses compile-time target features instead of runtime detection.
    /// enable `target-feature=+avx2` or `target-feature=+sse2` at compile time for SIMD acceleration.
    #[inline]
    pub fn detect() -> Self {
        #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "x86")))]
        {
            if is_x86_feature_detected!("avx2") {
                return SimdLevel::Avx2;
            }
            if is_x86_feature_detected!("sse2") {
                return SimdLevel::Sse2;
            }
        }

        // in no_std mode, use compile-time feature detection
        #[cfg(all(not(feature = "std"), any(target_arch = "x86_64", target_arch = "x86")))]
        {
            #[cfg(target_feature = "avx2")]
            {
                return SimdLevel::Avx2;
            }
            #[cfg(all(not(target_feature = "avx2"), target_feature = "sse2"))]
            {
                return SimdLevel::Sse2;
            }
        }

        SimdLevel::None
    }
}

/// SIMD-accelerated pattern scanner
pub struct SimdScanner {
    /// pattern bytes
    pattern: Vec<u8>,
    /// mask: true = wildcard (match any)
    mask: Vec<bool>,
    /// first non-wildcard byte index (for SIMD skip)
    first_concrete_idx: Option<usize>,
    /// first non-wildcard byte value
    first_concrete_byte: u8,
    /// detected SIMD level
    simd_level: SimdLevel,
}

impl SimdScanner {
    /// create a new SIMD scanner from pattern bytes and mask
    pub fn new(pattern: Vec<u8>, mask: Vec<bool>) -> Self {
        // find first non-wildcard byte for SIMD acceleration
        let (first_concrete_idx, first_concrete_byte) = mask
            .iter()
            .enumerate()
            .find(|(_, &is_wildcard)| !is_wildcard)
            .map(|(i, _)| (Some(i), pattern[i]))
            .unwrap_or((None, 0));

        Self {
            pattern,
            mask,
            first_concrete_idx,
            first_concrete_byte,
            simd_level: SimdLevel::detect(),
        }
    }

    /// get pattern length
    #[inline]
    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    /// check if pattern is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }

    /// scan data for pattern, returns offsets of all matches
    pub fn scan(&self, data: &[u8]) -> Vec<usize> {
        if self.pattern.is_empty() || data.len() < self.pattern.len() {
            return Vec::new();
        }

        // if pattern is all wildcards, match everything
        if self.first_concrete_idx.is_none() {
            return (0..=data.len() - self.pattern.len()).collect();
        }

        match self.simd_level {
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            SimdLevel::Avx2 => unsafe { self.scan_avx2(data) },
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            SimdLevel::Sse2 => unsafe { self.scan_sse2(data) },
            _ => self.scan_scalar(data),
        }
    }

    /// scan data for first match only
    pub fn scan_first(&self, data: &[u8]) -> Option<usize> {
        if self.pattern.is_empty() || data.len() < self.pattern.len() {
            return None;
        }

        if self.first_concrete_idx.is_none() {
            return Some(0);
        }

        match self.simd_level {
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            SimdLevel::Avx2 => unsafe { self.scan_first_avx2(data) },
            #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
            SimdLevel::Sse2 => unsafe { self.scan_first_sse2(data) },
            _ => self.scan_first_scalar(data),
        }
    }

    /// scalar fallback implementation
    fn scan_scalar(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let max_offset = data.len() - self.pattern.len();

        for offset in 0..=max_offset {
            if self.matches_at(data, offset) {
                results.push(offset);
            }
        }

        results
    }

    /// scalar first match
    fn scan_first_scalar(&self, data: &[u8]) -> Option<usize> {
        let max_offset = data.len() - self.pattern.len();

        for offset in 0..=max_offset {
            if self.matches_at(data, offset) {
                return Some(offset);
            }
        }

        None
    }

    /// check if pattern matches at offset
    #[inline]
    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        self.pattern
            .iter()
            .zip(self.mask.iter())
            .enumerate()
            .all(|(i, (&pattern_byte, &is_wildcard))| {
                is_wildcard || data[offset + i] == pattern_byte
            })
    }

    /// AVX2 accelerated scan (256-bit, 32 bytes at a time)
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[target_feature(enable = "avx2")]
    unsafe fn scan_avx2(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let pattern_len = self.pattern.len();
        let first_idx = self.first_concrete_idx.unwrap();

        if data.len() < pattern_len {
            return results;
        }

        let max_offset = data.len() - pattern_len;

        // SAFETY: avx2 is guaranteed available by target_feature
        // broadcast the first concrete byte to all lanes
        let needle = unsafe { _mm256_set1_epi8(self.first_concrete_byte as i8) };

        // we search for first_concrete_byte, accounting for its position in pattern
        // the first concrete byte can appear at positions first_idx through max_offset + first_idx
        let search_start = first_idx;
        let search_end = max_offset + first_idx + 1; // +1 for exclusive end

        if search_end <= search_start {
            return self.scan_scalar(data);
        }

        let mut pos = search_start;

        // process 32 bytes at a time
        while pos + 32 <= search_end {
            // SAFETY: bounds checked, avx2 available
            let chunk = unsafe { _mm256_loadu_si256(data.as_ptr().add(pos) as *const __m256i) };
            let cmp = unsafe { _mm256_cmpeq_epi8(chunk, needle) };
            let mut mask = unsafe { _mm256_movemask_epi8(cmp) } as u32;

            while mask != 0 {
                let bit_pos = mask.trailing_zeros() as usize;
                let candidate_offset = pos + bit_pos - first_idx;

                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    results.push(candidate_offset);
                }

                mask &= mask - 1; // clear lowest set bit
            }

            pos += 32;
        }

        // handle remaining bytes with scalar
        while pos < search_end {
            if data[pos] == self.first_concrete_byte {
                let candidate_offset = pos - first_idx;
                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    results.push(candidate_offset);
                }
            }
            pos += 1;
        }

        results
    }

    /// AVX2 first match
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[target_feature(enable = "avx2")]
    unsafe fn scan_first_avx2(&self, data: &[u8]) -> Option<usize> {
        let pattern_len = self.pattern.len();
        let first_idx = self.first_concrete_idx.unwrap();

        if data.len() < pattern_len {
            return None;
        }

        let max_offset = data.len() - pattern_len;
        // SAFETY: avx2 guaranteed by target_feature
        let needle = unsafe { _mm256_set1_epi8(self.first_concrete_byte as i8) };

        let search_start = first_idx;
        let search_end = max_offset + first_idx + 1; // +1 for exclusive end

        if search_end <= search_start {
            return self.scan_first_scalar(data);
        }

        let mut pos = search_start;

        while pos + 32 <= search_end {
            // SAFETY: bounds checked, avx2 available
            let chunk = unsafe { _mm256_loadu_si256(data.as_ptr().add(pos) as *const __m256i) };
            let cmp = unsafe { _mm256_cmpeq_epi8(chunk, needle) };
            let mut mask = unsafe { _mm256_movemask_epi8(cmp) } as u32;

            while mask != 0 {
                let bit_pos = mask.trailing_zeros() as usize;
                let candidate_offset = pos + bit_pos - first_idx;

                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    return Some(candidate_offset);
                }

                mask &= mask - 1;
            }

            pos += 32;
        }

        // scalar remainder
        while pos < search_end {
            if data[pos] == self.first_concrete_byte {
                let candidate_offset = pos - first_idx;
                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    return Some(candidate_offset);
                }
            }
            pos += 1;
        }

        None
    }

    /// SSE2 accelerated scan (128-bit, 16 bytes at a time)
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[target_feature(enable = "sse2")]
    unsafe fn scan_sse2(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let pattern_len = self.pattern.len();
        let first_idx = self.first_concrete_idx.unwrap();

        if data.len() < pattern_len {
            return results;
        }

        let max_offset = data.len() - pattern_len;
        // SAFETY: sse2 guaranteed by target_feature
        let needle = unsafe { _mm_set1_epi8(self.first_concrete_byte as i8) };

        let search_start = first_idx;
        let search_end = max_offset + first_idx + 1; // +1 for exclusive end

        if search_end <= search_start {
            return self.scan_scalar(data);
        }

        let mut pos = search_start;

        // process 16 bytes at a time
        while pos + 16 <= search_end {
            // SAFETY: bounds checked, sse2 available
            let chunk = unsafe { _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i) };
            let cmp = unsafe { _mm_cmpeq_epi8(chunk, needle) };
            let mut mask = unsafe { _mm_movemask_epi8(cmp) } as u16;

            while mask != 0 {
                let bit_pos = mask.trailing_zeros() as usize;
                let candidate_offset = pos + bit_pos - first_idx;

                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    results.push(candidate_offset);
                }

                mask &= mask - 1;
            }

            pos += 16;
        }

        // scalar remainder
        while pos < search_end {
            if data[pos] == self.first_concrete_byte {
                let candidate_offset = pos - first_idx;
                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    results.push(candidate_offset);
                }
            }
            pos += 1;
        }

        results
    }

    /// SSE2 first match
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[target_feature(enable = "sse2")]
    unsafe fn scan_first_sse2(&self, data: &[u8]) -> Option<usize> {
        let pattern_len = self.pattern.len();
        let first_idx = self.first_concrete_idx.unwrap();

        if data.len() < pattern_len {
            return None;
        }

        let max_offset = data.len() - pattern_len;
        // SAFETY: sse2 guaranteed by target_feature
        let needle = unsafe { _mm_set1_epi8(self.first_concrete_byte as i8) };

        let search_start = first_idx;
        let search_end = max_offset + first_idx + 1; // +1 for exclusive end

        if search_end <= search_start {
            return self.scan_first_scalar(data);
        }

        let mut pos = search_start;

        while pos + 16 <= search_end {
            // SAFETY: bounds checked, sse2 available
            let chunk = unsafe { _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i) };
            let cmp = unsafe { _mm_cmpeq_epi8(chunk, needle) };
            let mut mask = unsafe { _mm_movemask_epi8(cmp) } as u16;

            while mask != 0 {
                let bit_pos = mask.trailing_zeros() as usize;
                let candidate_offset = pos + bit_pos - first_idx;

                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    return Some(candidate_offset);
                }

                mask &= mask - 1;
            }

            pos += 16;
        }

        // scalar remainder
        while pos < search_end {
            if data[pos] == self.first_concrete_byte {
                let candidate_offset = pos - first_idx;
                if candidate_offset <= max_offset && self.matches_at(data, candidate_offset) {
                    return Some(candidate_offset);
                }
            }
            pos += 1;
        }

        None
    }
}

/// scan data for pattern using SIMD when available
///
/// pattern format: space-separated hex bytes, `?` or `??` for wildcards
pub fn simd_scan(data: &[u8], pattern: &str) -> Vec<usize> {
    let (bytes, mask) = match parse_pattern(pattern) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let scanner = SimdScanner::new(bytes, mask);
    scanner.scan(data)
}

/// scan data for first pattern match using SIMD
pub fn simd_scan_first(data: &[u8], pattern: &str) -> Option<usize> {
    let (bytes, mask) = parse_pattern(pattern)?;
    let scanner = SimdScanner::new(bytes, mask);
    scanner.scan_first(data)
}

/// parse IDA-style pattern into bytes and mask
fn parse_pattern(pattern: &str) -> Option<(Vec<u8>, Vec<bool>)> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let mut bytes = Vec::with_capacity(parts.len());
    let mut mask = Vec::with_capacity(parts.len());

    for part in parts {
        if part == "?" || part == "??" || part == "*" || part == "**" {
            bytes.push(0);
            mask.push(true);
        } else {
            let byte = u8::from_str_radix(part, 16).ok()?;
            bytes.push(byte);
            mask.push(false);
        }
    }

    Some((bytes, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simd_level_detect() {
        let level = SimdLevel::detect();
        // should at least detect something on modern CPUs
        println!("Detected SIMD level: {:?}", level);
    }

    #[test]
    fn test_simd_scan_simple() {
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90];
        let results = simd_scan(&data, "48 8B 05");
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_simd_scan_wildcards() {
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90];
        let results = simd_scan(&data, "48 8B ?? ?? 34");
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_simd_scan_no_match() {
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90];
        let results = simd_scan(&data, "FF FF FF");
        assert!(results.is_empty());
    }

    #[test]
    fn test_simd_scan_multiple_matches() {
        let data = [0x48, 0x8B, 0x48, 0x8B, 0x48, 0x8B];
        let results = simd_scan(&data, "48 8B");
        assert_eq!(results, vec![0, 2, 4]);
    }

    #[test]
    fn test_simd_scan_first() {
        let data = [0x48, 0x8B, 0x48, 0x8B, 0x48, 0x8B];
        let result = simd_scan_first(&data, "48 8B");
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_simd_scan_large_data() {
        // test with data larger than SIMD register width
        let mut data = vec![0u8; 1024];
        data[500] = 0xDE;
        data[501] = 0xAD;
        data[502] = 0xBE;
        data[503] = 0xEF;

        let results = simd_scan(&data, "DE AD BE EF");
        assert_eq!(results, vec![500]);
    }

    #[test]
    fn test_simd_scan_pattern_at_end() {
        let data = [0x00, 0x00, 0x00, 0x48, 0x8B];
        let results = simd_scan(&data, "48 8B");
        assert_eq!(results, vec![3]);
    }

    #[test]
    fn test_simd_scan_wildcard_first() {
        // pattern starts with wildcard - this exercises the edge case
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34];
        let results = simd_scan(&data, "?? 8B 05");
        assert_eq!(results, vec![0]);
    }
}
