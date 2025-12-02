//! Pattern scanning for memory and modules
//!
//! Supports multiple pattern formats:
//! - IDA-style: `"48 8B 05 ?? ?? ?? ?? 48 89"` (wildcards as `??` or `?`)
//! - Code-style: bytes + mask (`"\x48\x8B"` with `"xx??"`)
//! - Raw bytes with mask array

use crate::error::{Result, WraithError};

/// parsed byte pattern with wildcard mask
#[derive(Debug, Clone)]
pub struct Pattern {
    pub(crate) bytes: Vec<u8>,
    pub(crate) mask: Vec<bool>, // true = wildcard (match any)
}

impl Pattern {
    /// create pattern from bytes and mask arrays
    pub fn from_bytes_mask(bytes: &[u8], mask: &[bool]) -> Result<Self> {
        if bytes.len() != mask.len() {
            return Err(WraithError::PatternParseFailed {
                reason: "bytes and mask length mismatch".into(),
            });
        }
        if bytes.is_empty() {
            return Err(WraithError::PatternParseFailed {
                reason: "empty pattern".into(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            mask: mask.to_vec(),
        })
    }

    /// create pattern from bytes and string mask
    ///
    /// mask format: `x` = exact match, `?` = wildcard
    /// example: `"xx????xx"` for 8 bytes with 4 wildcards in middle
    pub fn from_code(bytes: &[u8], mask: &str) -> Result<Self> {
        if bytes.len() != mask.len() {
            return Err(WraithError::PatternParseFailed {
                reason: format!(
                    "bytes length ({}) != mask length ({})",
                    bytes.len(),
                    mask.len()
                ),
            });
        }
        if bytes.is_empty() {
            return Err(WraithError::PatternParseFailed {
                reason: "empty pattern".into(),
            });
        }

        let mask_bits: Vec<bool> = mask
            .chars()
            .map(|c| c == '?' || c == '.')
            .collect();

        Ok(Self {
            bytes: bytes.to_vec(),
            mask: mask_bits,
        })
    }

    /// parse IDA-style pattern string
    ///
    /// format: space-separated hex bytes, `?` or `??` for wildcards
    /// examples:
    /// - `"48 8B 05 ?? ?? ?? ?? 48 89"`
    /// - `"48 8B 05 ? ? ? ? 48 89"`
    /// - `"E8 ?? ?? ?? ?? 90 90"`
    pub fn from_ida(pattern: &str) -> Result<Self> {
        Self::parse(pattern)
    }

    /// auto-detect and parse pattern format
    ///
    /// handles both IDA-style (`"48 8B ??"`) and code-style input
    pub fn parse(pattern: &str) -> Result<Self> {
        let trimmed = pattern.trim();
        if trimmed.is_empty() {
            return Err(WraithError::PatternParseFailed {
                reason: "empty pattern".into(),
            });
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return Err(WraithError::PatternParseFailed {
                reason: "empty pattern".into(),
            });
        }

        let mut bytes = Vec::with_capacity(parts.len());
        let mut mask = Vec::with_capacity(parts.len());

        for part in parts {
            if part == "?" || part == "??" || part == "*" || part == "**" {
                bytes.push(0);
                mask.push(true);
            } else {
                let byte = u8::from_str_radix(part, 16).map_err(|_| {
                    WraithError::PatternParseFailed {
                        reason: format!("invalid hex byte: '{}'", part),
                    }
                })?;
                bytes.push(byte);
                mask.push(false);
            }
        }

        Ok(Self { bytes, mask })
    }

    /// get pattern length
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// check if pattern is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// check if data matches this pattern at given offset
    #[inline]
    fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }

        self.bytes
            .iter()
            .zip(self.mask.iter())
            .enumerate()
            .all(|(i, (&pattern_byte, &is_wildcard))| {
                is_wildcard || data[offset + i] == pattern_byte
            })
    }
}

/// result of a pattern scan with context
#[derive(Debug, Clone)]
pub struct ScanMatch {
    /// absolute address where pattern was found
    pub address: usize,
    /// offset from scan start (for slice scans)
    pub offset: usize,
    /// name of module containing this address (if applicable)
    pub module_name: Option<String>,
    /// base address of containing module (if applicable)
    pub module_base: Option<usize>,
}

impl ScanMatch {
    fn new(address: usize, offset: usize) -> Self {
        Self {
            address,
            offset,
            module_name: None,
            module_base: None,
        }
    }

    fn with_module(mut self, name: String, base: usize) -> Self {
        self.module_name = Some(name);
        self.module_base = Some(base);
        self
    }
}

/// configurable pattern scanner
///
/// uses SIMD acceleration (AVX2/SSE2) when available and alignment is 1
pub struct Scanner {
    pattern: Pattern,
    alignment: usize,
    max_results: Option<usize>,
    /// cached SIMD scanner for acceleration
    simd_scanner: Option<super::simd::SimdScanner>,
}

impl Scanner {
    /// create scanner from pattern string (auto-detect format)
    pub fn new(pattern: &str) -> Result<Self> {
        let parsed = Pattern::parse(pattern)?;
        let simd_scanner = Some(super::simd::SimdScanner::new(
            parsed.bytes.clone(),
            parsed.mask.clone(),
        ));
        Ok(Self {
            pattern: parsed,
            alignment: 1,
            max_results: None,
            simd_scanner,
        })
    }

    /// create scanner from pre-parsed pattern
    pub fn from_pattern(pattern: Pattern) -> Self {
        let simd_scanner = Some(super::simd::SimdScanner::new(
            pattern.bytes.clone(),
            pattern.mask.clone(),
        ));
        Self {
            pattern,
            alignment: 1,
            max_results: None,
            simd_scanner,
        }
    }

    /// set scan alignment (1, 2, 4, 8, 16)
    ///
    /// patterns will only be checked at addresses aligned to this value
    /// note: SIMD acceleration is disabled when alignment > 1
    pub fn alignment(mut self, align: usize) -> Self {
        self.alignment = align.max(1);
        // disable SIMD when alignment > 1 (SIMD assumes byte alignment)
        if self.alignment > 1 {
            self.simd_scanner = None;
        }
        self
    }

    /// limit maximum number of results
    pub fn max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }

    /// scan byte slice for pattern, returning offsets
    pub fn scan_slice(&self, data: &[u8]) -> Vec<usize> {
        let pattern_len = self.pattern.len();

        if pattern_len > data.len() {
            return Vec::new();
        }

        // use SIMD when alignment is 1 and no max_results limit
        // (SIMD finds all matches, then we'd have to truncate anyway)
        if self.alignment == 1 {
            if let Some(ref simd) = self.simd_scanner {
                let results = simd.scan(data);
                // apply max_results limit if set
                if let Some(max) = self.max_results {
                    return results.into_iter().take(max).collect();
                }
                return results;
            }
        }

        // fallback to scalar implementation
        self.scan_slice_scalar(data)
    }

    /// scalar fallback for aligned scans
    fn scan_slice_scalar(&self, data: &[u8]) -> Vec<usize> {
        let mut results = Vec::new();
        let pattern_len = self.pattern.len();
        let max_offset = data.len() - pattern_len;
        let mut offset = 0;

        while offset <= max_offset {
            if self.pattern.matches_at(data, offset) {
                results.push(offset);
                if let Some(max) = self.max_results {
                    if results.len() >= max {
                        break;
                    }
                }
            }
            offset += self.alignment;
        }

        results
    }

    /// scan byte slice, returning first match offset
    pub fn scan_slice_first(&self, data: &[u8]) -> Option<usize> {
        let pattern_len = self.pattern.len();

        if pattern_len > data.len() {
            return None;
        }

        // use SIMD for first match when alignment is 1
        if self.alignment == 1 {
            if let Some(ref simd) = self.simd_scanner {
                return simd.scan_first(data);
            }
        }

        // fallback to scalar
        let max_offset = data.len() - pattern_len;
        let mut offset = 0;

        while offset <= max_offset {
            if self.pattern.matches_at(data, offset) {
                return Some(offset);
            }
            offset += self.alignment;
        }

        None
    }

    /// scan memory range for pattern
    ///
    /// # Safety
    /// caller must ensure the memory range [start, start+size) is readable
    pub unsafe fn scan_range(&self, start: usize, size: usize) -> Result<Vec<ScanMatch>> {
        if start == 0 {
            return Err(WraithError::NullPointer {
                context: "scan_range start",
            });
        }
        if size == 0 || size < self.pattern.len() {
            return Ok(Vec::new());
        }

        // SAFETY: caller guarantees this memory is readable
        let data = unsafe { core::slice::from_raw_parts(start as *const u8, size) };
        let offsets = self.scan_slice(data);

        Ok(offsets
            .into_iter()
            .map(|offset| ScanMatch::new(start + offset, offset))
            .collect())
    }

    /// scan memory range, returning first match
    ///
    /// # Safety
    /// caller must ensure the memory range [start, start+size) is readable
    pub unsafe fn scan_range_first(&self, start: usize, size: usize) -> Result<Option<ScanMatch>> {
        if start == 0 {
            return Err(WraithError::NullPointer {
                context: "scan_range_first start",
            });
        }
        if size == 0 || size < self.pattern.len() {
            return Ok(None);
        }

        // SAFETY: caller guarantees this memory is readable
        let data = unsafe { core::slice::from_raw_parts(start as *const u8, size) };

        Ok(self
            .scan_slice_first(data)
            .map(|offset| ScanMatch::new(start + offset, offset)))
    }
}

/// pattern scanner for byte slices (backward compatible API)
pub struct PatternScanner<'a> {
    data: &'a [u8],
}

impl<'a> PatternScanner<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// scan for pattern with wildcards
    ///
    /// pattern format: `"48 8B ? ? 90"` where `?` is wildcard
    pub fn find(&self, pattern: &str) -> Option<usize> {
        let parsed = Pattern::parse(pattern).ok()?;
        let scanner = Scanner::from_pattern(parsed);
        scanner.scan_slice_first(self.data)
    }

    /// find all occurrences of pattern
    pub fn find_all(&self, pattern: &str) -> Vec<usize> {
        match Pattern::parse(pattern) {
            Ok(parsed) => {
                let scanner = Scanner::from_pattern(parsed);
                scanner.scan_slice(self.data)
            }
            Err(_) => vec![],
        }
    }
}

// ============================================================================
// Module and Memory Region Scanning (requires navigation feature)
// ============================================================================

#[cfg(feature = "navigation")]
mod navigation_scan {
    use super::*;
    use crate::navigation::{MemoryRegion, MemoryRegionIterator, Module, ModuleQuery};
    use crate::structures::Peb;

    impl Scanner {
        /// scan loaded module for pattern
        pub fn scan_module(&self, module: &Module) -> Result<Vec<ScanMatch>> {
            let base = module.base();
            let size = module.size();
            let name = module.name();

            // SAFETY: module memory is mapped and readable for loaded modules
            let matches = unsafe { self.scan_range(base, size)? };

            Ok(matches
                .into_iter()
                .map(|m| m.with_module(name.clone(), base))
                .collect())
        }

        /// scan module, returning first match
        pub fn scan_module_first(&self, module: &Module) -> Result<Option<ScanMatch>> {
            let base = module.base();
            let size = module.size();
            let name = module.name();

            // SAFETY: module memory is mapped and readable
            let result = unsafe { self.scan_range_first(base, size)? };

            Ok(result.map(|m| m.with_module(name, base)))
        }

        /// scan memory region for pattern
        pub fn scan_region(&self, region: &MemoryRegion) -> Result<Vec<ScanMatch>> {
            if !region.is_committed() || !region.is_readable() {
                return Ok(Vec::new());
            }

            // SAFETY: region is committed and readable
            unsafe { self.scan_range(region.base_address, region.region_size) }
        }

        /// scan all executable memory regions
        pub fn scan_executable_regions(&self) -> Result<Vec<ScanMatch>> {
            let mut all_matches = Vec::new();

            for region in MemoryRegionIterator::new() {
                if !region.is_committed() || !region.is_readable() || !region.is_executable() {
                    continue;
                }

                // SAFETY: region is committed and readable
                let matches = unsafe { self.scan_range(region.base_address, region.region_size)? };
                all_matches.extend(matches);

                if let Some(max) = self.max_results {
                    if all_matches.len() >= max {
                        all_matches.truncate(max);
                        break;
                    }
                }
            }

            Ok(all_matches)
        }

        /// scan all committed memory regions (more thorough, slower)
        pub fn scan_all_regions(&self) -> Result<Vec<ScanMatch>> {
            let mut all_matches = Vec::new();

            for region in MemoryRegionIterator::new() {
                if !region.is_committed() || !region.is_readable() {
                    continue;
                }

                // SAFETY: region is committed and readable
                let matches = unsafe { self.scan_range(region.base_address, region.region_size)? };
                all_matches.extend(matches);

                if let Some(max) = self.max_results {
                    if all_matches.len() >= max {
                        all_matches.truncate(max);
                        break;
                    }
                }
            }

            Ok(all_matches)
        }
    }

    /// find pattern in module by name
    ///
    /// convenience function that looks up the module and scans it
    pub fn find_pattern_in_module(module_name: &str, pattern: &str) -> Result<Vec<ScanMatch>> {
        let peb = Peb::current()?;
        let query = ModuleQuery::new(&peb);
        let module = query.find_by_name(module_name)?;
        Scanner::new(pattern)?.scan_module(&module)
    }

    /// find first pattern match in module
    pub fn find_pattern_in_module_first(
        module_name: &str,
        pattern: &str,
    ) -> Result<Option<ScanMatch>> {
        let peb = Peb::current()?;
        let query = ModuleQuery::new(&peb);
        let module = query.find_by_name(module_name)?;
        Scanner::new(pattern)?.scan_module_first(&module)
    }

    /// scan all loaded modules for pattern
    pub fn find_pattern_all_modules(pattern: &str) -> Result<Vec<ScanMatch>> {
        let peb = Peb::current()?;
        let scanner = Scanner::new(pattern)?;
        let mut all_matches = Vec::new();

        for module in crate::navigation::InLoadOrderIter::new(&peb)? {
            match scanner.scan_module(&module) {
                Ok(matches) => all_matches.extend(matches),
                Err(_) => continue, // skip modules we can't scan
            }
        }

        Ok(all_matches)
    }

    /// scan all executable regions for pattern
    pub fn find_pattern_executable(pattern: &str) -> Result<Vec<ScanMatch>> {
        Scanner::new(pattern)?.scan_executable_regions()
    }

    /// find pattern in specific memory region
    pub fn find_pattern_in_region(region: &MemoryRegion, pattern: &str) -> Result<Vec<ScanMatch>> {
        Scanner::new(pattern)?.scan_region(region)
    }
}

#[cfg(feature = "navigation")]
pub use navigation_scan::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_parse_ida() {
        let p = Pattern::parse("48 8B 05").unwrap();
        assert_eq!(p.bytes, vec![0x48, 0x8B, 0x05]);
        assert_eq!(p.mask, vec![false, false, false]);
    }

    #[test]
    fn test_pattern_parse_wildcards() {
        let p = Pattern::parse("48 8B ?? ?? 90").unwrap();
        assert_eq!(p.bytes, vec![0x48, 0x8B, 0, 0, 0x90]);
        assert_eq!(p.mask, vec![false, false, true, true, false]);
    }

    #[test]
    fn test_pattern_parse_single_wildcard() {
        let p = Pattern::parse("48 ? 05").unwrap();
        assert_eq!(p.bytes, vec![0x48, 0, 0x05]);
        assert_eq!(p.mask, vec![false, true, false]);
    }

    #[test]
    fn test_pattern_from_code() {
        let bytes = [0x48, 0x8B, 0x05, 0x00];
        let p = Pattern::from_code(&bytes, "xx??").unwrap();
        assert_eq!(p.bytes, vec![0x48, 0x8B, 0x05, 0x00]);
        assert_eq!(p.mask, vec![false, false, true, true]);
    }

    #[test]
    fn test_scanner_find() {
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90];
        let scanner = PatternScanner::new(&data);

        assert_eq!(scanner.find("48 8B 05"), Some(0));
        assert_eq!(scanner.find("48 8B ? ? 34"), Some(0));
        assert_eq!(scanner.find("FF FF"), None);
    }

    #[test]
    fn test_scanner_find_all() {
        let data = [0x48, 0x8B, 0x48, 0x8B, 0x48, 0x8B];
        let scanner = PatternScanner::new(&data);

        let results = scanner.find_all("48 8B");
        assert_eq!(results, vec![0, 2, 4]);
    }

    #[test]
    fn test_scanner_alignment() {
        let data = [0x48, 0x8B, 0x48, 0x8B, 0x48, 0x8B, 0x48, 0x8B];
        let scanner = Scanner::new("48 8B").unwrap().alignment(4);

        let results = scanner.scan_slice(&data);
        // only matches at offsets 0 and 4 (aligned to 4)
        assert_eq!(results, vec![0, 4]);
    }

    #[test]
    fn test_scanner_max_results() {
        let data = [0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48];
        let scanner = Scanner::new("48").unwrap().max_results(3);

        let results = scanner.scan_slice(&data);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_empty_pattern_error() {
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("   ").is_err());
    }

    #[test]
    fn test_invalid_hex_error() {
        assert!(Pattern::parse("48 ZZ 05").is_err());
        assert!(Pattern::parse("GG").is_err());
    }

    #[test]
    fn test_pattern_length_mismatch() {
        assert!(Pattern::from_code(&[0x48, 0x8B], "x").is_err());
        assert!(Pattern::from_bytes_mask(&[0x48], &[false, true]).is_err());
    }
}
