//! Pattern scanning

/// pattern scanner for finding byte sequences in memory
pub struct PatternScanner<'a> {
    data: &'a [u8],
}

impl<'a> PatternScanner<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// scan for pattern with wildcards
    ///
    /// pattern format: "48 8B ? ? 90" where ? is wildcard
    pub fn find(&self, pattern: &str) -> Option<usize> {
        let (bytes, mask) = Self::parse_pattern(pattern)?;

        self.data.windows(bytes.len()).position(|window| {
            window
                .iter()
                .zip(bytes.iter().zip(mask.iter()))
                .all(|(&data_byte, (&pattern_byte, &is_wildcard))| {
                    is_wildcard || data_byte == pattern_byte
                })
        })
    }

    /// find all occurrences of pattern
    pub fn find_all(&self, pattern: &str) -> Vec<usize> {
        let (bytes, mask) = match Self::parse_pattern(pattern) {
            Some(p) => p,
            None => return vec![],
        };

        let mut results = Vec::new();
        let mut offset = 0;

        while offset + bytes.len() <= self.data.len() {
            let matches = self.data[offset..offset + bytes.len()]
                .iter()
                .zip(bytes.iter().zip(mask.iter()))
                .all(|(&data_byte, (&pattern_byte, &is_wildcard))| {
                    is_wildcard || data_byte == pattern_byte
                });

            if matches {
                results.push(offset);
            }
            offset += 1;
        }

        results
    }

    fn parse_pattern(pattern: &str) -> Option<(Vec<u8>, Vec<bool>)> {
        let parts: Vec<&str> = pattern.split_whitespace().collect();
        let mut bytes = Vec::with_capacity(parts.len());
        let mut mask = Vec::with_capacity(parts.len());

        for part in parts {
            if part == "?" || part == "??" {
                bytes.push(0);
                mask.push(true); // wildcard
            } else {
                let byte = u8::from_str_radix(part, 16).ok()?;
                bytes.push(byte);
                mask.push(false); // exact match
            }
        }

        Some((bytes, mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_scan() {
        let data = [0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78, 0x90];
        let scanner = PatternScanner::new(&data);

        assert_eq!(scanner.find("48 8B 05"), Some(0));
        assert_eq!(scanner.find("48 8B ? ? 34"), Some(0));
        assert_eq!(scanner.find("FF FF"), None);
    }
}
