//! Base relocation structures

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
    // followed by Type/Offset entries
}

impl BaseRelocation {
    /// number of relocation entries in this block
    pub fn entry_count(&self) -> usize {
        if self.size_of_block <= 8 {
            0
        } else {
            ((self.size_of_block - 8) / 2) as usize
        }
    }
}

/// relocation entry (2 bytes: 4 bits type, 12 bits offset)
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry(pub u16);

impl RelocationEntry {
    pub fn reloc_type(&self) -> u8 {
        (self.0 >> 12) as u8
    }

    pub fn offset(&self) -> u16 {
        self.0 & 0x0FFF
    }
}

/// relocation types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    Absolute = 0, // skip
    High = 1,     // high 16 bits
    Low = 2,      // low 16 bits
    HighLow = 3,  // full 32 bits (x86)
    HighAdj = 4,  // high 16 bits adjusted
    Dir64 = 10,   // full 64 bits (x64)
}

impl From<u8> for RelocationType {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            10 => Self::Dir64,
            _ => Self::Absolute, // treat unknown as skip
        }
    }
}
