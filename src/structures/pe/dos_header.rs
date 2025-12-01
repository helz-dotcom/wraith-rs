//! DOS header (IMAGE_DOS_HEADER)

pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"

// reasonable bounds for e_lfanew - must be positive and within first 64MB
const MIN_NT_HEADERS_OFFSET: i32 = 0x40; // at least past DOS header
const MAX_NT_HEADERS_OFFSET: i32 = 0x4000000; // 64MB max

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16, // must be DOS_SIGNATURE
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32, // offset to NT headers
}

impl DosHeader {
    /// validate DOS signature
    pub fn is_valid(&self) -> bool {
        self.e_magic == DOS_SIGNATURE
    }

    /// check if e_lfanew offset is within reasonable bounds
    pub fn is_nt_offset_valid(&self) -> bool {
        self.e_lfanew >= MIN_NT_HEADERS_OFFSET && self.e_lfanew <= MAX_NT_HEADERS_OFFSET
    }

    /// get offset to NT headers (returns None if invalid)
    pub fn nt_headers_offset_checked(&self) -> Option<usize> {
        if self.is_nt_offset_valid() {
            Some(self.e_lfanew as usize)
        } else {
            None
        }
    }

    /// get offset to NT headers
    ///
    /// # Safety
    /// caller must ensure offset is valid via `is_nt_offset_valid()` or bounds check
    /// against module size. use `nt_headers_offset_checked()` for safe access.
    pub fn nt_headers_offset(&self) -> usize {
        self.e_lfanew as usize
    }
}
