//! Section header (IMAGE_SECTION_HEADER)

pub const SECTION_NAME_SIZE: usize = 8;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; SECTION_NAME_SIZE],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

// section characteristics flags
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;

impl SectionHeader {
    /// get section name as string (may not be null-terminated)
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SECTION_NAME_SIZE);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    /// check if section is executable
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// check if section is readable
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// check if section is writable
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// check if section contains code
    pub fn contains_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    /// convert section characteristics to memory protection flags
    pub fn to_protection(&self) -> u32 {
        let r = self.is_readable();
        let w = self.is_writable();
        let x = self.is_executable();

        // PAGE_* constants
        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_READONLY: u32 = 0x02;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        match (r, w, x) {
            (false, false, false) => PAGE_NOACCESS,
            (true, false, false) => PAGE_READONLY,
            (true, true, false) => PAGE_READWRITE,
            (false, false, true) => PAGE_EXECUTE,
            (true, false, true) => PAGE_EXECUTE_READ,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (false, true, false) => PAGE_READWRITE,          // fallback
            (false, true, true) => PAGE_EXECUTE_READWRITE,   // fallback
        }
    }
}
