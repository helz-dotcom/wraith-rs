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

/// macro for generating section characteristic check methods with `#[must_use]`
macro_rules! define_section_check {
    ($(#[$attr:meta])* $name:ident, $flag:ident) => {
        $(#[$attr])*
        #[must_use]
        pub fn $name(&self) -> bool {
            self.characteristics & $flag != 0
        }
    };
}

impl SectionHeader {
    /// get section name as string (may not be null-terminated)
    #[must_use]
    pub fn name_str(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(SECTION_NAME_SIZE);
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }

    define_section_check!(
        /// check if section is executable
        is_executable, IMAGE_SCN_MEM_EXECUTE
    );

    define_section_check!(
        /// check if section is readable
        is_readable, IMAGE_SCN_MEM_READ
    );

    define_section_check!(
        /// check if section is writable
        is_writable, IMAGE_SCN_MEM_WRITE
    );

    define_section_check!(
        /// check if section contains code
        contains_code, IMAGE_SCN_CNT_CODE
    );

    define_section_check!(
        /// check if section contains initialized data
        contains_initialized_data, IMAGE_SCN_CNT_INITIALIZED_DATA
    );

    define_section_check!(
        /// check if section contains uninitialized data
        contains_uninitialized_data, IMAGE_SCN_CNT_UNINITIALIZED_DATA
    );

    define_section_check!(
        /// check if section is discardable
        is_discardable, IMAGE_SCN_MEM_DISCARDABLE
    );

    /// convert section characteristics to memory protection flags
    #[must_use]
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
