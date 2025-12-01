//! NT headers (IMAGE_NT_HEADERS)

use super::data_directory::DataDirectory;

pub const NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
pub const PE32_MAGIC: u16 = 0x10b;
pub const PE32PLUS_MAGIC: u16 = 0x20b;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [DataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [DataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtHeaders32 {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NtHeaders64 {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader64,
}

/// architecture-independent NT headers access
pub enum NtHeaders {
    Headers32(NtHeaders32),
    Headers64(NtHeaders64),
}

impl NtHeaders {
    /// get number of sections
    pub fn number_of_sections(&self) -> u16 {
        match self {
            Self::Headers32(h) => h.file_header.number_of_sections,
            Self::Headers64(h) => h.file_header.number_of_sections,
        }
    }

    /// get entry point RVA
    pub fn entry_point(&self) -> u32 {
        match self {
            Self::Headers32(h) => h.optional_header.address_of_entry_point,
            Self::Headers64(h) => h.optional_header.address_of_entry_point,
        }
    }

    /// get image base
    pub fn image_base(&self) -> u64 {
        match self {
            Self::Headers32(h) => h.optional_header.image_base as u64,
            Self::Headers64(h) => h.optional_header.image_base,
        }
    }

    /// get size of image
    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::Headers32(h) => h.optional_header.size_of_image,
            Self::Headers64(h) => h.optional_header.size_of_image,
        }
    }

    /// get section alignment
    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::Headers32(h) => h.optional_header.section_alignment,
            Self::Headers64(h) => h.optional_header.section_alignment,
        }
    }

    /// get data directory by index
    pub fn data_directory(&self, index: usize) -> Option<&DataDirectory> {
        match self {
            Self::Headers32(h) => h.optional_header.data_directory.get(index),
            Self::Headers64(h) => h.optional_header.data_directory.get(index),
        }
    }

    /// check if 64-bit
    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::Headers64(_))
    }
}
