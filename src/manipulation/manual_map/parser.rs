//! PE file parsing

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::structures::pe::{
    DataDirectory, DataDirectoryType, DosHeader, FileHeader, OptionalHeader32, OptionalHeader64,
    SectionHeader,
};
use crate::structures::pe::nt_headers::{NT_SIGNATURE, PE32_MAGIC, PE32PLUS_MAGIC};

/// parsed PE file ready for mapping
pub struct ParsedPe {
    data: Vec<u8>,
    is_64bit: bool,
    nt_offset: usize,
}

impl ParsedPe {
    /// parse PE from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < core::mem::size_of::<DosHeader>() {
            return Err(WraithError::InvalidPeFormat {
                reason: "file too small for DOS header".into(),
            });
        }

        // SAFETY: we checked size, reading DOS header from aligned buffer
        let dos = unsafe { &*(data.as_ptr() as *const DosHeader) };
        if !dos.is_valid() {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid DOS signature".into(),
            });
        }

        let nt_offset = dos.nt_headers_offset();
        if nt_offset + 4 > data.len() {
            return Err(WraithError::InvalidPeFormat {
                reason: "NT headers offset out of bounds".into(),
            });
        }

        // SAFETY: offset bounds checked
        let signature = unsafe { *(data.as_ptr().add(nt_offset) as *const u32) };
        if signature != NT_SIGNATURE {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid NT signature".into(),
            });
        }

        // determine PE bitness
        let magic_offset = nt_offset + 4 + core::mem::size_of::<FileHeader>();
        if magic_offset + 2 > data.len() {
            return Err(WraithError::InvalidPeFormat {
                reason: "file too small for optional header".into(),
            });
        }

        // SAFETY: bounds checked
        let magic = unsafe { *(data.as_ptr().add(magic_offset) as *const u16) };
        let is_64bit = match magic {
            PE32_MAGIC => false,
            PE32PLUS_MAGIC => true,
            _ => {
                return Err(WraithError::InvalidPeFormat {
                    reason: format!("unknown PE magic: {magic:#x}"),
                });
            }
        };

        // validate we have enough data for headers
        let optional_size = if is_64bit {
            core::mem::size_of::<OptionalHeader64>()
        } else {
            core::mem::size_of::<OptionalHeader32>()
        };

        let headers_end = nt_offset + 4 + core::mem::size_of::<FileHeader>() + optional_size;
        if headers_end > data.len() {
            return Err(WraithError::InvalidPeFormat {
                reason: "file too small for full headers".into(),
            });
        }

        Ok(Self {
            data: data.to_vec(),
            is_64bit,
            nt_offset,
        })
    }

    /// check if 64-bit PE
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// get DOS header
    pub fn dos_header(&self) -> &DosHeader {
        // SAFETY: validated during parse
        unsafe { &*(self.data.as_ptr() as *const DosHeader) }
    }

    /// get file header
    pub fn file_header(&self) -> &FileHeader {
        let offset = self.nt_offset + 4;
        // SAFETY: validated during parse
        unsafe { &*(self.data.as_ptr().add(offset) as *const FileHeader) }
    }

    /// get optional header as 32-bit
    pub fn optional_header_32(&self) -> Option<&OptionalHeader32> {
        if self.is_64bit {
            None
        } else {
            let offset = self.nt_offset + 4 + core::mem::size_of::<FileHeader>();
            // SAFETY: validated during parse, is_64bit check ensures correct type
            Some(unsafe { &*(self.data.as_ptr().add(offset) as *const OptionalHeader32) })
        }
    }

    /// get optional header as 64-bit
    pub fn optional_header_64(&self) -> Option<&OptionalHeader64> {
        if !self.is_64bit {
            None
        } else {
            let offset = self.nt_offset + 4 + core::mem::size_of::<FileHeader>();
            // SAFETY: validated during parse, is_64bit check ensures correct type
            Some(unsafe { &*(self.data.as_ptr().add(offset) as *const OptionalHeader64) })
        }
    }

    /// get size of image (virtual size when loaded)
    pub fn size_of_image(&self) -> usize {
        if self.is_64bit {
            self.optional_header_64().unwrap().size_of_image as usize
        } else {
            self.optional_header_32().unwrap().size_of_image as usize
        }
    }

    /// get preferred base address
    pub fn preferred_base(&self) -> usize {
        if self.is_64bit {
            self.optional_header_64().unwrap().image_base as usize
        } else {
            self.optional_header_32().unwrap().image_base as usize
        }
    }

    /// get entry point RVA
    pub fn entry_point_rva(&self) -> u32 {
        if self.is_64bit {
            self.optional_header_64().unwrap().address_of_entry_point
        } else {
            self.optional_header_32().unwrap().address_of_entry_point
        }
    }

    /// get size of headers
    pub fn size_of_headers(&self) -> usize {
        if self.is_64bit {
            self.optional_header_64().unwrap().size_of_headers as usize
        } else {
            self.optional_header_32().unwrap().size_of_headers as usize
        }
    }

    /// get section alignment
    pub fn section_alignment(&self) -> u32 {
        if self.is_64bit {
            self.optional_header_64().unwrap().section_alignment
        } else {
            self.optional_header_32().unwrap().section_alignment
        }
    }

    /// get file alignment
    pub fn file_alignment(&self) -> u32 {
        if self.is_64bit {
            self.optional_header_64().unwrap().file_alignment
        } else {
            self.optional_header_32().unwrap().file_alignment
        }
    }

    /// get number of sections
    pub fn number_of_sections(&self) -> u16 {
        self.file_header().number_of_sections
    }

    /// get data directory by type
    pub fn data_directory(&self, dir_type: DataDirectoryType) -> Option<&DataDirectory> {
        let index = dir_type.index();
        if self.is_64bit {
            self.optional_header_64()?.data_directory.get(index)
        } else {
            self.optional_header_32()?.data_directory.get(index)
        }
    }

    /// get section headers
    pub fn sections(&self) -> &[SectionHeader] {
        let optional_size = if self.is_64bit {
            core::mem::size_of::<OptionalHeader64>()
        } else {
            core::mem::size_of::<OptionalHeader32>()
        };

        let sections_offset =
            self.nt_offset + 4 + core::mem::size_of::<FileHeader>() + optional_size;
        let num_sections = self.number_of_sections() as usize;

        // SAFETY: sections follow optional header, validated during parse
        unsafe {
            core::slice::from_raw_parts(
                self.data.as_ptr().add(sections_offset) as *const SectionHeader,
                num_sections,
            )
        }
    }

    /// get raw PE data
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// find section containing RVA
    pub fn section_from_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections()
            .iter()
            .find(|s| rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size)
    }

    /// convert RVA to file offset
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // check if RVA is in headers (before first section)
        if (rva as usize) < self.size_of_headers() {
            return Some(rva as usize);
        }

        let section = self.section_from_rva(rva)?;
        let offset_in_section = rva - section.virtual_address;
        Some(section.pointer_to_raw_data as usize + offset_in_section as usize)
    }

    /// read data at RVA
    pub fn read_at_rva<T: Copy>(&self, rva: u32) -> Option<T> {
        let offset = self.rva_to_offset(rva)?;
        if offset + core::mem::size_of::<T>() > self.data.len() {
            return None;
        }
        // SAFETY: bounds checked, unaligned read handles any alignment
        Some(unsafe { (self.data.as_ptr().add(offset) as *const T).read_unaligned() })
    }

    /// read null-terminated string at RVA
    pub fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        let mut end = offset;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        String::from_utf8(self.data[offset..end].to_vec()).ok()
    }

    /// check if PE has relocations
    pub fn has_relocations(&self) -> bool {
        self.data_directory(DataDirectoryType::Basereloc)
            .map(|d| d.is_present())
            .unwrap_or(false)
    }

    /// check if PE has TLS
    pub fn has_tls(&self) -> bool {
        self.data_directory(DataDirectoryType::Tls)
            .map(|d| d.is_present())
            .unwrap_or(false)
    }

    /// check if PE is a DLL
    pub fn is_dll(&self) -> bool {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        self.file_header().characteristics & IMAGE_FILE_DLL != 0
    }

    /// check if ASLR is supported
    pub fn supports_aslr(&self) -> bool {
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
        let dll_characteristics = if self.is_64bit {
            self.optional_header_64().unwrap().dll_characteristics
        } else {
            self.optional_header_32().unwrap().dll_characteristics
        };
        dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    }

    /// get DLL characteristics
    pub fn dll_characteristics(&self) -> u16 {
        if self.is_64bit {
            self.optional_header_64().unwrap().dll_characteristics
        } else {
            self.optional_header_32().unwrap().dll_characteristics
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_self() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();

        let pe = ParsedPe::parse(&data).expect("should parse");
        assert!(pe.size_of_image() > 0);
        assert!(pe.number_of_sections() > 0);
    }

    #[test]
    fn test_parse_ntdll() {
        let ntdll_path = r"C:\Windows\System32\ntdll.dll";
        if let Ok(data) = std::fs::read(ntdll_path) {
            let pe = ParsedPe::parse(&data).expect("should parse ntdll");

            #[cfg(target_arch = "x86_64")]
            assert!(pe.is_64bit());

            assert!(pe.has_relocations());
            assert!(pe.number_of_sections() > 0);
        }
    }

    #[test]
    fn test_section_access() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();
        let pe = ParsedPe::parse(&data).unwrap();

        let has_text = pe.sections().iter().any(|s| s.name_str() == ".text");
        assert!(has_text);
    }
}
