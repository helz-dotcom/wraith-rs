//! PE section mapping

use super::allocator::MappedMemory;
use super::parser::ParsedPe;
use crate::error::{Result, WraithError};
use crate::structures::pe::SectionHeader;

// page protection constants
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// map PE sections to allocated memory
pub fn map_sections(pe: &ParsedPe, memory: &mut MappedMemory) -> Result<()> {
    // copy headers first
    let header_size = pe.size_of_headers();
    let raw_data = pe.raw_data();

    if header_size > raw_data.len() {
        return Err(WraithError::MappingFailed {
            section: "headers".into(),
            reason: "header size exceeds file size".into(),
        });
    }

    memory.write_at(0, &raw_data[..header_size])?;

    // map each section
    for section in pe.sections() {
        map_section(pe, memory, section)?;
    }

    Ok(())
}

/// map a single section to memory
fn map_section(pe: &ParsedPe, memory: &mut MappedMemory, section: &SectionHeader) -> Result<()> {
    let virtual_address = section.virtual_address as usize;
    let virtual_size = section.virtual_size as usize;
    let raw_data_ptr = section.pointer_to_raw_data as usize;
    let raw_data_size = section.size_of_raw_data as usize;

    // skip sections with no raw data (like .bss)
    // memory is already zeroed from allocation
    if raw_data_ptr == 0 || raw_data_size == 0 {
        return Ok(());
    }

    let raw_data = pe.raw_data();

    // validate section bounds in file
    if raw_data_ptr + raw_data_size > raw_data.len() {
        return Err(WraithError::MappingFailed {
            section: section.name_str().to_string(),
            reason: "raw data exceeds file size".into(),
        });
    }

    // validate section bounds in memory
    if virtual_address + virtual_size > memory.size() {
        return Err(WraithError::MappingFailed {
            section: section.name_str().to_string(),
            reason: "virtual size exceeds allocated memory".into(),
        });
    }

    // copy raw data (may be smaller than virtual size, rest is zero)
    let copy_size = raw_data_size.min(virtual_size);
    let section_data = &raw_data[raw_data_ptr..raw_data_ptr + copy_size];
    memory.write_at(virtual_address, section_data)?;

    Ok(())
}

/// set final memory protections for all sections
pub fn set_section_protections(pe: &ParsedPe, memory: &MappedMemory) -> Result<()> {
    // set headers to read-only
    let header_size = align_up(pe.size_of_headers(), 0x1000);
    if header_size > 0 {
        memory.protect(0, header_size, PAGE_READONLY)?;
    }

    // set each section's protection
    for section in pe.sections() {
        let protection = section_to_protection(section);
        let virtual_address = section.virtual_address as usize;

        // align size to page boundary
        let size = align_up(section.virtual_size as usize, 0x1000);

        if size > 0 && virtual_address + size <= memory.size() {
            memory.protect(virtual_address, size, protection)?;
        }
    }

    Ok(())
}

/// convert section characteristics to memory protection flags
fn section_to_protection(section: &SectionHeader) -> u32 {
    let r = section.is_readable();
    let w = section.is_writable();
    let x = section.is_executable();

    match (r, w, x) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) | (false, true, true) => PAGE_EXECUTE_READWRITE,
        (false, true, false) => PAGE_READWRITE, // fallback
    }
}

/// find section by name
pub fn find_section<'a>(pe: &'a ParsedPe, name: &str) -> Option<&'a SectionHeader> {
    pe.sections().iter().find(|s| s.name_str() == name)
}

/// get .text section
pub fn get_text_section(pe: &ParsedPe) -> Option<&SectionHeader> {
    find_section(pe, ".text")
}

/// get .data section
pub fn get_data_section(pe: &ParsedPe) -> Option<&SectionHeader> {
    find_section(pe, ".data")
}

/// get .rdata section
pub fn get_rdata_section(pe: &ParsedPe) -> Option<&SectionHeader> {
    find_section(pe, ".rdata")
}

/// align value up to alignment boundary
fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manipulation::manual_map::allocator::allocate_anywhere;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn test_map_self() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();
        let pe = ParsedPe::parse(&data).unwrap();

        let mut mem = allocate_anywhere(pe.size_of_image()).unwrap();
        map_sections(&pe, &mut mem).expect("should map sections");

        // verify headers were copied
        let dos_sig = mem.read_at::<u16>(0).unwrap();
        assert_eq!(dos_sig, 0x5A4D); // MZ
    }
}
