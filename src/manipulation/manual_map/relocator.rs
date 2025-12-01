//! Base relocation processing

use super::allocator::MappedMemory;
use super::parser::ParsedPe;
use crate::error::{Result, WraithError};
use crate::structures::pe::{BaseRelocation, DataDirectoryType, RelocationEntry, RelocationType};

/// apply base relocations for address delta
pub fn apply_relocations(pe: &ParsedPe, memory: &mut MappedMemory, delta: i64) -> Result<()> {
    // no delta means no relocations needed
    if delta == 0 {
        return Ok(());
    }

    let reloc_dir = pe
        .data_directory(DataDirectoryType::Basereloc)
        .ok_or_else(|| WraithError::RelocationFailed {
            rva: 0,
            reason: "no relocation directory".into(),
        })?;

    if !reloc_dir.is_present() {
        // PE has no relocations - only valid if loaded at preferred base
        return Ok(());
    }

    let reloc_rva = reloc_dir.virtual_address as usize;
    let reloc_size = reloc_dir.size as usize;

    let mut offset = 0;

    while offset < reloc_size {
        // read relocation block header from mapped memory
        let block: BaseRelocation = memory.read_at(reloc_rva + offset)?;

        // zero block marks end
        if block.size_of_block == 0 {
            break;
        }

        // validate block size
        if block.size_of_block < 8 {
            return Err(WraithError::RelocationFailed {
                rva: (reloc_rva + offset) as u32,
                reason: "invalid relocation block size".into(),
            });
        }

        let entry_count = block.entry_count();
        let entries_offset = reloc_rva + offset + 8; // after block header

        for i in 0..entry_count {
            let entry_offset = entries_offset + i * 2;
            let entry_raw: u16 = memory.read_at(entry_offset)?;
            let entry = RelocationEntry(entry_raw);

            apply_single_relocation(memory, &block, &entry, delta)?;
        }

        offset += block.size_of_block as usize;
    }

    Ok(())
}

/// apply a single relocation entry
fn apply_single_relocation(
    memory: &mut MappedMemory,
    block: &BaseRelocation,
    entry: &RelocationEntry,
    delta: i64,
) -> Result<()> {
    let reloc_type = RelocationType::from(entry.reloc_type());
    let target_rva = block.virtual_address as usize + entry.offset() as usize;

    match reloc_type {
        RelocationType::Absolute => {
            // padding entry, skip
        }
        RelocationType::HighLow => {
            // 32-bit relocation (x86)
            let value: u32 = memory.read_at(target_rva)?;
            let new_value = (value as i64).wrapping_add(delta) as u32;
            memory.write_value_at(target_rva, new_value)?;
        }
        RelocationType::Dir64 => {
            // 64-bit relocation (x64)
            let value: u64 = memory.read_at(target_rva)?;
            let new_value = (value as i64).wrapping_add(delta) as u64;
            memory.write_value_at(target_rva, new_value)?;
        }
        RelocationType::High => {
            // high 16 bits of 32-bit value
            let value: u16 = memory.read_at(target_rva)?;
            let full_value = (value as u32) << 16;
            let new_full = (full_value as i64).wrapping_add(delta) as u32;
            let new_value = (new_full >> 16) as u16;
            memory.write_value_at(target_rva, new_value)?;
        }
        RelocationType::Low => {
            // low 16 bits of 32-bit value
            let value: u16 = memory.read_at(target_rva)?;
            let new_value = (value as i64).wrapping_add(delta) as u16;
            memory.write_value_at(target_rva, new_value)?;
        }
        RelocationType::HighAdj => {
            // high 16 bits adjusted - requires next entry for low 16 bits
            // this is complex and rarely used
            return Err(WraithError::RelocationFailed {
                rva: target_rva as u32,
                reason: "HIGHADJ relocations not supported".into(),
            });
        }
    }

    Ok(())
}

/// check if PE needs relocations (not loaded at preferred base)
pub fn needs_relocations(pe: &ParsedPe, actual_base: usize) -> bool {
    pe.preferred_base() != actual_base
}

/// calculate relocation delta
pub fn calculate_delta(pe: &ParsedPe, actual_base: usize) -> i64 {
    actual_base as i64 - pe.preferred_base() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_delta() {
        // mock PE with preferred base 0x10000000
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();
        let pe = ParsedPe::parse(&data).unwrap();

        let preferred = pe.preferred_base();
        let actual = preferred + 0x1000;
        let delta = calculate_delta(&pe, actual);
        assert_eq!(delta, 0x1000);

        let actual = preferred - 0x1000;
        let delta = calculate_delta(&pe, actual);
        assert_eq!(delta, -0x1000);
    }

    #[test]
    fn test_needs_relocations() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();
        let pe = ParsedPe::parse(&data).unwrap();

        let preferred = pe.preferred_base();
        assert!(!needs_relocations(&pe, preferred));
        assert!(needs_relocations(&pe, preferred + 0x1000));
    }
}
