//! Hook detection logic
//!
//! Detects various types of inline hooks by analyzing function prologues
//! and comparing against known hook patterns or clean copies from disk.

use core::fmt;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::navigation::Module;
use crate::structures::pe::{DataDirectoryType, ExportDirectory};

/// type of detected hook
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// direct jump at function start (jmp rel32)
    JmpRel32,
    /// indirect jump (jmp [rip+disp32] or jmp [addr])
    JmpIndirect,
    /// mov rax, addr; jmp rax pattern
    MovJmpRax,
    /// push addr; ret pattern (32-bit)
    PushRet,
    /// int3 breakpoint
    Breakpoint,
    /// bytes differ from clean copy but no recognized pattern
    Unknown,
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JmpRel32 => write!(f, "jmp rel32"),
            Self::JmpIndirect => write!(f, "jmp [addr]"),
            Self::MovJmpRax => write!(f, "mov rax, addr; jmp rax"),
            Self::PushRet => write!(f, "push addr; ret"),
            Self::Breakpoint => write!(f, "int3 breakpoint"),
            Self::Unknown => write!(f, "unknown modification"),
        }
    }
}

/// information about a detected hook
#[derive(Debug, Clone)]
pub struct HookInfo {
    /// name of hooked function
    pub function_name: String,
    /// address of function start
    pub function_address: usize,
    /// type of hook detected
    pub hook_type: HookType,
    /// where the hook redirects to (if determinable)
    pub hook_destination: Option<usize>,
    /// original bytes at function start (if available from clean copy)
    pub original_bytes: Vec<u8>,
    /// current bytes at function start
    pub hooked_bytes: Vec<u8>,
    /// module containing the function
    pub module_name: String,
}

impl HookInfo {
    /// check if we have original bytes for restoration
    pub fn can_restore(&self) -> bool {
        !self.original_bytes.is_empty()
    }
}

/// hook detection for a module
pub struct HookDetector<'a> {
    module: &'a Module<'a>,
    clean_copy: Option<Vec<u8>>,
}

impl<'a> HookDetector<'a> {
    /// create detector for module, attempting to load clean copy from disk
    pub fn new(module: &'a Module<'a>) -> Result<Self> {
        let clean_copy = Self::load_clean_copy(module).ok();
        Ok(Self { module, clean_copy })
    }

    /// create detector with explicit clean copy bytes
    pub fn with_clean_copy(module: &'a Module<'a>, clean_copy: Vec<u8>) -> Self {
        Self {
            module,
            clean_copy: Some(clean_copy),
        }
    }

    /// create detector without clean copy (pattern detection only)
    pub fn without_clean_copy(module: &'a Module<'a>) -> Self {
        Self {
            module,
            clean_copy: None,
        }
    }

    /// load clean copy of module from disk
    #[cfg(feature = "std")]
    fn load_clean_copy(module: &Module) -> Result<Vec<u8>> {
        let path = module.full_path();
        std::fs::read(&path).map_err(|_| WraithError::CleanCopyUnavailable)
    }

    /// load clean copy of module from disk (no_std stub)
    #[cfg(not(feature = "std"))]
    fn load_clean_copy(_module: &Module) -> Result<Vec<u8>> {
        Err(WraithError::CleanCopyUnavailable)
    }

    /// check if clean copy is available
    pub fn has_clean_copy(&self) -> bool {
        self.clean_copy.is_some()
    }

    /// scan all exports for hooks
    pub fn scan_exports(&self) -> Result<Vec<HookInfo>> {
        let mut hooks = Vec::new();

        let nt = self.module.nt_headers()?;
        let export_dir = match nt.data_directory(DataDirectoryType::Export.index()) {
            Some(dir) if dir.is_present() => dir,
            _ => return Ok(hooks),
        };

        let base = self.module.base();
        // SAFETY: export directory is present and valid for loaded modules
        let exports = unsafe {
            &*((base + export_dir.virtual_address as usize) as *const ExportDirectory)
        };

        let num_names = exports.number_of_names as usize;
        let names_va = base + exports.address_of_names as usize;
        let ordinals_va = base + exports.address_of_name_ordinals as usize;
        let functions_va = base + exports.address_of_functions as usize;

        for i in 0..num_names {
            // SAFETY: iterating within bounds of export arrays
            let name_rva = unsafe { *((names_va + i * 4) as *const u32) };
            let name_ptr = (base + name_rva as usize) as *const u8;

            let name = unsafe {
                let mut len = 0;
                while *name_ptr.add(len) != 0 && len < 256 {
                    len += 1;
                }
                String::from_utf8_lossy(core::slice::from_raw_parts(name_ptr, len)).to_string()
            };

            let ordinal = unsafe { *((ordinals_va + i * 2) as *const u16) };
            let func_rva = unsafe { *((functions_va + ordinal as usize * 4) as *const u32) };

            // check for forwarded export (RVA points into export directory)
            if func_rva >= export_dir.virtual_address
                && func_rva < export_dir.virtual_address + export_dir.size
            {
                continue;
            }

            let func_addr = base + func_rva as usize;

            if let Some(hook_info) = self.check_function(&name, func_addr)? {
                hooks.push(hook_info);
            }
        }

        Ok(hooks)
    }

    /// check a single function for hooks
    pub fn check_function(&self, name: &str, addr: usize) -> Result<Option<HookInfo>> {
        const PROLOGUE_SIZE: usize = 32;

        // read current bytes at function
        // SAFETY: function address is valid for loaded export
        let current_bytes: [u8; PROLOGUE_SIZE] = unsafe { *(addr as *const [u8; PROLOGUE_SIZE]) };

        // first check for known hook patterns
        if let Some((hook_type, destination)) = self.detect_hook_pattern(&current_bytes, addr) {
            let original_bytes = self
                .get_original_bytes(addr, PROLOGUE_SIZE)
                .unwrap_or_default();

            return Ok(Some(HookInfo {
                function_name: name.to_string(),
                function_address: addr,
                hook_type,
                hook_destination: destination,
                original_bytes,
                hooked_bytes: current_bytes.to_vec(),
                module_name: self.module.name(),
            }));
        }

        // if we have a clean copy, compare against it
        if let Some(clean) = &self.clean_copy {
            if let Some(rva) = self.module.va_to_rva(addr) {
                if let Some(original) = self.get_bytes_from_pe(clean, rva as usize, PROLOGUE_SIZE) {
                    if current_bytes[..] != original[..] {
                        return Ok(Some(HookInfo {
                            function_name: name.to_string(),
                            function_address: addr,
                            hook_type: HookType::Unknown,
                            hook_destination: None,
                            original_bytes: original,
                            hooked_bytes: current_bytes.to_vec(),
                            module_name: self.module.name(),
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    /// detect hook pattern in bytes
    fn detect_hook_pattern(&self, bytes: &[u8], addr: usize) -> Option<(HookType, Option<usize>)> {
        if bytes.len() < 5 {
            return None;
        }

        // E9 XX XX XX XX - jmp rel32
        if bytes[0] == 0xE9 {
            let offset = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let target = (addr as i64 + 5 + offset as i64) as usize;
            return Some((HookType::JmpRel32, Some(target)));
        }

        // FF 25 XX XX XX XX - jmp [rip+disp32] (x64)
        if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
            let offset = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
            let ptr_addr = (addr as i64 + 6 + offset as i64) as usize;
            // SAFETY: reading pointer from computed address
            let target = unsafe { *(ptr_addr as *const usize) };
            return Some((HookType::JmpIndirect, Some(target)));
        }

        // 48 B8 XX XX XX XX XX XX XX XX - mov rax, imm64
        // FF E0 - jmp rax
        if bytes.len() >= 12
            && bytes[0] == 0x48
            && bytes[1] == 0xB8
            && bytes[10] == 0xFF
            && bytes[11] == 0xE0
        {
            let target = u64::from_le_bytes([
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
            ]) as usize;
            return Some((HookType::MovJmpRax, Some(target)));
        }

        // 68 XX XX XX XX - push imm32
        // C3 - ret
        if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
            let target = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
            return Some((HookType::PushRet, Some(target)));
        }

        // CC - int3 breakpoint
        if bytes[0] == 0xCC {
            return Some((HookType::Breakpoint, None));
        }

        None
    }

    /// get bytes from PE file at given RVA
    fn get_bytes_from_pe(&self, pe_data: &[u8], rva: usize, len: usize) -> Option<Vec<u8>> {
        // need to map RVA to file offset using section headers
        let file_offset = self.rva_to_file_offset(pe_data, rva)?;

        if file_offset + len <= pe_data.len() {
            Some(pe_data[file_offset..file_offset + len].to_vec())
        } else {
            None
        }
    }

    /// convert RVA to file offset in PE
    fn rva_to_file_offset(&self, pe_data: &[u8], rva: usize) -> Option<usize> {
        if pe_data.len() < 64 {
            return None;
        }

        // check DOS signature
        if pe_data[0] != 0x4D || pe_data[1] != 0x5A {
            return None;
        }

        // get PE header offset
        let pe_offset = u32::from_le_bytes([pe_data[0x3C], pe_data[0x3D], pe_data[0x3E], pe_data[0x3F]]) as usize;

        if pe_offset + 24 > pe_data.len() {
            return None;
        }

        // check PE signature
        if pe_data[pe_offset..pe_offset + 4] != [0x50, 0x45, 0x00, 0x00] {
            return None;
        }

        // get number of sections and optional header size
        let num_sections =
            u16::from_le_bytes([pe_data[pe_offset + 6], pe_data[pe_offset + 7]]) as usize;
        let optional_header_size =
            u16::from_le_bytes([pe_data[pe_offset + 20], pe_data[pe_offset + 21]]) as usize;

        let section_table_offset = pe_offset + 24 + optional_header_size;

        // iterate sections to find which contains the RVA
        for i in 0..num_sections {
            let section_offset = section_table_offset + i * 40;

            if section_offset + 40 > pe_data.len() {
                break;
            }

            let virtual_size = u32::from_le_bytes([
                pe_data[section_offset + 8],
                pe_data[section_offset + 9],
                pe_data[section_offset + 10],
                pe_data[section_offset + 11],
            ]) as usize;

            let virtual_address = u32::from_le_bytes([
                pe_data[section_offset + 12],
                pe_data[section_offset + 13],
                pe_data[section_offset + 14],
                pe_data[section_offset + 15],
            ]) as usize;

            let raw_data_ptr = u32::from_le_bytes([
                pe_data[section_offset + 20],
                pe_data[section_offset + 21],
                pe_data[section_offset + 22],
                pe_data[section_offset + 23],
            ]) as usize;

            // check if RVA falls within this section
            if rva >= virtual_address && rva < virtual_address + virtual_size {
                let offset_in_section = rva - virtual_address;
                return Some(raw_data_ptr + offset_in_section);
            }
        }

        None
    }

    /// get original bytes from clean copy (if available)
    fn get_original_bytes(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let clean = self.clean_copy.as_ref()?;
        let rva = self.module.va_to_rva(addr)?;
        self.get_bytes_from_pe(clean, rva as usize, len)
    }
}

/// check if a specific function is hooked
pub fn is_hooked(module: &Module, function_name: &str) -> Result<bool> {
    let addr = module.get_export(function_name)?;
    let detector = HookDetector::new(module)?;
    Ok(detector.check_function(function_name, addr)?.is_some())
}

/// check if a specific function is hooked (pattern detection only, no disk access)
pub fn is_hooked_fast(module: &Module, function_name: &str) -> Result<bool> {
    let addr = module.get_export(function_name)?;
    let detector = HookDetector::without_clean_copy(module);
    Ok(detector.check_function(function_name, addr)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jmp_rel32_detection() {
        let detector = HookDetector {
            module: unsafe { &*(0x1000 as *const Module) }, // dummy, won't be used
            clean_copy: None,
        };

        // E9 01 00 00 00 = jmp +1
        let bytes = [0xE9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = detector.detect_hook_pattern(&bytes, 0x1000);

        assert!(result.is_some());
        let (hook_type, dest) = result.unwrap();
        assert_eq!(hook_type, HookType::JmpRel32);
        assert_eq!(dest, Some(0x1006)); // 0x1000 + 5 + 1
    }

    #[test]
    fn test_breakpoint_detection() {
        let detector = HookDetector {
            module: unsafe { &*(0x1000 as *const Module) },
            clean_copy: None,
        };

        let bytes = [0xCC, 0x00, 0x00, 0x00, 0x00];
        let result = detector.detect_hook_pattern(&bytes, 0x1000);

        assert!(result.is_some());
        let (hook_type, _) = result.unwrap();
        assert_eq!(hook_type, HookType::Breakpoint);
    }
}
