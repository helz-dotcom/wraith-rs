//! Syscall Service Number enumeration from ntdll
//!
//! Extracts SSNs by parsing ntdll export directory and reading
//! the syscall stub prologues to find the mov eax, imm32 instruction.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{string::{String, ToString}, vec::Vec};

#[cfg(feature = "std")]
use std::{string::{String, ToString}, vec::Vec};

use crate::error::{Result, WraithError};
use crate::navigation::{Module, ModuleQuery};
use crate::structures::pe::{DataDirectoryType, ExportDirectory};
use crate::structures::Peb;
use crate::util::hash::djb2_hash;

/// syscall stub patterns for detection
mod patterns {
    // x64 syscall stub pattern:
    // 4C 8B D1        mov r10, rcx
    // B8 XX XX 00 00  mov eax, <ssn>
    // ...
    // 0F 05           syscall
    // C3              ret
    #[cfg(target_arch = "x86_64")]
    pub const MOV_R10_RCX: [u8; 3] = [0x4C, 0x8B, 0xD1];

    pub const MOV_EAX: u8 = 0xB8;

    #[cfg(target_arch = "x86_64")]
    pub const SYSCALL: [u8; 2] = [0x0F, 0x05];

    // x86 syscall stub patterns
    #[cfg(target_arch = "x86")]
    pub const INT_2E: [u8; 2] = [0xCD, 0x2E];

    #[cfg(target_arch = "x86")]
    pub const SYSENTER: [u8; 2] = [0x0F, 0x34];
}

/// enumerates syscalls from ntdll exports
pub struct SyscallEnumerator<'a> {
    ntdll: Module<'a>,
}

impl<'a> SyscallEnumerator<'a> {
    /// create enumerator for ntdll
    pub fn new(ntdll: Module<'a>) -> Self {
        Self { ntdll }
    }

    /// enumerate all syscalls and their SSNs
    pub fn enumerate(&self) -> Result<Vec<EnumeratedSyscall>> {
        let mut syscalls = Vec::new();

        let nt = self.ntdll.nt_headers()?;
        let export_dir = nt
            .data_directory(DataDirectoryType::Export.index())
            .ok_or(WraithError::SyscallEnumerationFailed {
                reason: "no export directory".into(),
            })?;

        if !export_dir.is_present() {
            return Err(WraithError::SyscallEnumerationFailed {
                reason: "export directory not present".into(),
            });
        }

        let base = self.ntdll.base();
        // SAFETY: export directory RVA points to valid memory in loaded ntdll
        let exports = unsafe {
            &*((base + export_dir.virtual_address as usize) as *const ExportDirectory)
        };

        let num_names = exports.number_of_names as usize;
        let names = base + exports.address_of_names as usize;
        let ordinals = base + exports.address_of_name_ordinals as usize;
        let functions = base + exports.address_of_functions as usize;

        for i in 0..num_names {
            // SAFETY: iterating within bounds of export arrays
            let name_rva = unsafe { *((names + i * 4) as *const u32) };
            let name_ptr = (base + name_rva as usize) as *const u8;

            // read function name with bounds checking
            let name = unsafe {
                let mut len = 0;
                while *name_ptr.add(len) != 0 && len < 256 {
                    len += 1;
                }
                let bytes = core::slice::from_raw_parts(name_ptr, len);
                match core::str::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => continue, // skip invalid UTF-8
                }
            };

            // only process Nt/Zw functions (syscalls)
            if !name.starts_with("Nt") && !name.starts_with("Zw") {
                continue;
            }

            // skip Nt functions that aren't syscalls (they're just accessors)
            if matches!(
                name,
                "NtCurrentTeb"
                    | "NtCurrentPeb"
                    | "NtGetTickCount"
                    | "NtdllDefWindowProc_A"
                    | "NtdllDefWindowProc_W"
                    | "NtdllDialogWndProc_A"
                    | "NtdllDialogWndProc_W"
            ) {
                continue;
            }

            let ordinal = unsafe { *((ordinals + i * 2) as *const u16) };
            let func_rva = unsafe { *((functions + ordinal as usize * 4) as *const u32) };
            let func_addr = base + func_rva as usize;

            // check for forwarded export
            if func_rva >= export_dir.virtual_address
                && func_rva < export_dir.virtual_address + export_dir.size
            {
                continue;
            }

            // try to extract SSN from the stub
            if let Some(ssn) = self.extract_ssn(func_addr) {
                syscalls.push(EnumeratedSyscall {
                    name: name.to_string(),
                    name_hash: djb2_hash(name.as_bytes()),
                    ssn,
                    address: func_addr,
                    syscall_address: self.find_syscall_instruction(func_addr),
                });
            }
        }

        // sort by SSN (they should be sequential)
        syscalls.sort_by_key(|s| s.ssn);

        Ok(syscalls)
    }

    /// extract SSN from syscall stub (x64)
    #[cfg(target_arch = "x86_64")]
    fn extract_ssn(&self, addr: usize) -> Option<u16> {
        // SAFETY: reading from function address in loaded ntdll
        let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 32) };

        // standard pattern: 4C 8B D1 B8 XX XX 00 00
        if bytes.len() >= 8
            && bytes[0..3] == patterns::MOV_R10_RCX
            && bytes[3] == patterns::MOV_EAX
        {
            let ssn = u16::from_le_bytes([bytes[4], bytes[5]]);
            return Some(ssn);
        }

        // hooked stub might have different prologue - scan for mov eax pattern
        for i in 0..20 {
            if i + 2 < bytes.len() && bytes[i] == patterns::MOV_EAX {
                let ssn = u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]);
                if ssn < 0x1000 {
                    return Some(ssn);
                }
            }
        }

        None
    }

    /// extract SSN from syscall stub (x86)
    #[cfg(target_arch = "x86")]
    fn extract_ssn(&self, addr: usize) -> Option<u16> {
        // SAFETY: reading from function address in loaded ntdll
        let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 32) };

        // pattern: B8 XX XX 00 00
        if bytes.len() >= 5 && bytes[0] == patterns::MOV_EAX {
            let ssn = u16::from_le_bytes([bytes[1], bytes[2]]);
            return Some(ssn);
        }

        None
    }

    /// find syscall/sysenter instruction address in stub (x64)
    #[cfg(target_arch = "x86_64")]
    fn find_syscall_instruction(&self, func_addr: usize) -> Option<usize> {
        // SAFETY: reading from function in loaded ntdll
        let bytes = unsafe { core::slice::from_raw_parts(func_addr as *const u8, 32) };

        // look for syscall (0F 05)
        for i in 0..30 {
            if i + 1 < bytes.len() && bytes[i..].starts_with(&patterns::SYSCALL) {
                return Some(func_addr + i);
            }
        }

        None
    }

    /// find syscall/sysenter instruction address in stub (x86)
    #[cfg(target_arch = "x86")]
    fn find_syscall_instruction(&self, func_addr: usize) -> Option<usize> {
        // SAFETY: reading from function in loaded ntdll
        let bytes = unsafe { core::slice::from_raw_parts(func_addr as *const u8, 64) };

        // look for int 0x2e or sysenter
        for i in 0..60 {
            if i + 1 < bytes.len()
                && (bytes[i..].starts_with(&patterns::INT_2E)
                    || bytes[i..].starts_with(&patterns::SYSENTER))
            {
                return Some(func_addr + i);
            }
        }

        None
    }

    /// resolve SSN using "Halo's Gate" technique
    ///
    /// if a syscall is hooked, look at neighboring syscalls
    /// (SSNs are sequential, so Nt* functions nearby have SSN +/- N)
    #[allow(dead_code)]
    pub fn resolve_hooked_ssn(&self, target_addr: usize) -> Option<u16> {
        // search upward (earlier functions have lower SSNs)
        for offset in 1..=20u16 {
            // typical syscall stub size is ~32 bytes
            let check_addr = target_addr.wrapping_sub(offset as usize * 32);
            if let Some(ssn) = self.extract_ssn(check_addr) {
                return Some(ssn.wrapping_add(offset));
            }
        }

        // search downward (later functions have higher SSNs)
        for offset in 1..=20u16 {
            let check_addr = target_addr + (offset as usize * 32);
            if let Some(ssn) = self.extract_ssn(check_addr) {
                return ssn.checked_sub(offset);
            }
        }

        None
    }
}

/// enumerated syscall information
#[derive(Debug, Clone)]
pub struct EnumeratedSyscall {
    /// function name (e.g., "NtOpenProcess")
    pub name: String,
    /// hash of function name for fast lookup
    pub name_hash: u32,
    /// syscall service number
    pub ssn: u16,
    /// address in ntdll
    pub address: usize,
    /// address of syscall instruction (for indirect calls)
    pub syscall_address: Option<usize>,
}

/// enumerate syscalls from current process's ntdll
pub fn enumerate_syscalls() -> Result<Vec<EnumeratedSyscall>> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let ntdll = query.ntdll().map_err(|_| WraithError::NtdllNotFound)?;

    let enumerator = SyscallEnumerator::new(ntdll);
    enumerator.enumerate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_syscalls() {
        let syscalls = enumerate_syscalls().expect("should enumerate syscalls");
        assert!(!syscalls.is_empty(), "should find at least some syscalls");

        // should have NtClose
        let nt_close = syscalls.iter().find(|s| s.name == "NtClose");
        assert!(nt_close.is_some(), "should find NtClose");

        // SSN should be reasonable (< 0x500 on most Windows versions)
        let close = nt_close.unwrap();
        assert!(close.ssn < 0x500, "NtClose SSN should be reasonable");
    }

    #[test]
    fn test_ssn_ordering() {
        let syscalls = enumerate_syscalls().expect("should enumerate syscalls");

        // SSNs should be sorted after enumeration
        for i in 1..syscalls.len() {
            assert!(
                syscalls[i].ssn >= syscalls[i - 1].ssn,
                "SSNs should be sorted"
            );
        }
    }
}
