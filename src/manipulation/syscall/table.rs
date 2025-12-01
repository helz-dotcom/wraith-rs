//! Syscall lookup table
//!
//! Provides fast lookup of syscall information by name, hash, or SSN.

use super::enumerator::{enumerate_syscalls, EnumeratedSyscall};
use crate::error::{Result, WraithError};
use crate::util::hash::djb2_hash;
use std::collections::HashMap;

/// syscall entry in the table
#[derive(Debug, Clone)]
pub struct SyscallEntry {
    /// function name
    pub name: String,
    /// hash of name for fast lookup
    pub name_hash: u32,
    /// syscall service number
    pub ssn: u16,
    /// function address in ntdll
    pub address: usize,
    /// address of syscall instruction (for indirect calls)
    pub syscall_address: Option<usize>,
}

impl From<EnumeratedSyscall> for SyscallEntry {
    fn from(sc: EnumeratedSyscall) -> Self {
        Self {
            name: sc.name,
            name_hash: sc.name_hash,
            ssn: sc.ssn,
            address: sc.address,
            syscall_address: sc.syscall_address,
        }
    }
}

/// syscall lookup table
pub struct SyscallTable {
    /// entries by name hash
    by_hash: HashMap<u32, SyscallEntry>,
    /// entries by SSN
    by_ssn: HashMap<u16, SyscallEntry>,
    /// all entries in order
    entries: Vec<SyscallEntry>,
}

impl SyscallTable {
    /// enumerate and build syscall table
    pub fn enumerate() -> Result<Self> {
        let syscalls = enumerate_syscalls()?;

        let mut by_hash = HashMap::with_capacity(syscalls.len());
        let mut by_ssn = HashMap::with_capacity(syscalls.len());
        let mut entries = Vec::with_capacity(syscalls.len());

        for sc in syscalls {
            let entry = SyscallEntry::from(sc);

            by_hash.insert(entry.name_hash, entry.clone());
            by_ssn.insert(entry.ssn, entry.clone());
            entries.push(entry);
        }

        Ok(Self {
            by_hash,
            by_ssn,
            entries,
        })
    }

    /// get syscall by name
    pub fn get(&self, name: &str) -> Option<&SyscallEntry> {
        let hash = djb2_hash(name.as_bytes());
        self.by_hash.get(&hash)
    }

    /// get syscall by hash
    pub fn get_by_hash(&self, hash: u32) -> Option<&SyscallEntry> {
        self.by_hash.get(&hash)
    }

    /// get syscall by SSN
    pub fn get_by_ssn(&self, ssn: u16) -> Option<&SyscallEntry> {
        self.by_ssn.get(&ssn)
    }

    /// get all entries
    pub fn entries(&self) -> &[SyscallEntry] {
        &self.entries
    }

    /// number of syscalls
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// get SSN for syscall name
    pub fn get_ssn(&self, name: &str) -> Option<u16> {
        self.get(name).map(|e| e.ssn)
    }

    /// get syscall instruction address for indirect calls
    pub fn get_syscall_address(&self, name: &str) -> Option<usize> {
        self.get(name).and_then(|e| e.syscall_address)
    }

    /// find syscall containing address (for detecting which syscall is hooked)
    pub fn find_by_address(&self, addr: usize) -> Option<&SyscallEntry> {
        // typical syscall stub is ~32 bytes
        self.entries
            .iter()
            .find(|e| addr >= e.address && addr < e.address + 32)
    }

    /// get syscall or return error
    pub fn require(&self, name: &str) -> Result<&SyscallEntry> {
        self.get(name).ok_or_else(|| WraithError::SyscallNotFound {
            name: name.to_string(),
        })
    }

    /// get syscall by hash or return error
    pub fn require_by_hash(&self, hash: u32) -> Result<&SyscallEntry> {
        self.get_by_hash(hash)
            .ok_or_else(|| WraithError::SyscallNotFound {
                name: format!("hash {hash:#x}"),
            })
    }
}

/// common syscall name hashes (computed at compile time)
pub mod hashes {
    use crate::util::hash::djb2_hash;

    pub const NT_OPEN_PROCESS: u32 = djb2_hash(b"NtOpenProcess");
    pub const NT_CLOSE: u32 = djb2_hash(b"NtClose");
    pub const NT_READ_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtReadVirtualMemory");
    pub const NT_WRITE_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtWriteVirtualMemory");
    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtAllocateVirtualMemory");
    pub const NT_FREE_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtFreeVirtualMemory");
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtProtectVirtualMemory");
    pub const NT_QUERY_INFORMATION_PROCESS: u32 = djb2_hash(b"NtQueryInformationProcess");
    pub const NT_SET_INFORMATION_THREAD: u32 = djb2_hash(b"NtSetInformationThread");
    pub const NT_CREATE_THREAD_EX: u32 = djb2_hash(b"NtCreateThreadEx");
    pub const NT_QUERY_SYSTEM_INFORMATION: u32 = djb2_hash(b"NtQuerySystemInformation");
    pub const NT_QUERY_VIRTUAL_MEMORY: u32 = djb2_hash(b"NtQueryVirtualMemory");
    pub const NT_OPEN_FILE: u32 = djb2_hash(b"NtOpenFile");
    pub const NT_CREATE_FILE: u32 = djb2_hash(b"NtCreateFile");
    pub const NT_READ_FILE: u32 = djb2_hash(b"NtReadFile");
    pub const NT_WRITE_FILE: u32 = djb2_hash(b"NtWriteFile");
    pub const NT_CREATE_SECTION: u32 = djb2_hash(b"NtCreateSection");
    pub const NT_MAP_VIEW_OF_SECTION: u32 = djb2_hash(b"NtMapViewOfSection");
    pub const NT_UNMAP_VIEW_OF_SECTION: u32 = djb2_hash(b"NtUnmapViewOfSection");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_table() {
        let table = SyscallTable::enumerate().expect("should enumerate");
        assert!(!table.is_empty());
    }

    #[test]
    fn test_lookup_by_name() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        let entry = table.get("NtClose").expect("should find NtClose");
        assert_eq!(entry.name, "NtClose");
    }

    #[test]
    fn test_lookup_by_hash() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        let hash = djb2_hash(b"NtClose");
        let entry = table.get_by_hash(hash).expect("should find by hash");
        assert_eq!(entry.name, "NtClose");
    }

    #[test]
    fn test_precomputed_hash() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        let entry = table
            .get_by_hash(hashes::NT_CLOSE)
            .expect("should find by precomputed hash");
        assert_eq!(entry.name, "NtClose");
    }

    #[test]
    fn test_require() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        assert!(table.require("NtClose").is_ok());
        assert!(table.require("NonExistentSyscall").is_err());
    }
}
