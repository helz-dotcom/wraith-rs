//! Function integrity verification
//!
//! Stores checksums of function prologues and verifies they haven't
//! been modified at runtime. Useful for detecting hooks installed
//! after initial recording.

use crate::error::Result;
use crate::navigation::Module;
use crate::structures::pe::{DataDirectoryType, ExportDirectory};
use std::collections::HashMap;

/// stores checksums of function prologues for integrity checking
pub struct IntegrityChecker {
    checksums: HashMap<usize, u64>,
    prologue_size: usize,
}

impl IntegrityChecker {
    /// create new integrity checker with custom prologue size
    pub fn new(prologue_size: usize) -> Self {
        Self {
            checksums: HashMap::new(),
            prologue_size,
        }
    }

    /// create with default prologue size (32 bytes)
    pub fn with_default_size() -> Self {
        Self::new(32)
    }

    /// get configured prologue size
    pub fn prologue_size(&self) -> usize {
        self.prologue_size
    }

    /// number of recorded functions
    pub fn recorded_count(&self) -> usize {
        self.checksums.len()
    }

    /// record checksum of function at address
    pub fn record(&mut self, addr: usize) {
        let checksum = self.compute_checksum(addr);
        self.checksums.insert(addr, checksum);
    }

    /// record checksums for specific addresses
    pub fn record_addresses(&mut self, addresses: &[usize]) {
        for &addr in addresses {
            self.record(addr);
        }
    }

    /// record checksums for all exports in module
    pub fn record_module(&mut self, module: &Module) -> Result<usize> {
        let nt = module.nt_headers()?;
        let export_dir = match nt.data_directory(DataDirectoryType::Export.index()) {
            Some(dir) if dir.is_present() => dir,
            _ => return Ok(0),
        };

        let base = module.base();
        // SAFETY: export directory is present and valid for loaded modules
        let exports = unsafe {
            &*((base + export_dir.virtual_address as usize) as *const ExportDirectory)
        };

        let num_funcs = exports.number_of_functions as usize;
        let functions_va = base + exports.address_of_functions as usize;
        let mut count = 0;

        for i in 0..num_funcs {
            // SAFETY: iterating within bounds
            let func_rva = unsafe { *((functions_va + i * 4) as *const u32) };
            if func_rva != 0 {
                // skip forwarded exports
                if func_rva >= export_dir.virtual_address
                    && func_rva < export_dir.virtual_address + export_dir.size
                {
                    continue;
                }

                let func_addr = base + func_rva as usize;
                self.record(func_addr);
                count += 1;
            }
        }

        Ok(count)
    }

    /// record specific exports by name
    pub fn record_exports(&mut self, module: &Module, names: &[&str]) -> Result<usize> {
        let mut count = 0;
        for name in names {
            if let Ok(addr) = module.get_export(name) {
                self.record(addr);
                count += 1;
            }
        }
        Ok(count)
    }

    /// verify function hasn't been modified
    pub fn verify(&self, addr: usize) -> bool {
        match self.checksums.get(&addr) {
            Some(&expected) => {
                let current = self.compute_checksum(addr);
                current == expected
            }
            None => true, // not recorded, can't verify - assume ok
        }
    }

    /// verify all recorded functions, returning list of modified addresses
    pub fn verify_all(&self) -> Vec<usize> {
        self.checksums
            .keys()
            .filter(|&&addr| !self.verify(addr))
            .copied()
            .collect()
    }

    /// get addresses of all modified functions
    pub fn get_modified(&self) -> Vec<usize> {
        self.verify_all()
    }

    /// check if a specific address was recorded
    pub fn is_recorded(&self, addr: usize) -> bool {
        self.checksums.contains_key(&addr)
    }

    /// remove a recorded address
    pub fn unrecord(&mut self, addr: usize) -> bool {
        self.checksums.remove(&addr).is_some()
    }

    /// clear all recorded checksums
    pub fn clear(&mut self) {
        self.checksums.clear();
    }

    /// compute FNV-1a hash of bytes at address
    fn compute_checksum(&self, addr: usize) -> u64 {
        // SAFETY: caller ensures address is valid and readable
        let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, self.prologue_size) };

        // FNV-1a hash
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET;
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }
}

impl Default for IntegrityChecker {
    fn default() -> Self {
        Self::with_default_size()
    }
}

/// monitor for continuous integrity checking
pub struct IntegrityMonitor {
    checker: IntegrityChecker,
    module_name: String,
}

impl IntegrityMonitor {
    /// create monitor for a module
    pub fn for_module(module: &Module) -> Result<Self> {
        let mut checker = IntegrityChecker::with_default_size();
        checker.record_module(module)?;

        Ok(Self {
            checker,
            module_name: module.name(),
        })
    }

    /// create monitor for specific functions
    pub fn for_exports(module: &Module, exports: &[&str]) -> Result<Self> {
        let mut checker = IntegrityChecker::with_default_size();
        checker.record_exports(module, exports)?;

        Ok(Self {
            checker,
            module_name: module.name(),
        })
    }

    /// check for modifications
    pub fn check(&self) -> Vec<usize> {
        self.checker.get_modified()
    }

    /// get module name
    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    /// number of monitored functions
    pub fn monitored_count(&self) -> usize {
        self.checker.recorded_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_consistency() {
        let checker = IntegrityChecker::new(8);

        // same input should produce same hash
        let data = [0x90u8; 8]; // nops
        let addr = data.as_ptr() as usize;

        let hash1 = checker.compute_checksum(addr);
        let hash2 = checker.compute_checksum(addr);

        assert_eq!(hash1, hash2);
    }
}
