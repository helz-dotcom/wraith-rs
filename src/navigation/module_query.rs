//! Query interfaces for finding modules

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, vec::Vec};

#[cfg(feature = "std")]
use std::{format, vec::Vec};

use super::module::{Module, ModuleHandle};
use super::module_iter::{ModuleIterator, ModuleListType};
use crate::error::{Result, WraithError};
use crate::structures::Peb;
use crate::util::hash::djb2_hash_lowercase;

/// module query builder
pub struct ModuleQuery<'a> {
    peb: &'a Peb,
}

impl<'a> ModuleQuery<'a> {
    /// create new query for given PEB
    pub fn new(peb: &'a Peb) -> Self {
        Self { peb }
    }

    /// find module by name (case-insensitive)
    ///
    /// searches by base name (e.g., "ntdll.dll", not full path)
    pub fn find_by_name(&self, name: &str) -> Result<Module<'a>> {
        let name_lower = name.to_lowercase();

        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            if module.name_lowercase() == name_lower {
                return Ok(module);
            }
        }

        Err(WraithError::ModuleNotFound { name: name.into() })
    }

    /// find module by hash of name (for API hashing)
    ///
    /// hash is computed lowercase
    pub fn find_by_hash(&self, hash: u32) -> Result<Module<'a>> {
        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            let name = module.name();
            let name_bytes = name.as_bytes();
            if djb2_hash_lowercase(name_bytes) == hash {
                return Ok(module);
            }
        }

        Err(WraithError::ModuleNotFound {
            name: format!("hash {hash:#x}"),
        })
    }

    /// find module containing an address
    pub fn find_by_address(&self, address: usize) -> Result<Module<'a>> {
        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            if module.contains(address) {
                return Ok(module);
            }
        }

        Err(WraithError::AddressNotInModule {
            address: address as u64,
        })
    }

    /// find module by base address (exact match)
    pub fn find_by_base(&self, base: usize) -> Result<Module<'a>> {
        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            if module.base() == base {
                return Ok(module);
            }
        }

        Err(WraithError::AddressNotInModule {
            address: base as u64,
        })
    }

    /// find module by partial path match
    pub fn find_by_path_contains(&self, substring: &str) -> Result<Module<'a>> {
        let sub_lower = substring.to_lowercase();

        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            if module.full_path().to_lowercase().contains(&sub_lower) {
                return Ok(module);
            }
        }

        Err(WraithError::ModuleNotFound {
            name: substring.into(),
        })
    }

    /// get ntdll.dll module
    pub fn ntdll(&self) -> Result<Module<'a>> {
        self.find_by_name("ntdll.dll")
    }

    /// get kernel32.dll module
    pub fn kernel32(&self) -> Result<Module<'a>> {
        self.find_by_name("kernel32.dll")
    }

    /// get kernelbase.dll module
    pub fn kernelbase(&self) -> Result<Module<'a>> {
        self.find_by_name("kernelbase.dll")
    }

    /// get current executable module
    pub fn current_module(&self) -> Result<Module<'a>> {
        let image_base = self.peb.image_base() as usize;
        self.find_by_base(image_base)
    }

    /// find all modules matching a predicate
    pub fn find_all<F>(&self, predicate: F) -> Result<Vec<Module<'a>>>
    where
        F: Fn(&Module) -> bool,
    {
        let mut results = Vec::new();

        for module in ModuleIterator::new(self.peb, ModuleListType::InLoadOrder)? {
            if predicate(&module) {
                results.push(module);
            }
        }

        Ok(results)
    }

    /// check if a module is loaded
    pub fn is_loaded(&self, name: &str) -> bool {
        self.find_by_name(name).is_ok()
    }
}

/// convenient function to find ntdll
pub fn get_ntdll() -> Result<ModuleHandle> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.ntdll()?;

    // SAFETY: converting borrowed module to handle - we know the module exists
    unsafe {
        ModuleHandle::from_raw(module.as_ldr_entry() as *const _ as *mut _)
            .ok_or(WraithError::NullPointer {
                context: "ntdll entry",
            })
    }
}

/// convenient function to find kernel32
pub fn get_kernel32() -> Result<ModuleHandle> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.kernel32()?;

    // SAFETY: converting borrowed module to handle - we know the module exists
    unsafe {
        ModuleHandle::from_raw(module.as_ldr_entry() as *const _ as *mut _)
            .ok_or(WraithError::NullPointer {
                context: "kernel32 entry",
            })
    }
}

/// get export from a module by name
pub fn get_proc_address(module_name: &str, proc_name: &str) -> Result<usize> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(module_name)?;
    module.get_export(proc_name)
}

/// get export from ntdll by name
pub fn get_ntdll_export(proc_name: &str) -> Result<usize> {
    get_proc_address("ntdll.dll", proc_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ntdll() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let ntdll = query.ntdll().expect("should find ntdll");
        assert!(ntdll.name_lowercase().contains("ntdll"));
    }

    #[test]
    fn test_find_kernel32() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let kernel32 = query.kernel32().expect("should find kernel32");
        assert!(kernel32.name_lowercase().contains("kernel32"));
    }

    #[test]
    fn test_find_by_address() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);

        // use address of a function we know exists
        let addr = test_find_by_address as usize;
        let module = query.find_by_address(addr).expect("should find module");

        // should be our executable
        assert!(module.contains(addr));
    }

    #[test]
    fn test_get_ntdll_handle() {
        let handle = get_ntdll().expect("should get ntdll handle");
        let module = handle.as_module();
        assert!(module.name_lowercase().contains("ntdll"));
    }

    #[test]
    fn test_get_export() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let ntdll = query.ntdll().expect("should find ntdll");

        let addr = ntdll.get_export("NtClose").expect("should find NtClose");
        assert!(addr > ntdll.base());
        assert!(addr < ntdll.base() + ntdll.size());
    }

    #[test]
    fn test_is_loaded() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);

        assert!(query.is_loaded("ntdll.dll"));
        assert!(query.is_loaded("kernel32.dll"));
        assert!(!query.is_loaded("nonexistent_module_12345.dll"));
    }
}
