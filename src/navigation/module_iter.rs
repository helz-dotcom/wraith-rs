//! Iterators over loaded modules

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

use super::module::Module;
use crate::error::{Result, WraithError};
use crate::structures::ldr::{
    IN_INITIALIZATION_ORDER_LINKS_OFFSET, IN_LOAD_ORDER_LINKS_OFFSET, IN_MEMORY_ORDER_LINKS_OFFSET,
};
use crate::structures::{LdrDataTableEntry, ListEntry, Peb};

// re-export from error for consistency
pub use crate::error::ModuleListType;

// max iterations before assuming list is corrupted/circular
const MAX_MODULES: usize = 4096;

/// generic module iterator
pub struct ModuleIterator<'a> {
    head: *const ListEntry,
    current: *const ListEntry,
    offset: usize,
    list_type: ModuleListType,
    iterations: usize,
    _peb: &'a Peb, // keep PEB borrowed
}

impl<'a> ModuleIterator<'a> {
    /// create new iterator for specified list type
    pub fn new(peb: &'a Peb, list_type: ModuleListType) -> Result<Self> {
        let ldr = peb.ldr().ok_or(WraithError::NullPointer {
            context: "PEB.Ldr",
        })?;

        let (head, offset) = match list_type {
            ModuleListType::InLoadOrder => (
                &ldr.in_load_order_module_list as *const ListEntry,
                IN_LOAD_ORDER_LINKS_OFFSET,
            ),
            ModuleListType::InMemoryOrder => (
                &ldr.in_memory_order_module_list as *const ListEntry,
                IN_MEMORY_ORDER_LINKS_OFFSET,
            ),
            ModuleListType::InInitializationOrder => (
                &ldr.in_initialization_order_module_list as *const ListEntry,
                IN_INITIALIZATION_ORDER_LINKS_OFFSET,
            ),
        };

        // start at first entry (Flink from head)
        let current = unsafe { (*head).flink };

        Ok(Self {
            head,
            current,
            offset,
            list_type,
            iterations: 0,
            _peb: peb,
        })
    }

    /// get list type being iterated
    pub fn list_type(&self) -> ModuleListType {
        self.list_type
    }
}

impl<'a> Iterator for ModuleIterator<'a> {
    type Item = Module<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // stop when we wrap back to head
        if core::ptr::eq(self.current, self.head) {
            return None;
        }

        // protect against corrupted/circular lists
        if self.iterations >= MAX_MODULES {
            return None;
        }
        self.iterations += 1;

        // validate current pointer is non-null
        if self.current.is_null() {
            return None;
        }

        // CONTAINING_RECORD: get LDR_DATA_TABLE_ENTRY from ListEntry
        let entry_addr = (self.current as usize) - self.offset;
        // SAFETY: entry is valid LDR_DATA_TABLE_ENTRY for loaded module
        let entry = unsafe { &*(entry_addr as *const LdrDataTableEntry) };

        // advance to next
        self.current = unsafe { (*self.current).flink };

        Some(Module::from_entry(entry))
    }
}

/// iterator specifically for InLoadOrderModuleList
pub struct InLoadOrderIter<'a>(ModuleIterator<'a>);

impl<'a> InLoadOrderIter<'a> {
    pub fn new(peb: &'a Peb) -> Result<Self> {
        Ok(Self(ModuleIterator::new(peb, ModuleListType::InLoadOrder)?))
    }
}

impl<'a> Iterator for InLoadOrderIter<'a> {
    type Item = Module<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// iterator specifically for InMemoryOrderModuleList
pub struct InMemoryOrderIter<'a>(ModuleIterator<'a>);

impl<'a> InMemoryOrderIter<'a> {
    pub fn new(peb: &'a Peb) -> Result<Self> {
        Ok(Self(ModuleIterator::new(
            peb,
            ModuleListType::InMemoryOrder,
        )?))
    }
}

impl<'a> Iterator for InMemoryOrderIter<'a> {
    type Item = Module<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// iterator specifically for InInitializationOrderModuleList
pub struct InInitializationOrderIter<'a>(ModuleIterator<'a>);

impl<'a> InInitializationOrderIter<'a> {
    pub fn new(peb: &'a Peb) -> Result<Self> {
        Ok(Self(ModuleIterator::new(
            peb,
            ModuleListType::InInitializationOrder,
        )?))
    }
}

impl<'a> Iterator for InInitializationOrderIter<'a> {
    type Item = Module<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// count loaded modules
pub fn module_count(peb: &Peb) -> Result<usize> {
    Ok(ModuleIterator::new(peb, ModuleListType::InLoadOrder)?.count())
}

/// collect all modules into a Vec
pub fn collect_modules(peb: &Peb) -> Result<Vec<ModuleInfo>> {
    let iter = ModuleIterator::new(peb, ModuleListType::InLoadOrder)?;
    Ok(iter
        .map(|m| ModuleInfo {
            name: m.name(),
            path: m.full_path(),
            base: m.base(),
            size: m.size(),
            entry_point: m.entry_point(),
        })
        .collect())
}

/// owned module information (doesn't borrow from PEB)
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
    pub entry_point: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_count() {
        let peb = Peb::current().expect("should get PEB");
        let count = module_count(&peb).expect("should count modules");
        assert!(count > 0, "should have at least one module");
    }

    #[test]
    fn test_collect_modules() {
        let peb = Peb::current().expect("should get PEB");
        let modules = collect_modules(&peb).expect("should collect modules");
        assert!(!modules.is_empty(), "should have modules");

        // first module should be the executable
        let first = &modules[0];
        assert!(first.base > 0, "first module should have valid base");
    }

    #[test]
    fn test_all_three_lists() {
        let peb = Peb::current().expect("should get PEB");

        let load_order: Vec<_> = ModuleIterator::new(&peb, ModuleListType::InLoadOrder)
            .expect("load order iter")
            .collect();
        let memory_order: Vec<_> = ModuleIterator::new(&peb, ModuleListType::InMemoryOrder)
            .expect("memory order iter")
            .collect();
        let init_order: Vec<_> = ModuleIterator::new(&peb, ModuleListType::InInitializationOrder)
            .expect("init order iter")
            .collect();

        // all three lists should have same modules (maybe different order)
        assert_eq!(
            load_order.len(),
            memory_order.len(),
            "load and memory order should have same count"
        );
        // init order may have fewer (some DLLs don't have entry points)
        assert!(
            init_order.len() <= load_order.len(),
            "init order should have <= load order count"
        );
    }
}
