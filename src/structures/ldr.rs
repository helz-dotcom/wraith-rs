//! LDR_DATA_TABLE_ENTRY and PEB_LDR_DATA structures

use super::list_entry::ListEntry;
use super::unicode_string::UnicodeString;
use crate::arch::NativePtr;

/// PEB_LDR_DATA - contains the module lists
#[repr(C)]
pub struct PebLdrData {
    pub length: u32,
    pub initialized: u8,
    pub ss_handle: NativePtr,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
    pub entry_in_progress: NativePtr,
    pub shutdown_in_progress: u8,
    pub shutdown_thread_id: NativePtr,
}

/// LDR_DATA_TABLE_ENTRY - represents a loaded module
///
/// this is a simplified version; full structure has more fields
/// that vary by Windows version
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    pub dll_base: NativePtr,
    pub entry_point: NativePtr,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    // additional fields vary by Windows version
    // these are accessed via offsets when needed
}

impl LdrDataTableEntry {
    /// get module base address
    pub fn base(&self) -> usize {
        self.dll_base as usize
    }

    /// get module size
    pub fn size(&self) -> usize {
        self.size_of_image as usize
    }

    /// get entry point address
    pub fn entry_point(&self) -> usize {
        self.entry_point as usize
    }

    /// get full path as String
    ///
    /// # Safety
    /// full_dll_name buffer must be valid
    pub unsafe fn full_name(&self) -> String {
        unsafe { self.full_dll_name.to_string() }
    }

    /// get base name (filename only) as String
    ///
    /// # Safety
    /// base_dll_name buffer must be valid
    pub unsafe fn base_name(&self) -> String {
        unsafe { self.base_dll_name.to_string() }
    }

    /// check if address is within this module
    pub fn contains_address(&self, addr: usize) -> bool {
        let base = self.base();
        addr >= base && addr < base + self.size()
    }

    /// check if this module matches a name (case-insensitive)
    ///
    /// # Safety
    /// name buffers must be valid
    pub unsafe fn matches_name(&self, name: &str) -> bool {
        unsafe { self.base_dll_name.eq_ignore_case(name) }
    }
}

/// offset of InLoadOrderLinks within LDR_DATA_TABLE_ENTRY
pub const IN_LOAD_ORDER_LINKS_OFFSET: usize = 0;

/// offset of InMemoryOrderLinks within LDR_DATA_TABLE_ENTRY
#[cfg(target_arch = "x86_64")]
pub const IN_MEMORY_ORDER_LINKS_OFFSET: usize = 0x10;

#[cfg(target_arch = "x86")]
pub const IN_MEMORY_ORDER_LINKS_OFFSET: usize = 0x08;

/// offset of InInitializationOrderLinks within LDR_DATA_TABLE_ENTRY
#[cfg(target_arch = "x86_64")]
pub const IN_INITIALIZATION_ORDER_LINKS_OFFSET: usize = 0x20;

#[cfg(target_arch = "x86")]
pub const IN_INITIALIZATION_ORDER_LINKS_OFFSET: usize = 0x10;
