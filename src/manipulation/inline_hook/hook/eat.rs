//! EAT (Export Address Table) hooking
//!
//! EAT hooks work by modifying entries in a module's Export Address Table.
//! When a module exports a function, its address is stored in the EAT.
//! By replacing an EAT entry with an RVA pointing to a detour, all calls
//! that resolve the export (via GetProcAddress or loader resolution) are redirected.
//!
//! # Advantages
//! - Affects all future resolutions of the export
//! - No code modification (safer for integrity checks)
//! - Works across the entire process
//!
//! # Limitations
//! - Only affects future GetProcAddress calls (not already-resolved pointers)
//! - Does not affect direct calls to known addresses
//! - Requires the detour to be within ±2GB of the module (for RVA encoding)

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{collections::HashMap, format, string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::navigation::{Module, ModuleQuery};
use crate::structures::pe::{DataDirectoryType, ExportDirectory};
use crate::structures::Peb;
use crate::util::memory::ProtectionGuard;

const PAGE_READWRITE: u32 = 0x04;
const MAX_EXPORT_COUNT: usize = 0x10000;

/// information about a single EAT entry
#[derive(Debug, Clone)]
pub struct EatEntry {
    /// address of the EAT entry (pointer to the function RVA)
    pub entry_address: usize,
    /// current RVA value in the EAT
    pub current_rva: u32,
    /// current absolute address (base + rva)
    pub current_address: usize,
    /// function name (if exported by name)
    pub function_name: Option<String>,
    /// ordinal
    pub ordinal: u32,
    /// whether this is a forwarded export
    pub is_forwarded: bool,
    /// forwarder string (if forwarded)
    pub forwarder: Option<String>,
}

/// EAT hook instance
pub struct EatHook {
    /// address of the EAT entry (RVA pointer)
    eat_entry: usize,
    /// module base (needed to convert RVA <-> VA)
    module_base: usize,
    /// original RVA value
    original_rva: u32,
    /// detour RVA value
    detour_rva: u32,
    /// detour absolute address
    detour: usize,
    /// whether the hook is currently active
    active: bool,
    /// whether to restore on drop
    auto_restore: bool,
}

impl EatHook {
    /// create and install an EAT hook
    ///
    /// # Arguments
    /// * `module_name` - the module containing the export (e.g., "kernel32.dll")
    /// * `function_name` - the function name to hook
    /// * `detour` - address of the detour function
    ///
    /// # Note
    /// The detour function must be within ±2GB of the module base for the RVA
    /// to be encodable. For distant detours, consider using a trampoline.
    ///
    /// # Example
    /// ```ignore
    /// let hook = EatHook::new("kernel32.dll", "GetProcAddress", my_detour as usize)?;
    /// // future GetProcAddress("kernel32.dll", "GetProcAddress") calls return my_detour
    /// ```
    pub fn new(module_name: &str, function_name: &str, detour: usize) -> Result<Self> {
        let peb = Peb::current()?;
        let query = ModuleQuery::new(&peb);
        let module = query.find_by_name(module_name)?;

        Self::new_in_module(&module, function_name, detour)
    }

    /// create and install an EAT hook in a specific module
    pub fn new_in_module(module: &Module, function_name: &str, detour: usize) -> Result<Self> {
        let eat_entry = find_eat_entry(module, function_name)?;

        if eat_entry.is_forwarded {
            return Err(WraithError::ForwardedExport {
                forwarder: eat_entry.forwarder.unwrap_or_default(),
            });
        }

        Self::new_at_address(eat_entry.entry_address, module.base(), detour)
    }

    /// create and install an EAT hook at a specific EAT entry address
    pub fn new_at_address(eat_entry: usize, module_base: usize, detour: usize) -> Result<Self> {
        if eat_entry == 0 {
            return Err(WraithError::NullPointer { context: "eat_entry" });
        }

        // read original RVA
        // SAFETY: eat_entry points to valid EAT entry
        let original_rva = unsafe { *(eat_entry as *const u32) };

        // calculate detour RVA
        let detour_rva = address_to_rva(module_base, detour)?;

        let mut hook = Self {
            eat_entry,
            module_base,
            original_rva,
            detour_rva,
            detour,
            active: false,
            auto_restore: true,
        };

        hook.install()?;
        Ok(hook)
    }

    /// install the hook (write detour RVA to EAT)
    pub fn install(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }

        write_eat_entry(self.eat_entry, self.detour_rva)?;
        self.active = true;

        Ok(())
    }

    /// remove the hook (restore original RVA)
    pub fn uninstall(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        write_eat_entry(self.eat_entry, self.original_rva)?;
        self.active = false;

        Ok(())
    }

    /// check if hook is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// get the original function address
    pub fn original(&self) -> usize {
        self.module_base + self.original_rva as usize
    }

    /// get the original RVA
    pub fn original_rva(&self) -> u32 {
        self.original_rva
    }

    /// get the detour function address
    pub fn detour(&self) -> usize {
        self.detour
    }

    /// get the EAT entry address
    pub fn eat_entry(&self) -> usize {
        self.eat_entry
    }

    /// set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, restore: bool) {
        self.auto_restore = restore;
    }

    /// leak the hook (keep active after drop)
    pub fn leak(mut self) {
        self.auto_restore = false;
        core::mem::forget(self);
    }

    /// consume the hook and restore the original
    pub fn restore(mut self) -> Result<()> {
        self.uninstall()?;
        self.auto_restore = false;
        Ok(())
    }
}

impl Drop for EatHook {
    fn drop(&mut self) {
        if self.auto_restore && self.active {
            let _ = self.uninstall();
        }
    }
}

// SAFETY: EAT hook operates on process-wide memory
unsafe impl Send for EatHook {}
unsafe impl Sync for EatHook {}

/// RAII guard for an EAT hook
pub type EatHookGuard = EatHook;

/// find an EAT entry for a specific export
pub fn find_eat_entry(module: &Module, function_name: &str) -> Result<EatEntry> {
    let entries = enumerate_eat_entries(module)?;

    for entry in entries {
        if let Some(ref name) = entry.function_name {
            if name == function_name {
                return Ok(entry);
            }
        }
    }

    Err(WraithError::ModuleNotFound {
        name: format!("EAT entry for {}", function_name),
    })
}

/// find an EAT entry by ordinal
pub fn find_eat_entry_by_ordinal(module: &Module, ordinal: u32) -> Result<EatEntry> {
    let entries = enumerate_eat_entries(module)?;

    for entry in entries {
        if entry.ordinal == ordinal {
            return Ok(entry);
        }
    }

    Err(WraithError::ModuleNotFound {
        name: format!("EAT entry for ordinal {}", ordinal),
    })
}

/// enumerate all EAT entries in a module
pub fn enumerate_eat_entries(module: &Module) -> Result<Vec<EatEntry>> {
    let nt = module.nt_headers()?;
    let export_dir = nt
        .data_directory(DataDirectoryType::Export.index())
        .ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no export directory".into(),
        })?;

    if !export_dir.is_present() {
        return Ok(Vec::new());
    }

    let base = module.base();
    let export_va = base + export_dir.virtual_address as usize;
    let export_end = export_dir.virtual_address + export_dir.size;

    // SAFETY: export_va points to valid export directory
    let exports = unsafe { &*(export_va as *const ExportDirectory) };

    let num_functions = exports.number_of_functions as usize;
    let num_names = exports.number_of_names as usize;
    let ordinal_base = exports.base;

    if num_functions > MAX_EXPORT_COUNT || num_names > MAX_EXPORT_COUNT {
        return Err(WraithError::InvalidPeFormat {
            reason: format!("unreasonable export count: {} functions", num_functions),
        });
    }

    let functions_va = base + exports.address_of_functions as usize;
    let names_va = base + exports.address_of_names as usize;
    let ordinals_va = base + exports.address_of_name_ordinals as usize;

    let mut entries = Vec::with_capacity(num_functions);

    // build name -> ordinal mapping
    #[cfg(feature = "std")]
    let mut name_map = HashMap::new();
    #[cfg(not(feature = "std"))]
    let mut name_map = BTreeMap::new();
    for i in 0..num_names {
        // SAFETY: reading within export table bounds
        let ordinal = unsafe { *((ordinals_va + i * 2) as *const u16) };
        let name_rva = unsafe { *((names_va + i * 4) as *const u32) };
        let name_va = base + name_rva as usize;
        if let Ok(name) = read_cstring(name_va, 256) {
            name_map.insert(ordinal as usize, name);
        }
    }

    // enumerate all functions
    for i in 0..num_functions {
        let entry_addr = functions_va + i * 4;
        // SAFETY: reading within export table bounds
        let func_rva = unsafe { *(entry_addr as *const u32) };

        if func_rva == 0 {
            continue; // empty entry
        }

        let ordinal = ordinal_base + i as u32;

        // check if forwarded
        let is_forwarded = func_rva >= export_dir.virtual_address && func_rva < export_end;
        let forwarder = if is_forwarded {
            let forwarder_va = base + func_rva as usize;
            read_cstring(forwarder_va, 256).ok()
        } else {
            None
        };

        entries.push(EatEntry {
            entry_address: entry_addr,
            current_rva: func_rva,
            current_address: base + func_rva as usize,
            function_name: name_map.get(&i).cloned(),
            ordinal,
            is_forwarded,
            forwarder,
        });
    }

    Ok(entries)
}

/// convert absolute address to RVA
fn address_to_rva(module_base: usize, address: usize) -> Result<u32> {
    if address < module_base {
        return Err(WraithError::InvalidPeFormat {
            reason: format!(
                "address {:#x} is below module base {:#x}",
                address, module_base
            ),
        });
    }

    let offset = address - module_base;

    if offset > u32::MAX as usize {
        return Err(WraithError::InvalidPeFormat {
            reason: format!(
                "offset {:#x} exceeds u32 max for RVA encoding",
                offset
            ),
        });
    }

    Ok(offset as u32)
}

/// write a value to an EAT entry
fn write_eat_entry(entry: usize, rva: u32) -> Result<()> {
    let _guard = ProtectionGuard::new(entry, core::mem::size_of::<u32>(), PAGE_READWRITE)?;

    // SAFETY: entry is valid EAT address, protection changed to RW
    unsafe {
        *(entry as *mut u32) = rva;
    }

    Ok(())
}

/// read a null-terminated C string
fn read_cstring(addr: usize, max_len: usize) -> Result<String> {
    let mut bytes = Vec::new();

    for i in 0..max_len {
        // SAFETY: reading bytes within max_len
        let byte = unsafe { *((addr + i) as *const u8) };
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }

    String::from_utf8(bytes).map_err(|_| WraithError::InvalidPeFormat {
        reason: "invalid string encoding".into(),
    })
}

/// helper to create an EAT hook with a trampoline for distant detours
pub struct EatHookBuilder {
    module_name: Option<String>,
    function_name: Option<String>,
    detour: Option<usize>,
}

impl EatHookBuilder {
    /// create a new builder
    pub fn new() -> Self {
        Self {
            module_name: None,
            function_name: None,
            detour: None,
        }
    }

    /// set the module name
    pub fn module(mut self, name: &str) -> Self {
        self.module_name = Some(name.to_string());
        self
    }

    /// set the function name
    pub fn function(mut self, name: &str) -> Self {
        self.function_name = Some(name.to_string());
        self
    }

    /// set the detour address
    pub fn detour(mut self, addr: usize) -> Self {
        self.detour = Some(addr);
        self
    }

    /// build and install the hook
    pub fn build(self) -> Result<EatHook> {
        let module_name = self.module_name.ok_or(WraithError::NullPointer {
            context: "module_name not set",
        })?;
        let function_name = self.function_name.ok_or(WraithError::NullPointer {
            context: "function_name not set",
        })?;
        let detour = self.detour.ok_or(WraithError::NullPointer {
            context: "detour not set",
        })?;

        EatHook::new(&module_name, &function_name, detour)
    }
}

impl Default for EatHookBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_eat() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let ntdll = query.ntdll().expect("should get ntdll");

        let entries = enumerate_eat_entries(&ntdll).expect("should enumerate EAT");
        assert!(!entries.is_empty(), "ntdll should have exports");
    }

    #[test]
    fn test_find_ntclose() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let ntdll = query.ntdll().expect("should get ntdll");

        let entry = find_eat_entry(&ntdll, "NtClose").expect("should find NtClose");
        assert!(entry.function_name.as_deref() == Some("NtClose"));
        assert!(!entry.is_forwarded);
    }

    #[test]
    fn test_address_to_rva() {
        let base = 0x10000usize;
        let addr = 0x10500usize;

        let rva = address_to_rva(base, addr).expect("should convert");
        assert_eq!(rva, 0x500);
    }
}
