//! IAT (Import Address Table) hooking
//!
//! IAT hooks work by modifying entries in a module's Import Address Table.
//! When a module imports a function from another DLL, the loader fills the IAT
//! with the actual function addresses. By replacing an IAT entry with a detour
//! address, all calls through that import are redirected.
//!
//! # Advantages
//! - No code modification (safer for integrity checks)
//! - Easy to install and remove
//! - Works on any imported function
//!
//! # Limitations
//! - Only affects calls through the IAT (not direct calls or GetProcAddress)
//! - Module-specific (each module has its own IAT)
//! - Does not affect already-resolved function pointers

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::navigation::{Module, ModuleQuery};
use crate::structures::pe::{DataDirectoryType, ImportDescriptor, ImportByName};
use crate::structures::Peb;
use crate::util::memory::ProtectionGuard;

const PAGE_READWRITE: u32 = 0x04;

#[cfg(target_arch = "x86_64")]
use crate::structures::pe::{ThunkData64 as ThunkData, IMAGE_ORDINAL_FLAG64 as IMAGE_ORDINAL_FLAG};
#[cfg(target_arch = "x86")]
use crate::structures::pe::{ThunkData32 as ThunkData, IMAGE_ORDINAL_FLAG32 as IMAGE_ORDINAL_FLAG};

/// information about a single IAT entry
#[derive(Debug, Clone)]
pub struct IatEntry {
    /// address of the IAT entry (pointer to the function pointer)
    pub entry_address: usize,
    /// current value in the IAT (the function address being called)
    pub current_value: usize,
    /// name of the imported function (if imported by name)
    pub function_name: Option<String>,
    /// ordinal (if imported by ordinal)
    pub ordinal: Option<u16>,
    /// name of the DLL this function is imported from
    pub dll_name: String,
}

/// IAT hook instance
pub struct IatHook {
    /// address of the IAT entry we're hooking
    iat_entry: usize,
    /// original function address (what was in IAT before hook)
    original: usize,
    /// detour function address (what we replaced it with)
    detour: usize,
    /// whether the hook is currently active
    active: bool,
    /// whether to restore on drop
    auto_restore: bool,
}

impl IatHook {
    /// create and install an IAT hook
    ///
    /// # Arguments
    /// * `target_module` - the module whose IAT to modify
    /// * `import_dll` - the DLL name containing the function to hook (e.g., "kernel32.dll")
    /// * `function_name` - the function name to hook
    /// * `detour` - address of the detour function
    ///
    /// # Example
    /// ```ignore
    /// let hook = IatHook::new("myapp.exe", "kernel32.dll", "CreateFileW", my_detour as usize)?;
    /// // calls to CreateFileW from myapp.exe now go to my_detour
    /// ```
    pub fn new(
        target_module: &str,
        import_dll: &str,
        function_name: &str,
        detour: usize,
    ) -> Result<Self> {
        let peb = Peb::current()?;
        let query = ModuleQuery::new(&peb);
        let module = query.find_by_name(target_module)?;

        Self::new_in_module(&module, import_dll, function_name, detour)
    }

    /// create and install an IAT hook in a specific module
    pub fn new_in_module(
        module: &Module,
        import_dll: &str,
        function_name: &str,
        detour: usize,
    ) -> Result<Self> {
        let iat_entry = find_iat_entry(module, import_dll, function_name)?;
        Self::new_at_address(iat_entry.entry_address, detour)
    }

    /// create and install an IAT hook at a specific IAT entry address
    ///
    /// use this when you already know the IAT entry address
    pub fn new_at_address(iat_entry: usize, detour: usize) -> Result<Self> {
        if iat_entry == 0 {
            return Err(WraithError::NullPointer { context: "iat_entry" });
        }

        // read original value
        // SAFETY: iat_entry points to valid IAT entry
        let original = unsafe { *(iat_entry as *const usize) };

        let mut hook = Self {
            iat_entry,
            original,
            detour,
            active: false,
            auto_restore: true,
        };

        hook.install()?;
        Ok(hook)
    }

    /// install the hook (write detour address to IAT)
    pub fn install(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }

        write_iat_entry(self.iat_entry, self.detour)?;
        self.active = true;

        Ok(())
    }

    /// remove the hook (restore original address)
    pub fn uninstall(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        write_iat_entry(self.iat_entry, self.original)?;
        self.active = false;

        Ok(())
    }

    /// check if hook is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// get the original function address
    pub fn original(&self) -> usize {
        self.original
    }

    /// get the detour function address
    pub fn detour(&self) -> usize {
        self.detour
    }

    /// get the IAT entry address
    pub fn iat_entry(&self) -> usize {
        self.iat_entry
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

impl Drop for IatHook {
    fn drop(&mut self) {
        if self.auto_restore && self.active {
            let _ = self.uninstall();
        }
    }
}

// SAFETY: IAT hook operates on process-wide memory
unsafe impl Send for IatHook {}
unsafe impl Sync for IatHook {}

/// RAII guard for an IAT hook
pub type IatHookGuard = IatHook;

/// find an IAT entry for a specific import
pub fn find_iat_entry(
    module: &Module,
    import_dll: &str,
    function_name: &str,
) -> Result<IatEntry> {
    let entries = enumerate_iat_entries(module)?;
    let import_dll_lower = import_dll.to_lowercase();
    let function_name_lower = function_name.to_lowercase();

    for entry in entries {
        let dll_matches = entry.dll_name.to_lowercase() == import_dll_lower
            || entry.dll_name.to_lowercase().trim_end_matches(".dll")
                == import_dll_lower.trim_end_matches(".dll");

        if dll_matches {
            if let Some(ref name) = entry.function_name {
                if name.to_lowercase() == function_name_lower {
                    return Ok(entry);
                }
            }
        }
    }

    Err(WraithError::ModuleNotFound {
        name: format!("IAT entry for {}!{}", import_dll, function_name),
    })
}

/// enumerate all IAT entries in a module
pub fn enumerate_iat_entries(module: &Module) -> Result<Vec<IatEntry>> {
    let nt = module.nt_headers()?;
    let import_dir = nt
        .data_directory(DataDirectoryType::Import.index())
        .ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no import directory".into(),
        })?;

    if !import_dir.is_present() {
        return Ok(Vec::new());
    }

    let base = module.base();
    let mut entries = Vec::new();

    // iterate import descriptors
    let mut desc_va = base + import_dir.virtual_address as usize;
    loop {
        // SAFETY: desc_va points to valid import descriptor in loaded module
        let desc = unsafe { &*(desc_va as *const ImportDescriptor) };

        if desc.is_null() {
            break;
        }

        // get DLL name
        let dll_name_va = base + desc.name as usize;
        let dll_name = read_cstring(dll_name_va, 256)?;

        // get IAT and INT (Import Name Table)
        let iat_va = base + desc.first_thunk as usize;
        let int_va = if desc.original_first_thunk != 0 {
            base + desc.original_first_thunk as usize
        } else {
            iat_va // use IAT if INT is not present
        };

        // iterate thunks
        let mut thunk_idx = 0usize;
        loop {
            let thunk_size = core::mem::size_of::<ThunkData>();
            let iat_entry_addr = iat_va + thunk_idx * thunk_size;
            let int_entry_addr = int_va + thunk_idx * thunk_size;

            // SAFETY: reading thunk data from loaded module
            let iat_thunk = unsafe { *(iat_entry_addr as *const usize) };
            if iat_thunk == 0 {
                break;
            }

            let int_thunk = unsafe { *(int_entry_addr as *const usize) };

            let (function_name, ordinal) = if is_ordinal_import(int_thunk) {
                (None, Some(get_ordinal(int_thunk)))
            } else {
                // import by name
                let hint_name_va = base + (int_thunk & !IMAGE_ORDINAL_FLAG as usize);
                // SAFETY: hint_name_va points to valid IMAGE_IMPORT_BY_NAME
                let hint_name = unsafe { &*(hint_name_va as *const ImportByName) };
                let name_ptr = hint_name.name.as_ptr();
                let name = read_cstring(name_ptr as usize, 256).ok();
                (name, None)
            };

            entries.push(IatEntry {
                entry_address: iat_entry_addr,
                current_value: iat_thunk,
                function_name,
                ordinal,
                dll_name: dll_name.clone(),
            });

            thunk_idx += 1;
        }

        desc_va += core::mem::size_of::<ImportDescriptor>();
    }

    Ok(entries)
}

/// hook an import in the current module
pub fn hook_import(
    import_dll: &str,
    function_name: &str,
    detour: usize,
) -> Result<IatHook> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let current = query.current_module()?;

    IatHook::new_in_module(&current, import_dll, function_name, detour)
}

/// hook an import in any module that imports it
pub fn hook_import_all(
    import_dll: &str,
    function_name: &str,
    detour: usize,
) -> Result<Vec<IatHook>> {
    let peb = Peb::current()?;
    let mut hooks = Vec::new();

    for module in crate::navigation::ModuleIterator::new(&peb, crate::navigation::ModuleListType::InLoadOrder)? {
        if let Ok(hook) = IatHook::new_in_module(&module, import_dll, function_name, detour) {
            hooks.push(hook);
        }
    }

    if hooks.is_empty() {
        Err(WraithError::ModuleNotFound {
            name: format!("IAT entry for {}!{} in any module", import_dll, function_name),
        })
    } else {
        Ok(hooks)
    }
}

/// write a value to an IAT entry
fn write_iat_entry(entry: usize, value: usize) -> Result<()> {
    let _guard = ProtectionGuard::new(entry, core::mem::size_of::<usize>(), PAGE_READWRITE)?;

    // SAFETY: entry is valid IAT address, protection changed to RW
    unsafe {
        *(entry as *mut usize) = value;
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

/// check if a thunk is an ordinal import
#[cfg(target_arch = "x86_64")]
fn is_ordinal_import(thunk: usize) -> bool {
    (thunk as u64 & IMAGE_ORDINAL_FLAG) != 0
}

#[cfg(target_arch = "x86")]
fn is_ordinal_import(thunk: usize) -> bool {
    (thunk as u32 & IMAGE_ORDINAL_FLAG) != 0
}

/// extract ordinal from thunk
fn get_ordinal(thunk: usize) -> u16 {
    (thunk & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_iat() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let current = query.current_module().expect("should get current module");

        let entries = enumerate_iat_entries(&current).expect("should enumerate IAT");
        assert!(!entries.is_empty(), "should have imports");
    }

    #[test]
    fn test_find_kernel32_import() {
        let peb = Peb::current().expect("should get PEB");
        let query = ModuleQuery::new(&peb);
        let current = query.current_module().expect("should get current module");

        // most programs import something from kernel32
        let entries = enumerate_iat_entries(&current).expect("should enumerate IAT");
        let has_kernel32 = entries.iter().any(|e|
            e.dll_name.to_lowercase().contains("kernel32")
        );
        assert!(has_kernel32, "should import from kernel32");
    }
}
