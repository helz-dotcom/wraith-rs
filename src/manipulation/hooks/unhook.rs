//! Surgical function unhooking
//!
//! Restores hooked functions to their original state by copying
//! original bytes from a clean copy of the module (loaded from disk).

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

use super::detector::{HookDetector, HookInfo};
use crate::error::{Result, WraithError};
use crate::manipulation::manual_map::ParsedPe;
use crate::navigation::Module;
use crate::util::memory::ProtectionGuard;

/// protection constant for RWX memory
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// result of unhook operation
#[derive(Debug)]
pub struct UnhookResult {
    /// number of functions successfully unhooked
    pub unhooked_count: usize,
    /// functions that were unhooked
    pub unhooked_functions: Vec<String>,
    /// functions that failed to unhook (name, reason)
    pub failed_functions: Vec<(String, String)>,
}

impl UnhookResult {
    /// check if all hooks were removed
    pub fn all_successful(&self) -> bool {
        self.failed_functions.is_empty()
    }

    /// total number of hooks processed
    pub fn total(&self) -> usize {
        self.unhooked_count + self.failed_functions.len()
    }
}

/// module unhooker
pub struct Unhooker<'a> {
    module: &'a Module<'a>,
    clean_copy: Vec<u8>,
    parsed_pe: ParsedPe,
}

impl<'a> Unhooker<'a> {
    /// create unhooker for module (loads clean copy from disk)
    #[cfg(feature = "std")]
    pub fn new(module: &'a Module<'a>) -> Result<Self> {
        let path = module.full_path();
        let clean_copy = std::fs::read(&path).map_err(|_| WraithError::CleanCopyUnavailable)?;

        let parsed_pe = ParsedPe::parse(&clean_copy)?;

        Ok(Self {
            module,
            clean_copy,
            parsed_pe,
        })
    }

    /// create unhooker for module (no_std - requires explicit clean copy)
    #[cfg(not(feature = "std"))]
    pub fn new(_module: &'a Module<'a>) -> Result<Self> {
        Err(WraithError::CleanCopyUnavailable)
    }

    /// create unhooker with explicit clean copy
    pub fn with_clean_copy(module: &'a Module<'a>, clean_copy: Vec<u8>) -> Result<Self> {
        let parsed_pe = ParsedPe::parse(&clean_copy)?;

        Ok(Self {
            module,
            clean_copy,
            parsed_pe,
        })
    }

    /// unhook a single function by restoring original bytes
    pub fn unhook_function(&self, hook: &HookInfo) -> Result<()> {
        if hook.original_bytes.is_empty() {
            return Err(WraithError::UnhookFailed {
                function: hook.function_name.clone(),
                reason: "no original bytes available".into(),
            });
        }

        let addr = hook.function_address;
        let size = hook.original_bytes.len();

        // change protection to RWX
        let _guard = ProtectionGuard::new(addr, size, PAGE_EXECUTE_READWRITE)?;

        // restore original bytes
        // SAFETY: protection changed to RWX, original_bytes length is correct
        unsafe {
            core::ptr::copy_nonoverlapping(hook.original_bytes.as_ptr(), addr as *mut u8, size);
        }

        Ok(())
    }

    /// unhook all detected hooks
    pub fn unhook_all(&self) -> Result<UnhookResult> {
        let detector = HookDetector::with_clean_copy(self.module, self.clean_copy.clone());
        let hooks = detector.scan_exports()?;

        let mut result = UnhookResult {
            unhooked_count: 0,
            unhooked_functions: Vec::new(),
            failed_functions: Vec::new(),
        };

        for hook in hooks {
            match self.unhook_function(&hook) {
                Ok(()) => {
                    result.unhooked_count += 1;
                    result.unhooked_functions.push(hook.function_name);
                }
                Err(e) => {
                    result
                        .failed_functions
                        .push((hook.function_name, e.to_string()));
                }
            }
        }

        Ok(result)
    }

    /// unhook entire .text section by copying from clean copy
    pub fn unhook_text_section(&self) -> Result<()> {
        let text_section = self
            .parsed_pe
            .sections()
            .iter()
            .find(|s| s.name_str() == ".text")
            .ok_or_else(|| WraithError::UnhookFailed {
                function: ".text".into(),
                reason: "no .text section found".into(),
            })?;

        let text_rva = text_section.virtual_address as usize;
        let text_size = text_section.virtual_size as usize;
        let text_file_offset = text_section.pointer_to_raw_data as usize;
        let text_raw_size = text_section.size_of_raw_data as usize;

        let target_addr = self.module.base() + text_rva;

        // change protection
        let _guard = ProtectionGuard::new(target_addr, text_size, PAGE_EXECUTE_READWRITE)?;

        // get clean .text section data
        let copy_size = text_raw_size.min(text_size);
        if text_file_offset + copy_size > self.clean_copy.len() {
            return Err(WraithError::UnhookFailed {
                function: ".text".into(),
                reason: "clean copy too small".into(),
            });
        }

        let clean_text = &self.clean_copy[text_file_offset..text_file_offset + copy_size];

        // copy clean .text section
        // SAFETY: protection changed, bounds checked
        unsafe {
            core::ptr::copy_nonoverlapping(clean_text.as_ptr(), target_addr as *mut u8, copy_size);
        }

        Ok(())
    }

    /// unhook specific function by name
    pub fn unhook_by_name(&self, function_name: &str) -> Result<()> {
        let addr = self.module.get_export(function_name)?;

        // get RVA
        let rva = self.module.va_to_rva(addr).ok_or_else(|| WraithError::UnhookFailed {
            function: function_name.into(),
            reason: "address not in module".into(),
        })?;

        // get original bytes from clean copy
        let original = self.get_original_bytes(rva as usize, 32)?;

        // change protection and restore
        let _guard = ProtectionGuard::new(addr, original.len(), PAGE_EXECUTE_READWRITE)?;

        // SAFETY: protection changed, bounds verified
        unsafe {
            core::ptr::copy_nonoverlapping(original.as_ptr(), addr as *mut u8, original.len());
        }

        Ok(())
    }

    /// unhook multiple functions by name
    pub fn unhook_by_names(&self, names: &[&str]) -> UnhookResult {
        let mut result = UnhookResult {
            unhooked_count: 0,
            unhooked_functions: Vec::new(),
            failed_functions: Vec::new(),
        };

        for &name in names {
            match self.unhook_by_name(name) {
                Ok(()) => {
                    result.unhooked_count += 1;
                    result.unhooked_functions.push(name.to_string());
                }
                Err(e) => {
                    result.failed_functions.push((name.to_string(), e.to_string()));
                }
            }
        }

        result
    }

    /// get original bytes at RVA from clean copy
    fn get_original_bytes(&self, rva: usize, len: usize) -> Result<Vec<u8>> {
        for section in self.parsed_pe.sections() {
            let sec_rva = section.virtual_address as usize;
            let sec_size = section.virtual_size as usize;

            if rva >= sec_rva && rva < sec_rva + sec_size {
                let offset_in_section = rva - sec_rva;
                let file_offset = section.pointer_to_raw_data as usize + offset_in_section;

                if file_offset + len <= self.clean_copy.len() {
                    return Ok(self.clean_copy[file_offset..file_offset + len].to_vec());
                }
            }
        }

        Err(WraithError::UnhookFailed {
            function: format!("RVA {rva:#x}"),
            reason: "RVA not in any section".into(),
        })
    }
}

/// restore a single function to original state
pub fn restore_function(module: &Module, function_name: &str) -> Result<()> {
    let unhooker = Unhooker::new(module)?;
    unhooker.unhook_by_name(function_name)
}

/// restore entire .text section of a module
pub fn restore_text_section(module: &Module) -> Result<()> {
    let unhooker = Unhooker::new(module)?;
    unhooker.unhook_text_section()
}
