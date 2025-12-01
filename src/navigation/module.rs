//! High-level module abstraction

use crate::error::{Result, WraithError};
use crate::structures::pe::{
    DataDirectoryType, DosHeader, ExportDirectory, NtHeaders, NtHeaders32, NtHeaders64,
};
use crate::structures::{LdrDataTableEntry, ListEntry};
use crate::structures::pe::nt_headers::{NT_SIGNATURE, PE32_MAGIC};
use core::ptr::NonNull;

/// immutable reference to a loaded module
pub struct Module<'a> {
    entry: &'a LdrDataTableEntry,
}

impl<'a> Module<'a> {
    /// create module from LDR_DATA_TABLE_ENTRY reference
    pub(crate) fn from_entry(entry: &'a LdrDataTableEntry) -> Self {
        Self { entry }
    }

    /// get module base address
    pub fn base(&self) -> usize {
        self.entry.base()
    }

    /// get module size in bytes
    pub fn size(&self) -> usize {
        self.entry.size()
    }

    /// get entry point address (may be 0 if no entry point)
    pub fn entry_point(&self) -> usize {
        self.entry.entry_point()
    }

    /// get full path to module
    pub fn full_path(&self) -> String {
        // SAFETY: full_dll_name is valid for loaded modules
        unsafe { self.entry.full_name() }
    }

    /// get module filename only (e.g., "ntdll.dll")
    pub fn name(&self) -> String {
        // SAFETY: base_dll_name is valid for loaded modules
        unsafe { self.entry.base_name() }
    }

    /// get name as lowercase for comparison
    pub fn name_lowercase(&self) -> String {
        self.name().to_lowercase()
    }

    /// check if address falls within this module
    pub fn contains(&self, address: usize) -> bool {
        self.entry.contains_address(address)
    }

    /// check if module name matches (case-insensitive)
    pub fn matches_name(&self, name: &str) -> bool {
        // SAFETY: name buffers are valid for loaded modules
        unsafe { self.entry.matches_name(name) }
    }

    /// get raw LDR entry reference
    pub fn as_ldr_entry(&self) -> &LdrDataTableEntry {
        self.entry
    }

    /// get DOS header
    pub fn dos_header(&self) -> Result<&DosHeader> {
        let base = self.base();
        if base == 0 {
            return Err(WraithError::NullPointer {
                context: "module base",
            });
        }

        // SAFETY: base points to valid PE image for loaded modules
        let dos = unsafe { &*(base as *const DosHeader) };

        if !dos.is_valid() {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid DOS signature".into(),
            });
        }

        Ok(dos)
    }

    /// get NT headers
    pub fn nt_headers(&self) -> Result<NtHeaders> {
        let dos = self.dos_header()?;
        let nt_offset = dos.nt_headers_offset();
        let nt_addr = self.base() + nt_offset;

        // SAFETY: offset is from valid DOS header
        let signature = unsafe { *(nt_addr as *const u32) };
        if signature != NT_SIGNATURE {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid NT signature".into(),
            });
        }

        // check if 32 or 64 bit
        let magic_offset = nt_addr + 4 + 20; // after signature + file header
        let magic = unsafe { *(magic_offset as *const u16) };

        if magic == PE32_MAGIC {
            let headers = unsafe { &*(nt_addr as *const NtHeaders32) };
            Ok(NtHeaders::Headers32(*headers))
        } else {
            let headers = unsafe { &*(nt_addr as *const NtHeaders64) };
            Ok(NtHeaders::Headers64(*headers))
        }
    }

    /// convert RVA to absolute address
    pub fn rva_to_va(&self, rva: u32) -> usize {
        self.base() + rva as usize
    }

    /// convert absolute address to RVA
    pub fn va_to_rva(&self, va: usize) -> Option<u32> {
        if va >= self.base() && va < self.base() + self.size() {
            Some((va - self.base()) as u32)
        } else {
            None
        }
    }

    /// get export by name
    pub fn get_export(&self, name: &str) -> Result<usize> {
        let nt = self.nt_headers()?;
        let export_dir = nt
            .data_directory(DataDirectoryType::Export.index())
            .ok_or_else(|| WraithError::InvalidPeFormat {
                reason: "no export directory".into(),
            })?;

        if !export_dir.is_present() {
            return Err(WraithError::InvalidPeFormat {
                reason: "export directory not present".into(),
            });
        }

        let export_va = self.rva_to_va(export_dir.virtual_address);
        // SAFETY: export directory is present and valid
        let exports = unsafe { &*(export_va as *const ExportDirectory) };

        let num_names = exports.number_of_names as usize;
        let names_va = self.rva_to_va(exports.address_of_names);
        let ordinals_va = self.rva_to_va(exports.address_of_name_ordinals);
        let functions_va = self.rva_to_va(exports.address_of_functions);

        // search for name
        for i in 0..num_names {
            // SAFETY: iterating within bounds of export arrays
            let name_rva = unsafe { *((names_va + i * 4) as *const u32) };
            let name_va = self.rva_to_va(name_rva);
            let export_name = unsafe {
                let ptr = name_va as *const u8;
                let mut len = 0;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
            };

            if export_name == name {
                let ordinal = unsafe { *((ordinals_va + i * 2) as *const u16) } as usize;
                let func_rva = unsafe { *((functions_va + ordinal * 4) as *const u32) };

                // check for forwarded export
                let func_va = self.rva_to_va(func_rva);
                if func_rva >= export_dir.virtual_address
                    && func_rva < export_dir.virtual_address + export_dir.size
                {
                    // forwarded export - would need to resolve recursively
                    return Err(WraithError::InvalidPeFormat {
                        reason: format!("forwarded export: {name}"),
                    });
                }

                return Ok(func_va);
            }
        }

        Err(WraithError::ModuleNotFound {
            name: format!("export {name} not found"),
        })
    }

    /// get export by ordinal
    pub fn get_export_by_ordinal(&self, ordinal: u16) -> Result<usize> {
        let nt = self.nt_headers()?;
        let export_dir = nt
            .data_directory(DataDirectoryType::Export.index())
            .ok_or_else(|| WraithError::InvalidPeFormat {
                reason: "no export directory".into(),
            })?;

        if !export_dir.is_present() {
            return Err(WraithError::InvalidPeFormat {
                reason: "export directory not present".into(),
            });
        }

        let export_va = self.rva_to_va(export_dir.virtual_address);
        // SAFETY: export directory is present and valid
        let exports = unsafe { &*(export_va as *const ExportDirectory) };

        let index = ordinal as usize - exports.base as usize;
        if index >= exports.number_of_functions as usize {
            return Err(WraithError::InvalidPeFormat {
                reason: "ordinal out of range".into(),
            });
        }

        let functions_va = self.rva_to_va(exports.address_of_functions);
        let func_rva = unsafe { *((functions_va + index * 4) as *const u32) };

        Ok(self.rva_to_va(func_rva))
    }
}

/// owned handle to a module (allows modifications)
pub struct ModuleHandle {
    entry: NonNull<LdrDataTableEntry>,
}

impl ModuleHandle {
    /// create handle from raw LDR entry pointer
    ///
    /// # Safety
    /// pointer must be valid LDR_DATA_TABLE_ENTRY
    pub unsafe fn from_raw(ptr: *mut LdrDataTableEntry) -> Option<Self> {
        NonNull::new(ptr).map(|entry| Self { entry })
    }

    /// get raw pointer
    pub fn as_ptr(&self) -> *mut LdrDataTableEntry {
        self.entry.as_ptr()
    }

    /// borrow as immutable Module
    pub fn as_module(&self) -> Module<'_> {
        // SAFETY: entry pointer is valid for lifetime of handle
        Module::from_entry(unsafe { self.entry.as_ref() })
    }

    /// get mutable access to LDR entry (for unlinking)
    ///
    /// # Safety
    /// caller must ensure no other references exist
    pub unsafe fn as_entry_mut(&mut self) -> &mut LdrDataTableEntry {
        unsafe { self.entry.as_mut() }
    }

    /// get pointers to all three list links
    pub fn get_link_pointers(&self) -> ModuleLinkPointers {
        // SAFETY: entry is valid
        let entry = unsafe { self.entry.as_ref() };
        ModuleLinkPointers {
            in_load_order: &entry.in_load_order_links as *const _ as *mut ListEntry,
            in_memory_order: &entry.in_memory_order_links as *const _ as *mut ListEntry,
            in_initialization_order: &entry.in_initialization_order_links as *const _
                as *mut ListEntry,
        }
    }
}

// ModuleHandle doesn't impl Drop - it's a reference, not ownership

// SAFETY: ModuleHandle is a pointer to process-wide structure
unsafe impl Send for ModuleHandle {}
unsafe impl Sync for ModuleHandle {}

/// pointers to module's list entry links
pub struct ModuleLinkPointers {
    pub in_load_order: *mut ListEntry,
    pub in_memory_order: *mut ListEntry,
    pub in_initialization_order: *mut ListEntry,
}
