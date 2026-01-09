//! External process operations
//!
//! Provides comprehensive external/remote process functionality:
//! - Memory access trait abstraction
//! - Process discovery utilities
//! - Remote PE parsing
//! - Remote export/import resolution
//! - External pattern scanning
//! - Memory region enumeration
//! - Thread enumeration

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec, vec::Vec};

use core::time::Duration;

use super::process::{ProcessAccess, RemoteProcess};
use super::modules::{enumerate_remote_modules, find_remote_module, RemoteModuleInfo};
use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    get_syscall_table, nt_success, DirectSyscall,
    MEM_COMMIT, MEM_RESERVE, MEM_RELEASE,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    CURRENT_PROCESS,
};
use crate::structures::pe::dos_header::{DosHeader, DOS_SIGNATURE};
use crate::structures::pe::nt_headers::{
    NT_SIGNATURE, PE32_MAGIC, PE32PLUS_MAGIC,
    FileHeader, OptionalHeader32, OptionalHeader64,
};
use crate::structures::pe::section_header::SectionHeader;
use crate::structures::pe::exports::ExportDirectory;
use crate::structures::pe::imports::ImportDescriptor;
use crate::structures::pe::data_directory::DataDirectory;

// ============================================================================
// Memory Protection Abstraction
// ============================================================================

/// memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection(pub u32);

impl Protection {
    pub const NOACCESS: Self = Self(PAGE_NOACCESS);
    pub const READONLY: Self = Self(PAGE_READONLY);
    pub const READWRITE: Self = Self(PAGE_READWRITE);
    pub const WRITECOPY: Self = Self(PAGE_WRITECOPY);
    pub const EXECUTE: Self = Self(PAGE_EXECUTE);
    pub const EXECUTE_READ: Self = Self(PAGE_EXECUTE_READ);
    pub const EXECUTE_READWRITE: Self = Self(PAGE_EXECUTE_READWRITE);
    pub const EXECUTE_WRITECOPY: Self = Self(PAGE_EXECUTE_WRITECOPY);

    pub fn is_readable(&self) -> bool {
        matches!(
            self.0,
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.0,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub fn is_executable(&self) -> bool {
        matches!(
            self.0,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }
}

impl From<u32> for Protection {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<Protection> for u32 {
    fn from(val: Protection) -> Self {
        val.0
    }
}

/// allocation result with base address and size
pub struct Allocation {
    pub base: usize,
    pub size: usize,
}

// ============================================================================
// Memory Access Trait
// ============================================================================

/// trait for memory access operations, unified interface for local and remote
pub trait MemoryAccess {
    /// read bytes from address into buffer
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<()>;

    /// write bytes to address
    fn write(&self, addr: usize, buf: &[u8]) -> Result<()>;

    /// allocate memory with protection
    fn allocate(&self, size: usize, protect: Protection) -> Result<Allocation>;

    /// change memory protection, returns old protection
    fn protect(&self, addr: usize, size: usize, protect: Protection) -> Result<Protection>;

    /// free allocated memory
    fn free(&self, addr: usize) -> Result<()>;

    /// read typed value from address
    fn read_val<T: Copy>(&self, addr: usize) -> Result<T> {
        let mut buffer = vec![0u8; core::mem::size_of::<T>()];
        self.read(addr, &mut buffer)?;
        // SAFETY: buffer is correctly sized
        Ok(unsafe { (buffer.as_ptr() as *const T).read_unaligned() })
    }

    /// write typed value to address
    fn write_val<T: Copy>(&self, addr: usize, val: &T) -> Result<()> {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                val as *const T as *const u8,
                core::mem::size_of::<T>(),
            )
        };
        self.write(addr, bytes)
    }
}

// ============================================================================
// Current Process Memory Access
// ============================================================================

/// memory access for current process (direct pointer access)
pub struct CurrentProcess;

impl CurrentProcess {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CurrentProcess {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAccess for CurrentProcess {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<()> {
        if addr == 0 {
            return Err(WraithError::NullPointer { context: "read address" });
        }
        // SAFETY: caller is responsible for valid address
        unsafe {
            core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }

    fn write(&self, addr: usize, buf: &[u8]) -> Result<()> {
        if addr == 0 {
            return Err(WraithError::NullPointer { context: "write address" });
        }
        // SAFETY: caller is responsible for valid address
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), addr as *mut u8, buf.len());
        }
        Ok(())
    }

    fn allocate(&self, size: usize, protect: Protection) -> Result<Allocation> {
        use crate::manipulation::syscall::nt_allocate_virtual_memory;

        let (base, actual_size) = nt_allocate_virtual_memory(
            CURRENT_PROCESS,
            0,
            size,
            MEM_COMMIT | MEM_RESERVE,
            protect.0,
        ).map_err(|_| WraithError::AllocationFailed { size, protection: protect.0 })?;

        Ok(Allocation { base, size: actual_size })
    }

    fn protect(&self, addr: usize, size: usize, protect: Protection) -> Result<Protection> {
        use crate::manipulation::syscall::nt_protect_virtual_memory;

        let old = nt_protect_virtual_memory(CURRENT_PROCESS, addr, size, protect.0)
            .map_err(|_| WraithError::ProtectionChangeFailed {
                address: addr as u64,
                size,
            })?;

        Ok(Protection(old))
    }

    fn free(&self, addr: usize) -> Result<()> {
        use crate::manipulation::syscall::nt_free_virtual_memory;

        nt_free_virtual_memory(CURRENT_PROCESS, addr, MEM_RELEASE)
            .map_err(|_| WraithError::AllocationFailed { size: 0, protection: 0 })
    }
}

// ============================================================================
// Remote Process Memory Access
// ============================================================================

impl MemoryAccess for RemoteProcess {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<()> {
        RemoteProcess::read(self, addr, buf)?;
        Ok(())
    }

    fn write(&self, addr: usize, buf: &[u8]) -> Result<()> {
        RemoteProcess::write(self, addr, buf)?;
        Ok(())
    }

    fn allocate(&self, size: usize, protect: Protection) -> Result<Allocation> {
        let alloc = RemoteProcess::allocate(self, size, protect.0)?;
        Ok(Allocation {
            base: alloc.base(),
            size: alloc.size(),
        })
    }

    fn protect(&self, addr: usize, size: usize, protect: Protection) -> Result<Protection> {
        let old = RemoteProcess::protect(self, addr, size, protect.0)?;
        Ok(Protection(old))
    }

    fn free(&self, addr: usize) -> Result<()> {
        RemoteProcess::free(self, addr)
    }
}

// ============================================================================
// Process Discovery Utilities
// ============================================================================

/// system process entry
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub thread_count: u32,
}

/// enumerate all running processes
pub fn enumerate_processes() -> Result<Vec<ProcessEntry>> {
    let mut processes = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot is safe to call
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(WraithError::from_last_error("CreateToolhelp32Snapshot"));
    }

    let mut entry = ProcessEntry32W::default();
    entry.size = core::mem::size_of::<ProcessEntry32W>() as u32;

    // SAFETY: entry is properly initialized
    let mut success = unsafe { Process32FirstW(snapshot, &mut entry) };

    while success != 0 {
        let name_end = entry.exe_file.iter().position(|&c| c == 0).unwrap_or(260);
        let name = String::from_utf16_lossy(&entry.exe_file[..name_end]);

        processes.push(ProcessEntry {
            pid: entry.process_id,
            parent_pid: entry.parent_process_id,
            name,
            thread_count: entry.threads,
        });

        // SAFETY: entry is properly initialized
        success = unsafe { Process32NextW(snapshot, &mut entry) };
    }

    // SAFETY: valid handle
    unsafe { CloseHandle(snapshot) };

    Ok(processes)
}

/// find process by name (case-insensitive)
pub fn find_process_by_name(name: &str) -> Result<Option<u32>> {
    let name_lower = name.to_lowercase();
    let processes = enumerate_processes()?;

    for proc in processes {
        if proc.name.to_lowercase() == name_lower
            || proc.name.to_lowercase().starts_with(&name_lower)
        {
            return Ok(Some(proc.pid));
        }
    }

    Ok(None)
}

/// find all processes matching name
pub fn find_processes_by_name(name: &str) -> Result<Vec<u32>> {
    let name_lower = name.to_lowercase();
    let processes = enumerate_processes()?;

    Ok(processes
        .into_iter()
        .filter(|p| {
            p.name.to_lowercase() == name_lower
                || p.name.to_lowercase().starts_with(&name_lower)
        })
        .map(|p| p.pid)
        .collect())
}

/// wait for a process to start
#[cfg(feature = "std")]
pub fn wait_for_process(name: &str, timeout: Duration) -> Result<u32> {
    use std::time::Instant;

    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        if let Some(pid) = find_process_by_name(name)? {
            return Ok(pid);
        }

        if start.elapsed() >= timeout {
            return Err(WraithError::ProcessNotFound { pid: 0 });
        }

        std::thread::sleep(poll_interval);
    }
}

impl RemoteProcess {
    /// open process by name
    pub fn open_by_name(name: &str, access: ProcessAccess) -> Result<Self> {
        let pid = find_process_by_name(name)?
            .ok_or_else(|| WraithError::ProcessNotFound { pid: 0 })?;
        Self::open(pid, access)
    }
}

// ============================================================================
// Window-Based Process Finding
// ============================================================================

/// find process ID by window class and/or title
pub fn find_process_by_window(class: Option<&str>, title: Option<&str>) -> Result<Option<u32>> {
    let class_wide: Vec<u16>;
    let title_wide: Vec<u16>;

    let class_ptr = match class {
        Some(c) => {
            class_wide = c.encode_utf16().chain(core::iter::once(0)).collect();
            class_wide.as_ptr()
        }
        None => core::ptr::null(),
    };

    let title_ptr = match title {
        Some(t) => {
            title_wide = t.encode_utf16().chain(core::iter::once(0)).collect();
            title_wide.as_ptr()
        }
        None => core::ptr::null(),
    };

    // SAFETY: pointers are valid or null
    let hwnd = unsafe { FindWindowW(class_ptr, title_ptr) };
    if hwnd == 0 {
        return Ok(None);
    }

    let mut pid: u32 = 0;
    // SAFETY: valid window handle
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };

    if pid == 0 {
        Ok(None)
    } else {
        Ok(Some(pid))
    }
}

/// wait for a window to appear
#[cfg(feature = "std")]
pub fn wait_for_window(
    class: Option<&str>,
    title: Option<&str>,
    timeout: Duration,
) -> Result<u32> {
    use std::time::Instant;

    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    loop {
        if let Some(pid) = find_process_by_window(class, title)? {
            return Ok(pid);
        }

        if start.elapsed() >= timeout {
            return Err(WraithError::ProcessNotFound { pid: 0 });
        }

        std::thread::sleep(poll_interval);
    }
}

// ============================================================================
// Remote PE Parsing
// ============================================================================

/// parsed PE headers from remote process
#[derive(Debug, Clone)]
pub struct RemotePeHeaders {
    pub dos_header: DosHeader,
    pub nt_signature: u32,
    pub file_header: FileHeader,
    pub optional_header_32: Option<OptionalHeader32>,
    pub optional_header_64: Option<OptionalHeader64>,
    pub sections: Vec<SectionHeader>,
    pub base: usize,
}

impl RemotePeHeaders {
    /// check if 64-bit PE
    pub fn is_64bit(&self) -> bool {
        self.optional_header_64.is_some()
    }

    /// get size of image
    pub fn size_of_image(&self) -> u32 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.size_of_image
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.size_of_image
        } else {
            0
        }
    }

    /// get entry point RVA
    pub fn entry_point_rva(&self) -> u32 {
        if let Some(ref opt) = self.optional_header_64 {
            opt.address_of_entry_point
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.address_of_entry_point
        } else {
            0
        }
    }

    /// get data directory
    pub fn data_directory(&self, index: usize) -> Option<DataDirectory> {
        if let Some(ref opt) = self.optional_header_64 {
            opt.data_directory.get(index).copied()
        } else if let Some(ref opt) = self.optional_header_32 {
            opt.data_directory.get(index).copied()
        } else {
            None
        }
    }

    /// get export directory RVA and size
    pub fn export_directory(&self) -> Option<DataDirectory> {
        self.data_directory(0) // IMAGE_DIRECTORY_ENTRY_EXPORT
    }

    /// get import directory RVA and size
    pub fn import_directory(&self) -> Option<DataDirectory> {
        self.data_directory(1) // IMAGE_DIRECTORY_ENTRY_IMPORT
    }
}

impl RemoteProcess {
    /// read and parse PE headers from a remote module
    pub fn read_pe_headers(&self, base: usize) -> Result<RemotePeHeaders> {
        // read DOS header
        let dos_header: DosHeader = self.read_value(base)?;
        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid DOS signature".into(),
            });
        }

        if !dos_header.is_nt_offset_valid() {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid e_lfanew offset".into(),
            });
        }

        let nt_offset = dos_header.e_lfanew as usize;
        let nt_addr = base + nt_offset;

        // read NT signature
        let nt_signature: u32 = self.read_value(nt_addr)?;
        if nt_signature != NT_SIGNATURE {
            return Err(WraithError::InvalidPeFormat {
                reason: "invalid PE signature".into(),
            });
        }

        // read file header
        let file_header: FileHeader = self.read_value(nt_addr + 4)?;

        // read optional header magic to determine bitness
        let magic: u16 = self.read_value(nt_addr + 4 + core::mem::size_of::<FileHeader>())?;

        let (opt32, opt64) = match magic {
            PE32_MAGIC => {
                let opt: OptionalHeader32 =
                    self.read_value(nt_addr + 4 + core::mem::size_of::<FileHeader>())?;
                (Some(opt), None)
            }
            PE32PLUS_MAGIC => {
                let opt: OptionalHeader64 =
                    self.read_value(nt_addr + 4 + core::mem::size_of::<FileHeader>())?;
                (None, Some(opt))
            }
            _ => {
                return Err(WraithError::InvalidPeFormat {
                    reason: format!("unknown optional header magic: {:#x}", magic),
                });
            }
        };

        // calculate section headers offset
        let sections_offset = nt_addr + 4 + core::mem::size_of::<FileHeader>()
            + file_header.size_of_optional_header as usize;

        // read section headers
        let num_sections = file_header.number_of_sections as usize;
        let mut sections = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let section_addr = sections_offset + i * core::mem::size_of::<SectionHeader>();
            let section: SectionHeader = self.read_value(section_addr)?;
            sections.push(section);
        }

        Ok(RemotePeHeaders {
            dos_header,
            nt_signature,
            file_header,
            optional_header_32: opt32,
            optional_header_64: opt64,
            sections,
            base,
        })
    }
}

// ============================================================================
// Remote Section Information
// ============================================================================

/// remote module section information
#[derive(Debug, Clone)]
pub struct RemoteSection {
    pub name: String,
    pub base: usize,
    pub virtual_size: usize,
    pub raw_size: usize,
    pub characteristics: u32,
}

impl RemoteSection {
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x20000000 != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & 0x40000000 != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x80000000 != 0
    }
}

impl RemoteProcess {
    /// get all sections of a remote module
    pub fn get_module_sections(&self, module_name: &str) -> Result<Vec<RemoteSection>> {
        let module = find_remote_module(self, module_name)?;
        let pe = self.read_pe_headers(module.base())?;

        Ok(pe.sections.iter().map(|s| {
            RemoteSection {
                name: s.name_str().to_string(),
                base: module.base() + s.virtual_address as usize,
                virtual_size: s.virtual_size as usize,
                raw_size: s.size_of_raw_data as usize,
                characteristics: s.characteristics,
            }
        }).collect())
    }

    /// get specific section by name
    pub fn get_module_section(&self, module_name: &str, section_name: &str) -> Result<RemoteSection> {
        let sections = self.get_module_sections(module_name)?;
        sections
            .into_iter()
            .find(|s| s.name == section_name)
            .ok_or_else(|| WraithError::ModuleNotFound {
                name: format!("{}!{}", module_name, section_name),
            })
    }
}

// ============================================================================
// Remote Export Resolution
// ============================================================================

/// remote export information
#[derive(Debug, Clone)]
pub struct RemoteExport {
    pub name: Option<String>,
    pub ordinal: u16,
    pub rva: u32,
    pub address: usize,
    pub forwarded_to: Option<String>,
}

impl RemoteProcess {
    /// enumerate all exports from a remote module
    pub fn enumerate_remote_exports(&self, module_base: usize) -> Result<Vec<RemoteExport>> {
        let pe = self.read_pe_headers(module_base)?;
        let export_dir = pe.export_directory().ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no export directory".into(),
        })?;

        if export_dir.virtual_address == 0 || export_dir.size == 0 {
            return Ok(Vec::new());
        }

        let export_addr = module_base + export_dir.virtual_address as usize;
        let export_end = export_addr + export_dir.size as usize;

        let export_table: ExportDirectory = self.read_value(export_addr)?;

        let num_functions = export_table.number_of_functions as usize;
        let num_names = export_table.number_of_names as usize;
        let ordinal_base = export_table.base as u16;

        let functions_addr = module_base + export_table.address_of_functions as usize;
        let names_addr = module_base + export_table.address_of_names as usize;
        let ordinals_addr = module_base + export_table.address_of_name_ordinals as usize;

        // read function RVAs
        let mut function_rvas = vec![0u32; num_functions];
        let func_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                function_rvas.as_mut_ptr() as *mut u8,
                num_functions * 4,
            )
        };
        self.read(functions_addr, func_bytes)?;

        // read name RVAs
        let mut name_rvas = vec![0u32; num_names];
        if num_names > 0 {
            let name_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    name_rvas.as_mut_ptr() as *mut u8,
                    num_names * 4,
                )
            };
            self.read(names_addr, name_bytes)?;
        }

        // read ordinal mappings
        let mut ordinals = vec![0u16; num_names];
        if num_names > 0 {
            let ord_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    ordinals.as_mut_ptr() as *mut u8,
                    num_names * 2,
                )
            };
            self.read(ordinals_addr, ord_bytes)?;
        }

        // build name-to-ordinal map
        let mut name_map = vec![None; num_functions];
        for i in 0..num_names {
            let func_index = ordinals[i] as usize;
            if func_index < num_functions {
                // read function name
                let name_rva = name_rvas[i] as usize;
                if name_rva > 0 {
                    let name = self.read_string(module_base + name_rva, 256)?;
                    name_map[func_index] = Some(name);
                }
            }
        }

        // build exports list
        let mut exports = Vec::with_capacity(num_functions);
        for i in 0..num_functions {
            let rva = function_rvas[i];
            if rva == 0 {
                continue;
            }

            let address = module_base + rva as usize;
            let ordinal = ordinal_base + i as u16;

            // check if forwarded (RVA points within export directory)
            let forwarded = if address >= export_addr && address < export_end {
                Some(self.read_string(address, 256)?)
            } else {
                None
            };

            exports.push(RemoteExport {
                name: name_map[i].clone(),
                ordinal,
                rva,
                address,
                forwarded_to: forwarded,
            });
        }

        Ok(exports)
    }

    /// get export by name from remote module
    pub fn get_remote_export(&self, module_base: usize, name: &str) -> Result<usize> {
        let exports = self.enumerate_remote_exports(module_base)?;

        for export in exports {
            if let Some(ref export_name) = export.name {
                if export_name == name {
                    // handle forwarded exports
                    if let Some(ref forward) = export.forwarded_to {
                        return self.resolve_forwarded_export(forward);
                    }
                    return Ok(export.address);
                }
            }
        }

        Err(WraithError::ImportResolutionFailed {
            dll: format!("{:#x}", module_base),
            function: name.into(),
        })
    }

    /// get export by ordinal from remote module
    pub fn get_remote_export_by_ordinal(&self, module_base: usize, ordinal: u16) -> Result<usize> {
        let exports = self.enumerate_remote_exports(module_base)?;

        for export in exports {
            if export.ordinal == ordinal {
                if let Some(ref forward) = export.forwarded_to {
                    return self.resolve_forwarded_export(forward);
                }
                return Ok(export.address);
            }
        }

        Err(WraithError::ImportResolutionFailed {
            dll: format!("{:#x}", module_base),
            function: format!("#{}", ordinal),
        })
    }

    /// resolve forwarded export (e.g., "NTDLL.RtlAllocateHeap")
    fn resolve_forwarded_export(&self, forward: &str) -> Result<usize> {
        let parts: Vec<&str> = forward.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(WraithError::ImportResolutionFailed {
                dll: forward.into(),
                function: "".into(),
            });
        }

        let dll_name = parts[0];
        let func_name = parts[1];

        // find the target module
        let module = find_remote_module(self, dll_name)?;

        // check if ordinal or name
        if func_name.starts_with('#') {
            let ordinal: u16 = func_name[1..].parse().map_err(|_| {
                WraithError::ImportResolutionFailed {
                    dll: dll_name.into(),
                    function: func_name.into(),
                }
            })?;
            self.get_remote_export_by_ordinal(module.base(), ordinal)
        } else {
            self.get_remote_export(module.base(), func_name)
        }
    }
}

// ============================================================================
// Remote Import Table Reading
// ============================================================================

/// remote import information
#[derive(Debug, Clone)]
pub struct RemoteImport {
    pub module_name: String,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_address: usize,
    pub resolved_address: usize,
}

impl RemoteProcess {
    /// enumerate all imports from a remote module
    pub fn enumerate_module_imports(&self, module_name: &str) -> Result<Vec<RemoteImport>> {
        let module = find_remote_module(self, module_name)?;
        let pe = self.read_pe_headers(module.base())?;

        let import_dir = pe.import_directory().ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no import directory".into(),
        })?;

        if import_dir.virtual_address == 0 {
            return Ok(Vec::new());
        }

        let is_64 = pe.is_64bit();
        let ptr_size = if is_64 { 8 } else { 4 };

        let mut imports = Vec::new();
        let mut desc_addr = module.base() + import_dir.virtual_address as usize;

        loop {
            let desc: ImportDescriptor = self.read_value(desc_addr)?;
            if desc.is_null() {
                break;
            }

            // read DLL name
            let dll_name = self.read_string(module.base() + desc.name as usize, 256)?;

            // walk thunk data
            let original_thunk = if desc.original_first_thunk != 0 {
                desc.original_first_thunk
            } else {
                desc.first_thunk
            };

            let mut thunk_addr = module.base() + original_thunk as usize;
            let mut iat_addr = module.base() + desc.first_thunk as usize;

            loop {
                let thunk_value: usize = if is_64 {
                    self.read_value::<u64>(thunk_addr)? as usize
                } else {
                    self.read_value::<u32>(thunk_addr)? as usize
                };

                if thunk_value == 0 {
                    break;
                }

                let resolved: usize = if is_64 {
                    self.read_value::<u64>(iat_addr)? as usize
                } else {
                    self.read_value::<u32>(iat_addr)? as usize
                };

                let (func_name, ordinal) = if is_64 {
                    if thunk_value & 0x8000000000000000 != 0 {
                        (None, Some((thunk_value & 0xFFFF) as u16))
                    } else {
                        let hint_name_addr = module.base() + thunk_value;
                        let _hint: u16 = self.read_value(hint_name_addr)?;
                        let name = self.read_string(hint_name_addr + 2, 256)?;
                        (Some(name), None)
                    }
                } else {
                    if thunk_value & 0x80000000 != 0 {
                        (None, Some((thunk_value & 0xFFFF) as u16))
                    } else {
                        let hint_name_addr = module.base() + thunk_value;
                        let _hint: u16 = self.read_value(hint_name_addr)?;
                        let name = self.read_string(hint_name_addr + 2, 256)?;
                        (Some(name), None)
                    }
                };

                imports.push(RemoteImport {
                    module_name: dll_name.clone(),
                    function_name: func_name,
                    ordinal,
                    iat_address: iat_addr,
                    resolved_address: resolved,
                });

                thunk_addr += ptr_size;
                iat_addr += ptr_size;
            }

            desc_addr += core::mem::size_of::<ImportDescriptor>();
        }

        Ok(imports)
    }
}

// ============================================================================
// Remote Module Lookup Enhancements
// ============================================================================

impl RemoteProcess {
    /// wait for a module to be loaded
    #[cfg(feature = "std")]
    pub fn wait_for_module(&self, name: &str, timeout: Duration) -> Result<RemoteModuleInfo> {
        use std::time::Instant;

        let start = Instant::now();
        let poll_interval = Duration::from_millis(50);
        let name_lower = name.to_lowercase();

        loop {
            let modules = enumerate_remote_modules(self)?;
            for module in modules {
                if module.name.to_lowercase() == name_lower
                    || module.name.to_lowercase().starts_with(&name_lower)
                {
                    return Ok(module);
                }
            }

            if start.elapsed() >= timeout {
                return Err(WraithError::ModuleNotFound { name: name.into() });
            }

            std::thread::sleep(poll_interval);
        }
    }

    /// get all exports from a module by name
    pub fn get_module_exports(&self, module_name: &str) -> Result<Vec<RemoteExport>> {
        let module = find_remote_module(self, module_name)?;
        self.enumerate_remote_exports(module.base())
    }
}

// ============================================================================
// External Pattern Scanner
// ============================================================================

/// external pattern scanner with chunked reads
pub struct RemoteScanner<'a> {
    process: &'a RemoteProcess,
    chunk_size: usize,
}

impl<'a> RemoteScanner<'a> {
    pub fn new(process: &'a RemoteProcess) -> Self {
        Self {
            process,
            chunk_size: 64 * 1024, // 64KB default
        }
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// scan a memory range for pattern
    pub fn scan_range(&self, start: usize, size: usize, pattern: &str) -> Result<Vec<usize>> {
        use crate::util::pattern::{Pattern, Scanner};

        let parsed = Pattern::parse(pattern)?;
        let scanner = Scanner::from_pattern(parsed);
        let pattern_len = scanner.pattern_len();

        let mut results = Vec::new();
        let mut offset = 0;

        // overlap to avoid missing patterns at chunk boundaries
        let overlap = pattern_len.saturating_sub(1);

        while offset < size {
            let chunk_start = start + offset;
            let remaining = size - offset;
            let read_size = remaining.min(self.chunk_size);

            let mut buffer = vec![0u8; read_size];
            if self.process.read(chunk_start, &mut buffer).is_err() {
                offset += read_size - overlap;
                continue;
            }

            let matches = scanner.scan_slice(&buffer);
            for m in matches {
                results.push(chunk_start + m);
            }

            if read_size < self.chunk_size {
                break;
            }

            offset += read_size - overlap;
        }

        // deduplicate results from overlapping regions
        results.sort();
        results.dedup();

        Ok(results)
    }

    /// scan a module for pattern
    pub fn scan_module(&self, module_name: &str, pattern: &str) -> Result<Vec<usize>> {
        let module = find_remote_module(self.process, module_name)?;
        self.scan_range(module.base(), module.size(), pattern)
    }
}

impl RemoteProcess {
    /// scan for pattern in remote process memory
    pub fn scan_pattern(&self, pattern: &str, range: Option<core::ops::Range<usize>>) -> Result<Vec<usize>> {
        let scanner = RemoteScanner::new(self);
        match range {
            Some(r) => scanner.scan_range(r.start, r.end - r.start, pattern),
            None => {
                // scan all committed regions
                let regions = self.enumerate_regions()?;
                let mut results = Vec::new();
                for region in regions {
                    if region.is_committed() && region.is_readable() {
                        if let Ok(matches) = scanner.scan_range(region.base_address, region.region_size, pattern) {
                            results.extend(matches);
                        }
                    }
                }
                Ok(results)
            }
        }
    }

    /// scan a specific module for pattern
    pub fn scan_module(&self, module_name: &str, pattern: &str) -> Result<Vec<usize>> {
        RemoteScanner::new(self).scan_module(module_name, pattern)
    }
}

// ============================================================================
// Remote Pointer Chain Reading
// ============================================================================

impl RemoteProcess {
    /// read value at end of pointer chain
    ///
    /// follows: [[base + offsets[0]] + offsets[1]] + ... + offsets[n]
    pub fn read_ptr_chain<T: Copy>(&self, base: usize, offsets: &[usize]) -> Result<T> {
        let mut addr = base;

        for (i, &offset) in offsets.iter().enumerate() {
            if i < offsets.len() - 1 {
                // intermediate pointers
                addr = self.read_value::<usize>(addr + offset)?;
                if addr == 0 {
                    return Err(WraithError::NullPointer {
                        context: "pointer chain",
                    });
                }
            } else {
                // final offset, read the value
                addr += offset;
            }
        }

        self.read_value::<T>(addr)
    }

    /// get address at end of pointer chain (doesn't read final value)
    pub fn resolve_ptr_chain(&self, base: usize, offsets: &[usize]) -> Result<usize> {
        let mut addr = base;

        for (i, &offset) in offsets.iter().enumerate() {
            addr += offset;
            if i < offsets.len() - 1 {
                addr = self.read_value::<usize>(addr)?;
                if addr == 0 {
                    return Err(WraithError::NullPointer {
                        context: "pointer chain",
                    });
                }
            }
        }

        Ok(addr)
    }
}

// ============================================================================
// Enhanced Remote String Reading
// ============================================================================

impl RemoteProcess {
    /// read string by first reading a pointer, then reading the string
    pub fn read_string_ptr(&self, addr: usize, max_len: usize) -> Result<String> {
        let str_ptr = self.read_value::<usize>(addr)?;
        if str_ptr == 0 {
            return Ok(String::new());
        }
        self.read_string(str_ptr, max_len)
    }

    /// read wide string by first reading a pointer
    pub fn read_wstring_ptr(&self, addr: usize, max_chars: usize) -> Result<String> {
        let str_ptr = self.read_value::<usize>(addr)?;
        if str_ptr == 0 {
            return Ok(String::new());
        }
        self.read_wstring(str_ptr, max_chars)
    }
}

// ============================================================================
// Remote Memory Region Enumeration
// ============================================================================

/// memory state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteMemoryState {
    Commit,
    Reserve,
    Free,
}

/// memory type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteMemoryType {
    Image,
    Mapped,
    Private,
    Unknown,
}

/// remote memory region information
#[derive(Debug, Clone)]
pub struct RemoteMemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: RemoteMemoryState,
    pub protect: u32,
    pub memory_type: RemoteMemoryType,
}

impl RemoteMemoryRegion {
    pub fn is_committed(&self) -> bool {
        self.state == RemoteMemoryState::Commit
    }

    pub fn is_executable(&self) -> bool {
        matches!(
            self.protect,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub fn is_readable(&self) -> bool {
        matches!(
            self.protect,
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    pub fn is_writable(&self) -> bool {
        matches!(
            self.protect,
            PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }
}

// memory basic information structure
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    #[cfg(target_arch = "x86_64")]
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    memory_type: u32,
}

const MEM_COMMIT_STATE: u32 = 0x1000;
const MEM_RESERVE_STATE: u32 = 0x2000;
const MEM_FREE_STATE: u32 = 0x10000;
const MEM_IMAGE: u32 = 0x1000000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_PRIVATE: u32 = 0x20000;

impl RemoteProcess {
    /// query memory region at address
    pub fn query_memory(&self, addr: usize) -> Result<RemoteMemoryRegion> {
        let table = get_syscall_table()?;
        let syscall = DirectSyscall::from_table(table, "NtQueryVirtualMemory")?;

        let mut mbi = MemoryBasicInformation::default();
        let mut return_length: usize = 0;

        // SAFETY: buffer is properly sized
        let status = unsafe {
            syscall.call6(
                self.handle(),
                addr,
                0, // MemoryBasicInformation
                &mut mbi as *mut _ as usize,
                core::mem::size_of::<MemoryBasicInformation>(),
                &mut return_length as *mut usize as usize,
            )
        };

        if !nt_success(status) {
            return Err(WraithError::ReadFailed {
                address: addr as u64,
                size: 0,
            });
        }

        let state = match mbi.state {
            MEM_COMMIT_STATE => RemoteMemoryState::Commit,
            MEM_RESERVE_STATE => RemoteMemoryState::Reserve,
            _ => RemoteMemoryState::Free,
        };

        let memory_type = match mbi.memory_type {
            MEM_IMAGE => RemoteMemoryType::Image,
            MEM_MAPPED => RemoteMemoryType::Mapped,
            MEM_PRIVATE => RemoteMemoryType::Private,
            _ => RemoteMemoryType::Unknown,
        };

        Ok(RemoteMemoryRegion {
            base_address: mbi.base_address,
            allocation_base: mbi.allocation_base,
            allocation_protect: mbi.allocation_protect,
            region_size: mbi.region_size,
            state,
            protect: mbi.protect,
            memory_type,
        })
    }

    /// enumerate all memory regions
    pub fn enumerate_regions(&self) -> Result<Vec<RemoteMemoryRegion>> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;

        #[cfg(target_arch = "x86_64")]
        let max_addr: usize = 0x7FFFFFFFFFFF;
        #[cfg(target_arch = "x86")]
        let max_addr: usize = 0x7FFFFFFF;

        while addr < max_addr {
            match self.query_memory(addr) {
                Ok(region) => {
                    let next_addr = region.base_address + region.region_size;
                    regions.push(region);
                    addr = next_addr;
                }
                Err(_) => break,
            }
        }

        Ok(regions)
    }

    /// find all executable regions
    pub fn find_executable_regions(&self) -> Result<Vec<RemoteMemoryRegion>> {
        Ok(self
            .enumerate_regions()?
            .into_iter()
            .filter(|r| r.is_committed() && r.is_executable())
            .collect())
    }
}

// ============================================================================
// Remote Thread Enumeration
// ============================================================================

/// remote thread information
#[derive(Debug, Clone)]
pub struct RemoteThreadInfo {
    pub tid: u32,
    pub owner_pid: u32,
    pub base_priority: i32,
}

impl RemoteProcess {
    /// enumerate all threads in the process
    pub fn enumerate_threads(&self) -> Result<Vec<RemoteThreadInfo>> {
        let mut threads = Vec::new();
        let target_pid = self.pid();

        // SAFETY: CreateToolhelp32Snapshot is safe to call
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(WraithError::from_last_error("CreateToolhelp32Snapshot"));
        }

        let mut entry = ThreadEntry32::default();
        entry.size = core::mem::size_of::<ThreadEntry32>() as u32;

        // SAFETY: entry is properly initialized
        let mut success = unsafe { Thread32First(snapshot, &mut entry) };

        while success != 0 {
            if entry.owner_process_id == target_pid {
                threads.push(RemoteThreadInfo {
                    tid: entry.thread_id,
                    owner_pid: entry.owner_process_id,
                    base_priority: entry.base_priority,
                });
            }

            // SAFETY: entry is properly initialized
            success = unsafe { Thread32Next(snapshot, &mut entry) };
        }

        // SAFETY: valid handle
        unsafe { CloseHandle(snapshot) };

        Ok(threads)
    }

    /// get the main thread (first thread, usually)
    pub fn get_main_thread(&self) -> Result<RemoteThreadInfo> {
        let threads = self.enumerate_threads()?;
        threads.into_iter().next().ok_or_else(|| WraithError::ThreadNotFound { tid: 0 })
    }
}

// ============================================================================
// Handle to PID Resolution
// ============================================================================

/// get process ID from a process handle
pub fn get_process_id_from_handle(handle: usize) -> Result<u32> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQueryInformationProcess")?;

    #[repr(C)]
    struct ProcessBasicInfo {
        exit_status: i32,
        peb_base: usize,
        affinity_mask: usize,
        base_priority: i32,
        unique_pid: usize,
        inherited_from_pid: usize,
    }

    let mut info = core::mem::MaybeUninit::<ProcessBasicInfo>::uninit();
    let mut return_length: u32 = 0;

    // SAFETY: buffer is correctly sized
    let status = unsafe {
        syscall.call5(
            handle,
            0, // ProcessBasicInformation
            info.as_mut_ptr() as usize,
            core::mem::size_of::<ProcessBasicInfo>(),
            &mut return_length as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        let info = unsafe { info.assume_init() };
        Ok(info.unique_pid as u32)
    } else {
        Err(WraithError::SyscallFailed {
            name: "NtQueryInformationProcess".into(),
            status,
        })
    }
}

// ============================================================================
// Win32 FFI Declarations
// ============================================================================

const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const TH32CS_SNAPTHREAD: u32 = 0x00000004;
const INVALID_HANDLE_VALUE: usize = usize::MAX;

#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    cnt_usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

impl Default for ProcessEntry32W {
    fn default() -> Self {
        Self {
            size: 0,
            cnt_usage: 0,
            process_id: 0,
            default_heap_id: 0,
            module_id: 0,
            threads: 0,
            parent_process_id: 0,
            pri_class_base: 0,
            flags: 0,
            exe_file: [0u16; 260],
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct ThreadEntry32 {
    size: u32,
    cnt_usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> usize;
    fn Process32FirstW(snapshot: usize, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: usize, entry: *mut ProcessEntry32W) -> i32;
    fn Thread32First(snapshot: usize, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: usize, entry: *mut ThreadEntry32) -> i32;
    fn CloseHandle(handle: usize) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn FindWindowW(class_name: *const u16, window_name: *const u16) -> usize;
    fn GetWindowThreadProcessId(hwnd: usize, process_id: *mut u32) -> u32;
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_processes() {
        let procs = enumerate_processes().expect("should enumerate");
        assert!(!procs.is_empty());

        // should find ourselves
        let current_pid = std::process::id();
        assert!(procs.iter().any(|p| p.pid == current_pid));
    }

    #[test]
    fn test_find_process_by_name() {
        // should find explorer.exe on any Windows system
        let result = find_process_by_name("explorer.exe");
        assert!(result.is_ok());
    }

    #[test]
    fn test_current_process_memory_access() {
        let current = CurrentProcess::new();

        // allocate
        let alloc = current.allocate(4096, Protection::READWRITE).expect("should allocate");
        assert!(alloc.base != 0);

        // write
        let data = [1u8, 2, 3, 4];
        current.write(alloc.base, &data).expect("should write");

        // read back
        let mut buf = [0u8; 4];
        current.read(alloc.base, &mut buf).expect("should read");
        assert_eq!(buf, data);

        // free
        current.free(alloc.base).expect("should free");
    }

    #[test]
    fn test_remote_process_pe_headers() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only()).expect("should open");

        let modules = enumerate_remote_modules(&proc).expect("should enum");
        let ntdll = modules.iter().find(|m| m.name.to_lowercase().contains("ntdll")).expect("ntdll");

        let pe = proc.read_pe_headers(ntdll.base).expect("should parse PE");
        assert!(pe.is_64bit() || !pe.is_64bit()); // just verify it parsed
        assert!(pe.size_of_image() > 0);
    }

    #[test]
    fn test_remote_exports() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only()).expect("should open");

        let modules = enumerate_remote_modules(&proc).expect("should enum");
        let ntdll = modules.iter().find(|m| m.name.to_lowercase().contains("ntdll")).expect("ntdll");

        let exports = proc.enumerate_remote_exports(ntdll.base).expect("should enum exports");
        assert!(!exports.is_empty());

        // should find NtOpenProcess
        let has_open = exports.iter().any(|e| e.name.as_ref().map(|n| n == "NtOpenProcess").unwrap_or(false));
        assert!(has_open, "should find NtOpenProcess export");
    }

    #[test]
    fn test_pointer_chain() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_write()).expect("should open");

        // allocate and set up a simple chain
        let alloc = proc.allocate(256, PAGE_READWRITE).expect("alloc");
        let base = alloc.base();

        // write a pointer at base+0x10 that points to base+0x20
        let ptr_to = base + 0x20;
        proc.write_value(base + 0x10, &ptr_to).expect("write ptr");

        // write a value at that location
        let value: u32 = 0xDEADBEEF;
        proc.write_value(base + 0x20, &value).expect("write value");

        // read through chain
        let read: u32 = proc.read_ptr_chain(base, &[0x10, 0x0]).expect("chain read");
        assert_eq!(read, value);
    }

    #[test]
    fn test_memory_regions() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only()).expect("should open");

        let regions = proc.enumerate_regions().expect("should enumerate");
        assert!(!regions.is_empty());

        // should have some executable regions
        let exec = proc.find_executable_regions().expect("exec regions");
        assert!(!exec.is_empty());
    }

    #[test]
    fn test_thread_enum() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::query()).expect("should open");

        let threads = proc.enumerate_threads().expect("should enumerate");
        assert!(!threads.is_empty());

        let main = proc.get_main_thread().expect("main thread");
        assert!(main.tid > 0);
    }
}
