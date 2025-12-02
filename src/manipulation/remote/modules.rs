//! Remote module enumeration

use super::process::RemoteProcess;
use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    get_syscall_table, nt_success, DirectSyscall,
};
use crate::structures::offsets::PebOffsets;
use crate::version::WindowsVersion;

/// information about a remote module
#[derive(Debug, Clone)]
pub struct RemoteModuleInfo {
    pub name: String,
    pub path: String,
    pub base: usize,
    pub size: usize,
    pub entry_point: usize,
}

/// wrapper for remote module operations
pub struct RemoteModule {
    pub info: RemoteModuleInfo,
    process_handle: usize,
}

impl RemoteModule {
    /// get module base address
    pub fn base(&self) -> usize {
        self.info.base
    }

    /// get module size
    pub fn size(&self) -> usize {
        self.info.size
    }

    /// get module name
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// get full path
    pub fn path(&self) -> &str {
        &self.info.path
    }

    /// read memory from within this module
    pub fn read(&self, rva: usize, buffer: &mut [u8]) -> Result<usize> {
        let address = self.info.base + rva;
        let mut bytes_read: usize = 0;

        let table = get_syscall_table()?;
        let syscall = DirectSyscall::from_table(table, "NtReadVirtualMemory")?;

        // SAFETY: buffer is valid
        let status = unsafe {
            syscall.call5(
                self.process_handle,
                address,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                &mut bytes_read as *mut usize as usize,
            )
        };

        if nt_success(status) {
            Ok(bytes_read)
        } else {
            Err(WraithError::ReadFailed {
                address: address as u64,
                size: buffer.len(),
            })
        }
    }
}

/// enumerate modules in a remote process
pub fn enumerate_remote_modules(process: &RemoteProcess) -> Result<Vec<RemoteModuleInfo>> {
    let peb_address = get_remote_peb(process)?;
    let version = WindowsVersion::current()?;
    let offsets = PebOffsets::for_version(&version)?;

    // read PEB.Ldr pointer
    let ldr_ptr = process.read_value::<usize>(peb_address + offsets.ldr)?;
    if ldr_ptr == 0 {
        return Err(WraithError::RemoteModuleEnumFailed {
            reason: "null Ldr pointer".into(),
        });
    }

    // in PEB_LDR_DATA, InLoadOrderModuleList is at offset 0x10 (x64) or 0x0C (x86)
    #[cfg(target_arch = "x86_64")]
    const LDR_MODULE_LIST_OFFSET: usize = 0x10;
    #[cfg(target_arch = "x86")]
    const LDR_MODULE_LIST_OFFSET: usize = 0x0C;

    let list_head = ldr_ptr + LDR_MODULE_LIST_OFFSET;

    // read head.Flink to get first entry
    let first_entry = process.read_value::<usize>(list_head)?;
    if first_entry == 0 || first_entry == list_head {
        return Ok(Vec::new());
    }

    let mut modules = Vec::new();
    let mut current = first_entry;
    let max_iterations = 4096;

    for _ in 0..max_iterations {
        if current == list_head || current == 0 {
            break;
        }

        if let Ok(module) = read_ldr_entry(process, current) {
            modules.push(module);
        }

        // read Flink to get next entry
        let next = process.read_value::<usize>(current)?;
        if next == current {
            break; // corrupted list
        }
        current = next;
    }

    Ok(modules)
}

fn read_ldr_entry(process: &RemoteProcess, entry_address: usize) -> Result<RemoteModuleInfo> {
    // LDR_DATA_TABLE_ENTRY offsets (InLoadOrderLinks is at offset 0)
    #[cfg(target_arch = "x86_64")]
    const DLL_BASE_OFFSET: usize = 0x30;
    #[cfg(target_arch = "x86_64")]
    const SIZE_OFFSET: usize = 0x40;
    #[cfg(target_arch = "x86_64")]
    const ENTRY_POINT_OFFSET: usize = 0x38;
    #[cfg(target_arch = "x86_64")]
    const FULL_DLL_NAME_OFFSET: usize = 0x48;
    #[cfg(target_arch = "x86_64")]
    const BASE_DLL_NAME_OFFSET: usize = 0x58;

    #[cfg(target_arch = "x86")]
    const DLL_BASE_OFFSET: usize = 0x18;
    #[cfg(target_arch = "x86")]
    const SIZE_OFFSET: usize = 0x20;
    #[cfg(target_arch = "x86")]
    const ENTRY_POINT_OFFSET: usize = 0x1C;
    #[cfg(target_arch = "x86")]
    const FULL_DLL_NAME_OFFSET: usize = 0x24;
    #[cfg(target_arch = "x86")]
    const BASE_DLL_NAME_OFFSET: usize = 0x2C;

    let base = process.read_value::<usize>(entry_address + DLL_BASE_OFFSET)?;
    let size = process.read_value::<u32>(entry_address + SIZE_OFFSET)? as usize;
    let entry_point = process.read_value::<usize>(entry_address + ENTRY_POINT_OFFSET)?;

    let name = read_unicode_string(process, entry_address + BASE_DLL_NAME_OFFSET)
        .unwrap_or_else(|_| String::from("<unknown>"));
    let path = read_unicode_string(process, entry_address + FULL_DLL_NAME_OFFSET)
        .unwrap_or_else(|_| String::new());

    Ok(RemoteModuleInfo {
        name,
        path,
        base,
        size,
        entry_point,
    })
}

fn read_unicode_string(process: &RemoteProcess, address: usize) -> Result<String> {
    // UNICODE_STRING: Length (u16), MaxLength (u16), padding (u32 on x64), Buffer (ptr)
    #[cfg(target_arch = "x86_64")]
    const BUFFER_OFFSET: usize = 8;
    #[cfg(target_arch = "x86")]
    const BUFFER_OFFSET: usize = 4;

    let length = process.read_value::<u16>(address)? as usize;
    if length == 0 || length > 520 {
        return Ok(String::new());
    }

    let buffer_ptr = process.read_value::<usize>(address + BUFFER_OFFSET)?;
    if buffer_ptr == 0 {
        return Ok(String::new());
    }

    // read the wide string
    let mut buffer = vec![0u16; length / 2];
    let byte_buffer = unsafe {
        core::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, length)
    };

    process.read(buffer_ptr, byte_buffer)?;

    Ok(String::from_utf16_lossy(&buffer))
}

/// find a specific module in a remote process
pub fn find_remote_module(process: &RemoteProcess, name: &str) -> Result<RemoteModule> {
    let modules = enumerate_remote_modules(process)?;
    let name_lower = name.to_lowercase();

    for module in modules {
        if module.name.to_lowercase() == name_lower
            || module.name.to_lowercase().starts_with(&name_lower)
        {
            return Ok(RemoteModule {
                info: module,
                process_handle: process.handle(),
            });
        }
    }

    Err(WraithError::ModuleNotFound {
        name: name.to_string(),
    })
}

/// get PEB address of remote process
pub fn get_remote_peb(process: &RemoteProcess) -> Result<usize> {
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
            process.handle(),
            0, // ProcessBasicInformation
            info.as_mut_ptr() as usize,
            core::mem::size_of::<ProcessBasicInfo>(),
            &mut return_length as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        let info = unsafe { info.assume_init() };
        if info.peb_base == 0 {
            return Err(WraithError::RemoteModuleEnumFailed {
                reason: "null PEB address".into(),
            });
        }
        Ok(info.peb_base)
    } else {
        Err(WraithError::RemoteModuleEnumFailed {
            reason: format!("NtQueryInformationProcess failed: {:#x}", status as u32),
        })
    }
}

/// get image base from remote PEB
pub fn get_remote_image_base(process: &RemoteProcess) -> Result<usize> {
    let peb_address = get_remote_peb(process)?;
    let version = WindowsVersion::current()?;
    let offsets = PebOffsets::for_version(&version)?;

    process.read_value::<usize>(peb_address + offsets.image_base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manipulation::remote::ProcessAccess;

    #[test]
    fn test_get_remote_peb_self() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only());
        assert!(proc.is_ok());

        let proc = proc.unwrap();
        let peb = get_remote_peb(&proc);
        assert!(peb.is_ok());
        assert!(peb.unwrap() != 0);
    }

    #[test]
    fn test_enumerate_modules_self() {
        let pid = std::process::id();
        let proc = RemoteProcess::open(pid, ProcessAccess::read_only()).unwrap();
        let modules = enumerate_remote_modules(&proc);
        assert!(modules.is_ok());

        let modules = modules.unwrap();
        assert!(!modules.is_empty(), "should have at least one module");

        // should find ntdll
        let has_ntdll = modules.iter().any(|m| {
            m.name.to_lowercase().contains("ntdll")
        });
        assert!(has_ntdll, "should find ntdll.dll");
    }
}
