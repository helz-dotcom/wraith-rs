//! Kernel-mode process operations

use core::ffi::c_void;
use core::ptr::NonNull;
use alloc::vec::Vec;

use super::error::{status, KmError, KmResult, NtStatus};
use super::memory::{AccessMode, Mdl, LockOperation};

/// EPROCESS structure (opaque)
pub struct Eprocess {
    raw: NonNull<c_void>,
}

impl Eprocess {
    /// lookup EPROCESS by process ID
    pub fn lookup(process_id: u32) -> KmResult<Self> {
        let mut eprocess: *mut c_void = core::ptr::null_mut();

        // SAFETY: kernel API call
        let status = unsafe {
            PsLookupProcessByProcessId(process_id as *mut c_void, &mut eprocess)
        };

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: process_id,
                reason: "PsLookupProcessByProcessId failed",
            });
        }

        NonNull::new(eprocess)
            .map(|raw| Self { raw })
            .ok_or(KmError::ProcessOperationFailed {
                pid: process_id,
                reason: "process not found",
            })
    }

    /// get raw EPROCESS pointer
    pub fn as_raw(&self) -> *mut c_void {
        self.raw.as_ptr()
    }

    /// dereference (must call when done)
    pub fn dereference(&self) {
        // SAFETY: valid EPROCESS
        unsafe {
            ObDereferenceObject(self.raw.as_ptr());
        }
    }

    /// get process ID
    pub fn process_id(&self) -> u32 {
        // SAFETY: valid EPROCESS
        unsafe { PsGetProcessId(self.raw.as_ptr()) as u32 }
    }

    /// get process CR3 (directory table base)
    pub fn cr3(&self) -> u64 {
        // SAFETY: valid EPROCESS - this reads DirectoryTableBase field
        // offset varies by Windows version, using documented API
        unsafe { PsGetProcessCr3(self.raw.as_ptr()) }
    }

    /// get process image file name (up to 15 chars)
    pub fn image_file_name(&self) -> [u8; 15] {
        let mut name = [0u8; 15];
        // SAFETY: valid EPROCESS
        let ptr = unsafe { PsGetProcessImageFileName(self.raw.as_ptr()) };
        if !ptr.is_null() {
            unsafe {
                for (i, byte) in name.iter_mut().enumerate() {
                    let b = *ptr.add(i);
                    if b == 0 {
                        break;
                    }
                    *byte = b;
                }
            }
        }
        name
    }

    /// check if process is terminating
    pub fn is_terminating(&self) -> bool {
        // SAFETY: valid EPROCESS
        unsafe { PsGetProcessExitStatus(self.raw.as_ptr()) != 0x103 } // STATUS_PENDING
    }

    /// get process PEB (usermode)
    pub fn peb(&self) -> *mut c_void {
        // SAFETY: valid EPROCESS
        unsafe { PsGetProcessPeb(self.raw.as_ptr()) }
    }

    /// get process WoW64 PEB (32-bit PEB on 64-bit Windows)
    pub fn wow64_peb(&self) -> *mut c_void {
        // SAFETY: valid EPROCESS
        unsafe { PsGetProcessWow64Process(self.raw.as_ptr()) }
    }
}

impl Drop for Eprocess {
    fn drop(&mut self) {
        self.dereference();
    }
}

/// process access flags for opening
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccess {
    Terminate = 0x0001,
    CreateThread = 0x0002,
    VmOperation = 0x0008,
    VmRead = 0x0010,
    VmWrite = 0x0020,
    DupHandle = 0x0040,
    QueryInformation = 0x0400,
    SetInformation = 0x0200,
    All = 0x001F0FFF,
}

/// kernel process wrapper for memory operations
pub struct KmProcess {
    eprocess: Eprocess,
    apc_state: ApcState,
    attached: bool,
}

/// APC state for process attachment
#[repr(C)]
struct ApcState {
    apc_list_head: [[*mut c_void; 2]; 2],
    process: *mut c_void,
    kernel_apc_in_progress: u8,
    kernel_apc_pending: u8,
    user_apc_pending: u8,
}

impl Default for ApcState {
    fn default() -> Self {
        Self {
            apc_list_head: [[core::ptr::null_mut(); 2]; 2],
            process: core::ptr::null_mut(),
            kernel_apc_in_progress: 0,
            kernel_apc_pending: 0,
            user_apc_pending: 0,
        }
    }
}

impl KmProcess {
    /// open process by ID
    pub fn open(process_id: u32) -> KmResult<Self> {
        let eprocess = Eprocess::lookup(process_id)?;
        Ok(Self {
            eprocess,
            apc_state: ApcState::default(),
            attached: false,
        })
    }

    /// get EPROCESS
    pub fn eprocess(&self) -> &Eprocess {
        &self.eprocess
    }

    /// get process ID
    pub fn id(&self) -> u32 {
        self.eprocess.process_id()
    }

    /// attach to process address space
    pub fn attach(&mut self) -> KmResult<()> {
        if self.attached {
            return Ok(());
        }

        // SAFETY: valid EPROCESS
        unsafe {
            KeStackAttachProcess(self.eprocess.as_raw(), &mut self.apc_state as *mut _ as *mut _);
        }

        self.attached = true;
        Ok(())
    }

    /// detach from process address space
    pub fn detach(&mut self) {
        if self.attached {
            // SAFETY: we are attached
            unsafe {
                KeUnstackDetachProcess(&mut self.apc_state as *mut _ as *mut _);
            }
            self.attached = false;
        }
    }

    /// read memory from process
    pub fn read<T: Copy>(&mut self, address: u64) -> KmResult<T> {
        let mut value = core::mem::MaybeUninit::<T>::uninit();

        self.read_bytes(
            address,
            unsafe { core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, core::mem::size_of::<T>()) },
        )?;

        Ok(unsafe { value.assume_init() })
    }

    /// read bytes from process
    pub fn read_bytes(&mut self, address: u64, buffer: &mut [u8]) -> KmResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        self.attach()?;

        let mut bytes_read = 0usize;

        // SAFETY: we're attached to the process
        let status = unsafe {
            MmCopyVirtualMemory(
                self.eprocess.as_raw(),
                address as *const c_void,
                PsGetCurrentProcess(),
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                AccessMode::KernelMode as u8,
                &mut bytes_read,
            )
        };

        self.detach();

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "MmCopyVirtualMemory read failed",
            });
        }

        Ok(bytes_read)
    }

    /// write memory to process
    pub fn write<T: Copy>(&mut self, address: u64, value: &T) -> KmResult<()> {
        let bytes = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.write_bytes(address, bytes)?;
        Ok(())
    }

    /// write bytes to process
    pub fn write_bytes(&mut self, address: u64, buffer: &[u8]) -> KmResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        self.attach()?;

        let mut bytes_written = 0usize;

        // SAFETY: we're attached to the process
        let status = unsafe {
            MmCopyVirtualMemory(
                PsGetCurrentProcess(),
                buffer.as_ptr() as *const c_void,
                self.eprocess.as_raw(),
                address as *mut c_void,
                buffer.len(),
                AccessMode::KernelMode as u8,
                &mut bytes_written,
            )
        };

        self.detach();

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "MmCopyVirtualMemory write failed",
            });
        }

        Ok(bytes_written)
    }

    /// allocate virtual memory in process
    pub fn allocate(
        &mut self,
        size: usize,
        protection: u32,
        preferred_address: Option<u64>,
    ) -> KmResult<u64> {
        let mut base_address = preferred_address.unwrap_or(0) as *mut c_void;
        let mut region_size = size;

        let process_handle = self.open_handle(ProcessAccess::VmOperation as u32)?;

        // SAFETY: valid handle
        let status = unsafe {
            ZwAllocateVirtualMemory(
                process_handle,
                &mut base_address,
                0,
                &mut region_size,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                protection,
            )
        };

        unsafe { ZwClose(process_handle) };

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "ZwAllocateVirtualMemory failed",
            });
        }

        Ok(base_address as u64)
    }

    /// free virtual memory in process
    pub fn free(&mut self, address: u64) -> KmResult<()> {
        let mut base_address = address as *mut c_void;
        let mut region_size = 0usize;

        let process_handle = self.open_handle(ProcessAccess::VmOperation as u32)?;

        // SAFETY: valid handle
        let status = unsafe {
            ZwFreeVirtualMemory(
                process_handle,
                &mut base_address,
                &mut region_size,
                0x8000, // MEM_RELEASE
            )
        };

        unsafe { ZwClose(process_handle) };

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "ZwFreeVirtualMemory failed",
            });
        }

        Ok(())
    }

    /// change memory protection
    pub fn protect(&mut self, address: u64, size: usize, protection: u32) -> KmResult<u32> {
        let mut base_address = address as *mut c_void;
        let mut region_size = size;
        let mut old_protection = 0u32;

        let process_handle = self.open_handle(ProcessAccess::VmOperation as u32)?;

        // SAFETY: valid handle
        let status = unsafe {
            ZwProtectVirtualMemory(
                process_handle,
                &mut base_address,
                &mut region_size,
                protection,
                &mut old_protection,
            )
        };

        unsafe { ZwClose(process_handle) };

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "ZwProtectVirtualMemory failed",
            });
        }

        Ok(old_protection)
    }

    /// get module base address by name
    pub fn get_module_base(&mut self, module_name: &[u16]) -> KmResult<u64> {
        self.attach()?;

        // read PEB
        let peb = self.eprocess.peb();
        if peb.is_null() {
            self.detach();
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "PEB is null",
            });
        }

        // read PEB_LDR_DATA pointer (offset 0x18 on x64)
        let ldr_offset = if cfg!(target_arch = "x86_64") { 0x18 } else { 0x0C };
        let ldr_ptr = unsafe {
            *(peb.cast::<u8>().add(ldr_offset) as *const *const c_void)
        };

        if ldr_ptr.is_null() {
            self.detach();
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "PEB_LDR_DATA is null",
            });
        }

        // InLoadOrderModuleList offset (0x10 on x64)
        let list_offset = if cfg!(target_arch = "x86_64") { 0x10 } else { 0x0C };
        let head = unsafe { ldr_ptr.cast::<u8>().add(list_offset) as *const ListEntry };
        let mut current = unsafe { (*head).flink };

        while current != head as *mut _ {
            // get module entry (LDR_DATA_TABLE_ENTRY)
            // BaseDllName is at offset 0x58 on x64
            let name_offset = if cfg!(target_arch = "x86_64") { 0x58 } else { 0x2C };
            let name_ptr = unsafe { current.cast::<u8>().add(name_offset) as *const UnicodeStringKernel };

            let name = unsafe { &*name_ptr };
            if !name.buffer.is_null() && name.length > 0 {
                let name_slice = unsafe {
                    core::slice::from_raw_parts(name.buffer, (name.length / 2) as usize)
                };

                // case-insensitive comparison
                if name_slice.len() == module_name.len() {
                    let matches = name_slice.iter().zip(module_name.iter())
                        .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase());

                    if matches {
                        // DllBase is at offset 0x30 on x64
                        let base_offset = if cfg!(target_arch = "x86_64") { 0x30 } else { 0x18 };
                        let base = unsafe {
                            *(current.cast::<u8>().add(base_offset) as *const u64)
                        };
                        self.detach();
                        return Ok(base);
                    }
                }
            }

            current = unsafe { (*current).flink };
        }

        self.detach();
        Err(KmError::ProcessOperationFailed {
            pid: self.id(),
            reason: "module not found",
        })
    }

    /// open handle to this process
    fn open_handle(&self, access: u32) -> KmResult<*mut c_void> {
        let mut handle: *mut c_void = core::ptr::null_mut();

        // SAFETY: valid EPROCESS
        let status = unsafe {
            ObOpenObjectByPointer(
                self.eprocess.as_raw(),
                0x200, // OBJ_KERNEL_HANDLE
                core::ptr::null_mut(),
                access,
                core::ptr::null_mut(), // PsProcessType
                AccessMode::KernelMode as u8,
                &mut handle,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::ProcessOperationFailed {
                pid: self.id(),
                reason: "ObOpenObjectByPointer failed",
            });
        }

        Ok(handle)
    }
}

impl Drop for KmProcess {
    fn drop(&mut self) {
        self.detach();
    }
}

/// list entry structure
#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

/// unicode string for kernel
#[repr(C)]
struct UnicodeStringKernel {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

// process functions
extern "system" {
    fn PsLookupProcessByProcessId(ProcessId: *mut c_void, Process: *mut *mut c_void) -> NtStatus;
    fn PsGetProcessId(Process: *mut c_void) -> usize;
    fn PsGetProcessCr3(Process: *mut c_void) -> u64;
    fn PsGetProcessImageFileName(Process: *mut c_void) -> *const u8;
    fn PsGetProcessExitStatus(Process: *mut c_void) -> NtStatus;
    fn PsGetProcessPeb(Process: *mut c_void) -> *mut c_void;
    fn PsGetProcessWow64Process(Process: *mut c_void) -> *mut c_void;
    fn PsGetCurrentProcess() -> *mut c_void;

    fn ObDereferenceObject(Object: *mut c_void);
    fn ObOpenObjectByPointer(
        Object: *mut c_void,
        HandleAttributes: u32,
        PassedAccessState: *mut c_void,
        DesiredAccess: u32,
        ObjectType: *mut c_void,
        AccessMode: u8,
        Handle: *mut *mut c_void,
    ) -> NtStatus;

    fn KeStackAttachProcess(Process: *mut c_void, ApcState: *mut c_void);
    fn KeUnstackDetachProcess(ApcState: *mut c_void);

    fn MmCopyVirtualMemory(
        SourceProcess: *mut c_void,
        SourceAddress: *const c_void,
        TargetProcess: *mut c_void,
        TargetAddress: *mut c_void,
        BufferSize: usize,
        PreviousMode: u8,
        ReturnSize: *mut usize,
    ) -> NtStatus;

    fn ZwAllocateVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> NtStatus;

    fn ZwFreeVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        FreeType: u32,
    ) -> NtStatus;

    fn ZwProtectVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        NewProtect: u32,
        OldProtect: *mut u32,
    ) -> NtStatus;

    fn ZwClose(Handle: *mut c_void) -> NtStatus;
}
