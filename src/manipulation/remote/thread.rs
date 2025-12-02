//! Remote thread creation and manipulation

use super::process::RemoteProcess;
use crate::error::{Result, WraithError};
use crate::manipulation::syscall::{
    get_syscall_table, nt_close, nt_success, DirectSyscall, ObjectAttributes,
};

/// thread creation flags
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadCreationFlags {
    pub flags: u32,
}

impl ThreadCreationFlags {
    /// create thread in running state
    pub const fn running() -> Self {
        Self { flags: 0 }
    }

    /// create thread in suspended state
    pub const fn suspended() -> Self {
        Self { flags: CREATE_SUSPENDED }
    }

    /// skip thread attach notifications (dangerous)
    pub const fn skip_attach() -> Self {
        Self { flags: THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH }
    }

    /// hide thread from debugger
    pub const fn hide_from_debugger() -> Self {
        Self { flags: THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER }
    }

    /// combine flags
    pub const fn with(self, other: Self) -> Self {
        Self { flags: self.flags | other.flags }
    }
}

/// options for remote thread creation
#[derive(Debug, Clone, Copy)]
pub struct RemoteThreadOptions {
    pub flags: ThreadCreationFlags,
    pub stack_size: usize,
    pub create_suspended: bool,
}

impl Default for RemoteThreadOptions {
    fn default() -> Self {
        Self {
            flags: ThreadCreationFlags::running(),
            stack_size: 0, // default stack size
            create_suspended: false,
        }
    }
}

impl RemoteThreadOptions {
    pub fn suspended() -> Self {
        Self {
            flags: ThreadCreationFlags::suspended(),
            stack_size: 0,
            create_suspended: true,
        }
    }

    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.stack_size = size;
        self
    }
}

/// wrapper for a remote thread handle
pub struct RemoteThread {
    handle: usize,
    id: u32,
    owns_handle: bool,
}

impl RemoteThread {
    /// get the thread handle
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// get the thread ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// wait for thread to complete
    pub fn wait(&self, timeout_ms: u32) -> Result<()> {
        let result = unsafe { WaitForSingleObject(self.handle, timeout_ms) };
        if result == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(WraithError::RemoteThreadFailed {
                reason: format!("wait failed with result {}", result),
            })
        }
    }

    /// wait indefinitely for thread to complete
    pub fn wait_infinite(&self) -> Result<()> {
        self.wait(INFINITE)
    }

    /// get exit code (returns None if thread is still running)
    pub fn exit_code(&self) -> Result<Option<u32>> {
        let mut exit_code: u32 = 0;
        let result = unsafe { GetExitCodeThread(self.handle, &mut exit_code) };
        if result == 0 {
            return Err(WraithError::RemoteThreadFailed {
                reason: "GetExitCodeThread failed".into(),
            });
        }

        if exit_code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }

    /// suspend the thread
    pub fn suspend(&self) -> Result<u32> {
        let result = unsafe { SuspendThread(self.handle) };
        if result == u32::MAX {
            Err(WraithError::ThreadSuspendResumeFailed {
                reason: "SuspendThread failed".into(),
            })
        } else {
            Ok(result)
        }
    }

    /// resume the thread
    pub fn resume(&self) -> Result<u32> {
        let result = unsafe { ResumeThread(self.handle) };
        if result == u32::MAX {
            Err(WraithError::ThreadSuspendResumeFailed {
                reason: "ResumeThread failed".into(),
            })
        } else {
            Ok(result)
        }
    }

    /// terminate the thread
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let table = get_syscall_table()?;
        let syscall = DirectSyscall::from_table(table, "NtTerminateThread")?;

        // SAFETY: terminating a thread with valid handle
        let status = unsafe { syscall.call2(self.handle, exit_code as usize) };

        if nt_success(status) {
            Ok(())
        } else {
            Err(WraithError::SyscallFailed {
                name: "NtTerminateThread".into(),
                status,
            })
        }
    }

    /// leak the handle (don't close on drop)
    pub fn leak(mut self) -> usize {
        self.owns_handle = false;
        self.handle
    }
}

impl Drop for RemoteThread {
    fn drop(&mut self) {
        if self.owns_handle && self.handle != 0 {
            let _ = nt_close(self.handle);
        }
    }
}

// SAFETY: thread handle can be sent between threads
unsafe impl Send for RemoteThread {}
unsafe impl Sync for RemoteThread {}

/// create a remote thread in the target process
pub fn create_remote_thread(
    process: &RemoteProcess,
    start_address: usize,
    parameter: usize,
    options: RemoteThreadOptions,
) -> Result<RemoteThread> {
    // use NtCreateThreadEx for more control
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtCreateThreadEx")?;

    let mut thread_handle: usize = 0;
    let obj_attr = ObjectAttributes::new();

    let create_flags = if options.create_suspended {
        options.flags.flags | CREATE_SUSPENDED
    } else {
        options.flags.flags
    };

    // SAFETY: all pointers point to valid stack data
    let status = unsafe {
        syscall.call_many(&[
            &mut thread_handle as *mut usize as usize, // ThreadHandle
            THREAD_ALL_ACCESS as usize,                 // DesiredAccess
            &obj_attr as *const _ as usize,             // ObjectAttributes
            process.handle(),                           // ProcessHandle
            start_address,                              // StartRoutine
            parameter,                                  // Argument
            create_flags as usize,                      // CreateFlags
            0,                                          // ZeroBits
            options.stack_size,                         // StackSize
            0,                                          // MaximumStackSize
            0,                                          // AttributeList
        ])
    };

    if nt_success(status) {
        // get thread ID
        let tid = get_thread_id(thread_handle)?;
        Ok(RemoteThread {
            handle: thread_handle,
            id: tid,
            owns_handle: true,
        })
    } else {
        Err(WraithError::RemoteThreadFailed {
            reason: format!("NtCreateThreadEx failed with status {:#x}", status as u32),
        })
    }
}

/// create remote thread using Win32 API (simpler but more detectable)
pub fn create_remote_thread_win32(
    process: &RemoteProcess,
    start_address: usize,
    parameter: usize,
    suspended: bool,
) -> Result<RemoteThread> {
    let mut thread_id: u32 = 0;
    let flags = if suspended { CREATE_SUSPENDED } else { 0 };

    let handle = unsafe {
        CreateRemoteThread(
            process.handle(),
            core::ptr::null(),
            0,
            start_address,
            parameter,
            flags,
            &mut thread_id,
        )
    };

    if handle == 0 {
        return Err(WraithError::RemoteThreadFailed {
            reason: format!("CreateRemoteThread failed: {}", unsafe { GetLastError() }),
        });
    }

    Ok(RemoteThread {
        handle,
        id: thread_id,
        owns_handle: true,
    })
}

fn get_thread_id(thread_handle: usize) -> Result<u32> {
    let table = get_syscall_table()?;
    let syscall = DirectSyscall::from_table(table, "NtQueryInformationThread")?;

    #[repr(C)]
    struct ThreadBasicInfo {
        exit_status: i32,
        teb_base: usize,
        client_id: ClientId,
        affinity_mask: usize,
        priority: i32,
        base_priority: i32,
    }

    #[repr(C)]
    struct ClientId {
        unique_process: usize,
        unique_thread: usize,
    }

    let mut info = core::mem::MaybeUninit::<ThreadBasicInfo>::uninit();
    let mut return_length: u32 = 0;

    // SAFETY: buffer is correctly sized
    let status = unsafe {
        syscall.call5(
            thread_handle,
            0, // ThreadBasicInformation
            info.as_mut_ptr() as usize,
            core::mem::size_of::<ThreadBasicInfo>(),
            &mut return_length as *mut u32 as usize,
        )
    };

    if nt_success(status) {
        let info = unsafe { info.assume_init() };
        Ok(info.client_id.unique_thread as u32)
    } else {
        // fallback to GetThreadId if syscall fails
        let tid = unsafe { GetThreadId(thread_handle) };
        if tid != 0 {
            Ok(tid)
        } else {
            Err(WraithError::RemoteThreadFailed {
                reason: "failed to get thread ID".into(),
            })
        }
    }
}

// thread access rights
const THREAD_ALL_ACCESS: u32 = 0x1F03FF;

// thread creation flags
const CREATE_SUSPENDED: u32 = 0x00000004;
const THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH: u32 = 0x00000002;
const THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER: u32 = 0x00000004;

// wait constants
const WAIT_OBJECT_0: u32 = 0;
const INFINITE: u32 = 0xFFFFFFFF;
const STILL_ACTIVE: u32 = 259;

#[link(name = "kernel32")]
extern "system" {
    fn CreateRemoteThread(
        hProcess: usize,
        lpThreadAttributes: *const core::ffi::c_void,
        dwStackSize: usize,
        lpStartAddress: usize,
        lpParameter: usize,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> usize;

    fn WaitForSingleObject(hHandle: usize, dwMilliseconds: u32) -> u32;
    fn GetExitCodeThread(hThread: usize, lpExitCode: *mut u32) -> i32;
    fn SuspendThread(hThread: usize) -> u32;
    fn ResumeThread(hThread: usize) -> u32;
    fn GetThreadId(Thread: usize) -> u32;
    fn GetLastError() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_creation_flags() {
        let flags = ThreadCreationFlags::suspended();
        assert_eq!(flags.flags, CREATE_SUSPENDED);

        let combined = ThreadCreationFlags::suspended()
            .with(ThreadCreationFlags::hide_from_debugger());
        assert!(combined.flags & CREATE_SUSPENDED != 0);
    }
}
