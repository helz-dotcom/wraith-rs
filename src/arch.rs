//! Architecture detection and segment register access

/// true if compiling for 64-bit
#[cfg(target_arch = "x86_64")]
pub const IS_64BIT: bool = true;

/// true if compiling for 64-bit
#[cfg(target_arch = "x86")]
pub const IS_64BIT: bool = false;

/// pointer size in bytes for current architecture
pub const PTR_SIZE: usize = core::mem::size_of::<usize>();

/// x64 segment register access
#[cfg(target_arch = "x86_64")]
pub mod segment {
    use core::arch::asm;

    /// read 8 bytes from gs segment at given offset
    #[inline(always)]
    pub unsafe fn read_gs_qword(offset: u32) -> u64 {
        let value: u64;
        // SAFETY: caller ensures offset is valid within TEB
        unsafe {
            asm!(
                "mov {}, gs:[{:e}]",
                out(reg) value,
                in(reg) offset,
                options(nostack, preserves_flags, readonly)
            );
        }
        value
    }

    /// read 4 bytes from gs segment at given offset
    #[inline(always)]
    pub unsafe fn read_gs_dword(offset: u32) -> u32 {
        let value: u32;
        unsafe {
            asm!(
                "mov {:e}, gs:[{:e}]",
                out(reg) value,
                in(reg) offset,
                options(nostack, preserves_flags, readonly)
            );
        }
        value
    }

    /// get pointer to current thread's TEB
    ///
    /// on x64, TEB is at gs:[0x30] (self-reference)
    #[inline(always)]
    pub unsafe fn get_teb() -> *mut u8 {
        // SAFETY: gs:[0x30] is always the TEB self-pointer on x64
        unsafe { read_gs_qword(0x30) as *mut u8 }
    }

    /// get pointer to current process's PEB
    ///
    /// on x64, PEB pointer is at gs:[0x60]
    #[inline(always)]
    pub unsafe fn get_peb() -> *mut u8 {
        // SAFETY: gs:[0x60] is always the PEB pointer on x64
        unsafe { read_gs_qword(0x60) as *mut u8 }
    }

    /// get current thread ID
    ///
    /// on x64, ClientId.UniqueThread is at gs:[0x48]
    #[inline(always)]
    pub unsafe fn get_current_tid() -> u32 {
        // SAFETY: gs:[0x48] is the thread ID
        unsafe { read_gs_qword(0x48) as u32 }
    }

    /// get current process ID
    ///
    /// on x64, ClientId.UniqueProcess is at gs:[0x40]
    #[inline(always)]
    pub unsafe fn get_current_pid() -> u32 {
        // SAFETY: gs:[0x40] is the process ID
        unsafe { read_gs_qword(0x40) as u32 }
    }
}

/// x86 segment register access
#[cfg(target_arch = "x86")]
pub mod segment {
    use core::arch::asm;

    /// read 4 bytes from fs segment at given offset
    #[inline(always)]
    pub unsafe fn read_fs_dword(offset: u32) -> u32 {
        let value: u32;
        // SAFETY: caller ensures offset is valid within TEB
        unsafe {
            asm!(
                "mov {:e}, fs:[{:e}]",
                out(reg) value,
                in(reg) offset,
                options(nostack, preserves_flags, readonly)
            );
        }
        value
    }

    /// get pointer to current thread's TEB
    ///
    /// on x86, TEB is at fs:[0x18] (self-reference)
    #[inline(always)]
    pub unsafe fn get_teb() -> *mut u8 {
        // SAFETY: fs:[0x18] is always the TEB self-pointer on x86
        unsafe { read_fs_dword(0x18) as *mut u8 }
    }

    /// get pointer to current process's PEB
    ///
    /// on x86, PEB pointer is at fs:[0x30]
    #[inline(always)]
    pub unsafe fn get_peb() -> *mut u8 {
        // SAFETY: fs:[0x30] is always the PEB pointer on x86
        unsafe { read_fs_dword(0x30) as *mut u8 }
    }

    /// get current thread ID
    ///
    /// on x86, ClientId.UniqueThread is at fs:[0x24]
    #[inline(always)]
    pub unsafe fn get_current_tid() -> u32 {
        // SAFETY: fs:[0x24] is the thread ID
        unsafe { read_fs_dword(0x24) }
    }

    /// get current process ID
    ///
    /// on x86, ClientId.UniqueProcess is at fs:[0x20]
    #[inline(always)]
    pub unsafe fn get_current_pid() -> u32 {
        // SAFETY: fs:[0x20] is the process ID
        unsafe { read_fs_dword(0x20) }
    }
}

/// architecture-specific pointer type for interop
#[cfg(target_arch = "x86_64")]
pub type NativePtr = u64;

#[cfg(target_arch = "x86")]
pub type NativePtr = u32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_teb_not_null() {
        let teb = unsafe { segment::get_teb() };
        assert!(!teb.is_null());
    }

    #[test]
    fn test_get_peb_not_null() {
        let peb = unsafe { segment::get_peb() };
        assert!(!peb.is_null());
    }

    #[test]
    fn test_pid_tid_nonzero() {
        let pid = unsafe { segment::get_current_pid() };
        let tid = unsafe { segment::get_current_tid() };
        assert!(pid > 0);
        assert!(tid > 0);
    }
}
