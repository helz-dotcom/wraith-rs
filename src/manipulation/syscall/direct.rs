//! Direct syscall invocation (inline syscall instruction)
//!
//! Bypasses usermode hooks by using inline `syscall` instructions
//! instead of calling ntdll functions directly.

use super::table::{SyscallEntry, SyscallTable};
use crate::error::{Result, WraithError};
use core::arch::asm;

/// direct syscall invoker
///
/// holds the SSN and provides methods to invoke the syscall directly
/// with varying argument counts
pub struct DirectSyscall {
    ssn: u16,
}

impl DirectSyscall {
    /// create from SSN
    pub const fn new(ssn: u16) -> Self {
        Self { ssn }
    }

    /// create from syscall entry
    pub fn from_entry(entry: &SyscallEntry) -> Self {
        Self { ssn: entry.ssn }
    }

    /// create from syscall table lookup
    pub fn from_table(table: &SyscallTable, name: &str) -> Result<Self> {
        let entry = table.get(name).ok_or_else(|| WraithError::SyscallNotFound {
            name: name.to_string(),
        })?;
        Ok(Self::from_entry(entry))
    }

    /// get SSN
    pub const fn ssn(&self) -> u16 {
        self.ssn
    }
}

// x64 direct syscall implementations
#[cfg(target_arch = "x86_64")]
impl DirectSyscall {
    /// invoke syscall with 0 arguments
    ///
    /// # Safety
    /// caller must ensure the syscall is appropriate to call with 0 args
    #[inline(never)]
    pub unsafe fn call0(&self) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall validity
        unsafe {
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                ssn = in(reg) self.ssn as u32,
                out("eax") status,
                out("rcx") _,
                out("r10") _,
                out("r11") _,
                options(nostack)
            );
        }
        status
    }

    /// invoke syscall with 1 argument
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call1(&self, arg1: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                ssn = in(reg) self.ssn as u32,
                in("rcx") arg1,
                out("eax") status,
                out("r10") _,
                out("r11") _,
                options(nostack)
            );
        }
        status
    }

    /// invoke syscall with 2 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call2(&self, arg1: usize, arg2: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                ssn = in(reg) self.ssn as u32,
                in("rcx") arg1,
                in("rdx") arg2,
                out("eax") status,
                out("r10") _,
                out("r11") _,
                options(nostack)
            );
        }
        status
    }

    /// invoke syscall with 3 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call3(&self, arg1: usize, arg2: usize, arg3: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                ssn = in(reg) self.ssn as u32,
                in("rcx") arg1,
                in("rdx") arg2,
                in("r8") arg3,
                out("eax") status,
                out("r10") _,
                out("r11") _,
                options(nostack)
            );
        }
        status
    }

    /// invoke syscall with 4 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call4(&self, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                ssn = in(reg) self.ssn as u32,
                in("rcx") arg1,
                in("rdx") arg2,
                in("r8") arg3,
                in("r9") arg4,
                out("eax") status,
                out("r10") _,
                out("r11") _,
                options(nostack)
            );
        }
        status
    }

    /// invoke syscall with 5 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call5(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        // 5th arg goes on stack at rsp+0x28 (after 32-byte shadow space)
        unsafe {
            asm!(
                "sub rsp, 0x30",         // shadow space + arg5
                "mov [rsp+0x28], {arg5}",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                "add rsp, 0x30",
                ssn = in(reg) self.ssn as u32,
                arg5 = in(reg) arg5,
                in("rcx") arg1,
                in("rdx") arg2,
                in("r8") arg3,
                in("r9") arg4,
                out("eax") status,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke syscall with 6 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call6(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        // args 5-6 go on stack after shadow space
        unsafe {
            asm!(
                "sub rsp, 0x38",         // shadow space + arg5 + arg6
                "mov [rsp+0x28], {arg5}",
                "mov [rsp+0x30], {arg6}",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "syscall",
                "add rsp, 0x38",
                ssn = in(reg) self.ssn as u32,
                arg5 = in(reg) arg5,
                arg6 = in(reg) arg6,
                in("rcx") arg1,
                in("rdx") arg2,
                in("r8") arg3,
                in("r9") arg4,
                out("eax") status,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke syscall with variable arguments (uses array)
    ///
    /// supports up to 8 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call_many(&self, args: &[usize]) -> i32 {
        match args.len() {
            0 => unsafe { self.call0() },
            1 => unsafe { self.call1(args[0]) },
            2 => unsafe { self.call2(args[0], args[1]) },
            3 => unsafe { self.call3(args[0], args[1], args[2]) },
            4 => unsafe { self.call4(args[0], args[1], args[2], args[3]) },
            5 => unsafe { self.call5(args[0], args[1], args[2], args[3], args[4]) },
            6 => unsafe { self.call6(args[0], args[1], args[2], args[3], args[4], args[5]) },
            _ => {
                // for more args, use the 6-arg version and hope it's enough
                // most syscalls don't need more than 6 args
                unsafe { self.call6(args[0], args[1], args[2], args[3], args[4], args[5]) }
            }
        }
    }
}

// x86 direct syscall implementations
#[cfg(target_arch = "x86")]
impl DirectSyscall {
    /// invoke syscall with variable arguments (x86 uses stack for all args)
    ///
    /// # Safety
    /// caller must ensure the syscall and args are valid
    #[inline(never)]
    pub unsafe fn call(&self, args: &[usize]) -> i32 {
        // x86 uses int 0x2e with edx pointing to args on stack
        let status: i32;
        let args_ptr = args.as_ptr();

        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov eax, {ssn:e}",
                "mov edx, {args}",
                "int 0x2e",
                ssn = in(reg) self.ssn as u32,
                args = in(reg) args_ptr,
                out("eax") status,
                options(nostack)
            );
        }
        status
    }

    pub unsafe fn call0(&self) -> i32 {
        unsafe { self.call(&[]) }
    }

    pub unsafe fn call1(&self, arg1: usize) -> i32 {
        unsafe { self.call(&[arg1]) }
    }

    pub unsafe fn call2(&self, arg1: usize, arg2: usize) -> i32 {
        unsafe { self.call(&[arg1, arg2]) }
    }

    pub unsafe fn call3(&self, arg1: usize, arg2: usize, arg3: usize) -> i32 {
        unsafe { self.call(&[arg1, arg2, arg3]) }
    }

    pub unsafe fn call4(&self, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> i32 {
        unsafe { self.call(&[arg1, arg2, arg3, arg4]) }
    }

    pub unsafe fn call5(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> i32 {
        unsafe { self.call(&[arg1, arg2, arg3, arg4, arg5]) }
    }

    pub unsafe fn call6(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> i32 {
        unsafe { self.call(&[arg1, arg2, arg3, arg4, arg5, arg6]) }
    }

    pub unsafe fn call_many(&self, args: &[usize]) -> i32 {
        unsafe { self.call(args) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_syscall_ntclose() {
        let table = SyscallTable::enumerate().expect("should enumerate");
        let syscall = DirectSyscall::from_table(&table, "NtClose").expect("should find NtClose");

        // call with invalid handle - should fail but not crash
        // SAFETY: NtClose with invalid handle is safe (returns error status)
        let status = unsafe { syscall.call1(0xDEADBEEF) };

        // STATUS_INVALID_HANDLE = 0xC0000008
        assert_eq!(
            status, 0xC0000008_u32 as i32,
            "should return STATUS_INVALID_HANDLE"
        );
    }
}
