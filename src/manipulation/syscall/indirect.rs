//! Indirect syscall invocation (jump to ntdll's syscall instruction)
//!
//! Instead of using an inline syscall instruction, indirect syscalls
//! jump to the syscall instruction inside ntdll. This leaves a cleaner
//! call stack that appears to originate from ntdll, evading some
//! call stack analysis techniques.

use super::table::{SyscallEntry, SyscallTable};
use crate::error::{Result, WraithError};
use core::arch::asm;

#[cfg(target_arch = "x86_64")]
const SYSCALL_BYTES: [u8; 2] = [0x0F, 0x05]; // syscall

#[cfg(target_arch = "x86")]
const SYSCALL_BYTES: [u8; 2] = [0x0F, 0x34]; // sysenter (or could be int 0x2e)

/// indirect syscall invoker
///
/// instead of using inline syscall instruction, jumps to the
/// syscall instruction inside ntdll for cleaner call stack
pub struct IndirectSyscall {
    ssn: u16,
    syscall_addr: usize,
}

impl IndirectSyscall {
    /// create from SSN and syscall instruction address
    ///
    /// # Safety
    /// caller must ensure syscall_addr points to a valid syscall instruction
    pub const unsafe fn new_unchecked(ssn: u16, syscall_addr: usize) -> Self {
        Self { ssn, syscall_addr }
    }

    /// create from SSN and syscall instruction address with validation
    pub fn new(ssn: u16, syscall_addr: usize) -> Result<Self> {
        // validate the address actually contains a syscall instruction
        if !Self::validate_syscall_address(syscall_addr) {
            return Err(WraithError::SyscallEnumerationFailed {
                reason: format!(
                    "address {:#x} does not contain valid syscall instruction",
                    syscall_addr
                ),
            });
        }

        Ok(Self { ssn, syscall_addr })
    }

    /// validate that an address contains a syscall instruction
    fn validate_syscall_address(addr: usize) -> bool {
        if addr == 0 {
            return false;
        }

        // SAFETY: we're reading 2 bytes at the address to verify syscall instruction
        // this could fault if addr is invalid, but we're checking for null above
        // and this is called with addresses from ntdll which should be valid
        let bytes: [u8; 2] = unsafe { *(addr as *const [u8; 2]) };
        bytes == SYSCALL_BYTES
    }

    /// create from syscall entry
    pub fn from_entry(entry: &SyscallEntry) -> Result<Self> {
        let syscall_addr = entry.syscall_address.ok_or_else(|| {
            WraithError::SyscallEnumerationFailed {
                reason: format!("no syscall address for {}", entry.name),
            }
        })?;

        Self::new(entry.ssn, syscall_addr)
    }

    /// create from syscall table lookup
    pub fn from_table(table: &SyscallTable, name: &str) -> Result<Self> {
        let entry = table.get(name).ok_or_else(|| WraithError::SyscallNotFound {
            name: name.to_string(),
        })?;
        Self::from_entry(entry)
    }

    /// get SSN
    pub const fn ssn(&self) -> u16 {
        self.ssn
    }

    /// get syscall instruction address
    pub const fn syscall_address(&self) -> usize {
        self.syscall_addr
    }
}

#[cfg(target_arch = "x86_64")]
impl IndirectSyscall {
    /// invoke indirect syscall with 0 arguments
    ///
    /// # Safety
    /// caller must ensure the syscall is appropriate to call with 0 args
    #[inline(never)]
    pub unsafe fn call0(&self) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall validity, syscall_addr points to valid syscall instruction
        // we use `call` instead of `jmp` so that the `ret` after the syscall instruction has a valid return address
        unsafe {
            asm!(
                "sub rsp, 0x28",          // shadow space (32 bytes) + align
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
                out("eax") status,
                out("rcx") _,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke indirect syscall with 1 argument
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call1(&self, arg1: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "sub rsp, 0x28",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
                in("rcx") arg1,
                out("eax") status,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke indirect syscall with 2 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call2(&self, arg1: usize, arg2: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "sub rsp, 0x28",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
                in("rcx") arg1,
                in("rdx") arg2,
                out("eax") status,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke indirect syscall with 3 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call3(&self, arg1: usize, arg2: usize, arg3: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "sub rsp, 0x28",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
                in("rcx") arg1,
                in("rdx") arg2,
                in("r8") arg3,
                out("eax") status,
                out("r10") _,
                out("r11") _,
            );
        }
        status
    }

    /// invoke indirect syscall with 4 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call4(&self, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> i32 {
        let status: i32;
        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "sub rsp, 0x28",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
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

    /// invoke indirect syscall with 5 arguments
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
        // note: we put arg5 at [rsp+0x20] so that after `call` pushes return address,
        // the kernel sees it at [rsp+0x28] as expected by Windows x64 calling convention
        unsafe {
            asm!(
                "sub rsp, 0x28",
                "mov [rsp+0x20], {arg5}",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x28",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
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

    /// invoke indirect syscall with 6 arguments
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
        // note: we put args at [rsp+0x20] and [rsp+0x28] so that after `call` pushes return address,
        // the kernel sees them at [rsp+0x28] and [rsp+0x30] as expected
        unsafe {
            asm!(
                "sub rsp, 0x30",
                "mov [rsp+0x20], {arg5}",
                "mov [rsp+0x28], {arg6}",
                "mov r10, rcx",
                "mov eax, {ssn:e}",
                "call {addr}",
                "add rsp, 0x30",
                ssn = in(reg) self.ssn as u32,
                addr = in(reg) self.syscall_addr,
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

    /// invoke indirect syscall with variable arguments
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
            _ => unsafe { self.call6(args[0], args[1], args[2], args[3], args[4], args[5]) },
        }
    }
}

#[cfg(target_arch = "x86")]
impl IndirectSyscall {
    /// invoke indirect syscall (x86)
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call(&self, args: &[usize]) -> i32 {
        let status: i32;
        let args_ptr = args.as_ptr();

        // SAFETY: caller guarantees syscall and argument validity
        unsafe {
            asm!(
                "mov eax, {ssn:e}",
                "mov edx, {args}",
                "call {addr}",
                ssn = in(reg) self.ssn as u32,
                args = in(reg) args_ptr,
                addr = in(reg) self.syscall_addr,
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
    fn test_indirect_syscall_ntclose() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        if let Ok(syscall) = IndirectSyscall::from_table(&table, "NtClose") {
            // SAFETY: NtClose with invalid handle is safe (returns error status)
            let status = unsafe { syscall.call1(0xDEADBEEF) };
            assert_eq!(status, 0xC0000008_u32 as i32);
        }
    }

    #[test]
    fn test_syscall_address_in_ntdll() {
        let table = SyscallTable::enumerate().expect("should enumerate");

        if let Some(entry) = table.get("NtClose") {
            if let Some(addr) = entry.syscall_address {
                // should be within ntdll's address range
                assert!(addr > entry.address, "syscall should be after function start");
                assert!(
                    addr < entry.address + 32,
                    "syscall should be within stub"
                );
            }
        }
    }
}
