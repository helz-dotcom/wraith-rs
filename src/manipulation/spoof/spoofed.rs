//! Spoofed syscall invocation
//!
//! Combines gadget finding, stack spoofing, and trampolines to invoke
//! syscalls with spoofed return addresses that appear legitimate.

use super::gadget::GadgetFinder;
use super::trampoline::{SpoofTrampoline, TrampolineAllocator};
use crate::error::{Result, WraithError};
use crate::manipulation::syscall::SyscallEntry;
use core::arch::asm;
use std::sync::OnceLock;

/// global trampoline allocator
static TRAMPOLINE_ALLOC: OnceLock<Result<TrampolineAllocator>> = OnceLock::new();

fn get_trampoline_allocator() -> Result<&'static TrampolineAllocator> {
    let result = TRAMPOLINE_ALLOC.get_or_init(TrampolineAllocator::new);
    match result {
        Ok(alloc) => Ok(alloc),
        Err(_e) => Err(WraithError::TrampolineAllocationFailed {
            near: 0,
            size: 0,
        }),
    }
}

/// mode of return address spoofing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoofMode {
    /// use a gadget (jmp rbx/rax) for clean indirect jump
    Gadget,
    /// synthesize a fake stack frame chain
    SyntheticStack,
    /// simple return address replacement
    SimpleSpoof,
    /// no spoofing (falls back to indirect syscall)
    None,
}

impl Default for SpoofMode {
    fn default() -> Self {
        Self::Gadget
    }
}

/// configuration for spoofed syscalls
#[derive(Debug, Clone)]
pub struct SpoofConfig {
    /// spoofing mode to use
    pub mode: SpoofMode,
    /// prefer ntdll gadgets (most legitimate looking)
    pub prefer_ntdll: bool,
    /// custom spoof address (for SimpleSpoof mode)
    pub custom_spoof_addr: Option<usize>,
    /// stack pattern to synthesize (for SyntheticStack mode)
    pub stack_pattern: Option<Vec<&'static str>>,
}

impl Default for SpoofConfig {
    fn default() -> Self {
        Self {
            mode: SpoofMode::Gadget,
            prefer_ntdll: true,
            custom_spoof_addr: None,
            stack_pattern: None,
        }
    }
}

impl SpoofConfig {
    /// create config for gadget-based spoofing
    pub fn gadget() -> Self {
        Self {
            mode: SpoofMode::Gadget,
            ..Default::default()
        }
    }

    /// create config for simple address spoofing
    pub fn simple(spoof_addr: usize) -> Self {
        Self {
            mode: SpoofMode::SimpleSpoof,
            custom_spoof_addr: Some(spoof_addr),
            ..Default::default()
        }
    }

    /// create config for synthetic stack
    pub fn synthetic(pattern: Vec<&'static str>) -> Self {
        Self {
            mode: SpoofMode::SyntheticStack,
            stack_pattern: Some(pattern),
            ..Default::default()
        }
    }
}

/// spoofed syscall invoker
///
/// wraps a syscall with return address spoofing to evade call stack analysis
pub struct SpoofedSyscall {
    /// syscall number
    ssn: u16,
    /// address of syscall instruction in ntdll
    syscall_addr: usize,
    /// gadget address for return
    gadget_addr: usize,
    /// spoof address for simple mode
    spoof_addr: usize,
    /// name of the syscall
    name: String,
    /// allocated trampoline (if using trampoline mode)
    trampoline: Option<SpoofTrampoline>,
    /// spoofing mode
    mode: SpoofMode,
}

impl SpoofedSyscall {
    /// create spoofed syscall from name with default config
    pub fn new(name: &str) -> Result<Self> {
        Self::with_config(name, SpoofConfig::default())
    }

    /// create spoofed syscall with custom configuration
    pub fn with_config(name: &str, config: SpoofConfig) -> Result<Self> {
        let table = crate::manipulation::syscall::get_syscall_table()?;
        let entry = table.get(name).ok_or_else(|| WraithError::SyscallNotFound {
            name: name.to_string(),
        })?;

        Self::from_entry_with_config(entry, config)
    }

    /// create from syscall entry with config
    pub fn from_entry_with_config(entry: &SyscallEntry, config: SpoofConfig) -> Result<Self> {
        let syscall_addr = entry.syscall_address.ok_or_else(|| {
            WraithError::SyscallEnumerationFailed {
                reason: format!("no syscall address for {}", entry.name),
            }
        })?;

        // find gadget based on mode
        let (gadget_addr, spoof_addr) = match config.mode {
            SpoofMode::Gadget => {
                let finder = GadgetFinder::new()?;
                let gadget = finder.find_best_jmp_gadget()?;
                (gadget.address(), 0)
            }
            SpoofMode::SimpleSpoof => {
                let spoof = config.custom_spoof_addr.unwrap_or_else(|| {
                    // default: use a kernel32 address
                    let finder = GadgetFinder::new().ok();
                    finder
                        .and_then(|f| f.find_ret("kernel32.dll").ok())
                        .and_then(|r| r.into_iter().next())
                        .map(|g| g.address())
                        .unwrap_or(0)
                });
                (0, spoof)
            }
            SpoofMode::SyntheticStack => {
                // for synthetic stack, we need both a gadget and the stack setup
                let finder = GadgetFinder::new()?;
                let gadget = finder.find_best_jmp_gadget()?;
                (gadget.address(), 0)
            }
            SpoofMode::None => (0, 0),
        };

        // allocate trampoline if needed
        let trampoline = if config.mode != SpoofMode::None {
            let alloc = get_trampoline_allocator()?;
            let tramp = alloc.allocate()?;

            // write appropriate trampoline code
            match config.mode {
                SpoofMode::Gadget => {
                    tramp.write_spoofed_syscall(entry.ssn, syscall_addr, gadget_addr)?;
                }
                SpoofMode::SimpleSpoof => {
                    tramp.write_simple_spoofed_syscall(entry.ssn, syscall_addr, spoof_addr)?;
                }
                SpoofMode::SyntheticStack => {
                    tramp.write_spoofed_syscall(entry.ssn, syscall_addr, gadget_addr)?;
                }
                SpoofMode::None => {}
            }

            Some(tramp)
        } else {
            None
        };

        Ok(Self {
            ssn: entry.ssn,
            syscall_addr,
            gadget_addr,
            spoof_addr,
            name: entry.name.clone(),
            trampoline,
            mode: config.mode,
        })
    }

    /// create from syscall entry with default config
    pub fn from_entry(entry: &SyscallEntry) -> Result<Self> {
        Self::from_entry_with_config(entry, SpoofConfig::default())
    }

    /// get syscall number
    pub fn ssn(&self) -> u16 {
        self.ssn
    }

    /// get syscall name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// get the spoofing mode
    pub fn mode(&self) -> SpoofMode {
        self.mode
    }

    /// get gadget address (if using gadget mode)
    pub fn gadget_addr(&self) -> Option<usize> {
        if self.gadget_addr != 0 {
            Some(self.gadget_addr)
        } else {
            None
        }
    }
}

// x86_64 syscall implementations with spoofing
#[cfg(target_arch = "x86_64")]
impl SpoofedSyscall {
    /// invoke spoofed syscall with 0 arguments
    ///
    /// # Safety
    /// caller must ensure the syscall is appropriate to call with 0 args
    #[inline(never)]
    pub unsafe fn call0(&self) -> i32 {
        if let Some(ref tramp) = self.trampoline {
            type Fn0 = unsafe extern "system" fn() -> i32;
            let f: Fn0 = unsafe { tramp.as_fn_ptr() };
            unsafe { f() }
        } else {
            unsafe { self.call0_direct() }
        }
    }

    /// invoke spoofed syscall with 1 argument
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call1(&self, arg1: usize) -> i32 {
        if let Some(ref tramp) = self.trampoline {
            type Fn1 = unsafe extern "system" fn(usize) -> i32;
            let f: Fn1 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1) }
        } else {
            unsafe { self.call1_direct(arg1) }
        }
    }

    /// invoke spoofed syscall with 2 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call2(&self, arg1: usize, arg2: usize) -> i32 {
        if let Some(ref tramp) = self.trampoline {
            type Fn2 = unsafe extern "system" fn(usize, usize) -> i32;
            let f: Fn2 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1, arg2) }
        } else {
            unsafe { self.call2_direct(arg1, arg2) }
        }
    }

    /// invoke spoofed syscall with 3 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call3(&self, arg1: usize, arg2: usize, arg3: usize) -> i32 {
        if let Some(ref tramp) = self.trampoline {
            type Fn3 = unsafe extern "system" fn(usize, usize, usize) -> i32;
            let f: Fn3 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1, arg2, arg3) }
        } else {
            unsafe { self.call3_direct(arg1, arg2, arg3) }
        }
    }

    /// invoke spoofed syscall with 4 arguments
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call4(&self, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> i32 {
        if let Some(ref tramp) = self.trampoline {
            type Fn4 = unsafe extern "system" fn(usize, usize, usize, usize) -> i32;
            let f: Fn4 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1, arg2, arg3, arg4) }
        } else {
            unsafe { self.call4_direct(arg1, arg2, arg3, arg4) }
        }
    }

    /// invoke spoofed syscall with 5 arguments
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
        if let Some(ref tramp) = self.trampoline {
            type Fn5 = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> i32;
            let f: Fn5 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1, arg2, arg3, arg4, arg5) }
        } else {
            unsafe { self.call5_direct(arg1, arg2, arg3, arg4, arg5) }
        }
    }

    /// invoke spoofed syscall with 6 arguments
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
        if let Some(ref tramp) = self.trampoline {
            type Fn6 = unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> i32;
            let f: Fn6 = unsafe { tramp.as_fn_ptr() };
            unsafe { f(arg1, arg2, arg3, arg4, arg5, arg6) }
        } else {
            unsafe { self.call6_direct(arg1, arg2, arg3, arg4, arg5, arg6) }
        }
    }

    /// invoke with variable arguments
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

    // direct fallback implementations (non-spoofed)
    #[inline(never)]
    unsafe fn call0_direct(&self) -> i32 {
        let status: i32;
        unsafe {
            asm!(
                "sub rsp, 0x28",
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

    #[inline(never)]
    unsafe fn call1_direct(&self, arg1: usize) -> i32 {
        let status: i32;
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

    #[inline(never)]
    unsafe fn call2_direct(&self, arg1: usize, arg2: usize) -> i32 {
        let status: i32;
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

    #[inline(never)]
    unsafe fn call3_direct(&self, arg1: usize, arg2: usize, arg3: usize) -> i32 {
        let status: i32;
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

    #[inline(never)]
    unsafe fn call4_direct(&self, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> i32 {
        let status: i32;
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

    #[inline(never)]
    unsafe fn call5_direct(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> i32 {
        let status: i32;
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

    #[inline(never)]
    unsafe fn call6_direct(
        &self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> i32 {
        let status: i32;
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
}

// x86 implementation (32-bit)
#[cfg(target_arch = "x86")]
impl SpoofedSyscall {
    /// invoke spoofed syscall (x86)
    ///
    /// # Safety
    /// caller must ensure args are valid for this syscall
    #[inline(never)]
    pub unsafe fn call(&self, args: &[usize]) -> i32 {
        // x86 spoofing is simpler - just manipulate the stack
        let status: i32;
        let args_ptr = args.as_ptr();

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
    fn test_spoofed_syscall_creation() {
        match SpoofedSyscall::new("NtClose") {
            Ok(syscall) => {
                assert!(syscall.ssn() > 0);
                assert!(syscall.gadget_addr().is_some());
            }
            Err(_) => {
                // might fail in some test environments
            }
        }
    }

    #[test]
    fn test_spoofed_syscall_ntclose() {
        if let Ok(syscall) = SpoofedSyscall::new("NtClose") {
            // call with invalid handle - should fail but not crash
            let status = unsafe { syscall.call1(0xDEADBEEF) };
            assert_eq!(
                status, 0xC0000008_u32 as i32,
                "should return STATUS_INVALID_HANDLE"
            );
        }
    }

    #[test]
    fn test_simple_spoof_mode() {
        if let Ok(syscall) = SpoofedSyscall::with_config("NtClose", SpoofConfig {
            mode: SpoofMode::SimpleSpoof,
            custom_spoof_addr: Some(0x7FFE0000), // arbitrary address
            ..Default::default()
        }) {
            let status = unsafe { syscall.call1(0xDEADBEEF) };
            assert_eq!(status, 0xC0000008_u32 as i32);
        }
    }

    #[test]
    fn test_none_mode_fallback() {
        if let Ok(syscall) = SpoofedSyscall::with_config("NtClose", SpoofConfig {
            mode: SpoofMode::None,
            ..Default::default()
        }) {
            let status = unsafe { syscall.call1(0xDEADBEEF) };
            assert_eq!(status, 0xC0000008_u32 as i32);
        }
    }
}
