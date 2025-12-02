//! Mid-function hooks
//!
//! Hooks at arbitrary locations within a function, not just the prologue.
//! Requires saving and restoring CPU context around the detour call.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::util::memory::ProtectionGuard;
use crate::manipulation::inline_hook::arch::Architecture;
use crate::manipulation::inline_hook::guard::HookGuard;
use crate::manipulation::inline_hook::trampoline::ExecutableMemory;
use super::Hook;
use core::marker::PhantomData;

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// CPU context passed to mid-function hook handlers (x64)
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookContext {
    pub rflags: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
}

/// CPU context passed to mid-function hook handlers (x86)
#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HookContext {
    pub eflags: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
}

/// mid-function hook type signature
#[cfg(target_arch = "x86_64")]
pub type MidHookFn = extern "C" fn(ctx: *mut HookContext);

#[cfg(target_arch = "x86")]
pub type MidHookFn = extern "cdecl" fn(ctx: *mut HookContext);

/// mid-function hook
///
/// hooks at an arbitrary location within a function.
/// saves all registers, calls the detour with a context pointer,
/// then restores registers and continues execution.
pub struct MidFunctionHook<A: Architecture> {
    /// address to hook (not necessarily function start)
    address: usize,
    /// detour function receiving context pointer
    detour: usize,
    _arch: PhantomData<A>,
}

impl<A: Architecture> MidFunctionHook<A> {
    /// create a new mid-function hook
    ///
    /// # Arguments
    /// * `address` - the exact address to place the hook
    /// * `detour` - function pointer of type `MidHookFn`
    pub fn new(address: usize, detour: MidHookFn) -> Self {
        Self {
            address,
            detour: detour as usize,
            _arch: PhantomData,
        }
    }

    /// create from raw address
    pub fn from_raw(address: usize, detour: usize) -> Self {
        Self {
            address,
            detour,
            _arch: PhantomData,
        }
    }

    /// install the mid-function hook
    #[cfg(target_arch = "x86_64")]
    pub fn install(self) -> Result<HookGuard<A>> {
        let min_hook_size = A::MIN_HOOK_SIZE;

        // read original bytes at hook location
        let original_bytes = unsafe {
            let target_bytes = core::slice::from_raw_parts(self.address as *const u8, 64);
            let boundary = A::find_instruction_boundary(target_bytes, min_hook_size)
                .ok_or_else(|| WraithError::HookDetectionFailed {
                    function: format!("{:#x}", self.address),
                    reason: "failed to find instruction boundary".into(),
                })?;
            core::slice::from_raw_parts(self.address as *const u8, boundary).to_vec()
        };

        let prologue_size = original_bytes.len();

        // allocate memory for the wrapper stub
        let mut stub_memory = ExecutableMemory::allocate_near(self.address, 256)?;
        let stub_base = stub_memory.base();

        // build the context-saving wrapper stub
        let wrapper_code = build_x64_wrapper(
            stub_base,
            self.detour,
            self.address,
            &original_bytes,
        )?;

        stub_memory.write(&wrapper_code)?;
        stub_memory.flush_icache()?;

        // write jump to wrapper at hook location
        let hook_stub = A::encode_jmp_rel(self.address, stub_base)
            .or_else(|| Some(A::encode_jmp_abs(stub_base)))
            .unwrap();

        let mut padded_stub = hook_stub;
        if padded_stub.len() < prologue_size {
            let padding = A::encode_nop_sled(prologue_size - padded_stub.len());
            padded_stub.extend_from_slice(&padding);
        }

        // write the hook
        {
            let _guard = ProtectionGuard::new(
                self.address,
                prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            unsafe {
                core::ptr::copy_nonoverlapping(
                    padded_stub.as_ptr(),
                    self.address as *mut u8,
                    prologue_size,
                );
            }
        }

        flush_icache(self.address, prologue_size)?;

        Ok(HookGuard::new(
            self.address,
            self.detour,
            original_bytes,
            Some(stub_memory),
        ))
    }

    #[cfg(target_arch = "x86")]
    pub fn install(self) -> Result<HookGuard<A>> {
        let min_hook_size = A::MIN_HOOK_SIZE;

        let original_bytes = unsafe {
            let target_bytes = core::slice::from_raw_parts(self.address as *const u8, 32);
            let boundary = A::find_instruction_boundary(target_bytes, min_hook_size)
                .ok_or_else(|| WraithError::HookDetectionFailed {
                    function: format!("{:#x}", self.address),
                    reason: "failed to find instruction boundary".into(),
                })?;
            core::slice::from_raw_parts(self.address as *const u8, boundary).to_vec()
        };

        let prologue_size = original_bytes.len();

        let mut stub_memory = ExecutableMemory::allocate_near(self.address, 128)?;
        let stub_base = stub_memory.base();

        let wrapper_code = build_x86_wrapper(
            stub_base,
            self.detour,
            self.address,
            &original_bytes,
        )?;

        stub_memory.write(&wrapper_code)?;
        stub_memory.flush_icache()?;

        let hook_stub = A::encode_jmp_rel(self.address, stub_base)
            .or_else(|| Some(A::encode_jmp_abs(stub_base)))
            .unwrap();

        let mut padded_stub = hook_stub;
        if padded_stub.len() < prologue_size {
            let padding = A::encode_nop_sled(prologue_size - padded_stub.len());
            padded_stub.extend_from_slice(&padding);
        }

        {
            let _guard = ProtectionGuard::new(
                self.address,
                prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            unsafe {
                core::ptr::copy_nonoverlapping(
                    padded_stub.as_ptr(),
                    self.address as *mut u8,
                    prologue_size,
                );
            }
        }

        flush_icache(self.address, prologue_size)?;

        Ok(HookGuard::new(
            self.address,
            self.detour,
            original_bytes,
            Some(stub_memory),
        ))
    }
}

impl<A: Architecture> Hook for MidFunctionHook<A> {
    type Guard = HookGuard<A>;

    fn install(self) -> Result<Self::Guard> {
        MidFunctionHook::install(self)
    }

    fn target(&self) -> usize {
        self.address
    }

    fn detour(&self) -> usize {
        self.detour
    }
}

/// build x64 context-saving wrapper
#[cfg(target_arch = "x86_64")]
fn build_x64_wrapper(
    stub_base: usize,
    detour: usize,
    original_addr: usize,
    original_bytes: &[u8],
) -> Result<Vec<u8>> {
    use crate::manipulation::inline_hook::arch::X64;

    let mut code = Vec::with_capacity(256);

    // save all registers (context structure)
    // pushfq
    code.push(0x9C);

    // push r15-r8, rdi, rsi, rbp, rsp placeholder, rbx, rdx, rcx, rax
    code.extend_from_slice(&[0x41, 0x57]); // push r15
    code.extend_from_slice(&[0x41, 0x56]); // push r14
    code.extend_from_slice(&[0x41, 0x55]); // push r13
    code.extend_from_slice(&[0x41, 0x54]); // push r12
    code.extend_from_slice(&[0x41, 0x53]); // push r11
    code.extend_from_slice(&[0x41, 0x52]); // push r10
    code.extend_from_slice(&[0x41, 0x51]); // push r9
    code.extend_from_slice(&[0x41, 0x50]); // push r8
    code.push(0x57); // push rdi
    code.push(0x56); // push rsi
    code.push(0x55); // push rbp
    code.push(0x54); // push rsp (placeholder, will be fixed)
    code.push(0x53); // push rbx
    code.push(0x52); // push rdx
    code.push(0x51); // push rcx
    code.push(0x50); // push rax

    // fix rsp in context (add offset for pushes)
    // mov [rsp + 0x38], rsp; add qword ptr [rsp+0x38], 0x90
    code.extend_from_slice(&[0x48, 0x89, 0x64, 0x24, 0x38]); // mov [rsp+0x38], rsp
    code.extend_from_slice(&[0x48, 0x83, 0x44, 0x24, 0x38, 0x90]); // add [rsp+0x38], 0x90

    // mov rcx, rsp (first arg = context pointer)
    code.extend_from_slice(&[0x48, 0x89, 0xE1]);

    // sub rsp, 0x28 (shadow space + alignment)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // call detour
    // we'll use mov rax, imm64; call rax for simplicity
    code.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
    code.extend_from_slice(&detour.to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call rax

    // add rsp, 0x28
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // restore registers
    code.push(0x58); // pop rax
    code.push(0x59); // pop rcx
    code.push(0x5A); // pop rdx
    code.push(0x5B); // pop rbx
    code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]); // add rsp, 8 (skip rsp)
    code.push(0x5D); // pop rbp
    code.push(0x5E); // pop rsi
    code.push(0x5F); // pop rdi
    code.extend_from_slice(&[0x41, 0x58]); // pop r8
    code.extend_from_slice(&[0x41, 0x59]); // pop r9
    code.extend_from_slice(&[0x41, 0x5A]); // pop r10
    code.extend_from_slice(&[0x41, 0x5B]); // pop r11
    code.extend_from_slice(&[0x41, 0x5C]); // pop r12
    code.extend_from_slice(&[0x41, 0x5D]); // pop r13
    code.extend_from_slice(&[0x41, 0x5E]); // pop r14
    code.extend_from_slice(&[0x41, 0x5F]); // pop r15
    code.push(0x9D); // popfq

    // relocate and copy original instructions
    // we need to track the current position in the stub for relocation calculations
    let mut src_offset = 0;

    while src_offset < original_bytes.len() {
        let remaining = &original_bytes[src_offset..];

        // find instruction length
        let insn_len = X64::find_instruction_boundary(remaining, 1)
            .ok_or_else(|| WraithError::HookDetectionFailed {
                function: format!("{:#x}", original_addr + src_offset),
                reason: "failed to decode instruction during relocation".into(),
            })?;

        let instruction = &original_bytes[src_offset..src_offset + insn_len];
        let old_addr = original_addr + src_offset;
        let new_addr = stub_base + code.len();

        // check if instruction needs relocation
        if X64::needs_relocation(instruction) {
            match X64::relocate_instruction(instruction, old_addr, new_addr) {
                Some(relocated) => {
                    code.extend_from_slice(&relocated);
                }
                None => {
                    // relocation failed - instruction target is too far
                    // fall back to indirect: push target; ret pattern
                    return Err(WraithError::RelocationFailed {
                        rva: src_offset as u32,
                        reason: format!(
                            "instruction at {:#x} cannot be relocated to {:#x}",
                            old_addr, new_addr
                        ),
                    });
                }
            }
        } else {
            // no relocation needed, copy as-is
            code.extend_from_slice(instruction);
        }

        src_offset += insn_len;
    }

    // jump to continuation (original_addr + original_bytes.len())
    let continuation = original_addr + original_bytes.len();
    let jmp_location = stub_base + code.len();

    if let Some(jmp) = X64::encode_jmp_rel(jmp_location, continuation) {
        code.extend_from_slice(&jmp);
    } else {
        code.extend_from_slice(&X64::encode_jmp_abs(continuation));
    }

    Ok(code)
}

/// build x86 context-saving wrapper
#[cfg(target_arch = "x86")]
fn build_x86_wrapper(
    stub_base: usize,
    detour: usize,
    original_addr: usize,
    original_bytes: &[u8],
) -> Result<Vec<u8>> {
    use crate::manipulation::inline_hook::arch::X86;

    let mut code = Vec::with_capacity(128);

    // pushfd
    code.push(0x9C);
    // pushad (edi, esi, ebp, esp, ebx, edx, ecx, eax)
    code.push(0x60);

    // push esp (context pointer as argument)
    code.push(0x54);

    // call detour
    code.push(0xB8); // mov eax, imm32
    code.extend_from_slice(&(detour as u32).to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xD0]); // call eax

    // add esp, 4 (pop argument)
    code.extend_from_slice(&[0x83, 0xC4, 0x04]);

    // popad
    code.push(0x61);
    // popfd
    code.push(0x9D);

    // relocate and copy original instructions
    let mut src_offset = 0;

    while src_offset < original_bytes.len() {
        let remaining = &original_bytes[src_offset..];

        // find instruction length
        let insn_len = X86::find_instruction_boundary(remaining, 1)
            .ok_or_else(|| WraithError::HookDetectionFailed {
                function: format!("{:#x}", original_addr + src_offset),
                reason: "failed to decode instruction during relocation".into(),
            })?;

        let instruction = &original_bytes[src_offset..src_offset + insn_len];
        let old_addr = original_addr + src_offset;
        let new_addr = stub_base + code.len();

        // check if instruction needs relocation
        if X86::needs_relocation(instruction) {
            match X86::relocate_instruction(instruction, old_addr, new_addr) {
                Some(relocated) => {
                    code.extend_from_slice(&relocated);
                }
                None => {
                    return Err(WraithError::RelocationFailed {
                        rva: src_offset as u32,
                        reason: format!(
                            "instruction at {:#x} cannot be relocated to {:#x}",
                            old_addr, new_addr
                        ),
                    });
                }
            }
        } else {
            // no relocation needed, copy as-is
            code.extend_from_slice(instruction);
        }

        src_offset += insn_len;
    }

    // jump to continuation
    let continuation = original_addr + original_bytes.len();
    let jmp_location = stub_base + code.len();

    if let Some(jmp) = X86::encode_jmp_rel(jmp_location, continuation) {
        code.extend_from_slice(&jmp);
    } else {
        code.extend_from_slice(&X86::encode_jmp_abs(continuation as usize));
    }

    Ok(code)
}

fn flush_icache(address: usize, size: usize) -> Result<()> {
    let result = unsafe {
        FlushInstructionCache(
            GetCurrentProcess(),
            address as *const _,
            size,
        )
    };

    if result == 0 {
        Err(WraithError::from_last_error("FlushInstructionCache"))
    } else {
        Ok(())
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn FlushInstructionCache(
        hProcess: *mut core::ffi::c_void,
        lpBaseAddress: *const core::ffi::c_void,
        dwSize: usize,
    ) -> i32;

    fn GetCurrentProcess() -> *mut core::ffi::c_void;
}
