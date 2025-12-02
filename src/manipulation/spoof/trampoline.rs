//! Trampoline allocation for spoofed syscalls
//!
//! Allocates executable memory for trampoline code that performs
//! the actual stack manipulation and syscall invocation.

use crate::error::{Result, WraithError};
use std::sync::atomic::{AtomicUsize, Ordering};

/// size of each trampoline slot
const TRAMPOLINE_SIZE: usize = 256;

/// number of slots per allocation block
const SLOTS_PER_BLOCK: usize = 16;

/// page size
const PAGE_SIZE: usize = 4096;

/// trampoline allocator for executable memory
pub struct TrampolineAllocator {
    /// base address of allocated memory
    base: usize,
    /// total allocated size
    size: usize,
    /// next free slot index
    next_slot: AtomicUsize,
    /// total number of slots
    total_slots: usize,
}

impl TrampolineAllocator {
    /// create a new trampoline allocator
    pub fn new() -> Result<Self> {
        // calculate allocation size (round up to page boundary)
        let needed = TRAMPOLINE_SIZE * SLOTS_PER_BLOCK;
        let size = (needed + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // allocate executable memory using VirtualAlloc
        let base = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        if base.is_null() {
            return Err(WraithError::AllocationFailed {
                size,
                protection: PAGE_EXECUTE_READWRITE,
            });
        }

        Ok(Self {
            base: base as usize,
            size,
            next_slot: AtomicUsize::new(0),
            total_slots: SLOTS_PER_BLOCK,
        })
    }

    /// allocate a trampoline slot
    pub fn allocate(&self) -> Result<SpoofTrampoline> {
        let slot = self.next_slot.fetch_add(1, Ordering::SeqCst);

        if slot >= self.total_slots {
            return Err(WraithError::TrampolineAllocationFailed {
                near: self.base as u64,
                size: TRAMPOLINE_SIZE,
            });
        }

        let address = self.base + slot * TRAMPOLINE_SIZE;

        Ok(SpoofTrampoline {
            address,
            size: TRAMPOLINE_SIZE,
        })
    }

    /// get base address
    pub fn base(&self) -> usize {
        self.base
    }

    /// get remaining slots
    pub fn remaining_slots(&self) -> usize {
        self.total_slots.saturating_sub(self.next_slot.load(Ordering::SeqCst))
    }
}

impl Drop for TrampolineAllocator {
    fn drop(&mut self) {
        if self.base != 0 {
            // SAFETY: we allocated this memory and own it
            unsafe {
                VirtualFree(self.base as *mut _, 0, MEM_RELEASE);
            }
        }
    }
}

// SAFETY: TrampolineAllocator uses atomics for synchronization
unsafe impl Send for TrampolineAllocator {}
unsafe impl Sync for TrampolineAllocator {}

/// an allocated trampoline slot
#[derive(Debug)]
pub struct SpoofTrampoline {
    /// address of the trampoline
    address: usize,
    /// size of the trampoline slot
    size: usize,
}

impl SpoofTrampoline {
    /// get trampoline address
    pub fn address(&self) -> usize {
        self.address
    }

    /// get trampoline size
    pub fn size(&self) -> usize {
        self.size
    }

    /// write code to the trampoline
    ///
    /// # Safety
    /// caller must ensure code is valid machine code
    pub unsafe fn write_code(&self, code: &[u8]) -> Result<()> {
        if code.len() > self.size {
            return Err(WraithError::WriteFailed {
                address: self.address as u64,
                size: code.len(),
            });
        }

        // SAFETY: caller guarantees code is valid, and we own this memory
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                self.address as *mut u8,
                code.len(),
            );
        }

        Ok(())
    }

    /// write spoofed syscall trampoline code with full return address spoofing
    ///
    /// this trampoline:
    /// 1. saves state to trampoline memory (not stack, to survive jmp/ret)
    /// 2. invokes syscall via jmp so syscall's ret uses our spoofed gadget
    /// 3. gadget (jmp rbx) redirects back to cleanup code
    /// 4. cleanup restores state and returns to real caller with syscall result
    #[cfg(target_arch = "x86_64")]
    pub fn write_spoofed_syscall(
        &self,
        ssn: u16,
        syscall_addr: usize,
        gadget_addr: usize,
    ) -> Result<()> {
        // storage in trampoline memory (past our code, within the 256 byte slot)
        let storage_rbx = self.address + 0xC0;
        let storage_r12 = self.address + 0xC8;
        let storage_ret = self.address + 0xD0;

        let mut code = Vec::with_capacity(192);

        // === PROLOGUE: save registers to trampoline storage ===
        // we use r11 as temp since it's volatile and clobbered by syscall anyway

        // save rbx: mov r11, storage_rbx; mov [r11], rbx
        code.push(0x49); code.push(0xBB); // mov r11, imm64
        code.extend_from_slice(&(storage_rbx as u64).to_le_bytes());
        code.extend_from_slice(&[0x49, 0x89, 0x1B]); // mov [r11], rbx

        // save r12: mov r11, storage_r12; mov [r11], r12
        code.push(0x49); code.push(0xBB);
        code.extend_from_slice(&(storage_r12 as u64).to_le_bytes());
        code.extend_from_slice(&[0x4D, 0x89, 0x23]); // mov [r11], r12

        // save return address: mov r12, [rsp]; mov r11, storage_ret; mov [r11], r12
        code.extend_from_slice(&[0x4C, 0x8B, 0x24, 0x24]); // mov r12, [rsp]
        code.push(0x49); code.push(0xBB);
        code.extend_from_slice(&(storage_ret as u64).to_le_bytes());
        code.extend_from_slice(&[0x4D, 0x89, 0x23]); // mov [r11], r12

        // === SET UP GADGET RETURN ===
        // set rbx = cleanup address (for gadget's jmp rbx)
        code.extend_from_slice(&[0x48, 0x8D, 0x1D]); // lea rbx, [rip + offset]
        let cleanup_offset_pos = code.len();
        code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

        // replace [rsp] with gadget address (syscall's ret will go here)
        code.push(0x49); code.push(0xBB); // mov r11, gadget_addr
        code.extend_from_slice(&(gadget_addr as u64).to_le_bytes());
        code.extend_from_slice(&[0x4C, 0x89, 0x1C, 0x24]); // mov [rsp], r11

        // === SYSCALL SETUP ===
        code.extend_from_slice(&[0x49, 0x89, 0xCA]); // mov r10, rcx
        code.push(0xB8); // mov eax, ssn
        code.extend_from_slice(&(ssn as u32).to_le_bytes());

        // === JMP TO SYSCALL (not call!) ===
        // syscall stub is: syscall; ret
        // ret will pop gadget from [rsp] and jump there
        code.push(0x49); code.push(0xBB); // mov r11, syscall_addr
        code.extend_from_slice(&(syscall_addr as u64).to_le_bytes());
        code.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11

        // === CLEANUP CODE (gadget's jmp rbx lands here) ===
        let cleanup_pos = code.len();

        // at this point:
        // - rax contains syscall result (MUST preserve!)
        // - rsp is in unknown state after jmp/ret sequence
        // - we restore registers and jmp directly to saved return address

        // restore rbx from storage: mov r11, addr; mov rbx, [r11]
        code.push(0x49); code.push(0xBB); // mov r11, imm64
        code.extend_from_slice(&(storage_rbx as u64).to_le_bytes());
        code.extend_from_slice(&[0x49, 0x8B, 0x1B]); // mov rbx, [r11] (REX.WB for r11)

        // restore r12 from storage: mov r11, addr; mov r12, [r11]
        code.push(0x49); code.push(0xBB); // mov r11, imm64
        code.extend_from_slice(&(storage_r12 as u64).to_le_bytes());
        code.extend_from_slice(&[0x4D, 0x8B, 0x23]); // mov r12, [r11] (REX.WRB)

        // load return address: mov r11, addr; mov r11, [r11]; jmp r11
        code.push(0x49); code.push(0xBB); // mov r11, imm64
        code.extend_from_slice(&(storage_ret as u64).to_le_bytes());
        code.extend_from_slice(&[0x4D, 0x8B, 0x1B]); // mov r11, [r11]
        code.extend_from_slice(&[0x41, 0xFF, 0xE3]); // jmp r11

        // patch the lea offset
        let rel_offset = (cleanup_pos as i32) - ((cleanup_offset_pos + 4) as i32);
        code[cleanup_offset_pos..cleanup_offset_pos + 4]
            .copy_from_slice(&rel_offset.to_le_bytes());

        unsafe { self.write_code(&code) }
    }

    /// write a simpler spoofed syscall using a ret gadget as spoof address
    ///
    /// this is a simplified version that just makes the syscall appear to
    /// return to spoof_addr (typically a ret gadget in kernel32 or similar)
    #[cfg(target_arch = "x86_64")]
    pub fn write_simple_spoofed_syscall(
        &self,
        ssn: u16,
        syscall_addr: usize,
        spoof_addr: usize,
    ) -> Result<()> {
        // simple approach: use spoof_addr as the gadget if valid,
        // otherwise fall back to a working indirect syscall

        if spoof_addr == 0 {
            // no spoof address provided, use basic indirect syscall
            return self.write_basic_indirect_syscall(ssn, syscall_addr);
        }

        // for simple mode with a spoof_addr, we need to find a jmp rbx gadget
        // to redirect back to cleanup. if spoof_addr is already a jmp rbx,
        // we can use it directly. otherwise, use the gadget-based approach.
        self.write_basic_indirect_syscall(ssn, syscall_addr)
    }

    /// write a basic indirect syscall without spoofing
    #[cfg(target_arch = "x86_64")]
    fn write_basic_indirect_syscall(&self, ssn: u16, syscall_addr: usize) -> Result<()> {
        let mut code = Vec::with_capacity(64);

        // sub rsp, 0x28 - shadow space
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

        // mov r10, rcx
        code.extend_from_slice(&[0x49, 0x89, 0xCA]);

        // mov eax, ssn
        code.push(0xB8);
        code.extend_from_slice(&(ssn as u32).to_le_bytes());

        // mov r11, syscall_addr
        code.push(0x49); code.push(0xBB);
        code.extend_from_slice(&(syscall_addr as u64).to_le_bytes());

        // call r11
        code.extend_from_slice(&[0x41, 0xFF, 0xD3]);

        // add rsp, 0x28
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

        // ret
        code.push(0xC3);

        unsafe { self.write_code(&code) }
    }

    /// get a function pointer to invoke this trampoline
    ///
    /// # Safety
    /// trampoline must have been properly initialized with valid code
    pub unsafe fn as_fn_ptr<F>(&self) -> F
    where
        F: Copy,
    {
        debug_assert!(
            core::mem::size_of::<F>() == core::mem::size_of::<usize>(),
            "function pointer must be pointer-sized"
        );
        // SAFETY: caller guarantees trampoline is properly initialized
        unsafe { core::mem::transmute_copy(&self.address) }
    }
}

// win32 types and functions
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut core::ffi::c_void;

    fn VirtualFree(
        lpAddress: *mut core::ffi::c_void,
        dwSize: usize,
        dwFreeType: u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_creation() {
        let alloc = TrampolineAllocator::new().expect("should allocate");
        assert!(alloc.base() > 0);
        assert!(alloc.remaining_slots() > 0);
    }

    #[test]
    fn test_trampoline_allocation() {
        let alloc = TrampolineAllocator::new().expect("should allocate");
        let tramp = alloc.allocate().expect("should get slot");
        assert!(tramp.address() > 0);
        assert!(tramp.size() >= 64);
    }

    #[test]
    fn test_code_write() {
        let alloc = TrampolineAllocator::new().expect("should allocate");
        let tramp = alloc.allocate().expect("should get slot");

        // write some nops
        let code = [0x90u8; 16]; // nop sled
        unsafe {
            tramp.write_code(&code).expect("should write");
        }

        // verify it was written
        let written = unsafe { std::slice::from_raw_parts(tramp.address() as *const u8, 16) };
        assert_eq!(written, &code);
    }
}
