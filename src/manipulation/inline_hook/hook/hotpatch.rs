//! Hot-patch style hooks
//!
//! Windows functions compiled with /hotpatch have a 2-byte NOP (mov edi, edi)
//! at the entry point and 5 bytes of padding before. This allows atomic
//! hook installation with minimal disruption.

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

/// hot-patch style hook
///
/// uses the mov edi, edi / padding space present in Windows hot-patchable
/// functions. only modifies 2 bytes at the function entry point atomically.
pub struct HotPatchHook<A: Architecture> {
    target: usize,
    detour: usize,
    _arch: PhantomData<A>,
}

impl<A: Architecture> HotPatchHook<A> {
    /// create a new hot-patch hook
    pub fn new(target: usize, detour: usize) -> Self {
        Self {
            target,
            detour,
            _arch: PhantomData,
        }
    }

    /// check if the target function is hot-patchable
    ///
    /// looks for:
    /// - 5 bytes of padding (CC or 90) at target-5
    /// - 2-byte NOP (8B FF = mov edi,edi or 66 90) at target
    pub fn is_patchable(target: usize) -> bool {
        // read the bytes around the target
        let pre_bytes = unsafe {
            core::slice::from_raw_parts((target - 5) as *const u8, 5)
        };
        let entry_bytes = unsafe {
            core::slice::from_raw_parts(target as *const u8, 2)
        };

        // check for padding before function (CC or 90)
        let has_padding = pre_bytes.iter().all(|&b| b == 0xCC || b == 0x90);

        // check for 2-byte NOP at entry
        let has_nop_entry = entry_bytes == [0x8B, 0xFF]  // mov edi, edi
            || entry_bytes == [0x66, 0x90]               // 2-byte nop
            || entry_bytes == [0x89, 0xFF];              // mov edi, edi (alternate encoding)

        has_padding && has_nop_entry
    }

    /// install the hot-patch hook
    pub fn install(self) -> Result<HookGuard<A>> {
        // verify target is hot-patchable
        if !Self::is_patchable(self.target) {
            return Err(WraithError::HookDetectionFailed {
                function: format!("{:#x}", self.target),
                reason: "function is not hot-patchable".into(),
            });
        }

        // read original bytes (7 bytes: 5 padding + 2 entry)
        let original_bytes = unsafe {
            let ptr = (self.target - 5) as *const u8;
            core::slice::from_raw_parts(ptr, 7).to_vec()
        };

        // allocate trampoline
        // the trampoline just contains: original 2-byte nop + jump to target+2
        let mut trampoline = ExecutableMemory::allocate_near(self.target, 32)?;

        // build trampoline: copy the 2-byte nop + jump to target+2
        let entry_bytes = &original_bytes[5..7];
        let mut trampoline_code = Vec::with_capacity(16);
        trampoline_code.extend_from_slice(entry_bytes);

        // add jump to target+2 (continuation after the 2-byte nop)
        let continuation = self.target + 2;
        let trampoline_jmp_loc = trampoline.base() + trampoline_code.len();

        if let Some(jmp_bytes) = A::encode_jmp_rel(trampoline_jmp_loc, continuation) {
            trampoline_code.extend_from_slice(&jmp_bytes);
        } else {
            let jmp_bytes = A::encode_jmp_abs(continuation);
            trampoline_code.extend_from_slice(&jmp_bytes);
        }

        trampoline.write(&trampoline_code)?;
        trampoline.flush_icache()?;

        // write the hook:
        // 1. write long jump at target-5 (E9 rel32)
        // 2. write short jump at target (EB F9 = jmp -7)

        let long_jmp_addr = self.target - 5;

        // change protection for the whole area
        {
            let _guard = ProtectionGuard::new(
                long_jmp_addr,
                7,
                PAGE_EXECUTE_READWRITE,
            )?;

            // write long jump at target-5
            let long_jmp = A::encode_jmp_rel(long_jmp_addr, self.detour)
                .or_else(|| Some(A::encode_jmp_abs(self.detour)))
                .unwrap();

            // SAFETY: protection changed, writing to padding area
            unsafe {
                core::ptr::copy_nonoverlapping(
                    long_jmp.as_ptr(),
                    long_jmp_addr as *mut u8,
                    5.min(long_jmp.len()),
                );
            }

            // write short jump at entry point (EB F9 = jmp -7)
            // this jumps back to the long jump we just wrote
            // SAFETY: protection changed, writing 2 bytes atomically
            unsafe {
                let short_jmp: u16 = 0xF9EB; // little-endian: EB F9
                core::ptr::write_volatile(self.target as *mut u16, short_jmp);
            }
        }

        // flush instruction cache
        flush_icache(long_jmp_addr, 7)?;

        // create guard with original bytes (starting at target-5)
        Ok(HookGuard::new(
            long_jmp_addr,
            self.detour,
            original_bytes,
            Some(trampoline),
        ))
    }
}

impl<A: Architecture> Hook for HotPatchHook<A> {
    type Guard = HookGuard<A>;

    fn install(self) -> Result<Self::Guard> {
        HotPatchHook::install(self)
    }

    fn target(&self) -> usize {
        self.target
    }

    fn detour(&self) -> usize {
        self.detour
    }
}

/// check if a function is hot-patchable
pub fn is_hot_patchable(target: usize) -> bool {
    // read the bytes
    let pre_bytes = unsafe {
        core::slice::from_raw_parts((target - 5) as *const u8, 5)
    };
    let entry_bytes = unsafe {
        core::slice::from_raw_parts(target as *const u8, 2)
    };

    let has_padding = pre_bytes.iter().all(|&b| b == 0xCC || b == 0x90);
    let has_nop_entry = entry_bytes == [0x8B, 0xFF]
        || entry_bytes == [0x66, 0x90]
        || entry_bytes == [0x89, 0xFF];

    has_padding && has_nop_entry
}

/// convenience function to create and install a hot-patch hook
pub fn hotpatch<A: Architecture>(target: usize, detour: usize) -> Result<HookGuard<A>> {
    HotPatchHook::<A>::new(target, detour).install()
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
