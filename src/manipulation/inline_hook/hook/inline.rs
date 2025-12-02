//! Standard inline hook implementation
//!
//! Overwrites the function prologue with a jump to the detour function.
//! A trampoline is created to call the original function.

use crate::error::{Result, WraithError};
use crate::util::memory::ProtectionGuard;
use crate::manipulation::inline_hook::arch::Architecture;
use crate::manipulation::inline_hook::guard::{HookGuard, StatefulHookGuard};
use crate::manipulation::inline_hook::trampoline::TrampolineBuilder;
use super::Hook;
use core::marker::PhantomData;

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// standard inline hook
///
/// overwrites the function prologue with a jump to the detour.
/// creates a trampoline for calling the original function.
pub struct InlineHook<A: Architecture> {
    target: usize,
    detour: usize,
    _arch: PhantomData<A>,
}

impl<A: Architecture> InlineHook<A> {
    /// create a new inline hook
    ///
    /// # Arguments
    /// * `target` - address of the function to hook
    /// * `detour` - address of the detour function
    pub fn new(target: usize, detour: usize) -> Self {
        Self {
            target,
            detour,
            _arch: PhantomData,
        }
    }

    /// calculate the required hook size based on distance
    fn hook_size(&self) -> usize {
        A::preferred_hook_size(self.target, self.detour)
    }

    /// generate the hook stub bytes
    fn generate_hook_stub(&self) -> Vec<u8> {
        // try relative jump first
        if let Some(bytes) = A::encode_jmp_rel(self.target, self.detour) {
            bytes
        } else {
            // fall back to absolute jump
            A::encode_jmp_abs(self.detour)
        }
    }

    /// install the hook and return a guard
    pub fn install(self) -> Result<HookGuard<A>> {
        let hook_size = self.hook_size();

        // build trampoline
        let mut builder = TrampolineBuilder::<A>::new(self.target);
        builder.analyze(hook_size)?;
        builder.allocate()?;
        builder.build()?;

        let prologue_bytes = builder.prologue_bytes().to_vec();
        let prologue_size = builder.prologue_size();
        let trampoline_memory = builder.take_memory();

        // generate hook stub
        let hook_stub = self.generate_hook_stub();

        // verify we have enough space
        if prologue_size < hook_stub.len() {
            return Err(WraithError::HookDetectionFailed {
                function: format!("{:#x}", self.target),
                reason: format!(
                    "insufficient space: need {} bytes, have {}",
                    hook_stub.len(),
                    prologue_size
                ),
            });
        }

        // pad hook stub with NOPs if needed
        let mut final_stub = hook_stub;
        if final_stub.len() < prologue_size {
            let padding = A::encode_nop_sled(prologue_size - final_stub.len());
            final_stub.extend_from_slice(&padding);
        }

        // write hook stub to target
        {
            let _guard = ProtectionGuard::new(
                self.target,
                prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            // SAFETY: protection changed to RWX, size matches prologue
            unsafe {
                core::ptr::copy_nonoverlapping(
                    final_stub.as_ptr(),
                    self.target as *mut u8,
                    prologue_size,
                );
            }
        }

        // flush instruction cache
        flush_icache(self.target, prologue_size)?;

        Ok(HookGuard::new(
            self.target,
            self.detour,
            prologue_bytes,
            trampoline_memory,
        ))
    }

    /// install and return a stateful guard with enable/disable support
    pub fn install_stateful(self) -> Result<StatefulHookGuard<A>> {
        let hook_size = self.hook_size();

        // build trampoline
        let mut builder = TrampolineBuilder::<A>::new(self.target);
        builder.analyze(hook_size)?;
        builder.allocate()?;
        builder.build()?;

        let prologue_bytes = builder.prologue_bytes().to_vec();
        let prologue_size = builder.prologue_size();
        let trampoline_memory = builder.take_memory();

        // generate hook stub
        let hook_stub = self.generate_hook_stub();

        if prologue_size < hook_stub.len() {
            return Err(WraithError::HookDetectionFailed {
                function: format!("{:#x}", self.target),
                reason: format!(
                    "insufficient space: need {} bytes, have {}",
                    hook_stub.len(),
                    prologue_size
                ),
            });
        }

        let mut final_stub = hook_stub;
        if final_stub.len() < prologue_size {
            let padding = A::encode_nop_sled(prologue_size - final_stub.len());
            final_stub.extend_from_slice(&padding);
        }

        // write hook stub
        {
            let _guard = ProtectionGuard::new(
                self.target,
                prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            unsafe {
                core::ptr::copy_nonoverlapping(
                    final_stub.as_ptr(),
                    self.target as *mut u8,
                    prologue_size,
                );
            }
        }

        flush_icache(self.target, prologue_size)?;

        let guard = HookGuard::new(
            self.target,
            self.detour,
            prologue_bytes,
            trampoline_memory,
        );

        Ok(StatefulHookGuard::new(guard, final_stub))
    }
}

impl<A: Architecture> Hook for InlineHook<A> {
    type Guard = HookGuard<A>;

    fn install(self) -> Result<Self::Guard> {
        InlineHook::install(self)
    }

    fn target(&self) -> usize {
        self.target
    }

    fn detour(&self) -> usize {
        self.detour
    }
}

/// convenience function to create and install an inline hook
pub fn hook<A: Architecture>(target: usize, detour: usize) -> Result<HookGuard<A>> {
    InlineHook::<A>::new(target, detour).install()
}

/// convenience function using native architecture
#[cfg(target_arch = "x86_64")]
pub fn hook_native(target: usize, detour: usize) -> Result<HookGuard<crate::manipulation::inline_hook::arch::X64>> {
    hook::<crate::manipulation::inline_hook::arch::X64>(target, detour)
}

#[cfg(target_arch = "x86")]
pub fn hook_native(target: usize, detour: usize) -> Result<HookGuard<crate::manipulation::inline_hook::arch::X86>> {
    hook::<crate::manipulation::inline_hook::arch::X86>(target, detour)
}

/// flush instruction cache
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
