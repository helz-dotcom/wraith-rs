//! RAII hook guard for automatic cleanup
//!
//! Provides automatic restoration of hooked functions when the guard is dropped,
//! similar to UnlinkGuard in the unlink module.

use crate::error::{Result, WraithError};
use crate::util::memory::ProtectionGuard;
use super::arch::Architecture;
use super::trampoline::ExecutableMemory;
use core::marker::PhantomData;

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// RAII guard for an installed inline hook
///
/// when dropped, automatically restores the original function bytes
/// unless `leak()` was called.
pub struct HookGuard<A: Architecture> {
    /// address of the hooked function
    target: usize,
    /// address of the detour function
    detour: usize,
    /// original bytes that were overwritten
    original_bytes: Vec<u8>,
    /// trampoline memory (if allocated)
    trampoline: Option<ExecutableMemory>,
    /// whether to restore on drop
    auto_restore: bool,
    /// architecture marker
    _arch: PhantomData<A>,
}

impl<A: Architecture> HookGuard<A> {
    /// create a new hook guard
    pub(crate) fn new(
        target: usize,
        detour: usize,
        original_bytes: Vec<u8>,
        trampoline: Option<ExecutableMemory>,
    ) -> Self {
        Self {
            target,
            detour,
            original_bytes,
            trampoline,
            auto_restore: true,
            _arch: PhantomData,
        }
    }

    /// get the target (hooked) function address
    pub fn target(&self) -> usize {
        self.target
    }

    /// get the detour function address
    pub fn detour(&self) -> usize {
        self.detour
    }

    /// get the trampoline address (call this to invoke the original function)
    ///
    /// returns None if no trampoline was allocated
    pub fn trampoline(&self) -> Option<usize> {
        self.trampoline.as_ref().map(|t| t.base())
    }

    /// get the original bytes that were overwritten
    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    /// check if auto-restore is enabled
    pub fn will_auto_restore(&self) -> bool {
        self.auto_restore
    }

    /// set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, restore: bool) {
        self.auto_restore = restore;
    }

    /// disable auto-restore and keep the hook active permanently
    ///
    /// consumes the guard without restoring the original function.
    /// the trampoline memory is leaked and remains valid.
    pub fn leak(mut self) {
        self.auto_restore = false;
        if let Some(trampoline) = self.trampoline.take() {
            trampoline.leak();
        }
        core::mem::forget(self);
    }

    /// manually restore the original function
    ///
    /// consumes the guard and restores the hooked function to its original state.
    pub fn restore(self) -> Result<()> {
        self.restore_internal()?;
        // prevent double-restore in Drop
        core::mem::forget(self);
        Ok(())
    }

    /// temporarily disable the hook
    ///
    /// restores original bytes but keeps the guard and trampoline alive
    /// for re-enabling later.
    pub fn disable(&mut self) -> Result<()> {
        let _guard = ProtectionGuard::new(
            self.target,
            self.original_bytes.len(),
            PAGE_EXECUTE_READWRITE,
        )?;

        // SAFETY: protection changed to RWX, original bytes length matches what we overwrote
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.target as *mut u8,
                self.original_bytes.len(),
            );
        }

        flush_icache(self.target, self.original_bytes.len())?;

        Ok(())
    }

    /// re-enable a previously disabled hook
    ///
    /// writes the hook stub back to the target function.
    pub fn enable(&mut self, hook_bytes: &[u8]) -> Result<()> {
        if hook_bytes.len() != self.original_bytes.len() {
            return Err(WraithError::WriteFailed {
                address: self.target as u64,
                size: hook_bytes.len(),
            });
        }

        let _guard = ProtectionGuard::new(
            self.target,
            hook_bytes.len(),
            PAGE_EXECUTE_READWRITE,
        )?;

        // SAFETY: protection changed, size matches
        unsafe {
            core::ptr::copy_nonoverlapping(
                hook_bytes.as_ptr(),
                self.target as *mut u8,
                hook_bytes.len(),
            );
        }

        flush_icache(self.target, hook_bytes.len())?;

        Ok(())
    }

    /// internal restore implementation
    fn restore_internal(&self) -> Result<()> {
        let _guard = ProtectionGuard::new(
            self.target,
            self.original_bytes.len(),
            PAGE_EXECUTE_READWRITE,
        )?;

        // SAFETY: protection changed, original_bytes verified at hook install time
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.target as *mut u8,
                self.original_bytes.len(),
            );
        }

        flush_icache(self.target, self.original_bytes.len())?;

        Ok(())
    }
}

impl<A: Architecture> Drop for HookGuard<A> {
    fn drop(&mut self) {
        if self.auto_restore {
            // ignore errors during drop
            let _ = self.restore_internal();
        }
    }
}

// SAFETY: HookGuard contains process-wide memory addresses
// the hook state is shared across threads anyway
unsafe impl<A: Architecture> Send for HookGuard<A> {}
unsafe impl<A: Architecture> Sync for HookGuard<A> {}

/// hook state for enable/disable tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookState {
    /// hook is active
    Enabled,
    /// hook is temporarily disabled
    Disabled,
}

/// stateful hook guard that tracks enable/disable state
pub struct StatefulHookGuard<A: Architecture> {
    guard: HookGuard<A>,
    hook_bytes: Vec<u8>,
    state: HookState,
}

impl<A: Architecture> StatefulHookGuard<A> {
    /// create from guard and hook bytes
    pub(crate) fn new(guard: HookGuard<A>, hook_bytes: Vec<u8>) -> Self {
        Self {
            guard,
            hook_bytes,
            state: HookState::Enabled,
        }
    }

    /// get current state
    pub fn state(&self) -> HookState {
        self.state
    }

    /// check if enabled
    pub fn is_enabled(&self) -> bool {
        self.state == HookState::Enabled
    }

    /// disable the hook
    pub fn disable(&mut self) -> Result<()> {
        if self.state == HookState::Enabled {
            self.guard.disable()?;
            self.state = HookState::Disabled;
        }
        Ok(())
    }

    /// enable the hook
    pub fn enable(&mut self) -> Result<()> {
        if self.state == HookState::Disabled {
            self.guard.enable(&self.hook_bytes)?;
            self.state = HookState::Enabled;
        }
        Ok(())
    }

    /// toggle hook state
    pub fn toggle(&mut self) -> Result<()> {
        match self.state {
            HookState::Enabled => self.disable(),
            HookState::Disabled => self.enable(),
        }
    }

    /// get target address
    pub fn target(&self) -> usize {
        self.guard.target()
    }

    /// get detour address
    pub fn detour(&self) -> usize {
        self.guard.detour()
    }

    /// get trampoline address
    pub fn trampoline(&self) -> Option<usize> {
        self.guard.trampoline()
    }

    /// leak the hook (keep it active permanently)
    pub fn leak(self) {
        self.guard.leak();
    }

    /// restore and consume
    pub fn restore(self) -> Result<()> {
        self.guard.restore()
    }
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
