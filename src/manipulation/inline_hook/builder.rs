//! Type-state hook builder
//!
//! Provides a compile-time safe builder pattern for creating hooks,
//! similar to ManualMapper in the manual_map module.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

use crate::error::{Result, WraithError};
use crate::manipulation::inline_hook::arch::Architecture;
use crate::manipulation::inline_hook::guard::HookGuard;
use crate::manipulation::inline_hook::trampoline::ExecutableMemory;
use crate::util::memory::ProtectionGuard;
use core::marker::PhantomData;

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// type-state markers for hook building stages
pub mod state {
    /// initial state - no target set
    pub struct Uninitialized;
    /// target function has been set
    pub struct TargetSet;
    /// detour function has been set
    pub struct DetourSet;
    /// trampoline has been allocated
    pub struct TrampolineAllocated;
    /// trampoline has been built
    pub struct TrampolineBuilt;
    /// ready to install
    pub struct Ready;
}

/// type-state hook builder
///
/// ensures hook creation follows the correct sequence:
/// `Uninitialized -> TargetSet -> DetourSet -> TrampolineAllocated -> TrampolineBuilt -> Ready`
pub struct HookBuilder<A: Architecture, S> {
    target: Option<usize>,
    detour: Option<usize>,
    prologue_bytes: Option<Vec<u8>>,
    prologue_size: Option<usize>,
    trampoline_memory: Option<ExecutableMemory>,
    hook_stub: Option<Vec<u8>>,
    _arch: PhantomData<A>,
    _state: PhantomData<S>,
}

impl<A: Architecture> HookBuilder<A, state::Uninitialized> {
    /// create a new hook builder
    pub fn new() -> Self {
        Self {
            target: None,
            detour: None,
            prologue_bytes: None,
            prologue_size: None,
            trampoline_memory: None,
            hook_stub: None,
            _arch: PhantomData,
            _state: PhantomData,
        }
    }

    /// set the target function address
    pub fn target(self, addr: usize) -> Result<HookBuilder<A, state::TargetSet>> {
        if addr == 0 {
            return Err(WraithError::NullPointer {
                context: "hook target",
            });
        }

        Ok(HookBuilder {
            target: Some(addr),
            detour: None,
            prologue_bytes: None,
            prologue_size: None,
            trampoline_memory: None,
            hook_stub: None,
            _arch: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: Architecture> Default for HookBuilder<A, state::Uninitialized> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Architecture> HookBuilder<A, state::TargetSet> {
    /// get the target address
    pub fn get_target(&self) -> usize {
        self.target.unwrap()
    }

    /// set the detour function address
    pub fn detour(self, addr: usize) -> Result<HookBuilder<A, state::DetourSet>> {
        if addr == 0 {
            return Err(WraithError::NullPointer {
                context: "hook detour",
            });
        }

        Ok(HookBuilder {
            target: self.target,
            detour: Some(addr),
            prologue_bytes: None,
            prologue_size: None,
            trampoline_memory: None,
            hook_stub: None,
            _arch: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: Architecture> HookBuilder<A, state::DetourSet> {
    /// get the target address
    pub fn get_target(&self) -> usize {
        self.target.unwrap()
    }

    /// get the detour address
    pub fn get_detour(&self) -> usize {
        self.detour.unwrap()
    }

    /// analyze target and allocate trampoline
    pub fn allocate_trampoline(self) -> Result<HookBuilder<A, state::TrampolineAllocated>> {
        let target = self.target.unwrap();
        let detour = self.detour.unwrap();

        // calculate required hook size
        let hook_size = A::preferred_hook_size(target, detour);

        // analyze target function
        let target_bytes = unsafe {
            core::slice::from_raw_parts(target as *const u8, 64)
        };

        let boundary = A::find_instruction_boundary(target_bytes, hook_size)
            .ok_or_else(|| WraithError::HookDetectionFailed {
                function: format!("{:#x}", target),
                reason: "failed to find instruction boundary".into(),
            })?;

        let prologue_bytes = target_bytes[..boundary].to_vec();

        // allocate trampoline memory
        let trampoline_size = boundary + A::JMP_ABS_SIZE + 16;
        let trampoline_memory = ExecutableMemory::allocate_near(target, trampoline_size)?;

        Ok(HookBuilder {
            target: self.target,
            detour: self.detour,
            prologue_bytes: Some(prologue_bytes),
            prologue_size: Some(boundary),
            trampoline_memory: Some(trampoline_memory),
            hook_stub: None,
            _arch: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: Architecture> HookBuilder<A, state::TrampolineAllocated> {
    /// get the target address
    pub fn get_target(&self) -> usize {
        self.target.unwrap()
    }

    /// get prologue size
    pub fn prologue_size(&self) -> usize {
        self.prologue_size.unwrap()
    }

    /// build the trampoline
    pub fn build_trampoline(mut self) -> Result<HookBuilder<A, state::TrampolineBuilt>> {
        let target = self.target.unwrap();
        let prologue_bytes = self.prologue_bytes.as_ref().unwrap();
        let prologue_size = self.prologue_size.unwrap();
        let trampoline = self.trampoline_memory.as_mut().unwrap();

        let trampoline_base = trampoline.base();

        // build trampoline code
        let mut trampoline_code = Vec::with_capacity(prologue_size + A::JMP_ABS_SIZE);

        // relocate prologue bytes
        let mut src_offset = 0;
        let mut dst_offset = 0;

        while src_offset < prologue_size {
            let remaining = &prologue_bytes[src_offset..];
            if remaining.is_empty() {
                break;
            }

            let insn_len = A::find_instruction_boundary(remaining, 1)
                .ok_or_else(|| WraithError::HookDetectionFailed {
                    function: format!("{:#x}", target + src_offset),
                    reason: "failed to decode instruction".into(),
                })?;

            let instruction = &prologue_bytes[src_offset..src_offset + insn_len];

            if A::needs_relocation(instruction) {
                let old_addr = target + src_offset;
                let new_addr = trampoline_base + dst_offset;

                let relocated = A::relocate_instruction(instruction, old_addr, new_addr)
                    .ok_or_else(|| WraithError::RelocationFailed {
                        rva: src_offset as u32,
                        reason: "instruction cannot be relocated".into(),
                    })?;

                trampoline_code.extend_from_slice(&relocated);
                dst_offset += relocated.len();
            } else {
                trampoline_code.extend_from_slice(instruction);
                dst_offset += insn_len;
            }

            src_offset += insn_len;
        }

        // append jump back
        let continuation = target + prologue_size;
        let jmp_location = trampoline_base + dst_offset;

        if let Some(jmp_bytes) = A::encode_jmp_rel(jmp_location, continuation) {
            trampoline_code.extend_from_slice(&jmp_bytes);
        } else {
            trampoline_code.extend_from_slice(&A::encode_jmp_abs(continuation));
        }

        // write to memory
        trampoline.write(&trampoline_code)?;
        trampoline.flush_icache()?;

        Ok(HookBuilder {
            target: self.target,
            detour: self.detour,
            prologue_bytes: self.prologue_bytes,
            prologue_size: self.prologue_size,
            trampoline_memory: self.trampoline_memory,
            hook_stub: None,
            _arch: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: Architecture> HookBuilder<A, state::TrampolineBuilt> {
    /// get the target address
    pub fn get_target(&self) -> usize {
        self.target.unwrap()
    }

    /// get the trampoline address
    pub fn trampoline(&self) -> usize {
        self.trampoline_memory.as_ref().unwrap().base()
    }

    /// generate hook stub and prepare for installation
    pub fn prepare(mut self) -> Result<HookBuilder<A, state::Ready>> {
        let target = self.target.unwrap();
        let detour = self.detour.unwrap();
        let prologue_size = self.prologue_size.unwrap();

        // generate hook stub
        let hook_stub = A::encode_jmp_rel(target, detour)
            .unwrap_or_else(|| A::encode_jmp_abs(detour));

        // pad with NOPs if needed
        let mut padded_stub = hook_stub;
        if padded_stub.len() < prologue_size {
            let padding = A::encode_nop_sled(prologue_size - padded_stub.len());
            padded_stub.extend_from_slice(&padding);
        }

        Ok(HookBuilder {
            target: self.target,
            detour: self.detour,
            prologue_bytes: self.prologue_bytes,
            prologue_size: self.prologue_size,
            trampoline_memory: self.trampoline_memory,
            hook_stub: Some(padded_stub),
            _arch: PhantomData,
            _state: PhantomData,
        })
    }
}

impl<A: Architecture> HookBuilder<A, state::Ready> {
    /// get the target address
    pub fn get_target(&self) -> usize {
        self.target.unwrap()
    }

    /// get the trampoline address
    pub fn trampoline(&self) -> usize {
        self.trampoline_memory.as_ref().unwrap().base()
    }

    /// install the hook
    pub fn install(mut self) -> Result<HookGuard<A>> {
        let target = self.target.unwrap();
        let detour = self.detour.unwrap();
        let prologue_bytes = self.prologue_bytes.take().unwrap();
        let prologue_size = self.prologue_size.unwrap();
        let hook_stub = self.hook_stub.as_ref().unwrap();

        // write hook stub to target
        {
            let _guard = ProtectionGuard::new(
                target,
                prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            unsafe {
                core::ptr::copy_nonoverlapping(
                    hook_stub.as_ptr(),
                    target as *mut u8,
                    prologue_size,
                );
            }
        }

        // flush instruction cache
        flush_icache(target, prologue_size)?;

        Ok(HookGuard::new(
            target,
            detour,
            prologue_bytes,
            self.trampoline_memory.take(),
        ))
    }
}

/// convenience function to build a hook step-by-step
///
/// # Example
/// ```ignore
/// let guard = HookBuilder::<NativeArch, _>::new()
///     .target(target_addr)?
///     .detour(detour_addr)?
///     .allocate_trampoline()?
///     .build_trampoline()?
///     .prepare()?
///     .install()?;
/// ```
pub fn build<A: Architecture>() -> HookBuilder<A, state::Uninitialized> {
    HookBuilder::new()
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
