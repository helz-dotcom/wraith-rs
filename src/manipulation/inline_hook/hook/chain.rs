//! Hook chaining support
//!
//! Allows multiple hooks on the same target function, organized by priority.
//! Each hook in the chain can call the next via its trampoline.

use crate::error::{Result, WraithError};
use crate::util::memory::ProtectionGuard;
use crate::manipulation::inline_hook::arch::Architecture;
use crate::manipulation::inline_hook::trampoline::{ExecutableMemory, TrampolineBuilder};
use core::marker::PhantomData;

const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// entry in the hook chain
struct ChainEntry {
    /// detour function address
    detour: usize,
    /// trampoline to call next in chain (or original)
    trampoline: ExecutableMemory,
    /// priority (lower = called first)
    priority: i32,
}

/// hook chain for multiple hooks on one target
///
/// manages a chain of hooks on a single function. hooks are called
/// in priority order (lower priority first). each hook receives a
/// trampoline to call the next hook in the chain.
pub struct HookChain<A: Architecture> {
    /// target function address
    target: usize,
    /// chain entries sorted by priority
    entries: Vec<ChainEntry>,
    /// original function bytes
    original_bytes: Vec<u8>,
    /// prologue size
    prologue_size: usize,
    /// current hook bytes at target
    current_hook: Vec<u8>,
    _arch: PhantomData<A>,
}

impl<A: Architecture> HookChain<A> {
    /// create a new hook chain on target function
    ///
    /// this analyzes the target but does not install any hooks yet.
    pub fn new(target: usize) -> Result<Self> {
        let min_size = A::MIN_HOOK_SIZE;

        // analyze target function
        let target_bytes = unsafe {
            core::slice::from_raw_parts(target as *const u8, 64)
        };

        let boundary = A::find_instruction_boundary(target_bytes, min_size)
            .ok_or_else(|| WraithError::HookDetectionFailed {
                function: format!("{:#x}", target),
                reason: "failed to find instruction boundary".into(),
            })?;

        let original_bytes = target_bytes[..boundary].to_vec();

        Ok(Self {
            target,
            entries: Vec::new(),
            original_bytes,
            prologue_size: boundary,
            current_hook: Vec::new(),
            _arch: PhantomData,
        })
    }

    /// add a hook to the chain
    ///
    /// returns the trampoline address for calling the next hook in chain.
    /// lower priority values are called first.
    pub fn add(&mut self, detour: usize, priority: i32) -> Result<usize> {
        // find insertion position (sorted by priority)
        let pos = self.entries
            .iter()
            .position(|e| e.priority > priority)
            .unwrap_or(self.entries.len());

        // build trampoline for this entry
        // it will call the next entry (or original if last)
        let next_target = if pos < self.entries.len() {
            // there's a next entry - call its detour
            self.entries[pos].detour
        } else {
            // this is the last entry - build trampoline to original
            self.target
        };

        let trampoline = self.build_trampoline_to(next_target)?;
        let trampoline_addr = trampoline.base();

        // insert new entry
        self.entries.insert(pos, ChainEntry {
            detour,
            trampoline,
            priority,
        });

        // update trampolines for entries before this one
        self.rebuild_trampolines_before(pos)?;

        // update the hook at target to call first entry
        self.update_target_hook()?;

        Ok(trampoline_addr)
    }

    /// remove a hook from the chain by detour address
    ///
    /// returns true if the hook was found and removed.
    pub fn remove(&mut self, detour: usize) -> Result<bool> {
        let pos = match self.entries.iter().position(|e| e.detour == detour) {
            Some(p) => p,
            None => return Ok(false),
        };

        self.entries.remove(pos);

        if self.entries.is_empty() {
            // no more hooks, restore original
            self.restore_original()?;
        } else {
            // rebuild trampolines and update target
            self.rebuild_all_trampolines()?;
            self.update_target_hook()?;
        }

        Ok(true)
    }

    /// get the trampoline for calling the original function
    ///
    /// this is the trampoline of the last entry in the chain.
    pub fn original(&self) -> Option<usize> {
        self.entries.last().map(|e| e.trampoline.base())
    }

    /// get number of hooks in the chain
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// get target address
    pub fn target(&self) -> usize {
        self.target
    }

    /// restore original function and drop all hooks
    pub fn restore(mut self) -> Result<()> {
        self.restore_original()?;
        Ok(())
    }

    /// build a trampoline that jumps to given address
    fn build_trampoline_to(&self, target: usize) -> Result<ExecutableMemory> {
        let mut memory = ExecutableMemory::allocate_near(self.target, 64)?;

        // if target is the original function, we need to copy prologue
        if target == self.target {
            let mut code = Vec::with_capacity(self.prologue_size + A::JMP_ABS_SIZE);

            // copy and relocate original bytes
            let mut src_offset = 0;
            while src_offset < self.prologue_size {
                let remaining = &self.original_bytes[src_offset..];
                let insn_len = A::find_instruction_boundary(remaining, 1).unwrap_or(1);
                let instruction = &self.original_bytes[src_offset..src_offset + insn_len];

                if A::needs_relocation(instruction) {
                    let old_addr = self.target + src_offset;
                    let new_addr = memory.base() + code.len();
                    if let Some(relocated) = A::relocate_instruction(instruction, old_addr, new_addr) {
                        code.extend_from_slice(&relocated);
                    } else {
                        code.extend_from_slice(instruction);
                    }
                } else {
                    code.extend_from_slice(instruction);
                }

                src_offset += insn_len;
            }

            // jump to continuation
            let continuation = self.target + self.prologue_size;
            let jmp_location = memory.base() + code.len();

            if let Some(jmp) = A::encode_jmp_rel(jmp_location, continuation) {
                code.extend_from_slice(&jmp);
            } else {
                code.extend_from_slice(&A::encode_jmp_abs(continuation));
            }

            memory.write(&code)?;
        } else {
            // just jump to the target detour
            let jmp = A::encode_jmp_rel(memory.base(), target)
                .unwrap_or_else(|| A::encode_jmp_abs(target));
            memory.write(&jmp)?;
        }

        memory.flush_icache()?;

        Ok(memory)
    }

    /// rebuild trampolines before position
    fn rebuild_trampolines_before(&mut self, pos: usize) -> Result<()> {
        // entries before `pos` need their trampolines updated
        // to call the new entry at `pos`
        if pos > 0 {
            let new_target = self.entries[pos].detour;
            let prev = &mut self.entries[pos - 1];

            // rebuild trampoline
            let mut new_tramp = ExecutableMemory::allocate_near(self.target, 64)?;
            let jmp = A::encode_jmp_rel(new_tramp.base(), new_target)
                .unwrap_or_else(|| A::encode_jmp_abs(new_target));
            new_tramp.write(&jmp)?;
            new_tramp.flush_icache()?;

            prev.trampoline = new_tramp;
        }

        Ok(())
    }

    /// rebuild all trampolines in the chain
    fn rebuild_all_trampolines(&mut self) -> Result<()> {
        let len = self.entries.len();

        for i in 0..len {
            let next_target = if i + 1 < len {
                self.entries[i + 1].detour
            } else {
                self.target // original
            };

            let new_tramp = self.build_trampoline_to(next_target)?;
            self.entries[i].trampoline = new_tramp;
        }

        Ok(())
    }

    /// update the hook at target to call first entry
    fn update_target_hook(&mut self) -> Result<()> {
        if self.entries.is_empty() {
            return self.restore_original();
        }

        let first_detour = self.entries[0].detour;

        // generate hook stub
        let hook_stub = A::encode_jmp_rel(self.target, first_detour)
            .unwrap_or_else(|| A::encode_jmp_abs(first_detour));

        let mut padded = hook_stub.clone();
        if padded.len() < self.prologue_size {
            let padding = A::encode_nop_sled(self.prologue_size - padded.len());
            padded.extend_from_slice(&padding);
        }

        // write to target
        {
            let _guard = ProtectionGuard::new(
                self.target,
                self.prologue_size,
                PAGE_EXECUTE_READWRITE,
            )?;

            unsafe {
                core::ptr::copy_nonoverlapping(
                    padded.as_ptr(),
                    self.target as *mut u8,
                    self.prologue_size,
                );
            }
        }

        flush_icache(self.target, self.prologue_size)?;
        self.current_hook = padded;

        Ok(())
    }

    /// restore original function bytes
    fn restore_original(&mut self) -> Result<()> {
        let _guard = ProtectionGuard::new(
            self.target,
            self.prologue_size,
            PAGE_EXECUTE_READWRITE,
        )?;

        unsafe {
            core::ptr::copy_nonoverlapping(
                self.original_bytes.as_ptr(),
                self.target as *mut u8,
                self.prologue_size,
            );
        }

        flush_icache(self.target, self.prologue_size)?;
        self.current_hook.clear();

        Ok(())
    }
}

impl<A: Architecture> Drop for HookChain<A> {
    fn drop(&mut self) {
        // restore original on drop
        let _ = self.restore_original();
    }
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
