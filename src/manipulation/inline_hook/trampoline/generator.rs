//! Trampoline code generation
//!
//! Generates trampolines that contain the relocated original function prologue
//! followed by a jump back to the continuation point.

use crate::error::{Result, WraithError};
use super::allocator::ExecutableMemory;
use crate::manipulation::inline_hook::arch::Architecture;

/// trampoline builder for generating function trampolines
pub struct TrampolineBuilder<A: Architecture> {
    /// target function address
    target: usize,
    /// bytes to relocate from the target
    prologue_size: usize,
    /// copied prologue bytes
    prologue_bytes: Vec<u8>,
    /// allocated memory for trampoline
    memory: Option<ExecutableMemory>,
    _arch: core::marker::PhantomData<A>,
}

impl<A: Architecture> TrampolineBuilder<A> {
    /// create a new trampoline builder
    pub fn new(target: usize) -> Self {
        Self {
            target,
            prologue_size: 0,
            prologue_bytes: Vec::new(),
            memory: None,
            _arch: core::marker::PhantomData,
        }
    }

    /// analyze target function and determine prologue size
    ///
    /// finds the minimum number of bytes that need to be copied
    /// to make room for the hook stub.
    pub fn analyze(&mut self, min_size: usize) -> Result<&mut Self> {
        // read bytes from target
        let max_read = 64; // reasonable max for prologue analysis
        let target_bytes = unsafe {
            core::slice::from_raw_parts(self.target as *const u8, max_read)
        };

        // find instruction boundary at or after min_size
        let boundary = A::find_instruction_boundary(target_bytes, min_size)
            .ok_or_else(|| WraithError::HookDetectionFailed {
                function: format!("{:#x}", self.target),
                reason: "failed to find instruction boundary".into(),
            })?;

        self.prologue_size = boundary;
        self.prologue_bytes = target_bytes[..boundary].to_vec();

        Ok(self)
    }

    /// set prologue size explicitly (advanced use)
    pub fn with_prologue_size(&mut self, size: usize) -> Result<&mut Self> {
        let target_bytes = unsafe {
            core::slice::from_raw_parts(self.target as *const u8, size)
        };
        self.prologue_size = size;
        self.prologue_bytes = target_bytes.to_vec();
        Ok(self)
    }

    /// allocate memory for the trampoline
    pub fn allocate(&mut self) -> Result<&mut Self> {
        // trampoline needs: prologue + jump back (max 14 bytes on x64)
        let trampoline_size = self.prologue_size + A::JMP_ABS_SIZE + 16; // extra for safety

        let memory = ExecutableMemory::allocate_near(self.target, trampoline_size)?;
        self.memory = Some(memory);

        Ok(self)
    }

    /// build the trampoline
    ///
    /// copies and relocates the prologue, then appends a jump back
    /// to target + prologue_size.
    pub fn build(&mut self) -> Result<usize> {
        let memory = self.memory.as_mut().ok_or_else(|| WraithError::NullPointer {
            context: "trampoline memory not allocated",
        })?;

        let trampoline_base = memory.base();
        let mut trampoline_code = Vec::with_capacity(self.prologue_size + A::JMP_ABS_SIZE);

        // relocate each instruction in the prologue
        let mut src_offset = 0;
        let mut dst_offset = 0;

        while src_offset < self.prologue_size {
            let remaining = &self.prologue_bytes[src_offset..];
            if remaining.is_empty() {
                break;
            }

            // find instruction length
            let insn_len = A::find_instruction_boundary(remaining, 1)
                .ok_or_else(|| WraithError::HookDetectionFailed {
                    function: format!("{:#x}", self.target + src_offset),
                    reason: "failed to decode instruction".into(),
                })?;

            let instruction = &self.prologue_bytes[src_offset..src_offset + insn_len];

            // check if instruction needs relocation
            if A::needs_relocation(instruction) {
                let old_addr = self.target + src_offset;
                let new_addr = trampoline_base + dst_offset;

                let relocated = A::relocate_instruction(instruction, old_addr, new_addr)
                    .ok_or_else(|| WraithError::RelocationFailed {
                        rva: src_offset as u32,
                        reason: "instruction cannot be relocated".into(),
                    })?;

                trampoline_code.extend_from_slice(&relocated);
                dst_offset += relocated.len();
            } else {
                // copy as-is
                trampoline_code.extend_from_slice(instruction);
                dst_offset += insn_len;
            }

            src_offset += insn_len;
        }

        // append jump back to continuation point
        let continuation = self.target + self.prologue_size;
        let jmp_location = trampoline_base + dst_offset;

        // try relative jump first, fall back to absolute
        if let Some(jmp_bytes) = A::encode_jmp_rel(jmp_location, continuation) {
            trampoline_code.extend_from_slice(&jmp_bytes);
        } else {
            let jmp_bytes = A::encode_jmp_abs(continuation);
            trampoline_code.extend_from_slice(&jmp_bytes);
        }

        // write to memory
        memory.write(&trampoline_code)?;
        memory.flush_icache()?;

        Ok(trampoline_base)
    }

    /// get the prologue size
    pub fn prologue_size(&self) -> usize {
        self.prologue_size
    }

    /// get the prologue bytes
    pub fn prologue_bytes(&self) -> &[u8] {
        &self.prologue_bytes
    }

    /// take the allocated memory (transfers ownership)
    pub fn take_memory(&mut self) -> Option<ExecutableMemory> {
        self.memory.take()
    }

    /// get target address
    pub fn target(&self) -> usize {
        self.target
    }
}

/// build a trampoline for a target function
///
/// this is a convenience function that performs all steps:
/// 1. analyze the target to find prologue size
/// 2. allocate executable memory near target
/// 3. copy and relocate prologue
/// 4. append jump back to continuation
pub fn build_trampoline<A: Architecture>(
    target: usize,
    min_hook_size: usize,
) -> Result<(ExecutableMemory, Vec<u8>, usize)> {
    let mut builder = TrampolineBuilder::<A>::new(target);

    builder.analyze(min_hook_size)?;
    builder.allocate()?;
    let trampoline_addr = builder.build()?;

    let prologue_bytes = builder.prologue_bytes().to_vec();
    let prologue_size = builder.prologue_size();
    let memory = builder.take_memory().unwrap();

    Ok((memory, prologue_bytes, prologue_size))
}

/// result of trampoline generation
pub struct TrampolineResult {
    /// allocated executable memory containing the trampoline
    pub memory: ExecutableMemory,
    /// original prologue bytes (for restoration)
    pub original_bytes: Vec<u8>,
    /// number of bytes in the prologue
    pub prologue_size: usize,
    /// address of the trampoline entry point
    pub entry: usize,
}

impl TrampolineResult {
    /// get the trampoline entry point
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// get the original bytes
    pub fn original_bytes(&self) -> &[u8] {
        &self.original_bytes
    }

    /// get prologue size
    pub fn prologue_size(&self) -> usize {
        self.prologue_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // tests require actual function targets, so we test the builder setup
    #[test]
    fn test_builder_creation() {
        use crate::manipulation::inline_hook::arch::NativeArch;

        let builder = TrampolineBuilder::<NativeArch>::new(0x12345678);
        assert_eq!(builder.target(), 0x12345678);
        assert_eq!(builder.prologue_size(), 0);
    }
}
