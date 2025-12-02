//! Architecture abstraction for inline hooking
//!
//! This module provides a trait-based abstraction over different CPU architectures,
//! allowing the hooking framework to support both x86 and x64 with compile-time
//! architecture selection.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

mod x64;
mod x86;

pub use x64::X64;
pub use x86::X86;

/// native architecture type alias based on target
#[cfg(target_arch = "x86_64")]
pub type NativeArch = X64;

#[cfg(target_arch = "x86")]
pub type NativeArch = X86;

/// architecture-specific code generation trait
///
/// implementors provide the low-level instruction encoding and decoding
/// needed for inline hooking on their respective architectures.
pub trait Architecture: Sized + 'static {
    /// size of a near relative jump instruction (jmp rel32)
    const JMP_REL_SIZE: usize;

    /// size of an absolute jump stub (varies by architecture)
    const JMP_ABS_SIZE: usize;

    /// native pointer size in bytes
    const PTR_SIZE: usize;

    /// required alignment for executable code
    const CODE_ALIGNMENT: usize;

    /// minimum bytes needed to install a hook
    /// typically JMP_REL_SIZE for near targets, JMP_ABS_SIZE for far
    const MIN_HOOK_SIZE: usize;

    /// encode a near relative jump from source to target
    ///
    /// returns None if the distance exceeds the rel32 range (±2GB)
    fn encode_jmp_rel(source: usize, target: usize) -> Option<Vec<u8>>;

    /// encode an absolute jump (architecture-specific stub)
    fn encode_jmp_abs(target: usize) -> Vec<u8>;

    /// encode a relative call instruction
    ///
    /// returns None if the distance exceeds the rel32 range
    fn encode_call_rel(source: usize, target: usize) -> Option<Vec<u8>>;

    /// encode a NOP sled of the specified size
    fn encode_nop_sled(size: usize) -> Vec<u8>;

    /// find instruction boundary at or after required_size bytes
    ///
    /// scans code bytes and returns the offset where an instruction boundary
    /// exists that is >= required_size. returns None if decoding fails.
    fn find_instruction_boundary(code: &[u8], required_size: usize) -> Option<usize>;

    /// relocate an instruction that was moved to a new address
    ///
    /// handles relative addressing adjustments for instructions like
    /// jmp rel32, call rel32, and RIP-relative addressing (x64).
    ///
    /// returns the relocated bytes, or None if the instruction cannot be relocated.
    fn relocate_instruction(
        instruction: &[u8],
        old_address: usize,
        new_address: usize,
    ) -> Option<Vec<u8>>;

    /// check if an instruction needs relocation when moved
    fn needs_relocation(instruction: &[u8]) -> bool;

    /// preferred hook method based on distance between target and detour
    fn preferred_hook_size(target: usize, detour: usize) -> usize {
        let distance = (target as i64 - detour as i64).abs();
        if distance <= i32::MAX as i64 {
            Self::JMP_REL_SIZE
        } else {
            Self::JMP_ABS_SIZE
        }
    }
}

/// result of instruction decoding
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// length of the instruction in bytes
    pub length: usize,
    /// whether this instruction uses relative addressing
    pub is_relative: bool,
    /// for relative instructions, the target address
    pub relative_target: Option<usize>,
}

/// relocation result
#[derive(Debug)]
pub struct RelocationResult {
    /// the relocated instruction bytes
    pub bytes: Vec<u8>,
    /// whether the instruction grew in size (e.g., short jmp -> long jmp)
    pub size_changed: bool,
}
