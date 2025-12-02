//! x86 (32-bit) architecture implementation

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use super::Architecture;
use crate::manipulation::inline_hook::asm::{
    iced_decoder::InstructionDecoder,
    iced_relocator::InstructionRelocator,
};

/// x86 (32-bit) architecture
pub struct X86;

impl Architecture for X86 {
    // E9 rel32 - 5 bytes
    const JMP_REL_SIZE: usize = 5;

    // push imm32; ret - 6 bytes
    const JMP_ABS_SIZE: usize = 6;

    const PTR_SIZE: usize = 4;
    const CODE_ALIGNMENT: usize = 4;

    // x86 can always use 5-byte jmp rel32 (full address space reachable)
    const MIN_HOOK_SIZE: usize = 5;

    fn encode_jmp_rel(source: usize, target: usize) -> Option<Vec<u8>> {
        // on x86, all addresses are reachable with rel32
        let offset = (target as i32).wrapping_sub((source as i32).wrapping_add(5));

        let mut bytes = Vec::with_capacity(5);
        bytes.push(0xE9);
        bytes.extend_from_slice(&offset.to_le_bytes());
        Some(bytes)
    }

    fn encode_jmp_abs(target: usize) -> Vec<u8> {
        // push imm32; ret
        let mut bytes = Vec::with_capacity(6);
        bytes.push(0x68); // push imm32
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.push(0xC3); // ret
        bytes
    }

    fn encode_call_rel(source: usize, target: usize) -> Option<Vec<u8>> {
        let offset = (target as i32).wrapping_sub((source as i32).wrapping_add(5));

        let mut bytes = Vec::with_capacity(5);
        bytes.push(0xE8);
        bytes.extend_from_slice(&offset.to_le_bytes());
        Some(bytes)
    }

    fn encode_nop_sled(size: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(size);
        let mut remaining = size;

        while remaining > 0 {
            match remaining {
                1 => {
                    bytes.push(0x90);
                    remaining -= 1;
                }
                2 => {
                    bytes.extend_from_slice(&[0x66, 0x90]);
                    remaining -= 2;
                }
                3 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x00]);
                    remaining -= 3;
                }
                4 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
                    remaining -= 4;
                }
                5 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 5;
                }
                6 => {
                    bytes.extend_from_slice(&[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 6;
                }
                _ => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 7;
                }
            }
        }

        bytes
    }

    fn find_instruction_boundary(code: &[u8], required_size: usize) -> Option<usize> {
        // use iced-x86 for accurate instruction boundary detection
        let decoder = InstructionDecoder::x86();
        decoder.find_boundary(0, code, required_size)
    }

    fn relocate_instruction(
        instruction: &[u8],
        old_address: usize,
        new_address: usize,
    ) -> Option<Vec<u8>> {
        if instruction.is_empty() {
            return None;
        }

        // use iced-x86 for accurate instruction relocation
        let relocator = InstructionRelocator::x86();
        let result = relocator.relocate_instruction(
            instruction,
            old_address as u64,
            new_address as u64,
        );

        if result.success {
            Some(result.bytes)
        } else {
            None
        }
    }

    fn needs_relocation(instruction: &[u8]) -> bool {
        if instruction.is_empty() {
            return false;
        }

        // use iced-x86 to check if instruction uses relative addressing
        crate::manipulation::inline_hook::asm::iced_relocator::instruction_needs_relocation(
            instruction,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_jmp_rel() {
        let bytes = X86::encode_jmp_rel(0x1000, 0x1100).unwrap();
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0xE9);
        let offset = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(offset, 0xFB);
    }

    #[test]
    fn test_encode_jmp_abs() {
        let bytes = X86::encode_jmp_abs(0xDEADBEEF);
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[0], 0x68); // push
        let addr = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(addr, 0xDEADBEEF);
        assert_eq!(bytes[5], 0xC3); // ret
    }

    #[test]
    fn test_find_instruction_boundary() {
        // push ebp; mov ebp, esp; sub esp, 0x10
        let code = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let boundary = X86::find_instruction_boundary(&code, 5).unwrap();
        assert!(boundary >= 5);
    }

    #[test]
    fn test_relocate_jmp_rel32() {
        // jmp +0x100 from 0x1000 (target: 0x1105)
        let jmp = [0xE9, 0x00, 0x01, 0x00, 0x00];

        // relocate to 0x2000, target should still be 0x1105
        let result = X86::relocate_instruction(&jmp, 0x1000, 0x2000).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], 0xE9);
    }

    #[test]
    fn test_needs_relocation() {
        // JMP rel32 - needs relocation
        assert!(X86::needs_relocation(&[0xE9, 0x00, 0x00, 0x00, 0x00]));

        // CALL rel32 - needs relocation
        assert!(X86::needs_relocation(&[0xE8, 0x00, 0x00, 0x00, 0x00]));

        // PUSH EBP - doesn't need relocation
        assert!(!X86::needs_relocation(&[0x55]));

        // NOP - doesn't need relocation
        assert!(!X86::needs_relocation(&[0x90]));
    }
}
