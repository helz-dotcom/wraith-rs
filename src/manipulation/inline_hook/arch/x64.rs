//! x86_64 architecture implementation

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use super::Architecture;
use crate::manipulation::inline_hook::asm::{
    iced_decoder::InstructionDecoder,
    iced_relocator::InstructionRelocator,
};

/// x86_64 (64-bit) architecture
pub struct X64;

impl Architecture for X64 {
    // E9 rel32 - 5 bytes
    const JMP_REL_SIZE: usize = 5;

    // FF 25 00 00 00 00 + 8-byte addr = 14 bytes
    const JMP_ABS_SIZE: usize = 14;

    const PTR_SIZE: usize = 8;
    const CODE_ALIGNMENT: usize = 16;

    // we can use 5-byte jmp rel32 if within ±2GB, otherwise need 14 bytes
    const MIN_HOOK_SIZE: usize = 5;

    fn encode_jmp_rel(source: usize, target: usize) -> Option<Vec<u8>> {
        // calculate relative offset (accounting for instruction length)
        let offset = (target as i64) - (source as i64) - 5;

        // check if within 32-bit signed range
        if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
            return None;
        }

        let mut bytes = Vec::with_capacity(5);
        bytes.push(0xE9); // jmp rel32
        bytes.extend_from_slice(&(offset as i32).to_le_bytes());
        Some(bytes)
    }

    fn encode_jmp_abs(target: usize) -> Vec<u8> {
        // FF 25 00 00 00 00 = jmp qword ptr [rip+0]
        // followed by 8-byte absolute address
        let mut bytes = Vec::with_capacity(14);
        bytes.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&(target as u64).to_le_bytes());
        bytes
    }

    fn encode_call_rel(source: usize, target: usize) -> Option<Vec<u8>> {
        let offset = (target as i64) - (source as i64) - 5;

        if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
            return None;
        }

        let mut bytes = Vec::with_capacity(5);
        bytes.push(0xE8); // call rel32
        bytes.extend_from_slice(&(offset as i32).to_le_bytes());
        Some(bytes)
    }

    fn encode_nop_sled(size: usize) -> Vec<u8> {
        // use multi-byte NOPs for efficiency
        let mut bytes = Vec::with_capacity(size);
        let mut remaining = size;

        while remaining > 0 {
            match remaining {
                1 => {
                    bytes.push(0x90); // NOP
                    remaining -= 1;
                }
                2 => {
                    bytes.extend_from_slice(&[0x66, 0x90]); // 66 NOP
                    remaining -= 2;
                }
                3 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x00]); // NOP dword ptr [rax]
                    remaining -= 3;
                }
                4 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x40, 0x00]); // NOP dword ptr [rax+0]
                    remaining -= 4;
                }
                5 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x44, 0x00, 0x00]); // NOP dword ptr [rax+rax*1+0]
                    remaining -= 5;
                }
                6 => {
                    bytes.extend_from_slice(&[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]); // 66 NOP dword ptr [rax+rax*1+0]
                    remaining -= 6;
                }
                7 => {
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]); // NOP dword ptr [rax+0]
                    remaining -= 7;
                }
                _ => {
                    // 8+ byte NOP
                    bytes.extend_from_slice(&[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 8;
                }
            }
        }

        bytes
    }

    fn find_instruction_boundary(code: &[u8], required_size: usize) -> Option<usize> {
        // use iced-x86 for accurate instruction boundary detection
        let decoder = InstructionDecoder::x64();
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
        let relocator = InstructionRelocator::x64();
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
    fn test_encode_jmp_rel_near() {
        // source at 0x1000, target at 0x1100 (within range)
        let bytes = X64::encode_jmp_rel(0x1000, 0x1100).unwrap();
        assert_eq!(bytes.len(), 5);
        assert_eq!(bytes[0], 0xE9);
        // offset should be 0x100 - 5 = 0xFB
        let offset = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
        assert_eq!(offset, 0xFB);
    }

    #[test]
    fn test_encode_jmp_rel_far() {
        // source and target more than 2GB apart - should fail
        let result = X64::encode_jmp_rel(0x0000_0000_0000_1000, 0x0000_0001_0000_0000);
        assert!(result.is_none());
    }

    #[test]
    fn test_encode_jmp_abs() {
        let bytes = X64::encode_jmp_abs(0xDEADBEEF12345678);
        assert_eq!(bytes.len(), 14);
        assert_eq!(&bytes[0..6], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        let addr = u64::from_le_bytes(bytes[6..14].try_into().unwrap());
        assert_eq!(addr, 0xDEADBEEF12345678);
    }

    #[test]
    fn test_nop_sled() {
        for size in 1..=16 {
            let bytes = X64::encode_nop_sled(size);
            assert_eq!(bytes.len(), size);
        }
    }

    #[test]
    fn test_find_instruction_boundary() {
        // typical prologue: push rbp; mov rbp, rsp; sub rsp, 0x28
        let code = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28];

        // need at least 5 bytes for hook
        let boundary = X64::find_instruction_boundary(&code, 5).unwrap();
        assert!(boundary >= 5);
        assert!(boundary <= 8);
    }

    #[test]
    fn test_relocate_jmp_rel32() {
        // jmp +0x100 from 0x1000 (target: 0x1105)
        let jmp = [0xE9, 0x00, 0x01, 0x00, 0x00];

        // relocate to 0x2000, target should still be 0x1105
        let result = X64::relocate_instruction(&jmp, 0x1000, 0x2000).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0], 0xE9);

        // verify new offset: 0x1105 - 0x2000 - 5 = -0xF00
        let new_offset = i32::from_le_bytes(result[1..5].try_into().unwrap());
        assert_eq!(new_offset, -0xF00);
    }

    #[test]
    fn test_relocate_non_relative() {
        // push rbp - not relative, should copy as-is
        let push = [0x55];
        let result = X64::relocate_instruction(&push, 0x1000, 0x2000).unwrap();
        assert_eq!(result, vec![0x55]);
    }

    #[test]
    fn test_needs_relocation() {
        // JMP rel32 - needs relocation
        assert!(X64::needs_relocation(&[0xE9, 0x00, 0x00, 0x00, 0x00]));

        // CALL rel32 - needs relocation
        assert!(X64::needs_relocation(&[0xE8, 0x00, 0x00, 0x00, 0x00]));

        // PUSH RBP - doesn't need relocation
        assert!(!X64::needs_relocation(&[0x55]));

        // NOP - doesn't need relocation
        assert!(!X64::needs_relocation(&[0x90]));
    }
}
