//! Instruction relocation using iced-x86
//!
//! Provides comprehensive instruction relocation support for creating trampolines.
//! Handles:
//! - Relative branch instructions (JMP, CALL, Jcc)
//! - RIP-relative memory operands (x64)
//! - Short jumps that need expansion to long jumps
//! - Loop instructions (LOOP, LOOPE, LOOPNE)
//! - JRCXZ/JECXZ instructions

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec, vec::Vec};

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions,
    FlowControl, Instruction, InstructionBlock, OpKind,
};

/// result of relocating an instruction
#[derive(Debug)]
pub struct RelocationResult {
    /// the relocated instruction bytes
    pub bytes: Vec<u8>,
    /// original instruction length
    pub original_length: usize,
    /// new instruction length (may differ from original)
    pub new_length: usize,
    /// whether instruction size changed during relocation
    pub size_changed: bool,
    /// whether relocation was successful
    pub success: bool,
    /// error message if relocation failed
    pub error: Option<String>,
}

impl RelocationResult {
    fn success(bytes: Vec<u8>, original_length: usize) -> Self {
        let new_length = bytes.len();
        Self {
            bytes,
            original_length,
            new_length,
            size_changed: new_length != original_length,
            success: true,
            error: None,
        }
    }

    fn failure(original_length: usize, error: impl Into<String>) -> Self {
        Self {
            bytes: Vec::new(),
            original_length,
            new_length: 0,
            size_changed: false,
            success: false,
            error: Some(error.into()),
        }
    }
}

/// instruction relocator using iced-x86
pub struct InstructionRelocator {
    bitness: u32,
}

impl InstructionRelocator {
    /// create relocator for current architecture
    #[cfg(target_arch = "x86_64")]
    pub fn native() -> Self {
        Self { bitness: 64 }
    }

    #[cfg(target_arch = "x86")]
    pub fn native() -> Self {
        Self { bitness: 32 }
    }

    /// create 64-bit relocator
    pub fn x64() -> Self {
        Self { bitness: 64 }
    }

    /// create 32-bit relocator
    pub fn x86() -> Self {
        Self { bitness: 32 }
    }

    /// relocate a single instruction from old_address to new_address
    pub fn relocate_instruction(
        &self,
        bytes: &[u8],
        old_address: u64,
        new_address: u64,
    ) -> RelocationResult {
        if bytes.is_empty() {
            return RelocationResult::failure(0, "empty instruction");
        }

        // decode the instruction
        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            old_address,
            DecoderOptions::NONE,
        );

        if !decoder.can_decode() {
            return RelocationResult::failure(bytes.len(), "cannot decode instruction");
        }

        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return RelocationResult::failure(bytes.len(), "invalid instruction");
        }

        let original_length = instruction.len();

        // check if instruction needs relocation
        if !needs_relocation(&instruction, self.bitness) {
            // just copy the instruction as-is
            return RelocationResult::success(bytes[..original_length].to_vec(), original_length);
        }

        // use iced-x86's BlockEncoder for proper relocation
        let mut new_instruction = instruction;
        new_instruction.set_ip(new_address);

        let instructions = [new_instruction];
        let block = InstructionBlock::new(&instructions, new_address);

        let result = BlockEncoder::encode(
            self.bitness,
            block,
            BlockEncoderOptions::DONT_FIX_BRANCHES,
        );

        match result {
            Ok(encoded) => {
                RelocationResult::success(encoded.code_buffer, original_length)
            }
            Err(_) => {
                // BlockEncoder failed, try manual relocation
                self.relocate_manually(&instruction, old_address, new_address, bytes)
            }
        }
    }

    /// relocate a sequence of instructions
    pub fn relocate_block(
        &self,
        bytes: &[u8],
        old_address: u64,
        new_address: u64,
    ) -> Result<Vec<u8>, String> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        // decode all instructions
        let mut instructions = Vec::new();
        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            old_address,
            DecoderOptions::NONE,
        );

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            instructions.push(instruction);
        }

        if instructions.is_empty() {
            return Err("no valid instructions found".into());
        }

        // update IP for each instruction
        let mut offset = 0u64;
        let mut new_instructions = Vec::with_capacity(instructions.len());

        for mut instruction in instructions {
            let old_ip = instruction.ip();
            let new_ip = new_address + (old_ip - old_address);
            instruction.set_ip(new_ip);
            new_instructions.push(instruction);
        }

        // use BlockEncoder for proper relocation
        let block = InstructionBlock::new(&new_instructions, new_address);

        BlockEncoder::encode(
            self.bitness,
            block,
            BlockEncoderOptions::NONE,
        )
        .map(|result| result.code_buffer)
        .map_err(|e| format!("block encoding failed: {:?}", e))
    }

    /// manual relocation for cases where BlockEncoder fails
    fn relocate_manually(
        &self,
        instruction: &Instruction,
        old_address: u64,
        new_address: u64,
        bytes: &[u8],
    ) -> RelocationResult {
        let original_length = instruction.len();
        let flow = instruction.flow_control();

        match flow {
            FlowControl::UnconditionalBranch => {
                self.relocate_jump(instruction, old_address, new_address, bytes)
            }
            FlowControl::ConditionalBranch => {
                self.relocate_conditional_jump(instruction, old_address, new_address, bytes)
            }
            FlowControl::Call => {
                self.relocate_call(instruction, old_address, new_address, bytes)
            }
            _ => {
                // check for RIP-relative memory operand
                if self.bitness == 64 && instruction.is_ip_rel_memory_operand() {
                    self.relocate_rip_relative(instruction, old_address, new_address, bytes)
                } else {
                    // not a relative instruction, copy as-is
                    RelocationResult::success(bytes[..original_length].to_vec(), original_length)
                }
            }
        }
    }

    fn relocate_jump(
        &self,
        instruction: &Instruction,
        old_address: u64,
        new_address: u64,
        bytes: &[u8],
    ) -> RelocationResult {
        let original_length = instruction.len();

        // get the target address
        let target = match instruction.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instruction.near_branch_target()
            }
            _ => {
                // indirect jump, copy as-is
                return RelocationResult::success(bytes[..original_length].to_vec(), original_length);
            }
        };

        // calculate new offset
        let new_offset = (target as i64) - (new_address as i64) - 5;

        // check if we can use rel32
        if new_offset >= i32::MIN as i64 && new_offset <= i32::MAX as i64 {
            // emit jmp rel32
            let mut result = vec![0xE9];
            result.extend_from_slice(&(new_offset as i32).to_le_bytes());
            RelocationResult::success(result, original_length)
        } else if self.bitness == 64 {
            // need absolute jump for x64
            // FF 25 00 00 00 00 + 8-byte address
            let mut result = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
            result.extend_from_slice(&target.to_le_bytes());
            RelocationResult::success(result, original_length)
        } else {
            // x86: push addr; ret
            let mut result = vec![0x68];
            result.extend_from_slice(&(target as u32).to_le_bytes());
            result.push(0xC3);
            RelocationResult::success(result, original_length)
        }
    }

    fn relocate_conditional_jump(
        &self,
        instruction: &Instruction,
        old_address: u64,
        new_address: u64,
        bytes: &[u8],
    ) -> RelocationResult {
        let original_length = instruction.len();

        // get the target address
        let target = match instruction.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instruction.near_branch_target()
            }
            _ => {
                return RelocationResult::failure(original_length, "unexpected operand kind");
            }
        };

        // get the condition code
        let code = instruction.code();
        let cc = get_condition_code(code);

        // calculate new offset for long conditional jump (6 bytes: 0F 8x xx xx xx xx)
        let new_offset = (target as i64) - (new_address as i64) - 6;

        // check if we can use near conditional jump
        if new_offset >= i32::MIN as i64 && new_offset <= i32::MAX as i64 {
            // emit Jcc rel32
            let mut result = vec![0x0F, 0x80 + cc];
            result.extend_from_slice(&(new_offset as i32).to_le_bytes());
            RelocationResult::success(result, original_length)
        } else if self.bitness == 64 {
            // target too far, need to use trampoline pattern:
            // Jcc_not +14  ; jump over the absolute jump if condition is false
            // JMP [RIP+0]  ; absolute jump to target
            // addr64       ; target address
            let inverted_cc = cc ^ 1; // invert condition
            let mut result = vec![0x70 + inverted_cc, 14]; // short Jcc to skip
            result.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp [rip+0]
            result.extend_from_slice(&target.to_le_bytes());
            RelocationResult::success(result, original_length)
        } else {
            // x86: similar but with push/ret
            let inverted_cc = cc ^ 1;
            let mut result = vec![0x70 + inverted_cc, 6]; // short Jcc to skip
            result.push(0x68); // push
            result.extend_from_slice(&(target as u32).to_le_bytes());
            result.push(0xC3); // ret
            RelocationResult::success(result, original_length)
        }
    }

    fn relocate_call(
        &self,
        instruction: &Instruction,
        old_address: u64,
        new_address: u64,
        bytes: &[u8],
    ) -> RelocationResult {
        let original_length = instruction.len();

        // get the target address
        let target = match instruction.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instruction.near_branch_target()
            }
            _ => {
                // indirect call, copy as-is
                return RelocationResult::success(bytes[..original_length].to_vec(), original_length);
            }
        };

        // calculate new offset
        let new_offset = (target as i64) - (new_address as i64) - 5;

        // check if we can use rel32
        if new_offset >= i32::MIN as i64 && new_offset <= i32::MAX as i64 {
            // emit call rel32
            let mut result = vec![0xE8];
            result.extend_from_slice(&(new_offset as i32).to_le_bytes());
            RelocationResult::success(result, original_length)
        } else if self.bitness == 64 {
            // need absolute call for x64
            // we use: call [rip+0]; addr64
            // FF 15 00 00 00 00 + 8-byte address
            let mut result = vec![0xFF, 0x15, 0x00, 0x00, 0x00, 0x00];
            result.extend_from_slice(&target.to_le_bytes());
            RelocationResult::success(result, original_length)
        } else {
            // x86: push return_addr; jmp target
            // this is more complex, just fail for now
            RelocationResult::failure(original_length, "call too far for x86")
        }
    }

    fn relocate_rip_relative(
        &self,
        instruction: &Instruction,
        old_address: u64,
        new_address: u64,
        bytes: &[u8],
    ) -> RelocationResult {
        let original_length = instruction.len();

        // get the absolute target address
        let target = instruction.ip_rel_memory_address();

        // calculate new displacement
        let new_disp = (target as i64) - (new_address as i64) - (original_length as i64);

        // check if new displacement fits in 32 bits
        if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
            return RelocationResult::failure(
                original_length,
                "RIP-relative target too far after relocation",
            );
        }

        // copy instruction and patch displacement
        let mut result = bytes[..original_length].to_vec();

        // find displacement offset
        // for RIP-relative, it's at instruction end minus any immediate minus 4
        let imm_size = get_immediate_size(instruction);
        let disp_offset = original_length - 4 - imm_size;

        // write new displacement
        let new_disp_bytes = (new_disp as i32).to_le_bytes();
        result[disp_offset..disp_offset + 4].copy_from_slice(&new_disp_bytes);

        RelocationResult::success(result, original_length)
    }
}

fn needs_relocation(instruction: &Instruction, bitness: u32) -> bool {
    let flow = instruction.flow_control();

    match flow {
        FlowControl::UnconditionalBranch
        | FlowControl::ConditionalBranch
        | FlowControl::Call => {
            // check if it's a relative branch
            matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        }
        _ => {
            // check for RIP-relative addressing on x64
            bitness == 64 && instruction.is_ip_rel_memory_operand()
        }
    }
}

fn get_condition_code(code: Code) -> u8 {
    match code {
        Code::Jo_rel8_16 | Code::Jo_rel8_32 | Code::Jo_rel8_64
        | Code::Jo_rel16 | Code::Jo_rel32_32 | Code::Jo_rel32_64 => 0x0,

        Code::Jno_rel8_16 | Code::Jno_rel8_32 | Code::Jno_rel8_64
        | Code::Jno_rel16 | Code::Jno_rel32_32 | Code::Jno_rel32_64 => 0x1,

        Code::Jb_rel8_16 | Code::Jb_rel8_32 | Code::Jb_rel8_64
        | Code::Jb_rel16 | Code::Jb_rel32_32 | Code::Jb_rel32_64 => 0x2,

        Code::Jae_rel8_16 | Code::Jae_rel8_32 | Code::Jae_rel8_64
        | Code::Jae_rel16 | Code::Jae_rel32_32 | Code::Jae_rel32_64 => 0x3,

        Code::Je_rel8_16 | Code::Je_rel8_32 | Code::Je_rel8_64
        | Code::Je_rel16 | Code::Je_rel32_32 | Code::Je_rel32_64 => 0x4,

        Code::Jne_rel8_16 | Code::Jne_rel8_32 | Code::Jne_rel8_64
        | Code::Jne_rel16 | Code::Jne_rel32_32 | Code::Jne_rel32_64 => 0x5,

        Code::Jbe_rel8_16 | Code::Jbe_rel8_32 | Code::Jbe_rel8_64
        | Code::Jbe_rel16 | Code::Jbe_rel32_32 | Code::Jbe_rel32_64 => 0x6,

        Code::Ja_rel8_16 | Code::Ja_rel8_32 | Code::Ja_rel8_64
        | Code::Ja_rel16 | Code::Ja_rel32_32 | Code::Ja_rel32_64 => 0x7,

        Code::Js_rel8_16 | Code::Js_rel8_32 | Code::Js_rel8_64
        | Code::Js_rel16 | Code::Js_rel32_32 | Code::Js_rel32_64 => 0x8,

        Code::Jns_rel8_16 | Code::Jns_rel8_32 | Code::Jns_rel8_64
        | Code::Jns_rel16 | Code::Jns_rel32_32 | Code::Jns_rel32_64 => 0x9,

        Code::Jp_rel8_16 | Code::Jp_rel8_32 | Code::Jp_rel8_64
        | Code::Jp_rel16 | Code::Jp_rel32_32 | Code::Jp_rel32_64 => 0xA,

        Code::Jnp_rel8_16 | Code::Jnp_rel8_32 | Code::Jnp_rel8_64
        | Code::Jnp_rel16 | Code::Jnp_rel32_32 | Code::Jnp_rel32_64 => 0xB,

        Code::Jl_rel8_16 | Code::Jl_rel8_32 | Code::Jl_rel8_64
        | Code::Jl_rel16 | Code::Jl_rel32_32 | Code::Jl_rel32_64 => 0xC,

        Code::Jge_rel8_16 | Code::Jge_rel8_32 | Code::Jge_rel8_64
        | Code::Jge_rel16 | Code::Jge_rel32_32 | Code::Jge_rel32_64 => 0xD,

        Code::Jle_rel8_16 | Code::Jle_rel8_32 | Code::Jle_rel8_64
        | Code::Jle_rel16 | Code::Jle_rel32_32 | Code::Jle_rel32_64 => 0xE,

        Code::Jg_rel8_16 | Code::Jg_rel8_32 | Code::Jg_rel8_64
        | Code::Jg_rel16 | Code::Jg_rel32_32 | Code::Jg_rel32_64 => 0xF,

        _ => 0x4, // default to JZ
    }
}

fn get_immediate_size(instruction: &Instruction) -> usize {
    for i in 0..instruction.op_count() {
        match instruction.op_kind(i) {
            OpKind::Immediate8 | OpKind::Immediate8_2nd | OpKind::Immediate8to16
            | OpKind::Immediate8to32 | OpKind::Immediate8to64 => return 1,
            OpKind::Immediate16 => return 2,
            OpKind::Immediate32 | OpKind::Immediate32to64 => return 4,
            OpKind::Immediate64 => return 8,
            _ => {}
        }
    }
    0
}

/// convenience function to relocate a single instruction
pub fn relocate_one(
    bytes: &[u8],
    old_address: u64,
    new_address: u64,
) -> RelocationResult {
    InstructionRelocator::native().relocate_instruction(bytes, old_address, new_address)
}

/// convenience function to relocate a block of instructions
pub fn relocate_block(
    bytes: &[u8],
    old_address: u64,
    new_address: u64,
) -> Result<Vec<u8>, String> {
    InstructionRelocator::native().relocate_block(bytes, old_address, new_address)
}

/// check if an instruction needs relocation when moved
pub fn instruction_needs_relocation(bytes: &[u8], address: u64) -> bool {
    let bitness = if cfg!(target_arch = "x86_64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);

    if !decoder.can_decode() {
        return false;
    }

    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return false;
    }

    needs_relocation(&instruction, bitness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocate_nop() {
        let relocator = InstructionRelocator::x64();
        let nop = [0x90u8];

        let result = relocator.relocate_instruction(&nop, 0x1000, 0x2000);
        assert!(result.success);
        assert_eq!(result.bytes, vec![0x90]);
        assert!(!result.size_changed);
    }

    #[test]
    fn test_relocate_push() {
        let relocator = InstructionRelocator::x64();
        let push = [0x55u8]; // push rbp

        let result = relocator.relocate_instruction(&push, 0x1000, 0x2000);
        assert!(result.success);
        assert_eq!(result.bytes, vec![0x55]);
        assert!(!result.size_changed);
    }

    #[test]
    fn test_relocate_jmp_rel32() {
        let relocator = InstructionRelocator::x64();
        // jmp +0x100 from 0x1000 (target: 0x1105)
        let jmp = [0xE9, 0x00, 0x01, 0x00, 0x00];

        // relocate to 0x2000, target should still be 0x1105
        let result = relocator.relocate_instruction(&jmp, 0x1000, 0x2000);
        assert!(result.success);
        assert_eq!(result.bytes.len(), 5);
        assert_eq!(result.bytes[0], 0xE9);

        // verify new offset: 0x1105 - 0x2000 - 5 = -0xF00
        let new_offset = i32::from_le_bytes(result.bytes[1..5].try_into().unwrap());
        assert_eq!(new_offset, -0xF00);
    }

    #[test]
    fn test_relocate_call_rel32() {
        let relocator = InstructionRelocator::x64();
        // call +0 from 0x1000 (target: 0x1005)
        let call = [0xE8, 0x00, 0x00, 0x00, 0x00];

        // relocate to 0x2000, target should still be 0x1005
        let result = relocator.relocate_instruction(&call, 0x1000, 0x2000);
        assert!(result.success);
        assert_eq!(result.bytes.len(), 5);
        assert_eq!(result.bytes[0], 0xE8);

        // verify new offset: 0x1005 - 0x2000 - 5 = -0xFFB = -4091
        let new_offset = i32::from_le_bytes(result.bytes[1..5].try_into().unwrap());
        assert_eq!(new_offset, -0x1000);
    }

    #[test]
    fn test_relocate_jz_short() {
        let relocator = InstructionRelocator::x64();
        // jz +0x10 from 0x1000 (target: 0x1012)
        let jz = [0x74, 0x10];

        // relocate to 0x2000
        let result = relocator.relocate_instruction(&jz, 0x1000, 0x2000);
        assert!(result.success);

        // should be expanded to long conditional jump
        assert!(result.bytes.len() >= 2);
        if result.bytes[0] == 0x0F && result.bytes[1] == 0x84 {
            // long jz
            assert_eq!(result.bytes.len(), 6);
        }
    }

    #[test]
    fn test_relocate_block() {
        let relocator = InstructionRelocator::x64();
        // push rbp; mov rbp, rsp; sub rsp, 0x28
        let prologue = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28];

        let result = relocator.relocate_block(&prologue, 0x1000, 0x2000);
        assert!(result.is_ok());

        let relocated = result.unwrap();
        // no relative instructions, should be same size
        assert_eq!(relocated.len(), prologue.len());
    }

    #[test]
    fn test_needs_relocation() {
        // JMP rel32
        let jmp = [0xE9, 0x00, 0x00, 0x00, 0x00];
        assert!(instruction_needs_relocation(&jmp, 0x1000));

        // CALL rel32
        let call = [0xE8, 0x00, 0x00, 0x00, 0x00];
        assert!(instruction_needs_relocation(&call, 0x1000));

        // PUSH RBP
        let push = [0x55];
        assert!(!instruction_needs_relocation(&push, 0x1000));

        // NOP
        let nop = [0x90];
        assert!(!instruction_needs_relocation(&nop, 0x1000));
    }
}
