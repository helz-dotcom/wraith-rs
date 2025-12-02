//! Instruction decoding using iced-x86
//!
//! Provides comprehensive instruction decoding with full support for
//! all x86/x64 instructions, including proper handling of:
//! - Instruction lengths
//! - Relative addressing (RIP-relative, branches)
//! - Control flow analysis
//! - Instruction operand information

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};

/// decoded instruction with full metadata
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// the raw iced-x86 instruction
    pub inner: Instruction,
    /// instruction length in bytes
    pub length: usize,
    /// whether instruction uses relative addressing that needs relocation
    pub is_relative: bool,
    /// whether this is a control flow instruction (branch, call, ret)
    pub is_control_flow: bool,
    /// for relative instructions, the computed absolute target address
    pub branch_target: Option<u64>,
    /// whether this is a RIP-relative memory access
    pub is_rip_relative: bool,
    /// for RIP-relative access, the displacement offset within the instruction
    pub rip_disp_offset: Option<usize>,
    /// for RIP-relative access, the displacement size
    pub rip_disp_size: Option<usize>,
    /// computed absolute address for RIP-relative access
    pub rip_target: Option<u64>,
}

impl DecodedInstruction {
    /// check if instruction can be safely relocated
    pub fn is_relocatable(&self) -> bool {
        if !self.is_relative && !self.is_rip_relative {
            return true;
        }

        match self.inner.flow_control() {
            FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt => false,
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                self.is_rip_relative
            }
            _ => true,
        }
    }

    /// get the instruction mnemonic
    pub fn mnemonic(&self) -> iced_x86::Mnemonic {
        self.inner.mnemonic()
    }
}

/// instruction decoder using iced-x86
pub struct InstructionDecoder {
    bitness: u32,
}

impl InstructionDecoder {
    /// create decoder for current architecture
    #[cfg(target_arch = "x86_64")]
    pub fn native() -> Self {
        Self { bitness: 64 }
    }

    #[cfg(target_arch = "x86")]
    pub fn native() -> Self {
        Self { bitness: 32 }
    }

    /// create 64-bit decoder
    pub fn x64() -> Self {
        Self { bitness: 64 }
    }

    /// create 32-bit decoder
    pub fn x86() -> Self {
        Self { bitness: 32 }
    }

    /// decode a single instruction at the given address
    pub fn decode_at(&self, address: usize, bytes: &[u8]) -> Option<DecodedInstruction> {
        if bytes.is_empty() {
            return None;
        }

        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            address as u64,
            DecoderOptions::NONE,
        );

        if !decoder.can_decode() {
            return None;
        }

        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }

        Some(self.analyze_instruction(instruction, address))
    }

    /// decode all instructions in the byte slice
    pub fn decode_all(&self, address: usize, bytes: &[u8]) -> Vec<DecodedInstruction> {
        let mut result = Vec::new();
        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            address as u64,
            DecoderOptions::NONE,
        );

        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            result.push(self.analyze_instruction(instruction, instruction.ip() as usize));
        }

        result
    }

    /// decode instructions until we have at least min_bytes
    pub fn decode_until_size(
        &self,
        address: usize,
        bytes: &[u8],
        min_bytes: usize,
    ) -> Vec<DecodedInstruction> {
        let mut result = Vec::new();
        let mut total_size = 0;

        let mut decoder = Decoder::with_ip(
            self.bitness,
            bytes,
            address as u64,
            DecoderOptions::NONE,
        );

        while decoder.can_decode() && total_size < min_bytes {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            let decoded = self.analyze_instruction(instruction, instruction.ip() as usize);
            total_size += decoded.length;
            result.push(decoded);
        }

        result
    }

    /// find instruction boundary at or after required_size
    pub fn find_boundary(&self, address: usize, bytes: &[u8], required_size: usize) -> Option<usize> {
        let instructions = self.decode_until_size(address, bytes, required_size);
        if instructions.is_empty() {
            return None;
        }

        let total: usize = instructions.iter().map(|i| i.length).sum();
        if total >= required_size {
            Some(total)
        } else {
            None
        }
    }

    fn analyze_instruction(&self, instruction: Instruction, address: usize) -> DecodedInstruction {
        let length = instruction.len();
        let flow = instruction.flow_control();

        let is_control_flow = matches!(
            flow,
            FlowControl::UnconditionalBranch
                | FlowControl::ConditionalBranch
                | FlowControl::Call
                | FlowControl::IndirectBranch
                | FlowControl::IndirectCall
                | FlowControl::Return
                | FlowControl::Interrupt
                | FlowControl::XbeginXabortXend
                | FlowControl::Exception
        );

        let mut is_relative = false;
        let mut branch_target = None;

        match flow {
            FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call => {
                if instruction.op0_kind() == OpKind::NearBranch16
                    || instruction.op0_kind() == OpKind::NearBranch32
                    || instruction.op0_kind() == OpKind::NearBranch64
                {
                    is_relative = true;
                    branch_target = Some(instruction.near_branch_target());
                }
            }
            FlowControl::IndirectBranch | FlowControl::IndirectCall => {
                // check if using RIP-relative addressing
            }
            _ => {}
        }

        // check for RIP-relative memory access
        let mut is_rip_relative = false;
        let mut rip_disp_offset = None;
        let mut rip_disp_size = None;
        let mut rip_target = None;

        if self.bitness == 64 {
            for i in 0..instruction.op_count() {
                if instruction.op_kind(i) == OpKind::Memory {
                    if instruction.is_ip_rel_memory_operand() {
                        is_rip_relative = true;
                        is_relative = true;

                        // calculate displacement offset and target
                        let disp = instruction.memory_displacement64();
                        rip_target = Some(instruction.ip_rel_memory_address());

                        // find displacement offset in instruction bytes
                        // for RIP-relative, displacement is always 4 bytes and comes
                        // after ModR/M (and optionally SIB)
                        rip_disp_size = Some(4);

                        // the displacement offset is instruction length - 4 (for disp32)
                        // minus any immediate operand size
                        let imm_size = get_immediate_size(&instruction);
                        if length > 4 + imm_size {
                            rip_disp_offset = Some(length - 4 - imm_size);
                        }
                    }
                    break;
                }
            }
        }

        DecodedInstruction {
            inner: instruction,
            length,
            is_relative,
            is_control_flow,
            branch_target,
            is_rip_relative,
            rip_disp_offset,
            rip_disp_size,
            rip_target,
        }
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

/// convenience function to decode a single instruction
pub fn decode_one(address: usize, bytes: &[u8]) -> Option<DecodedInstruction> {
    InstructionDecoder::native().decode_at(address, bytes)
}

/// convenience function to find instruction boundary
pub fn find_instruction_boundary(address: usize, bytes: &[u8], required_size: usize) -> Option<usize> {
    InstructionDecoder::native().find_boundary(address, bytes, required_size)
}

/// check if instruction at address uses relative addressing
pub fn uses_relative_addressing(address: usize, bytes: &[u8]) -> bool {
    decode_one(address, bytes)
        .map(|i| i.is_relative)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        let decoder = InstructionDecoder::x64();
        let nop = [0x90u8];
        let decoded = decoder.decode_at(0x1000, &nop).unwrap();

        assert_eq!(decoded.length, 1);
        assert!(!decoded.is_relative);
        assert!(!decoded.is_control_flow);
    }

    #[test]
    fn test_decode_jmp_rel32() {
        let decoder = InstructionDecoder::x64();
        // jmp +0x100 from 0x1000 -> target 0x1105
        let jmp = [0xE9, 0x00, 0x01, 0x00, 0x00];
        let decoded = decoder.decode_at(0x1000, &jmp).unwrap();

        assert_eq!(decoded.length, 5);
        assert!(decoded.is_relative);
        assert!(decoded.is_control_flow);
        assert_eq!(decoded.branch_target, Some(0x1105));
    }

    #[test]
    fn test_decode_call_rel32() {
        let decoder = InstructionDecoder::x64();
        // call +0 from 0x1000 -> target 0x1005
        let call = [0xE8, 0x00, 0x00, 0x00, 0x00];
        let decoded = decoder.decode_at(0x1000, &call).unwrap();

        assert_eq!(decoded.length, 5);
        assert!(decoded.is_relative);
        assert!(decoded.is_control_flow);
        assert_eq!(decoded.branch_target, Some(0x1005));
    }

    #[test]
    fn test_decode_push_rbp() {
        let decoder = InstructionDecoder::x64();
        let push = [0x55u8];
        let decoded = decoder.decode_at(0x1000, &push).unwrap();

        assert_eq!(decoded.length, 1);
        assert!(!decoded.is_relative);
        assert!(!decoded.is_control_flow);
    }

    #[test]
    fn test_decode_mov_rbp_rsp() {
        let decoder = InstructionDecoder::x64();
        // mov rbp, rsp = 48 89 E5
        let mov = [0x48, 0x89, 0xE5];
        let decoded = decoder.decode_at(0x1000, &mov).unwrap();

        assert_eq!(decoded.length, 3);
        assert!(!decoded.is_relative);
    }

    #[test]
    fn test_decode_sub_rsp_imm8() {
        let decoder = InstructionDecoder::x64();
        // sub rsp, 0x28 = 48 83 EC 28
        let sub = [0x48, 0x83, 0xEC, 0x28];
        let decoded = decoder.decode_at(0x1000, &sub).unwrap();

        assert_eq!(decoded.length, 4);
        assert!(!decoded.is_relative);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_decode_rip_relative() {
        let decoder = InstructionDecoder::x64();
        // mov rax, [rip+0x12345678]
        // 48 8B 05 78 56 34 12
        let mov = [0x48, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12];
        let decoded = decoder.decode_at(0x1000, &mov).unwrap();

        assert_eq!(decoded.length, 7);
        assert!(decoded.is_rip_relative);
        assert!(decoded.is_relative);
        // target = IP + insn_len + disp = 0x1000 + 7 + 0x12345678 = 0x1234667F
        assert_eq!(decoded.rip_target, Some(0x1234667F));
    }

    #[test]
    fn test_find_boundary() {
        let decoder = InstructionDecoder::x64();
        // typical x64 prologue: push rbp; mov rbp, rsp; sub rsp, 0x28
        let prologue = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28];

        let boundary = decoder.find_boundary(0x1000, &prologue, 5).unwrap();
        assert!(boundary >= 5);
        assert!(boundary <= 8);
    }

    #[test]
    fn test_decode_conditional_jump() {
        let decoder = InstructionDecoder::x64();
        // jz +0x10 (short)
        let jz_short = [0x74, 0x10];
        let decoded = decoder.decode_at(0x1000, &jz_short).unwrap();

        assert_eq!(decoded.length, 2);
        assert!(decoded.is_relative);
        assert!(decoded.is_control_flow);
        assert_eq!(decoded.branch_target, Some(0x1012));
    }

    #[test]
    fn test_decode_long_conditional_jump() {
        let decoder = InstructionDecoder::x64();
        // jz +0x100 (near)
        let jz_near = [0x0F, 0x84, 0x00, 0x01, 0x00, 0x00];
        let decoded = decoder.decode_at(0x1000, &jz_near).unwrap();

        assert_eq!(decoded.length, 6);
        assert!(decoded.is_relative);
        assert!(decoded.is_control_flow);
        assert_eq!(decoded.branch_target, Some(0x1106));
    }
}
