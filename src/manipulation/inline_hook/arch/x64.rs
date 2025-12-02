//! x86_64 architecture implementation

use super::{Architecture, DecodedInstruction};

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
        let mut offset = 0;

        while offset < required_size && offset < code.len() {
            let insn = decode_instruction_x64(&code[offset..])?;
            offset += insn.length;
        }

        if offset >= required_size {
            Some(offset)
        } else {
            None
        }
    }

    fn relocate_instruction(
        instruction: &[u8],
        old_address: usize,
        new_address: usize,
    ) -> Option<Vec<u8>> {
        if instruction.is_empty() {
            return None;
        }

        let decoded = decode_instruction_x64(instruction)?;

        // if not relative, just copy as-is
        if !decoded.is_relative {
            return Some(instruction[..decoded.length].to_vec());
        }

        // handle different relative instruction types
        match instruction[0] {
            // E8 - call rel32
            0xE8 => {
                if instruction.len() < 5 {
                    return None;
                }
                let orig_offset = i32::from_le_bytes(instruction[1..5].try_into().ok()?);
                let orig_target = (old_address as i64 + 5 + orig_offset as i64) as usize;
                let new_offset = (orig_target as i64 - new_address as i64 - 5) as i32;

                let mut bytes = vec![0xE8];
                bytes.extend_from_slice(&new_offset.to_le_bytes());
                Some(bytes)
            }

            // E9 - jmp rel32
            0xE9 => {
                if instruction.len() < 5 {
                    return None;
                }
                let orig_offset = i32::from_le_bytes(instruction[1..5].try_into().ok()?);
                let orig_target = (old_address as i64 + 5 + orig_offset as i64) as usize;
                let new_offset = (orig_target as i64 - new_address as i64 - 5) as i32;

                let mut bytes = vec![0xE9];
                bytes.extend_from_slice(&new_offset.to_le_bytes());
                Some(bytes)
            }

            // EB - jmp rel8
            0xEB => {
                if instruction.len() < 2 {
                    return None;
                }
                let orig_offset = instruction[1] as i8;
                let orig_target = (old_address as i64 + 2 + orig_offset as i64) as usize;

                // try to keep as short jump if possible
                let new_offset = (orig_target as i64 - new_address as i64 - 2) as i64;
                if new_offset >= i8::MIN as i64 && new_offset <= i8::MAX as i64 {
                    Some(vec![0xEB, new_offset as u8])
                } else {
                    // expand to jmp rel32
                    let new_offset = (orig_target as i64 - new_address as i64 - 5) as i32;
                    let mut bytes = vec![0xE9];
                    bytes.extend_from_slice(&new_offset.to_le_bytes());
                    Some(bytes)
                }
            }

            // 0F 80-8F - conditional jumps rel32
            0x0F if instruction.len() >= 2 && (0x80..=0x8F).contains(&instruction[1]) => {
                if instruction.len() < 6 {
                    return None;
                }
                let orig_offset = i32::from_le_bytes(instruction[2..6].try_into().ok()?);
                let orig_target = (old_address as i64 + 6 + orig_offset as i64) as usize;
                let new_offset = (orig_target as i64 - new_address as i64 - 6) as i32;

                let mut bytes = vec![0x0F, instruction[1]];
                bytes.extend_from_slice(&new_offset.to_le_bytes());
                Some(bytes)
            }

            // 70-7F - short conditional jumps
            b if (0x70..=0x7F).contains(&b) => {
                if instruction.len() < 2 {
                    return None;
                }
                let orig_offset = instruction[1] as i8;
                let orig_target = (old_address as i64 + 2 + orig_offset as i64) as usize;

                // expand to long conditional jump
                let new_offset = (orig_target as i64 - new_address as i64 - 6) as i32;
                let long_opcode = 0x80 + (b - 0x70);
                let mut bytes = vec![0x0F, long_opcode];
                bytes.extend_from_slice(&new_offset.to_le_bytes());
                Some(bytes)
            }

            // handle RIP-relative addressing in other instructions
            _ => relocate_rip_relative_x64(instruction, old_address, new_address),
        }
    }

    fn needs_relocation(instruction: &[u8]) -> bool {
        if instruction.is_empty() {
            return false;
        }

        match instruction[0] {
            // relative jumps and calls
            0xE8 | 0xE9 | 0xEB => true,
            // short conditional jumps
            0x70..=0x7F => true,
            // long conditional jumps
            0x0F if instruction.len() >= 2 && (0x80..=0x8F).contains(&instruction[1]) => true,
            // check for RIP-relative addressing (ModR/M with mod=00, r/m=101)
            _ => has_rip_relative_addressing(instruction),
        }
    }
}

/// decode a single x64 instruction and return its properties
fn decode_instruction_x64(code: &[u8]) -> Option<DecodedInstruction> {
    if code.is_empty() {
        return None;
    }

    let mut offset = 0;

    // skip legacy prefixes
    while offset < code.len() {
        match code[offset] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                offset += 1;
            }
            _ => break,
        }
    }

    if offset >= code.len() {
        return None;
    }

    // check for REX prefix
    let has_rex = (0x40..=0x4F).contains(&code[offset]);
    if has_rex {
        offset += 1;
    }

    if offset >= code.len() {
        return None;
    }

    let opcode = code[offset];
    offset += 1;

    // decode based on opcode
    let (length, is_relative, relative_target) = match opcode {
        // single-byte instructions
        0x50..=0x5F | 0x90..=0x9F | 0xC3 | 0xCC | 0xCB | 0xCF => {
            (offset, false, None)
        }

        // push/pop with immediate
        0x68 => (offset + 4, false, None), // push imm32
        0x6A => (offset + 1, false, None), // push imm8

        // ret with immediate
        0xC2 => (offset + 2, false, None),

        // jmp/call rel32
        0xE8 | 0xE9 => {
            if code.len() < offset + 4 {
                return None;
            }
            let rel = i32::from_le_bytes(code[offset..offset + 4].try_into().ok()?);
            let target = (code.as_ptr() as usize + offset + 4).wrapping_add(rel as usize);
            (offset + 4, true, Some(target))
        }

        // jmp rel8
        0xEB => {
            if code.len() < offset + 1 {
                return None;
            }
            let rel = code[offset] as i8;
            let target = (code.as_ptr() as usize + offset + 1).wrapping_add(rel as usize);
            (offset + 1, true, Some(target))
        }

        // short conditional jumps
        0x70..=0x7F => {
            if code.len() < offset + 1 {
                return None;
            }
            let rel = code[offset] as i8;
            let target = (code.as_ptr() as usize + offset + 1).wrapping_add(rel as usize);
            (offset + 1, true, Some(target))
        }

        // mov r64, imm64 (REX.W + B8+rd)
        0xB8..=0xBF if has_rex && (code[offset - 2] & 0x08) != 0 => {
            (offset + 8, false, None)
        }

        // mov r32, imm32
        0xB8..=0xBF => (offset + 4, false, None),

        // mov r8, imm8
        0xB0..=0xB7 => (offset + 1, false, None),

        // two-byte opcodes (0F xx)
        0x0F => {
            if offset >= code.len() {
                return None;
            }
            let op2 = code[offset];
            offset += 1;

            match op2 {
                // long conditional jumps
                0x80..=0x8F => {
                    if code.len() < offset + 4 {
                        return None;
                    }
                    let rel = i32::from_le_bytes(code[offset..offset + 4].try_into().ok()?);
                    let target = (code.as_ptr() as usize + offset + 4).wrapping_add(rel as usize);
                    (offset + 4, true, Some(target))
                }
                // setcc
                0x90..=0x9F => decode_modrm_instruction(code, offset, has_rex),
                // cmovcc
                0x40..=0x4F => decode_modrm_instruction(code, offset, has_rex),
                // movzx/movsx
                0xB6 | 0xB7 | 0xBE | 0xBF => decode_modrm_instruction(code, offset, has_rex),
                // other two-byte with ModR/M
                _ => decode_modrm_instruction(code, offset, has_rex),
            }
        }

        // immediate group instructions: ModR/M + imm8
        0x80 | 0x83 | 0xC0 | 0xC1 => {
            let (len, is_rel, target) = decode_modrm_instruction(code, offset, has_rex);
            (len + 1, is_rel, target) // +1 for imm8
        }

        // immediate group instructions: ModR/M + imm32
        0x81 | 0xC7 => {
            let (len, is_rel, target) = decode_modrm_instruction(code, offset, has_rex);
            (len + 4, is_rel, target) // +4 for imm32
        }

        // imul r, r/m, imm8
        0x6B => {
            let (len, is_rel, target) = decode_modrm_instruction(code, offset, has_rex);
            (len + 1, is_rel, target)
        }

        // imul r, r/m, imm32
        0x69 => {
            let (len, is_rel, target) = decode_modrm_instruction(code, offset, has_rex);
            (len + 4, is_rel, target)
        }

        // mov r/m8, imm8
        0xC6 => {
            let (len, is_rel, target) = decode_modrm_instruction(code, offset, has_rex);
            (len + 1, is_rel, target)
        }

        // instructions with ModR/M byte only (no immediate)
        0x00..=0x3F | 0x84..=0x8F | 0xD0..=0xD3 | 0xF6..=0xF7
        | 0xFE..=0xFF | 0x63 | 0x8D => {
            decode_modrm_instruction(code, offset, has_rex)
        }

        // int3
        0xCC => (offset, false, None),

        // int imm8
        0xCD => (offset + 1, false, None),

        // instructions with immediate
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => (offset + 1, false, None), // AL, imm8
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (offset + 4, false, None), // EAX, imm32

        // default: try ModR/M decode
        _ => decode_modrm_instruction(code, offset, has_rex),
    };

    Some(DecodedInstruction {
        length,
        is_relative,
        relative_target,
    })
}

/// decode ModR/M-based instruction length
fn decode_modrm_instruction(code: &[u8], offset: usize, _has_rex: bool) -> (usize, bool, Option<usize>) {
    if offset >= code.len() {
        return (offset, false, None);
    }

    let modrm = code[offset];
    let mod_field = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    let mut len = offset + 1; // +1 for ModR/M

    // check for RIP-relative (mod=00, rm=101)
    let is_rip_relative = mod_field == 0 && rm == 5;

    match mod_field {
        0b00 => {
            if rm == 4 {
                // SIB byte follows
                len += 1;
                if len <= code.len() && (code[len - 1] & 0x07) == 5 {
                    len += 4; // disp32 with SIB base=5
                }
            } else if rm == 5 {
                len += 4; // RIP-relative disp32
            }
        }
        0b01 => {
            if rm == 4 {
                len += 1; // SIB
            }
            len += 1; // disp8
        }
        0b10 => {
            if rm == 4 {
                len += 1; // SIB
            }
            len += 4; // disp32
        }
        0b11 => {
            // register-direct, no additional bytes
        }
        _ => {}
    }

    (len.min(code.len()), is_rip_relative, None)
}

/// check if instruction uses RIP-relative addressing
fn has_rip_relative_addressing(instruction: &[u8]) -> bool {
    if instruction.is_empty() {
        return false;
    }

    let mut offset = 0;

    // skip prefixes
    while offset < instruction.len() {
        match instruction[offset] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                offset += 1;
            }
            _ => break,
        }
    }

    // skip REX
    if offset < instruction.len() && (0x40..=0x4F).contains(&instruction[offset]) {
        offset += 1;
    }

    if offset >= instruction.len() {
        return false;
    }

    // skip opcode(s)
    let opcode = instruction[offset];
    offset += 1;

    if opcode == 0x0F && offset < instruction.len() {
        offset += 1; // two-byte opcode
    }

    // check ModR/M
    if offset >= instruction.len() {
        return false;
    }

    let modrm = instruction[offset];
    let mod_field = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    // RIP-relative: mod=00, rm=101
    mod_field == 0 && rm == 5
}

/// relocate RIP-relative instructions
fn relocate_rip_relative_x64(
    instruction: &[u8],
    old_address: usize,
    new_address: usize,
) -> Option<Vec<u8>> {
    if !has_rip_relative_addressing(instruction) {
        // not RIP-relative, copy as-is
        return Some(instruction.to_vec());
    }

    let decoded = decode_instruction_x64(instruction)?;
    let mut result = instruction[..decoded.length].to_vec();

    // find ModR/M offset
    let mut modrm_offset = 0;

    // skip prefixes
    while modrm_offset < result.len() {
        match result[modrm_offset] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                modrm_offset += 1;
            }
            _ => break,
        }
    }

    // skip REX
    if modrm_offset < result.len() && (0x40..=0x4F).contains(&result[modrm_offset]) {
        modrm_offset += 1;
    }

    // skip opcode(s)
    if modrm_offset < result.len() {
        modrm_offset += 1;
        if result[modrm_offset - 1] == 0x0F && modrm_offset < result.len() {
            modrm_offset += 1;
        }
    }

    // modrm_offset now points to ModR/M byte
    if modrm_offset >= result.len() {
        return Some(result);
    }

    // disp32 follows ModR/M for RIP-relative
    let disp_offset = modrm_offset + 1;
    if disp_offset + 4 > result.len() {
        return Some(result);
    }

    // read original displacement
    let orig_disp = i32::from_le_bytes(result[disp_offset..disp_offset + 4].try_into().ok()?);

    // calculate original absolute target
    let insn_end = old_address + decoded.length;
    let orig_target = (insn_end as i64 + orig_disp as i64) as usize;

    // calculate new displacement
    let new_insn_end = new_address + decoded.length;
    let new_disp = (orig_target as i64 - new_insn_end as i64) as i32;

    // check if new displacement fits in 32 bits
    let target_diff = orig_target as i64 - new_insn_end as i64;
    if target_diff < i32::MIN as i64 || target_diff > i32::MAX as i64 {
        // can't relocate - target too far
        return None;
    }

    // write new displacement
    result[disp_offset..disp_offset + 4].copy_from_slice(&new_disp.to_le_bytes());

    Some(result)
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
    fn test_decode_push_rbp() {
        // push rbp = 55
        let code = [0x55];
        let decoded = decode_instruction_x64(&code).unwrap();
        assert_eq!(decoded.length, 1);
        assert!(!decoded.is_relative);
    }

    #[test]
    fn test_decode_mov_rbp_rsp() {
        // mov rbp, rsp = 48 89 E5
        let code = [0x48, 0x89, 0xE5];
        let decoded = decode_instruction_x64(&code).unwrap();
        assert_eq!(decoded.length, 3);
        assert!(!decoded.is_relative);
    }

    #[test]
    fn test_decode_sub_rsp_imm8() {
        // sub rsp, 0x28 = 48 83 EC 28
        let code = [0x48, 0x83, 0xEC, 0x28];
        let decoded = decode_instruction_x64(&code).unwrap();
        assert_eq!(decoded.length, 4);
        assert!(!decoded.is_relative);
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
}
