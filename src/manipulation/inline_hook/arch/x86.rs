//! x86 (32-bit) architecture implementation

use super::{Architecture, DecodedInstruction};

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
        let mut offset = 0;

        while offset < required_size && offset < code.len() {
            let insn = decode_instruction_x86(&code[offset..])?;
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

        let decoded = decode_instruction_x86(instruction)?;

        if !decoded.is_relative {
            return Some(instruction[..decoded.length].to_vec());
        }

        match instruction[0] {
            // E8 - call rel32
            0xE8 => {
                if instruction.len() < 5 {
                    return None;
                }
                let orig_offset = i32::from_le_bytes(instruction[1..5].try_into().ok()?);
                let orig_target = (old_address as i32).wrapping_add(5).wrapping_add(orig_offset);
                let new_offset = (orig_target as i32)
                    .wrapping_sub((new_address as i32).wrapping_add(5));

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
                let orig_target = (old_address as i32).wrapping_add(5).wrapping_add(orig_offset);
                let new_offset = (orig_target as i32)
                    .wrapping_sub((new_address as i32).wrapping_add(5));

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
                let orig_target = (old_address as i32).wrapping_add(2).wrapping_add(orig_offset as i32);

                // try to keep as short jump
                let new_offset = (orig_target as i32)
                    .wrapping_sub((new_address as i32).wrapping_add(2));
                if new_offset >= i8::MIN as i32 && new_offset <= i8::MAX as i32 {
                    Some(vec![0xEB, new_offset as u8])
                } else {
                    // expand to jmp rel32
                    let new_offset = (orig_target as i32)
                        .wrapping_sub((new_address as i32).wrapping_add(5));
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
                let orig_target = (old_address as i32).wrapping_add(6).wrapping_add(orig_offset);
                let new_offset = (orig_target as i32)
                    .wrapping_sub((new_address as i32).wrapping_add(6));

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
                let orig_target = (old_address as i32).wrapping_add(2).wrapping_add(orig_offset as i32);

                // expand to long conditional jump
                let new_offset = (orig_target as i32)
                    .wrapping_sub((new_address as i32).wrapping_add(6));
                let long_opcode = 0x80 + (b - 0x70);
                let mut bytes = vec![0x0F, long_opcode];
                bytes.extend_from_slice(&new_offset.to_le_bytes());
                Some(bytes)
            }

            // not relative, copy as-is
            _ => Some(instruction[..decoded.length].to_vec()),
        }
    }

    fn needs_relocation(instruction: &[u8]) -> bool {
        if instruction.is_empty() {
            return false;
        }

        match instruction[0] {
            0xE8 | 0xE9 | 0xEB => true,
            0x70..=0x7F => true,
            0x0F if instruction.len() >= 2 && (0x80..=0x8F).contains(&instruction[1]) => true,
            _ => false,
        }
    }
}

/// decode a single x86 instruction
fn decode_instruction_x86(code: &[u8]) -> Option<DecodedInstruction> {
    if code.is_empty() {
        return None;
    }

    let mut offset = 0;

    // skip prefixes
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

    let opcode = code[offset];
    offset += 1;

    let (length, is_relative, relative_target) = match opcode {
        // single-byte
        0x50..=0x5F | 0x90..=0x9F | 0xC3 | 0xCC | 0xCB | 0xCF => {
            (offset, false, None)
        }

        // push imm
        0x68 => (offset + 4, false, None),
        0x6A => (offset + 1, false, None),

        // ret imm16
        0xC2 => (offset + 2, false, None),

        // call/jmp rel32
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

        // mov r32, imm32
        0xB8..=0xBF => (offset + 4, false, None),

        // mov r8, imm8
        0xB0..=0xB7 => (offset + 1, false, None),

        // two-byte opcodes
        0x0F => {
            if offset >= code.len() {
                return None;
            }
            let op2 = code[offset];
            offset += 1;

            match op2 {
                // conditional jumps rel32
                0x80..=0x8F => {
                    if code.len() < offset + 4 {
                        return None;
                    }
                    let rel = i32::from_le_bytes(code[offset..offset + 4].try_into().ok()?);
                    let target = (code.as_ptr() as usize + offset + 4).wrapping_add(rel as usize);
                    (offset + 4, true, Some(target))
                }
                // other two-byte with ModR/M
                _ => decode_modrm_x86(code, offset),
            }
        }

        // immediate group instructions: ModR/M + imm8
        0x80 | 0x83 | 0xC0 | 0xC1 => {
            let (len, is_rel, target) = decode_modrm_x86(code, offset);
            (len + 1, is_rel, target) // +1 for imm8
        }

        // immediate group instructions: ModR/M + imm32
        0x81 | 0xC7 => {
            let (len, is_rel, target) = decode_modrm_x86(code, offset);
            (len + 4, is_rel, target) // +4 for imm32
        }

        // imul r, r/m, imm8
        0x6B => {
            let (len, is_rel, target) = decode_modrm_x86(code, offset);
            (len + 1, is_rel, target)
        }

        // imul r, r/m, imm32
        0x69 => {
            let (len, is_rel, target) = decode_modrm_x86(code, offset);
            (len + 4, is_rel, target)
        }

        // mov r/m8, imm8
        0xC6 => {
            let (len, is_rel, target) = decode_modrm_x86(code, offset);
            (len + 1, is_rel, target)
        }

        // instructions with ModR/M only (no immediate)
        0x00..=0x3F | 0x84..=0x8F | 0xD0..=0xD3 | 0xF6..=0xF7
        | 0xFE..=0xFF | 0x8D => {
            decode_modrm_x86(code, offset)
        }

        // int imm8
        0xCD => (offset + 1, false, None),

        // AL/EAX + imm
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => (offset + 1, false, None),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (offset + 4, false, None),

        _ => decode_modrm_x86(code, offset),
    };

    Some(DecodedInstruction {
        length,
        is_relative,
        relative_target,
    })
}

/// decode ModR/M for x86
fn decode_modrm_x86(code: &[u8], offset: usize) -> (usize, bool, Option<usize>) {
    if offset >= code.len() {
        return (offset, false, None);
    }

    let modrm = code[offset];
    let mod_field = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    let mut len = offset + 1;

    match mod_field {
        0b00 => {
            if rm == 4 {
                len += 1; // SIB
                if len <= code.len() && (code[len - 1] & 0x07) == 5 {
                    len += 4; // disp32
                }
            } else if rm == 5 {
                len += 4; // disp32
            }
        }
        0b01 => {
            if rm == 4 {
                len += 1;
            }
            len += 1; // disp8
        }
        0b10 => {
            if rm == 4 {
                len += 1;
            }
            len += 4; // disp32
        }
        0b11 => {}
        _ => {}
    }

    (len.min(code.len()), false, None)
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
    fn test_decode_push_ebp() {
        let code = [0x55];
        let decoded = decode_instruction_x86(&code).unwrap();
        assert_eq!(decoded.length, 1);
        assert!(!decoded.is_relative);
    }

    #[test]
    fn test_decode_mov_ebp_esp() {
        // mov ebp, esp = 89 E5 (with 8B it's mov esp, ebp)
        // or mov ebp, esp = 8B EC
        let code = [0x8B, 0xEC];
        let decoded = decode_instruction_x86(&code).unwrap();
        assert_eq!(decoded.length, 2);
        assert!(!decoded.is_relative);
    }

    #[test]
    fn test_find_instruction_boundary() {
        // push ebp; mov ebp, esp; sub esp, 0x10
        let code = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let boundary = X86::find_instruction_boundary(&code, 5).unwrap();
        assert!(boundary >= 5);
    }
}
