//! Instruction length decoder
//!
//! Provides instruction length detection for x86/x64 instructions,
//! used to find safe hook points at instruction boundaries.

/// information about a decoded instruction
#[derive(Debug, Clone)]
pub struct InstructionInfo {
    /// length of the instruction in bytes
    pub length: usize,
    /// whether the instruction uses relative addressing
    pub is_relative: bool,
    /// whether the instruction is a control flow instruction (jmp, call, ret)
    pub is_control_flow: bool,
    /// for relative instructions, the computed target address (if calculable)
    pub relative_target: Option<usize>,
}

/// decode instruction at given address
///
/// returns instruction info or None if decoding fails
#[cfg(target_arch = "x86_64")]
pub fn decode_instruction(address: usize, max_bytes: usize) -> Option<InstructionInfo> {
    if max_bytes == 0 {
        return None;
    }

    // SAFETY: caller must ensure address is valid readable memory
    let code = unsafe { core::slice::from_raw_parts(address as *const u8, max_bytes.min(15)) };

    decode_x64(code)
}

#[cfg(target_arch = "x86")]
pub fn decode_instruction(address: usize, max_bytes: usize) -> Option<InstructionInfo> {
    if max_bytes == 0 {
        return None;
    }

    let code = unsafe { core::slice::from_raw_parts(address as *const u8, max_bytes.min(15)) };

    decode_x86(code)
}

/// decode x64 instruction from bytes
#[cfg(target_arch = "x86_64")]
fn decode_x64(code: &[u8]) -> Option<InstructionInfo> {
    if code.is_empty() {
        return None;
    }

    let mut offset = 0;

    // skip legacy prefixes (group 1-4)
    while offset < code.len() {
        match code[offset] {
            // segment overrides
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => offset += 1,
            // operand size / address size
            0x66 | 0x67 => offset += 1,
            // lock / rep
            0xF0 | 0xF2 | 0xF3 => offset += 1,
            _ => break,
        }
    }

    if offset >= code.len() {
        return None;
    }

    // check for REX prefix (0x40-0x4F)
    let has_rex = (0x40..=0x4F).contains(&code[offset]);
    let rex_w = has_rex && (code[offset] & 0x08) != 0;
    if has_rex {
        offset += 1;
    }

    if offset >= code.len() {
        return None;
    }

    let opcode = code[offset];
    offset += 1;

    match opcode {
        // single-byte instructions
        0x50..=0x5F => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // NOP, XCHG AX,AX
        0x90 => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // RET
        0xC3 => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        // RET imm16
        0xC2 => Some(InstructionInfo {
            length: offset + 2,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        // INT3
        0xCC => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        // CALL rel32
        0xE8 => {
            if code.len() < offset + 4 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 4,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        // JMP rel32
        0xE9 => {
            if code.len() < offset + 4 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 4,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        // JMP rel8
        0xEB => {
            if code.len() < offset + 1 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 1,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        // short conditional jumps (Jcc rel8)
        0x70..=0x7F => {
            if code.len() < offset + 1 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 1,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        // PUSH imm32
        0x68 => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // PUSH imm8
        0x6A => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // MOV r64, imm64 (with REX.W)
        0xB8..=0xBF if rex_w => Some(InstructionInfo {
            length: offset + 8,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // MOV r32, imm32
        0xB8..=0xBF => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // MOV r8, imm8
        0xB0..=0xB7 => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // two-byte opcodes (0F xx)
        0x0F => {
            if offset >= code.len() {
                return None;
            }
            let op2 = code[offset];
            offset += 1;

            match op2 {
                // Jcc rel32 (long conditional jumps)
                0x80..=0x8F => {
                    if code.len() < offset + 4 {
                        return None;
                    }
                    Some(InstructionInfo {
                        length: offset + 4,
                        is_relative: true,
                        is_control_flow: true,
                        relative_target: None,
                    })
                }

                // SETcc rm8
                0x90..=0x9F => decode_modrm(code, offset, has_rex, false, false),

                // CMOVcc r, rm
                0x40..=0x4F => decode_modrm(code, offset, has_rex, false, false),

                // MOVZX/MOVSX
                0xB6 | 0xB7 | 0xBE | 0xBF => decode_modrm(code, offset, has_rex, false, false),

                // SYSCALL
                0x05 => Some(InstructionInfo {
                    length: offset,
                    is_relative: false,
                    is_control_flow: true,
                    relative_target: None,
                }),

                // other two-byte with ModR/M
                _ => decode_modrm(code, offset, has_rex, false, false),
            }
        }

        // instructions with ModR/M
        0x00..=0x3F | 0x63 | 0x69 | 0x6B | 0x80..=0x8F | 0x8D | 0xC0..=0xC1 | 0xC6..=0xC7
        | 0xD0..=0xD3 | 0xF6..=0xF7 | 0xFE..=0xFF => {
            let has_imm8 = matches!(opcode, 0x80 | 0x83 | 0xC0 | 0xC1 | 0xC6 | 0x6B);
            let has_imm32 = matches!(opcode, 0x81 | 0xC7 | 0x69);
            decode_modrm(code, offset, has_rex, has_imm8, has_imm32)
        }

        // AL/AX/EAX/RAX immediate operations
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | 0xA8 => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0xA9 => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // INT imm8
        0xCD => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        // LEAVE
        0xC9 => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        // default: try ModR/M decode
        _ => decode_modrm(code, offset, has_rex, false, false),
    }
}

/// decode x86 instruction
#[cfg(target_arch = "x86")]
fn decode_x86(code: &[u8]) -> Option<InstructionInfo> {
    if code.is_empty() {
        return None;
    }

    let mut offset = 0;

    // skip prefixes
    while offset < code.len() {
        match code[offset] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                offset += 1
            }
            _ => break,
        }
    }

    if offset >= code.len() {
        return None;
    }

    let opcode = code[offset];
    offset += 1;

    match opcode {
        0x50..=0x5F | 0x90 | 0xC3 | 0xCC => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: matches!(opcode, 0xC3 | 0xCC),
            relative_target: None,
        }),

        0xC2 => Some(InstructionInfo {
            length: offset + 2,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        0xE8 | 0xE9 => {
            if code.len() < offset + 4 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 4,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        0xEB | 0x70..=0x7F => {
            if code.len() < offset + 1 {
                return None;
            }
            Some(InstructionInfo {
                length: offset + 1,
                is_relative: true,
                is_control_flow: true,
                relative_target: None,
            })
        }

        0x68 => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0x6A => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0xB8..=0xBF => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0xB0..=0xB7 => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0x0F => {
            if offset >= code.len() {
                return None;
            }
            let op2 = code[offset];
            offset += 1;

            if (0x80..=0x8F).contains(&op2) {
                if code.len() < offset + 4 {
                    return None;
                }
                Some(InstructionInfo {
                    length: offset + 4,
                    is_relative: true,
                    is_control_flow: true,
                    relative_target: None,
                })
            } else {
                decode_modrm(code, offset, false, false, false)
            }
        }

        0x00..=0x3F | 0x69 | 0x6B | 0x80..=0x8F | 0x8D | 0xC0..=0xC1 | 0xC6..=0xC7
        | 0xD0..=0xD3 | 0xF6..=0xF7 | 0xFE..=0xFF => {
            let has_imm8 = matches!(opcode, 0x80 | 0x83 | 0xC0 | 0xC1 | 0xC6 | 0x6B);
            let has_imm32 = matches!(opcode, 0x81 | 0xC7 | 0x69);
            decode_modrm(code, offset, false, has_imm8, has_imm32)
        }

        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | 0xA8 => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0xA9 => Some(InstructionInfo {
            length: offset + 4,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        0xCD => Some(InstructionInfo {
            length: offset + 1,
            is_relative: false,
            is_control_flow: true,
            relative_target: None,
        }),

        0xC9 => Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        }),

        _ => decode_modrm(code, offset, false, false, false),
    }
}

/// decode ModR/M byte and compute total instruction length
fn decode_modrm(
    code: &[u8],
    offset: usize,
    has_rex: bool,
    has_imm8: bool,
    has_imm32: bool,
) -> Option<InstructionInfo> {
    if offset >= code.len() {
        return Some(InstructionInfo {
            length: offset,
            is_relative: false,
            is_control_flow: false,
            relative_target: None,
        });
    }

    let modrm = code[offset];
    let mod_field = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    let mut len = offset + 1;

    // check for RIP-relative on x64 (mod=00, rm=101)
    #[cfg(target_arch = "x86_64")]
    let is_rip_relative = mod_field == 0 && rm == 5;
    #[cfg(target_arch = "x86")]
    let is_rip_relative = false;

    match mod_field {
        0b00 => {
            if rm == 4 {
                // SIB byte
                if len < code.len() {
                    let sib = code[len];
                    len += 1;
                    let base = sib & 0x07;
                    if base == 5 {
                        len += 4; // disp32 when base=5
                    }
                }
            } else if rm == 5 {
                len += 4; // disp32 (or RIP-relative on x64)
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
            // register direct, no extra bytes
        }
        _ => {}
    }

    // add immediate if present
    if has_imm8 {
        len += 1;
    }
    if has_imm32 {
        len += 4;
    }

    let _ = has_rex; // used only for x64

    Some(InstructionInfo {
        length: len.min(code.len()),
        is_relative: is_rip_relative,
        is_control_flow: false,
        relative_target: None,
    })
}

/// find instruction boundary at or after required_size
///
/// scans instructions starting at address until we have at least required_size bytes
pub fn find_boundary(address: usize, required_size: usize, max_scan: usize) -> Option<usize> {
    let mut current = address;
    let mut total = 0;

    while total < required_size && (current - address) < max_scan {
        let info = decode_instruction(current, max_scan - (current - address))?;
        total += info.length;
        current += info.length;
    }

    if total >= required_size {
        Some(total)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop() {
        let code = [0x90u8];
        #[cfg(target_arch = "x86_64")]
        let info = decode_x64(&code).unwrap();
        #[cfg(target_arch = "x86")]
        let info = decode_x86(&code).unwrap();

        assert_eq!(info.length, 1);
        assert!(!info.is_relative);
    }

    #[test]
    fn test_decode_push_pop() {
        // push rbp/ebp
        let push = [0x55u8];
        #[cfg(target_arch = "x86_64")]
        let info = decode_x64(&push).unwrap();
        #[cfg(target_arch = "x86")]
        let info = decode_x86(&push).unwrap();
        assert_eq!(info.length, 1);

        // pop rbp/ebp
        let pop = [0x5Du8];
        #[cfg(target_arch = "x86_64")]
        let info = decode_x64(&pop).unwrap();
        #[cfg(target_arch = "x86")]
        let info = decode_x86(&pop).unwrap();
        assert_eq!(info.length, 1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_decode_mov_rbp_rsp() {
        // mov rbp, rsp = 48 89 E5
        let code = [0x48, 0x89, 0xE5];
        let info = decode_x64(&code).unwrap();
        assert_eq!(info.length, 3);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_decode_sub_rsp_imm8() {
        // sub rsp, 0x28 = 48 83 EC 28
        let code = [0x48, 0x83, 0xEC, 0x28];
        let info = decode_x64(&code).unwrap();
        assert_eq!(info.length, 4);
    }

    #[test]
    fn test_decode_jmp_rel32() {
        let code = [0xE9, 0x00, 0x00, 0x00, 0x00];
        #[cfg(target_arch = "x86_64")]
        let info = decode_x64(&code).unwrap();
        #[cfg(target_arch = "x86")]
        let info = decode_x86(&code).unwrap();
        assert_eq!(info.length, 5);
        assert!(info.is_relative);
        assert!(info.is_control_flow);
    }

    #[test]
    fn test_decode_call_rel32() {
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00];
        #[cfg(target_arch = "x86_64")]
        let info = decode_x64(&code).unwrap();
        #[cfg(target_arch = "x86")]
        let info = decode_x86(&code).unwrap();
        assert_eq!(info.length, 5);
        assert!(info.is_relative);
        assert!(info.is_control_flow);
    }
}
