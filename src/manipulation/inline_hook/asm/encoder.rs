//! Instruction encoding utilities
//!
//! Provides a builder-style API for constructing x86/x64 instruction sequences.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// instruction encoder with builder API
pub struct Encoder {
    buffer: Vec<u8>,
}

impl Encoder {
    /// create new empty encoder
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(64),
        }
    }

    /// create encoder with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// get the encoded bytes
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// consume encoder and return bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    /// get current length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// append raw bytes
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// append single byte
    pub fn byte(&mut self, b: u8) -> &mut Self {
        self.buffer.push(b);
        self
    }

    // === x86/x64 common instructions ===

    /// NOP (single byte)
    pub fn nop(&mut self) -> &mut Self {
        self.buffer.push(0x90);
        self
    }

    /// multi-byte NOP sled
    pub fn nop_sled(&mut self, count: usize) -> &mut Self {
        let mut remaining = count;
        while remaining > 0 {
            match remaining {
                1 => {
                    self.buffer.push(0x90);
                    remaining -= 1;
                }
                2 => {
                    self.buffer.extend_from_slice(&[0x66, 0x90]);
                    remaining -= 2;
                }
                3 => {
                    self.buffer.extend_from_slice(&[0x0F, 0x1F, 0x00]);
                    remaining -= 3;
                }
                4 => {
                    self.buffer.extend_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
                    remaining -= 4;
                }
                5 => {
                    self.buffer
                        .extend_from_slice(&[0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 5;
                }
                6 => {
                    self.buffer
                        .extend_from_slice(&[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]);
                    remaining -= 6;
                }
                7 => {
                    self.buffer
                        .extend_from_slice(&[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 7;
                }
                _ => {
                    self.buffer
                        .extend_from_slice(&[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    remaining -= 8;
                }
            }
        }
        self
    }

    /// INT3 breakpoint
    pub fn int3(&mut self) -> &mut Self {
        self.buffer.push(0xCC);
        self
    }

    /// RET (near return)
    pub fn ret(&mut self) -> &mut Self {
        self.buffer.push(0xC3);
        self
    }

    /// PUSH imm32
    pub fn push_imm32(&mut self, value: u32) -> &mut Self {
        self.buffer.push(0x68);
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// PUSH imm8 (sign-extended)
    pub fn push_imm8(&mut self, value: i8) -> &mut Self {
        self.buffer.push(0x6A);
        self.buffer.push(value as u8);
        self
    }

    /// JMP rel32 (5 bytes)
    pub fn jmp_rel32(&mut self, from: usize, to: usize) -> &mut Self {
        let offset = (to as i64 - from as i64 - 5) as i32;
        self.buffer.push(0xE9);
        self.buffer.extend_from_slice(&offset.to_le_bytes());
        self
    }

    /// JMP rel8 (2 bytes)
    pub fn jmp_rel8(&mut self, offset: i8) -> &mut Self {
        self.buffer.push(0xEB);
        self.buffer.push(offset as u8);
        self
    }

    /// CALL rel32 (5 bytes)
    pub fn call_rel32(&mut self, from: usize, to: usize) -> &mut Self {
        let offset = (to as i64 - from as i64 - 5) as i32;
        self.buffer.push(0xE8);
        self.buffer.extend_from_slice(&offset.to_le_bytes());
        self
    }

    // === x64-specific instructions ===

    /// JMP [RIP+0] with absolute address (14 bytes, x64)
    #[cfg(target_arch = "x86_64")]
    pub fn jmp_abs64(&mut self, target: u64) -> &mut Self {
        // FF 25 00 00 00 00 = jmp qword ptr [rip+0]
        self.buffer
            .extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        self.buffer.extend_from_slice(&target.to_le_bytes());
        self
    }

    /// MOV RAX, imm64 (10 bytes, x64)
    #[cfg(target_arch = "x86_64")]
    pub fn mov_rax_imm64(&mut self, value: u64) -> &mut Self {
        // 48 B8 = REX.W MOV RAX, imm64
        self.buffer.extend_from_slice(&[0x48, 0xB8]);
        self.buffer.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// JMP RAX (2 bytes, x64)
    #[cfg(target_arch = "x86_64")]
    pub fn jmp_rax(&mut self) -> &mut Self {
        // FF E0 = jmp rax
        self.buffer.extend_from_slice(&[0xFF, 0xE0]);
        self
    }

    /// CALL RAX (2 bytes, x64)
    #[cfg(target_arch = "x86_64")]
    pub fn call_rax(&mut self) -> &mut Self {
        // FF D0 = call rax
        self.buffer.extend_from_slice(&[0xFF, 0xD0]);
        self
    }

    /// CALL [RIP+0] with absolute address (14 bytes, x64)
    #[cfg(target_arch = "x86_64")]
    pub fn call_abs64(&mut self, target: u64) -> &mut Self {
        // FF 15 00 00 00 00 = call qword ptr [rip+0]
        self.buffer
            .extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]);
        self.buffer.extend_from_slice(&target.to_le_bytes());
        self
    }

    /// PUSH RAX (x64)
    #[cfg(target_arch = "x86_64")]
    pub fn push_rax(&mut self) -> &mut Self {
        self.buffer.push(0x50);
        self
    }

    /// POP RAX (x64)
    #[cfg(target_arch = "x86_64")]
    pub fn pop_rax(&mut self) -> &mut Self {
        self.buffer.push(0x58);
        self
    }

    /// SUB RSP, imm8 (x64)
    #[cfg(target_arch = "x86_64")]
    pub fn sub_rsp_imm8(&mut self, value: i8) -> &mut Self {
        // 48 83 EC XX
        self.buffer.extend_from_slice(&[0x48, 0x83, 0xEC]);
        self.buffer.push(value as u8);
        self
    }

    /// ADD RSP, imm8 (x64)
    #[cfg(target_arch = "x86_64")]
    pub fn add_rsp_imm8(&mut self, value: i8) -> &mut Self {
        // 48 83 C4 XX
        self.buffer.extend_from_slice(&[0x48, 0x83, 0xC4]);
        self.buffer.push(value as u8);
        self
    }

    // === x86-specific instructions ===

    /// PUSH EAX (x86)
    #[cfg(target_arch = "x86")]
    pub fn push_eax(&mut self) -> &mut Self {
        self.buffer.push(0x50);
        self
    }

    /// POP EAX (x86)
    #[cfg(target_arch = "x86")]
    pub fn pop_eax(&mut self) -> &mut Self {
        self.buffer.push(0x58);
        self
    }

    /// PUSH EBP (x86)
    #[cfg(target_arch = "x86")]
    pub fn push_ebp(&mut self) -> &mut Self {
        self.buffer.push(0x55);
        self
    }

    /// MOV EBP, ESP (x86)
    #[cfg(target_arch = "x86")]
    pub fn mov_ebp_esp(&mut self) -> &mut Self {
        self.buffer.extend_from_slice(&[0x8B, 0xEC]);
        self
    }

    /// JMP [mem32] absolute (6 bytes, x86)
    #[cfg(target_arch = "x86")]
    pub fn jmp_abs32(&mut self, target: u32) -> &mut Self {
        // push addr; ret
        self.push_imm32(target);
        self.ret();
        self
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for Encoder {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        let mut enc = Encoder::new();
        enc.nop();
        assert_eq!(enc.bytes(), &[0x90]);
    }

    #[test]
    fn test_nop_sled() {
        for size in 1..=16 {
            let mut enc = Encoder::new();
            enc.nop_sled(size);
            assert_eq!(enc.len(), size);
        }
    }

    #[test]
    fn test_push_ret() {
        let mut enc = Encoder::new();
        enc.push_imm32(0xDEADBEEF).ret();
        assert_eq!(enc.bytes(), &[0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3]);
    }

    #[test]
    fn test_jmp_rel32() {
        let mut enc = Encoder::new();
        enc.jmp_rel32(0x1000, 0x1100);
        assert_eq!(enc.len(), 5);
        assert_eq!(enc.bytes()[0], 0xE9);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_jmp_abs64() {
        let mut enc = Encoder::new();
        enc.jmp_abs64(0xDEADBEEF12345678);
        assert_eq!(enc.len(), 14);
        assert_eq!(&enc.bytes()[0..6], &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_mov_jmp_rax() {
        let mut enc = Encoder::new();
        enc.mov_rax_imm64(0xDEADBEEF12345678).jmp_rax();
        assert_eq!(enc.len(), 12);
    }
}
