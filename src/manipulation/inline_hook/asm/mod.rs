//! Assembly instruction encoding and decoding utilities
//!
//! This module provides low-level instruction encoding primitives used
//! by the hooking framework for generating hook stubs and trampolines.
//!
//! # iced-x86 Integration
//!
//! When the `inline-hook` feature is enabled, this module uses iced-x86
//! for comprehensive instruction decoding and relocation. This provides:
//!
//! - Full x86/x64 instruction set support
//! - Proper handling of all relative addressing modes
//! - RIP-relative memory operand relocation
//! - Short-to-long jump expansion
//! - Conditional branch handling
//!
//! # Example
//!
//! ```ignore
//! use wraith::manipulation::inline_hook::asm::{
//!     iced_decoder::{InstructionDecoder, decode_one},
//!     iced_relocator::{InstructionRelocator, relocate_one},
//! };
//!
//! // decode an instruction
//! let decoded = decode_one(0x1000, &[0xE9, 0x00, 0x01, 0x00, 0x00]).unwrap();
//! println!("Length: {}, Relative: {}", decoded.length, decoded.is_relative);
//!
//! // relocate an instruction
//! let result = relocate_one(&[0xE9, 0x00, 0x01, 0x00, 0x00], 0x1000, 0x2000);
//! assert!(result.success);
//! ```

pub mod decoder;
pub mod encoder;
pub mod iced_decoder;
pub mod iced_relocator;

pub use decoder::{decode_instruction, InstructionInfo};
pub use encoder::Encoder;

// re-export iced-x86 based types for convenience
pub use iced_decoder::{
    DecodedInstruction, InstructionDecoder,
    decode_one, find_instruction_boundary, uses_relative_addressing,
};
pub use iced_relocator::{
    RelocationResult, InstructionRelocator,
    relocate_one, relocate_block, instruction_needs_relocation,
};
