//! Assembly instruction encoding and decoding utilities
//!
//! This module provides low-level instruction encoding primitives used
//! by the hooking framework for generating hook stubs and trampolines.

pub mod decoder;
pub mod encoder;

pub use decoder::{decode_instruction, InstructionInfo};
pub use encoder::Encoder;
