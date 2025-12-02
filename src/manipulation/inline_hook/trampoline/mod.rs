//! Trampoline building and memory management
//!
//! This module provides the infrastructure for allocating executable memory
//! and generating trampolines that preserve original function behavior.

pub mod allocator;
pub mod generator;

pub use allocator::ExecutableMemory;
pub use generator::TrampolineBuilder;
