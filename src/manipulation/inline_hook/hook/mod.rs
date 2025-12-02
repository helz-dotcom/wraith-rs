//! Hook type implementations
//!
//! This module provides different hook types:
//! - `InlineHook`: Standard prologue replacement hook
//! - `HotPatchHook`: Windows hot-patching style hook
//! - `MidFunctionHook`: Hook at arbitrary location within a function
//! - `HookChain`: Multiple hooks on the same target

pub mod chain;
pub mod hotpatch;
pub mod inline;
pub mod mid;

pub use chain::HookChain;
pub use hotpatch::HotPatchHook;
pub use inline::InlineHook;
pub use mid::MidFunctionHook;

use crate::error::Result;

/// common hook trait
pub trait Hook: Sized {
    /// the guard type returned when the hook is installed
    type Guard;

    /// install the hook
    fn install(self) -> Result<Self::Guard>;

    /// get the target address
    fn target(&self) -> usize;

    /// get the detour address
    fn detour(&self) -> usize;
}
