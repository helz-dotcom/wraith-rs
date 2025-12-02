//! Hook type implementations
//!
//! This module provides different hook types:
//! - `InlineHook`: Standard prologue replacement hook
//! - `HotPatchHook`: Windows hot-patching style hook
//! - `MidFunctionHook`: Hook at arbitrary location within a function
//! - `HookChain`: Multiple hooks on the same target
//! - `IatHook`: Import Address Table hook
//! - `EatHook`: Export Address Table hook
//! - `VehHook`: Vectored Exception Handler hook
//! - `VmtHook` / `ShadowVmt`: Virtual Method Table hooks

pub mod chain;
pub mod eat;
pub mod hotpatch;
pub mod iat;
pub mod inline;
pub mod mid;
pub mod veh;
pub mod vmt;

pub use chain::HookChain;
pub use eat::{EatHook, EatHookBuilder, EatHookGuard, EatEntry, enumerate_eat_entries, find_eat_entry, find_eat_entry_by_ordinal};
pub use hotpatch::HotPatchHook;
pub use iat::{IatHook, IatHookGuard, IatEntry, enumerate_iat_entries, find_iat_entry, hook_import, hook_import_all};
pub use inline::InlineHook;
pub use mid::MidFunctionHook;
pub use veh::{VehHook, VehHookType, DebugRegister, BreakCondition, BreakLength, get_available_debug_register};
pub use vmt::{VmtHook, VmtHookGuard, VmtHookBuilder, ShadowVmt, VmtObject, get_vtable, get_vtable_entry, estimate_vtable_size};

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
