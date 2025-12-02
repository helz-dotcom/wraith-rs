//! Inline hooking framework
//!
//! Provides comprehensive inline hooking capabilities including:
//! - Standard inline hooks (prologue replacement)
//! - Hot-patch style hooks
//! - Mid-function hooks with context
//! - Hook chaining with priorities
//!
//! # Architecture Support
//!
//! Both x86 and x86_64 are supported via the `Architecture` trait.
//! Use `NativeArch` for compile-time architecture selection.
//!
//! # Example
//!
//! ```ignore
//! use wraith::manipulation::inline_hook::{hook, NativeArch};
//!
//! // define the original function type
//! type TargetFn = extern "system" fn(i32) -> i32;
//!
//! // your detour function
//! extern "system" fn my_detour(x: i32) -> i32 {
//!     // do something
//!     // call original via trampoline
//!     unsafe { ORIGINAL.unwrap()(x) }
//! }
//!
//! static mut ORIGINAL: Option<TargetFn> = None;
//!
//! // install hook
//! let guard = hook::<NativeArch>(target_addr, my_detour as usize)?;
//! unsafe {
//!     ORIGINAL = Some(std::mem::transmute(guard.trampoline().unwrap()));
//! }
//!
//! // hook is active until guard is dropped
//! // or call guard.leak() to keep it permanently
//! ```
//!
//! # Hook Types
//!
//! - [`InlineHook`]: Standard prologue replacement hook
//! - [`HotPatchHook`]: Uses Windows hot-patching space (2-byte atomic)
//! - [`MidFunctionHook`]: Hook at arbitrary location with context
//! - [`HookChain`]: Multiple hooks on same target with priorities
//!
//! # Builder Pattern
//!
//! For more control, use the type-state builder:
//!
//! ```ignore
//! use wraith::manipulation::inline_hook::{HookBuilder, NativeArch};
//!
//! let guard = HookBuilder::<NativeArch, _>::new()
//!     .target(target_addr)?
//!     .detour(detour_addr)?
//!     .allocate_trampoline()?
//!     .build_trampoline()?
//!     .prepare()?
//!     .install()?;
//! ```

pub mod arch;
pub mod asm;
pub mod builder;
pub mod guard;
pub mod hook;
pub mod registry;
pub mod trampoline;

// re-exports
pub use arch::{Architecture, NativeArch, X64, X86};
pub use builder::{state as BuilderState, HookBuilder};
pub use guard::{HookGuard, HookState, StatefulHookGuard};
pub use hook::{Hook, HookChain, HotPatchHook, InlineHook, MidFunctionHook};
pub use registry::{HookRegistry, HookType, RegisteredHook};
pub use trampoline::ExecutableMemory;

#[cfg(target_arch = "x86_64")]
pub use hook::mid::HookContext;
#[cfg(target_arch = "x86")]
pub use hook::mid::HookContext;
pub use hook::mid::MidHookFn;

use crate::error::Result;

/// install an inline hook with native architecture
///
/// this is the simplest way to install a hook. returns a guard that
/// automatically restores the original function when dropped.
///
/// # Arguments
/// * `target` - address of the function to hook
/// * `detour` - address of the detour function
///
/// # Returns
/// `HookGuard` that restores the original on drop
///
/// # Example
/// ```ignore
/// let guard = hook::<NativeArch>(target, detour)?;
/// let trampoline = guard.trampoline().unwrap();
/// ```
pub fn hook<A: Architecture>(target: usize, detour: usize) -> Result<HookGuard<A>> {
    InlineHook::<A>::new(target, detour).install()
}

/// install an inline hook using the native architecture
#[cfg(target_arch = "x86_64")]
pub fn hook_native(target: usize, detour: usize) -> Result<HookGuard<X64>> {
    hook::<X64>(target, detour)
}

#[cfg(target_arch = "x86")]
pub fn hook_native(target: usize, detour: usize) -> Result<HookGuard<X86>> {
    hook::<X86>(target, detour)
}

/// install a hot-patch hook
///
/// uses the Windows hot-patching mechanism for minimal disruption.
/// only works on functions compiled with /hotpatch.
pub fn hotpatch<A: Architecture>(target: usize, detour: usize) -> Result<HookGuard<A>> {
    HotPatchHook::<A>::new(target, detour).install()
}

/// check if a function is hot-patchable
pub fn is_hot_patchable(target: usize) -> bool {
    hook::hotpatch::is_hot_patchable(target)
}

/// install a mid-function hook
///
/// hooks at an arbitrary location within a function.
/// the detour receives a context pointer with all registers.
pub fn mid_hook<A: Architecture>(
    address: usize,
    detour: MidHookFn,
) -> Result<HookGuard<A>> {
    MidFunctionHook::<A>::new(address, detour).install()
}

/// create a hook chain on a target function
///
/// allows multiple hooks on the same target with priority ordering.
pub fn create_chain<A: Architecture>(target: usize) -> Result<HookChain<A>> {
    HookChain::new(target)
}

/// convenience function to hook by module export name
#[cfg(feature = "navigation")]
pub fn hook_export<A: Architecture>(
    module: &str,
    export: &str,
    detour: usize,
) -> Result<HookGuard<A>> {
    use crate::navigation::ModuleQuery;
    use crate::structures::Peb;

    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(module)?;
    let target = module.get_export(export)?;

    hook::<A>(target, detour)
}

/// convenience function to hook export using native architecture
#[cfg(all(feature = "navigation", target_arch = "x86_64"))]
pub fn hook_export_native(
    module: &str,
    export: &str,
    detour: usize,
) -> Result<HookGuard<X64>> {
    hook_export::<X64>(module, export, detour)
}

#[cfg(all(feature = "navigation", target_arch = "x86"))]
pub fn hook_export_native(
    module: &str,
    export: &str,
    detour: usize,
) -> Result<HookGuard<X86>> {
    hook_export::<X86>(module, export, detour)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_arch_defined() {
        // just verify NativeArch type is available
        let _: usize = NativeArch::JMP_REL_SIZE;
        let _: usize = NativeArch::JMP_ABS_SIZE;
        let _: usize = NativeArch::PTR_SIZE;
    }
}
