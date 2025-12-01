//! Hook detection and removal
//!
//! This module provides functionality to detect inline hooks, IAT hooks,
//! and other code modifications commonly used by EDR/AV software.
//! It also provides the ability to restore hooked functions to their
//! original state.

mod detector;
mod integrity;
mod tracker;
mod unhook;

pub use detector::{is_hooked, HookDetector, HookInfo, HookType};
pub use integrity::IntegrityChecker;
pub use tracker::HookTracker;
pub use unhook::{UnhookResult, Unhooker};

use crate::error::Result;
use crate::navigation::ModuleQuery;
use crate::structures::Peb;

/// scan common system DLLs for hooks
pub fn scan_for_hooks() -> Result<Vec<HookInfo>> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);

    let mut all_hooks = Vec::new();

    // scan ntdll
    if let Ok(ntdll) = query.find_by_name("ntdll.dll") {
        let detector = HookDetector::new(&ntdll)?;
        if let Ok(hooks) = detector.scan_exports() {
            all_hooks.extend(hooks);
        }
    }

    // scan kernel32
    if let Ok(kernel32) = query.find_by_name("kernel32.dll") {
        let detector = HookDetector::new(&kernel32)?;
        if let Ok(hooks) = detector.scan_exports() {
            all_hooks.extend(hooks);
        }
    }

    // scan kernelbase
    if let Ok(kernelbase) = query.find_by_name("kernelbase.dll") {
        let detector = HookDetector::new(&kernelbase)?;
        if let Ok(hooks) = detector.scan_exports() {
            all_hooks.extend(hooks);
        }
    }

    Ok(all_hooks)
}

/// unhook all detected hooks in ntdll
pub fn unhook_ntdll() -> Result<UnhookResult> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let ntdll = query.find_by_name("ntdll.dll")?;

    let unhooker = Unhooker::new(&ntdll)?;
    unhooker.unhook_all()
}

/// scan a specific module for hooks
pub fn scan_module(module_name: &str) -> Result<Vec<HookInfo>> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(module_name)?;

    let detector = HookDetector::new(&module)?;
    detector.scan_exports()
}

/// unhook a specific module
pub fn unhook_module(module_name: &str) -> Result<UnhookResult> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(module_name)?;

    let unhooker = Unhooker::new(&module)?;
    unhooker.unhook_all()
}
