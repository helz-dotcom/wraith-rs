//! Global hook registry
//!
//! Tracks all installed hooks for management and conflict detection.

use std::collections::HashMap;
use std::sync::Mutex;

/// global hook registry singleton
static REGISTRY: Mutex<Option<HookRegistry>> = Mutex::new(None);

/// information about a registered hook
#[derive(Debug, Clone)]
pub struct RegisteredHook {
    /// target function address
    pub target: usize,
    /// detour function address
    pub detour: usize,
    /// trampoline address (if available)
    pub trampoline: Option<usize>,
    /// type of hook
    pub hook_type: HookType,
    /// when the hook was installed
    pub installed_at: std::time::Instant,
    /// whether the hook is currently active
    pub active: bool,
}

/// type of hook
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// standard inline hook (prologue replacement)
    Inline,
    /// hot-patch style hook
    HotPatch,
    /// mid-function hook
    MidFunction,
    /// hook in a chain
    Chained,
}

/// hook registry for tracking installed hooks
#[derive(Default)]
pub struct HookRegistry {
    /// hooks by target address
    by_target: HashMap<usize, RegisteredHook>,
    /// target address by detour address
    by_detour: HashMap<usize, usize>,
}

impl HookRegistry {
    /// create a new registry
    pub fn new() -> Self {
        Self::default()
    }

    /// register a new hook
    pub fn register(&mut self, hook: RegisteredHook) {
        let target = hook.target;
        let detour = hook.detour;

        self.by_detour.insert(detour, target);
        self.by_target.insert(target, hook);
    }

    /// unregister a hook by target address
    pub fn unregister(&mut self, target: usize) -> Option<RegisteredHook> {
        if let Some(hook) = self.by_target.remove(&target) {
            self.by_detour.remove(&hook.detour);
            Some(hook)
        } else {
            None
        }
    }

    /// get hook info by target address
    pub fn get(&self, target: usize) -> Option<&RegisteredHook> {
        self.by_target.get(&target)
    }

    /// get hook info by target address (mutable)
    pub fn get_mut(&mut self, target: usize) -> Option<&mut RegisteredHook> {
        self.by_target.get_mut(&target)
    }

    /// check if an address is hooked
    pub fn is_hooked(&self, target: usize) -> bool {
        self.by_target.contains_key(&target)
    }

    /// find target by detour address
    pub fn find_by_detour(&self, detour: usize) -> Option<usize> {
        self.by_detour.get(&detour).copied()
    }

    /// get all registered hooks
    pub fn all(&self) -> impl Iterator<Item = &RegisteredHook> {
        self.by_target.values()
    }

    /// get count of registered hooks
    pub fn count(&self) -> usize {
        self.by_target.len()
    }

    /// clear all hooks (does not actually remove them, just clears registry)
    pub fn clear(&mut self) {
        self.by_target.clear();
        self.by_detour.clear();
    }

    /// set hook active state
    pub fn set_active(&mut self, target: usize, active: bool) -> bool {
        if let Some(hook) = self.by_target.get_mut(&target) {
            hook.active = active;
            true
        } else {
            false
        }
    }
}

/// get the global registry (initializes if needed)
pub fn get_registry() -> std::sync::MutexGuard<'static, Option<HookRegistry>> {
    let mut guard = REGISTRY.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HookRegistry::new());
    }
    guard
}

/// execute a function with the registry
pub fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&mut HookRegistry) -> R,
{
    let mut guard = get_registry();
    let registry = guard.as_mut().unwrap();
    f(registry)
}

/// register a hook in the global registry
pub fn register_hook(
    target: usize,
    detour: usize,
    trampoline: Option<usize>,
    hook_type: HookType,
) {
    with_registry(|registry| {
        registry.register(RegisteredHook {
            target,
            detour,
            trampoline,
            hook_type,
            installed_at: std::time::Instant::now(),
            active: true,
        });
    });
}

/// unregister a hook from the global registry
pub fn unregister_hook(target: usize) -> Option<RegisteredHook> {
    with_registry(|registry| registry.unregister(target))
}

/// check if a target is hooked
pub fn is_hooked(target: usize) -> bool {
    with_registry(|registry| registry.is_hooked(target))
}

/// get hook info for a target
pub fn get_hook_info(target: usize) -> Option<RegisteredHook> {
    with_registry(|registry| registry.get(target).cloned())
}

/// get all hooks targeting a module's address range
pub fn get_hooks_in_range(start: usize, end: usize) -> Vec<RegisteredHook> {
    with_registry(|registry| {
        registry
            .all()
            .filter(|h| h.target >= start && h.target < end)
            .cloned()
            .collect()
    })
}

/// get count of active hooks
pub fn active_hook_count() -> usize {
    with_registry(|registry| registry.all().filter(|h| h.active).count())
}

/// get total hook count
pub fn total_hook_count() -> usize {
    with_registry(|registry| registry.count())
}
