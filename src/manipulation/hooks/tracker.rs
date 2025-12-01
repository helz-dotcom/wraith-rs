//! Hook state tracking
//!
//! Tracks hooks that have been detected and/or removed, allowing
//! for continuous monitoring and selective re-hooking if needed.

use super::detector::{HookInfo, HookType};
use std::collections::HashMap;
use std::sync::Mutex;

/// global hook tracker instance
static GLOBAL_TRACKER: Mutex<Option<HookTracker>> = Mutex::new(None);

/// state of a tracked hook
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookState {
    /// hook is currently active
    Active,
    /// hook was removed by us
    Removed,
    /// hook was restored (re-installed)
    Restored,
}

/// tracked hook entry
#[derive(Debug, Clone)]
pub struct TrackedHook {
    /// original hook information
    pub info: HookInfo,
    /// current state
    pub state: HookState,
    /// when this hook was first detected
    pub detected_at: std::time::Instant,
    /// when state last changed
    pub last_changed: std::time::Instant,
}

impl TrackedHook {
    fn new(info: HookInfo) -> Self {
        let now = std::time::Instant::now();
        Self {
            info,
            state: HookState::Active,
            detected_at: now,
            last_changed: now,
        }
    }
}

/// tracks hooks across the process
pub struct HookTracker {
    /// hooks by function address
    hooks: HashMap<usize, TrackedHook>,
    /// hooks indexed by module name
    by_module: HashMap<String, Vec<usize>>,
}

impl HookTracker {
    /// create new hook tracker
    pub fn new() -> Self {
        Self {
            hooks: HashMap::new(),
            by_module: HashMap::new(),
        }
    }

    /// register a detected hook
    pub fn register(&mut self, info: HookInfo) {
        let addr = info.function_address;
        let module = info.module_name.clone();

        self.hooks.insert(addr, TrackedHook::new(info));

        self.by_module
            .entry(module)
            .or_insert_with(Vec::new)
            .push(addr);
    }

    /// register multiple hooks
    pub fn register_all(&mut self, hooks: impl IntoIterator<Item = HookInfo>) {
        for hook in hooks {
            self.register(hook);
        }
    }

    /// mark hook as removed
    pub fn mark_removed(&mut self, address: usize) {
        if let Some(tracked) = self.hooks.get_mut(&address) {
            tracked.state = HookState::Removed;
            tracked.last_changed = std::time::Instant::now();
        }
    }

    /// mark hook as restored
    pub fn mark_restored(&mut self, address: usize) {
        if let Some(tracked) = self.hooks.get_mut(&address) {
            tracked.state = HookState::Restored;
            tracked.last_changed = std::time::Instant::now();
        }
    }

    /// get hook info by address
    pub fn get(&self, address: usize) -> Option<&TrackedHook> {
        self.hooks.get(&address)
    }

    /// get all hooks for a module
    pub fn get_by_module(&self, module_name: &str) -> Vec<&TrackedHook> {
        self.by_module
            .get(module_name)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|&addr| self.hooks.get(&addr))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// get all active hooks
    pub fn active_hooks(&self) -> Vec<&TrackedHook> {
        self.hooks
            .values()
            .filter(|h| h.state == HookState::Active)
            .collect()
    }

    /// get all removed hooks
    pub fn removed_hooks(&self) -> Vec<&TrackedHook> {
        self.hooks
            .values()
            .filter(|h| h.state == HookState::Removed)
            .collect()
    }

    /// get hooks by type
    pub fn get_by_type(&self, hook_type: HookType) -> Vec<&TrackedHook> {
        self.hooks
            .values()
            .filter(|h| h.info.hook_type == hook_type)
            .collect()
    }

    /// total number of tracked hooks
    pub fn count(&self) -> usize {
        self.hooks.len()
    }

    /// number of active hooks
    pub fn active_count(&self) -> usize {
        self.hooks
            .values()
            .filter(|h| h.state == HookState::Active)
            .count()
    }

    /// number of removed hooks
    pub fn removed_count(&self) -> usize {
        self.hooks
            .values()
            .filter(|h| h.state == HookState::Removed)
            .count()
    }

    /// check if an address is tracked
    pub fn is_tracked(&self, address: usize) -> bool {
        self.hooks.contains_key(&address)
    }

    /// unregister a hook (remove from tracking)
    pub fn unregister(&mut self, address: usize) -> Option<TrackedHook> {
        if let Some(hook) = self.hooks.remove(&address) {
            // remove from module index
            if let Some(addrs) = self.by_module.get_mut(&hook.info.module_name) {
                addrs.retain(|&a| a != address);
            }
            Some(hook)
        } else {
            None
        }
    }

    /// clear all tracked hooks
    pub fn clear(&mut self) {
        self.hooks.clear();
        self.by_module.clear();
    }

    /// get modules with tracked hooks
    pub fn modules(&self) -> Vec<&str> {
        self.by_module.keys().map(|s| s.as_str()).collect()
    }

    /// get statistics
    pub fn stats(&self) -> HookStats {
        let mut stats = HookStats::default();

        for hook in self.hooks.values() {
            match hook.state {
                HookState::Active => stats.active += 1,
                HookState::Removed => stats.removed += 1,
                HookState::Restored => stats.restored += 1,
            }

            match hook.info.hook_type {
                HookType::JmpRel32 => stats.jmp_rel32 += 1,
                HookType::JmpIndirect => stats.jmp_indirect += 1,
                HookType::MovJmpRax => stats.mov_jmp_rax += 1,
                HookType::PushRet => stats.push_ret += 1,
                HookType::Breakpoint => stats.breakpoints += 1,
                HookType::Unknown => stats.unknown += 1,
            }
        }

        stats.total = self.hooks.len();
        stats.modules = self.by_module.len();

        stats
    }
}

impl Default for HookTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// hook statistics
#[derive(Debug, Default, Clone)]
pub struct HookStats {
    pub total: usize,
    pub active: usize,
    pub removed: usize,
    pub restored: usize,
    pub modules: usize,
    pub jmp_rel32: usize,
    pub jmp_indirect: usize,
    pub mov_jmp_rax: usize,
    pub push_ret: usize,
    pub breakpoints: usize,
    pub unknown: usize,
}

impl std::fmt::Display for HookStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Hook Statistics:")?;
        writeln!(f, "  Total: {}", self.total)?;
        writeln!(f, "  Active: {}", self.active)?;
        writeln!(f, "  Removed: {}", self.removed)?;
        writeln!(f, "  Restored: {}", self.restored)?;
        writeln!(f, "  Modules: {}", self.modules)?;
        writeln!(f, "  By type:")?;
        writeln!(f, "    jmp rel32: {}", self.jmp_rel32)?;
        writeln!(f, "    jmp indirect: {}", self.jmp_indirect)?;
        writeln!(f, "    mov rax; jmp rax: {}", self.mov_jmp_rax)?;
        writeln!(f, "    push; ret: {}", self.push_ret)?;
        writeln!(f, "    breakpoints: {}", self.breakpoints)?;
        writeln!(f, "    unknown: {}", self.unknown)
    }
}

// global tracker functions

/// initialize global tracker
pub fn init_global_tracker() {
    let mut guard = GLOBAL_TRACKER.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HookTracker::new());
    }
}

/// get reference to global tracker (returns MutexGuard)
pub fn global_tracker() -> std::sync::MutexGuard<'static, Option<HookTracker>> {
    GLOBAL_TRACKER.lock().unwrap()
}

/// modify global tracker
pub fn with_global_tracker<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut HookTracker) -> R,
{
    let mut guard = GLOBAL_TRACKER.lock().unwrap();
    guard.as_mut().map(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hook(name: &str, addr: usize) -> HookInfo {
        HookInfo {
            function_name: name.to_string(),
            function_address: addr,
            hook_type: HookType::JmpRel32,
            hook_destination: Some(0xDEADBEEF),
            original_bytes: vec![0x90; 5],
            hooked_bytes: vec![0xE9, 0x00, 0x00, 0x00, 0x00],
            module_name: "test.dll".to_string(),
        }
    }

    #[test]
    fn test_tracker_basic() {
        let mut tracker = HookTracker::new();

        tracker.register(dummy_hook("NtReadVirtualMemory", 0x1000));
        tracker.register(dummy_hook("NtWriteVirtualMemory", 0x2000));

        assert_eq!(tracker.count(), 2);
        assert_eq!(tracker.active_count(), 2);

        tracker.mark_removed(0x1000);
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.removed_count(), 1);
    }

    #[test]
    fn test_stats() {
        let mut tracker = HookTracker::new();

        tracker.register(dummy_hook("Func1", 0x1000));
        tracker.register(dummy_hook("Func2", 0x2000));
        tracker.mark_removed(0x1000);

        let stats = tracker.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.jmp_rel32, 2);
    }
}
