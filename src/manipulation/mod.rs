//! Manipulation primitives for PE loading, module hiding, syscalls, hooks, and anti-debug

#[cfg(feature = "manual-map")]
pub mod manual_map;

#[cfg(feature = "syscalls")]
pub mod syscall;

#[cfg(feature = "spoof")]
pub mod spoof;

#[cfg(feature = "hooks")]
pub mod hooks;

#[cfg(feature = "inline-hook")]
pub mod inline_hook;

#[cfg(feature = "antidebug")]
pub mod antidebug;

#[cfg(feature = "unlink")]
pub mod unlink;

#[cfg(feature = "remote")]
pub mod remote;
