//! Manipulation primitives for PE loading, module hiding, syscalls, and anti-debug

#[cfg(feature = "manual-map")]
pub mod manual_map;

#[cfg(feature = "syscalls")]
pub mod syscall;

#[cfg(feature = "hooks")]
pub mod hooks;

#[cfg(feature = "antidebug")]
pub mod antidebug;

#[cfg(feature = "unlink")]
pub mod unlink;
