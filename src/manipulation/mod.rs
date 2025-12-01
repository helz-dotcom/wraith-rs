//! Manipulation primitives for PE loading, module hiding, and syscalls

#[cfg(feature = "manual-map")]
pub mod manual_map;

#[cfg(feature = "syscalls")]
pub mod syscall;
