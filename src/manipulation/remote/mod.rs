//! Remote process manipulation
//!
//! Provides cross-process operations including:
//! - Memory read/write
//! - Remote thread creation
//! - Various injection methods (section mapping, APC, thread hijacking)
//! - Cross-process module enumeration
//! - Handle duplication/stealing

mod handle;
mod inject;
mod modules;
mod process;
mod thread;

pub use handle::{
    duplicate_handle, steal_handle, HandleDuplicateOptions, HandleInfo, StolenHandle,
};
pub use inject::{
    inject_apc, inject_shellcode, inject_thread_hijack, inject_via_section, InjectionMethod,
    InjectionResult,
};
pub use modules::{
    enumerate_remote_modules, find_remote_module, get_remote_peb, RemoteModule, RemoteModuleInfo,
};
pub use process::{
    ProcessAccess, RemoteAllocation, RemoteProcess, RemoteProtectionGuard,
};
pub use thread::{
    create_remote_thread, RemoteThread, RemoteThreadOptions, ThreadCreationFlags,
};
