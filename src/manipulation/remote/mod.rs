//! Remote process manipulation
//!
//! Provides cross-process operations including:
//! - Memory read/write
//! - Remote thread creation
//! - Various injection methods (section mapping, APC, thread hijacking)
//! - Cross-process module enumeration
//! - Handle duplication/stealing
//! - External process operations
//! - Remote PE parsing and export/import resolution
//! - External pattern scanning
//! - Memory region and thread enumeration

mod external;
mod handle;
mod inject;
mod modules;
mod process;
mod thread;

pub use external::{
    // memory access trait
    MemoryAccess, Protection, Allocation, CurrentProcess,
    // process discovery
    ProcessEntry, enumerate_processes, find_process_by_name, find_processes_by_name,
    // window-based process finding
    find_process_by_window,
    // remote PE parsing
    RemotePeHeaders, RemoteSection, RemoteExport, RemoteImport,
    // external scanner
    RemoteScanner,
    // memory regions
    RemoteMemoryState, RemoteMemoryType, RemoteMemoryRegion,
    // thread info
    RemoteThreadInfo,
    // utilities
    get_process_id_from_handle,
};

#[cfg(feature = "std")]
pub use external::{wait_for_process, wait_for_window};

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
