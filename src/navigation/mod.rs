//! Navigation abstractions for PEB data structures
//!
//! This module provides iterators and query interfaces for traversing
//! loaded modules, threads, and memory regions.

mod module;
mod module_iter;
mod module_query;
mod thread_iter;
mod memory_regions;

pub use module::{Module, ModuleHandle, ModuleLinkPointers};
pub use module_iter::{
    collect_modules, module_count, InInitializationOrderIter, InLoadOrderIter, InMemoryOrderIter,
    ModuleInfo, ModuleIterator, ModuleListType,
};
pub use module_query::{
    get_kernel32, get_ntdll, get_ntdll_export, get_proc_address, ModuleQuery,
};
pub use thread_iter::{get_thread_ids, thread_count, ThreadEntry, ThreadInfo, ThreadIterator};
pub use memory_regions::{
    find_executable_regions, find_image_regions, find_private_regions, query_region,
    MemoryRegion, MemoryRegionIterator, MemoryState, MemoryType,
};
