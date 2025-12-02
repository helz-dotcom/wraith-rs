//! Module unlinking from PEB lists
//!
//! Removes modules from the PEB's three module lists (InLoadOrder,
//! InMemoryOrder, InInitializationOrder) to hide them from enumeration.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;

#[cfg(feature = "std")]
use std::string::String;

mod list_unlink;

pub use list_unlink::{relink_module, unlink_module, SavedLinks, UnlinkGuard};

use crate::error::{Result, WraithError};
use crate::navigation::{ModuleHandle, ModuleQuery};
use crate::structures::Peb;

/// unlink a module from all PEB lists by name
pub fn unlink_by_name(name: &str) -> Result<UnlinkGuard> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(name)?;

    // get handle for modification
    // SAFETY: LDR entry is valid for found module
    let handle = unsafe {
        ModuleHandle::from_raw(module.as_ldr_entry() as *const _ as *mut _).ok_or(
            WraithError::NullPointer {
                context: "module entry",
            },
        )?
    };

    unlink_module(handle)
}

/// check if module is currently linked in PEB lists
pub fn is_module_linked(name: &str) -> Result<bool> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    Ok(query.find_by_name(name).is_ok())
}

/// unlink current executable from PEB lists
pub fn unlink_self() -> Result<UnlinkGuard> {
    let peb = Peb::current()?;
    let image_base = peb.image_base() as usize;

    let query = ModuleQuery::new(&peb);
    let module = query.find_by_base(image_base)?;

    // SAFETY: our own module entry is valid
    let handle = unsafe {
        ModuleHandle::from_raw(module.as_ldr_entry() as *const _ as *mut _).ok_or(
            WraithError::NullPointer {
                context: "self module entry",
            },
        )?
    };

    unlink_module(handle)
}

/// information about unlinked module
#[derive(Debug)]
pub struct UnlinkInfo {
    pub module_name: String,
    pub base_address: usize,
    pub size: usize,
    pub was_linked: bool,
}

/// get info about an unlink operation
pub fn get_unlink_info(guard: &UnlinkGuard) -> UnlinkInfo {
    let module = guard.handle().as_module();
    UnlinkInfo {
        module_name: module.name(),
        base_address: module.base(),
        size: module.size(),
        was_linked: true,
    }
}
