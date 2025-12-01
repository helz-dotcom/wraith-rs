//! PEB list unlinking implementation
//!
//! Manipulates the doubly-linked lists in PEB_LDR_DATA to hide
//! modules from enumeration.

use crate::error::{Result, WraithError};
use crate::navigation::ModuleHandle;
use crate::structures::list_entry::{unlink_entry, ListEntry};

/// saved link state for relinking
pub struct SavedLinks {
    in_load_order_flink: *mut ListEntry,
    in_load_order_blink: *mut ListEntry,
    in_memory_order_flink: *mut ListEntry,
    in_memory_order_blink: *mut ListEntry,
    in_init_order_flink: *mut ListEntry,
    in_init_order_blink: *mut ListEntry,
}

// SAFETY: SavedLinks just holds pointers that are valid within the process
unsafe impl Send for SavedLinks {}
unsafe impl Sync for SavedLinks {}

/// RAII guard that can relink module on drop
pub struct UnlinkGuard {
    handle: ModuleHandle,
    saved: SavedLinks,
    auto_relink: bool,
}

impl UnlinkGuard {
    /// disable auto-relink on drop (module stays hidden)
    pub fn leak(mut self) {
        self.auto_relink = false;
        core::mem::forget(self);
    }

    /// consume guard without relinking
    pub fn forget(mut self) {
        self.auto_relink = false;
    }

    /// manually relink the module
    pub fn relink(self) -> Result<()> {
        // guard.drop() will handle relinking if auto_relink is true
        // if not, we manually relink
        if !self.auto_relink {
            relink_module_internal(&self.handle, &self.saved)?;
        }
        // drop will handle it otherwise
        Ok(())
    }

    /// get module handle
    pub fn handle(&self) -> &ModuleHandle {
        &self.handle
    }

    /// check if auto-relink is enabled
    pub fn will_auto_relink(&self) -> bool {
        self.auto_relink
    }

    /// set auto-relink behavior
    pub fn set_auto_relink(&mut self, auto: bool) {
        self.auto_relink = auto;
    }
}

impl Drop for UnlinkGuard {
    fn drop(&mut self) {
        if self.auto_relink {
            let _ = relink_module_internal(&self.handle, &self.saved);
        }
    }
}

/// unlink module from all three PEB lists
///
/// returns guard that will relink on drop (can be disabled)
pub fn unlink_module(handle: ModuleHandle) -> Result<UnlinkGuard> {
    let links = handle.get_link_pointers();

    // validate pointers before proceeding
    if links.in_load_order.is_null()
        || links.in_memory_order.is_null()
        || links.in_initialization_order.is_null()
    {
        return Err(WraithError::NullPointer {
            context: "module list links",
        });
    }

    // save current links for restoration
    // SAFETY: pointers validated above
    let saved = unsafe {
        SavedLinks {
            in_load_order_flink: (*links.in_load_order).flink,
            in_load_order_blink: (*links.in_load_order).blink,
            in_memory_order_flink: (*links.in_memory_order).flink,
            in_memory_order_blink: (*links.in_memory_order).blink,
            in_init_order_flink: (*links.in_initialization_order).flink,
            in_init_order_blink: (*links.in_initialization_order).blink,
        }
    };

    // unlink from all three lists
    // SAFETY: we're manipulating valid list entries
    unsafe {
        unlink_entry(links.in_load_order);
        unlink_entry(links.in_memory_order);
        unlink_entry(links.in_initialization_order);
    }

    Ok(UnlinkGuard {
        handle,
        saved,
        auto_relink: true,
    })
}

/// relink module to PEB lists (convenience function)
pub fn relink_module(guard: UnlinkGuard) -> Result<()> {
    guard.relink()
}

/// internal function to restore links
fn relink_module_internal(handle: &ModuleHandle, saved: &SavedLinks) -> Result<()> {
    let links = handle.get_link_pointers();

    // SAFETY: we're restoring previously saved valid links
    unsafe {
        // restore InLoadOrder links
        (*links.in_load_order).flink = saved.in_load_order_flink;
        (*links.in_load_order).blink = saved.in_load_order_blink;
        (*saved.in_load_order_blink).flink = links.in_load_order;
        (*saved.in_load_order_flink).blink = links.in_load_order;

        // restore InMemoryOrder links
        (*links.in_memory_order).flink = saved.in_memory_order_flink;
        (*links.in_memory_order).blink = saved.in_memory_order_blink;
        (*saved.in_memory_order_blink).flink = links.in_memory_order;
        (*saved.in_memory_order_flink).blink = links.in_memory_order;

        // restore InInitializationOrder links
        (*links.in_initialization_order).flink = saved.in_init_order_flink;
        (*links.in_initialization_order).blink = saved.in_init_order_blink;
        (*saved.in_init_order_blink).flink = links.in_initialization_order;
        (*saved.in_init_order_flink).blink = links.in_initialization_order;
    }

    Ok(())
}

/// unlink module without guard (permanent)
pub fn unlink_permanent(handle: ModuleHandle) -> Result<()> {
    let guard = unlink_module(handle)?;
    guard.leak();
    Ok(())
}

#[cfg(test)]
mod tests {
    // testing unlinking is tricky as it affects the running process
    // these tests are more for documentation than actual testing

    #[test]
    fn test_saved_links_size() {
        // just verify the structure is the expected size
        use super::SavedLinks;
        let expected = 6 * core::mem::size_of::<*mut ()>();
        assert_eq!(core::mem::size_of::<SavedLinks>(), expected);
    }
}
