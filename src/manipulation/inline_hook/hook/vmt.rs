//! VMT (Virtual Method Table) hooking
//!
//! VMT hooks work by modifying entries in a C++ object's virtual method table.
//! In C++, virtual functions are called through a vtable pointer stored at the
//! beginning of each polymorphic object. By replacing vtable entries, we can
//! intercept virtual function calls.
//!
//! # Approaches
//!
//! 1. **Direct VMT hook**: Modify the vtable entry directly (affects all instances)
//! 2. **Shadow VMT**: Create a copy of the vtable and swap the object's vptr
//!    (affects only specific instances, safer)
//!
//! # Advantages
//! - No code modification
//! - Easy to enable/disable
//! - Works on any virtual function
//!
//! # Limitations
//! - Only works with virtual functions (not final/non-virtual)
//! - Requires knowing vtable layout
//! - Direct hooks affect all objects of that class
//! - May conflict with RTTI or other vtable-dependent features

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{boxed::Box, format, string::String, vec, vec::Vec};

use crate::error::{Result, WraithError};
use crate::util::memory::ProtectionGuard;
use core::marker::PhantomData;

const PAGE_READWRITE: u32 = 0x04;

/// a single VMT entry hook (modifies vtable directly)
///
/// this affects all objects of the class. use `ShadowVmt` for
/// instance-specific hooking.
pub struct VmtHook {
    /// address of the vtable entry
    vtable_entry: usize,
    /// original function pointer
    original: usize,
    /// detour function pointer
    detour: usize,
    /// whether the hook is active
    active: bool,
    /// whether to restore on drop
    auto_restore: bool,
}

impl VmtHook {
    /// create and install a VMT hook
    ///
    /// # Arguments
    /// * `object` - pointer to the C++ object (or any pointer to a vptr)
    /// * `index` - index of the virtual function in the vtable
    /// * `detour` - address of the detour function
    ///
    /// # Safety
    /// The object pointer must point to a valid C++ object with a vtable.
    /// The index must be a valid vtable index for that class.
    ///
    /// # Example
    /// ```ignore
    /// // hook the 3rd virtual function (index 2)
    /// let hook = unsafe { VmtHook::new(object_ptr, 2, my_detour as usize)? };
    /// let original: fn() = unsafe { std::mem::transmute(hook.original()) };
    /// ```
    pub unsafe fn new(object: *const (), index: usize, detour: usize) -> Result<Self> {
        if object.is_null() {
            return Err(WraithError::NullPointer { context: "object" });
        }

        // read vptr (first pointer in object)
        let vptr = unsafe { *(object as *const usize) };
        if vptr == 0 {
            return Err(WraithError::NullPointer { context: "vptr" });
        }

        Self::new_at_vtable(vptr, index, detour)
    }

    /// create and install a VMT hook at a known vtable address
    ///
    /// # Arguments
    /// * `vtable` - address of the vtable
    /// * `index` - index of the virtual function
    /// * `detour` - address of the detour function
    pub fn new_at_vtable(vtable: usize, index: usize, detour: usize) -> Result<Self> {
        if vtable == 0 {
            return Err(WraithError::NullPointer { context: "vtable" });
        }

        let ptr_size = core::mem::size_of::<usize>();
        let vtable_entry = vtable + index * ptr_size;

        // read original function pointer
        // SAFETY: vtable_entry points to valid vtable entry
        let original = unsafe { *(vtable_entry as *const usize) };

        let mut hook = Self {
            vtable_entry,
            original,
            detour,
            active: false,
            auto_restore: true,
        };

        hook.install()?;
        Ok(hook)
    }

    /// install the hook
    pub fn install(&mut self) -> Result<()> {
        if self.active {
            return Ok(());
        }

        write_vtable_entry(self.vtable_entry, self.detour)?;
        self.active = true;

        Ok(())
    }

    /// remove the hook
    pub fn uninstall(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        write_vtable_entry(self.vtable_entry, self.original)?;
        self.active = false;

        Ok(())
    }

    /// check if hook is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// get the original function pointer
    pub fn original(&self) -> usize {
        self.original
    }

    /// get the detour function pointer
    pub fn detour(&self) -> usize {
        self.detour
    }

    /// get the vtable entry address
    pub fn vtable_entry(&self) -> usize {
        self.vtable_entry
    }

    /// set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, restore: bool) {
        self.auto_restore = restore;
    }

    /// leak the hook
    pub fn leak(mut self) {
        self.auto_restore = false;
        core::mem::forget(self);
    }

    /// restore and consume
    pub fn restore(mut self) -> Result<()> {
        self.uninstall()?;
        self.auto_restore = false;
        Ok(())
    }
}

impl Drop for VmtHook {
    fn drop(&mut self) {
        if self.auto_restore && self.active {
            let _ = self.uninstall();
        }
    }
}

// SAFETY: VmtHook operates on process-wide memory
unsafe impl Send for VmtHook {}
unsafe impl Sync for VmtHook {}

/// shadow VMT for instance-specific hooking
///
/// creates a copy of the original vtable and replaces the object's
/// vptr to point to the shadow copy. this allows hooking specific
/// instances without affecting other objects of the same class.
pub struct ShadowVmt<T: ?Sized = ()> {
    /// pointer to the object
    object: *mut (),
    /// pointer to the original vtable
    original_vtable: usize,
    /// pointer to our shadow vtable copy
    shadow_vtable: Box<[usize]>,
    /// list of hooked indices and their original values
    hooks: Vec<(usize, usize)>,
    /// whether auto-restore is enabled
    auto_restore: bool,
    /// marker for the object type
    _marker: PhantomData<T>,
}

impl<T: ?Sized> ShadowVmt<T> {
    /// create a shadow VMT for an object
    ///
    /// # Arguments
    /// * `object` - pointer to the C++ object
    /// * `vtable_size` - number of entries in the vtable
    ///
    /// # Safety
    /// The object must be a valid C++ object with a vtable.
    /// vtable_size must be accurate (too small = missing functions, too large = garbage).
    ///
    /// # Example
    /// ```ignore
    /// // create shadow for an object with 10 virtual functions
    /// let mut shadow = unsafe { ShadowVmt::new(object_ptr, 10)? };
    ///
    /// // hook the 3rd virtual function
    /// shadow.hook(2, my_detour as usize)?;
    ///
    /// // get original to call
    /// let original: fn() = unsafe { std::mem::transmute(shadow.original(2)) };
    /// ```
    pub unsafe fn new(object: *mut (), vtable_size: usize) -> Result<Self> {
        if object.is_null() {
            return Err(WraithError::NullPointer { context: "object" });
        }

        if vtable_size == 0 {
            return Err(WraithError::InvalidPeFormat {
                reason: "vtable_size cannot be 0".into(),
            });
        }

        // read original vptr
        let original_vtable = unsafe { *(object as *const usize) };
        if original_vtable == 0 {
            return Err(WraithError::NullPointer { context: "vptr" });
        }

        // copy the vtable
        let mut shadow = Vec::with_capacity(vtable_size);
        for i in 0..vtable_size {
            let entry_addr = original_vtable + i * core::mem::size_of::<usize>();
            // SAFETY: reading within vtable bounds
            let entry = unsafe { *(entry_addr as *const usize) };
            shadow.push(entry);
        }
        let shadow_vtable = shadow.into_boxed_slice();

        // replace object's vptr with our shadow
        // SAFETY: object pointer is valid, we're replacing vptr
        unsafe {
            *(object as *mut usize) = shadow_vtable.as_ptr() as usize;
        }

        Ok(Self {
            object,
            original_vtable,
            shadow_vtable,
            hooks: Vec::new(),
            auto_restore: true,
            _marker: PhantomData,
        })
    }

    /// hook a virtual function by index
    ///
    /// # Arguments
    /// * `index` - vtable index to hook
    /// * `detour` - address of the detour function
    pub fn hook(&mut self, index: usize, detour: usize) -> Result<()> {
        if index >= self.shadow_vtable.len() {
            return Err(WraithError::InvalidPeFormat {
                reason: format!(
                    "vtable index {} out of bounds (size {})",
                    index,
                    self.shadow_vtable.len()
                ),
            });
        }

        // save original if not already hooked at this index
        if !self.hooks.iter().any(|(i, _)| *i == index) {
            self.hooks.push((index, self.shadow_vtable[index]));
        }

        // replace with detour
        self.shadow_vtable[index] = detour;

        Ok(())
    }

    /// unhook a specific index
    pub fn unhook(&mut self, index: usize) -> Result<()> {
        if let Some(pos) = self.hooks.iter().position(|(i, _)| *i == index) {
            let (_, original) = self.hooks.remove(pos);
            if index < self.shadow_vtable.len() {
                self.shadow_vtable[index] = original;
            }
        }
        Ok(())
    }

    /// unhook all
    pub fn unhook_all(&mut self) {
        for (index, original) in self.hooks.drain(..) {
            if index < self.shadow_vtable.len() {
                self.shadow_vtable[index] = original;
            }
        }
    }

    /// get the original function at an index
    pub fn original(&self, index: usize) -> Option<usize> {
        // check if we have a saved original
        for (i, original) in &self.hooks {
            if *i == index {
                return Some(*original);
            }
        }
        // otherwise return current value
        self.shadow_vtable.get(index).copied()
    }

    /// get the original vtable address
    pub fn original_vtable(&self) -> usize {
        self.original_vtable
    }

    /// get the shadow vtable address
    pub fn shadow_vtable(&self) -> usize {
        self.shadow_vtable.as_ptr() as usize
    }

    /// get the vtable size
    pub fn vtable_size(&self) -> usize {
        self.shadow_vtable.len()
    }

    /// check if an index is hooked
    pub fn is_hooked(&self, index: usize) -> bool {
        self.hooks.iter().any(|(i, _)| *i == index)
    }

    /// get number of active hooks
    pub fn hook_count(&self) -> usize {
        self.hooks.len()
    }

    /// set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, restore: bool) {
        self.auto_restore = restore;
    }

    /// restore and consume
    pub fn restore(mut self) -> Result<()> {
        self.restore_internal()?;
        self.auto_restore = false;
        Ok(())
    }

    fn restore_internal(&mut self) -> Result<()> {
        // restore original vptr
        // SAFETY: object pointer is still valid
        unsafe {
            *(self.object as *mut usize) = self.original_vtable;
        }
        Ok(())
    }
}

impl<T: ?Sized> Drop for ShadowVmt<T> {
    fn drop(&mut self) {
        if self.auto_restore {
            let _ = self.restore_internal();
        }
    }
}

// SAFETY: ShadowVmt operates on the object's vtable
unsafe impl<T: ?Sized> Send for ShadowVmt<T> {}
unsafe impl<T: ?Sized> Sync for ShadowVmt<T> {}

/// RAII guard for VMT hook
pub type VmtHookGuard = VmtHook;

/// helper to get vtable pointer from an object
///
/// # Safety
/// Object must be a valid C++ polymorphic object.
pub unsafe fn get_vtable(object: *const ()) -> Result<usize> {
    if object.is_null() {
        return Err(WraithError::NullPointer { context: "object" });
    }

    // SAFETY: caller guarantees valid object
    let vptr = unsafe { *(object as *const usize) };
    if vptr == 0 {
        return Err(WraithError::NullPointer { context: "vptr" });
    }

    Ok(vptr)
}

/// helper to get a vtable entry
///
/// # Safety
/// vtable must be a valid vtable pointer.
pub unsafe fn get_vtable_entry(vtable: usize, index: usize) -> Result<usize> {
    if vtable == 0 {
        return Err(WraithError::NullPointer { context: "vtable" });
    }

    let entry_addr = vtable + index * core::mem::size_of::<usize>();
    // SAFETY: caller guarantees valid vtable
    let entry = unsafe { *(entry_addr as *const usize) };

    Ok(entry)
}

/// estimate vtable size by scanning for entries
///
/// # Safety
/// vtable must be a valid vtable pointer.
pub unsafe fn estimate_vtable_size(vtable: usize, max_scan: usize) -> usize {
    if vtable == 0 {
        return 0;
    }

    let mut count = 0;
    for i in 0..max_scan {
        let entry_addr = vtable + i * core::mem::size_of::<usize>();

        // try to read the entry
        let entry = unsafe { *(entry_addr as *const usize) };

        // heuristic: vtable entries should be non-null and look like code addresses
        // this is a rough estimate and may not be accurate for all cases
        if entry == 0 {
            break;
        }

        // on Windows x64, code is typically in high memory
        #[cfg(target_arch = "x86_64")]
        {
            if entry < 0x10000 || entry > 0x7FFF_FFFF_FFFF {
                break;
            }
        }

        #[cfg(target_arch = "x86")]
        {
            if entry < 0x10000 {
                break;
            }
        }

        count = i + 1;
    }

    count
}

/// write a value to a vtable entry
fn write_vtable_entry(entry: usize, value: usize) -> Result<()> {
    let _guard = ProtectionGuard::new(entry, core::mem::size_of::<usize>(), PAGE_READWRITE)?;

    // SAFETY: entry is valid vtable address, protection changed
    unsafe {
        *(entry as *mut usize) = value;
    }

    Ok(())
}

/// helper trait to get vtable for typed objects
pub trait VmtObject {
    /// get the vtable pointer
    fn vtable(&self) -> usize {
        // SAFETY: self is a valid object
        unsafe { *(self as *const Self as *const usize) }
    }
}

/// builder for VMT hooks
pub struct VmtHookBuilder {
    object: Option<*const ()>,
    vtable: Option<usize>,
    index: Option<usize>,
    detour: Option<usize>,
}

impl VmtHookBuilder {
    /// create a new builder
    pub fn new() -> Self {
        Self {
            object: None,
            vtable: None,
            index: None,
            detour: None,
        }
    }

    /// set the object to hook
    ///
    /// # Safety
    /// Object must be a valid C++ polymorphic object.
    pub unsafe fn object(mut self, object: *const ()) -> Self {
        self.object = Some(object);
        self
    }

    /// set the vtable directly
    pub fn vtable(mut self, vtable: usize) -> Self {
        self.vtable = Some(vtable);
        self
    }

    /// set the function index
    pub fn index(mut self, index: usize) -> Self {
        self.index = Some(index);
        self
    }

    /// set the detour
    pub fn detour(mut self, detour: usize) -> Self {
        self.detour = Some(detour);
        self
    }

    /// build and install the hook
    pub fn build(self) -> Result<VmtHook> {
        let vtable = if let Some(vt) = self.vtable {
            vt
        } else if let Some(obj) = self.object {
            unsafe { get_vtable(obj)? }
        } else {
            return Err(WraithError::NullPointer {
                context: "neither object nor vtable set",
            });
        };

        let index = self.index.ok_or(WraithError::NullPointer {
            context: "index not set",
        })?;

        let detour = self.detour.ok_or(WraithError::NullPointer {
            context: "detour not set",
        })?;

        VmtHook::new_at_vtable(vtable, index, detour)
    }
}

impl Default for VmtHookBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // create a test object with a vtable
    #[repr(C)]
    struct TestVtable {
        func1: usize,
        func2: usize,
        func3: usize,
    }

    #[repr(C)]
    struct TestObject {
        vptr: *const TestVtable,
    }

    extern "C" fn test_func1() -> i32 {
        1
    }
    extern "C" fn test_func2() -> i32 {
        2
    }
    extern "C" fn test_func3() -> i32 {
        3
    }

    #[test]
    fn test_get_vtable() {
        static VTABLE: TestVtable = TestVtable {
            func1: test_func1 as usize,
            func2: test_func2 as usize,
            func3: test_func3 as usize,
        };

        let obj = TestObject {
            vptr: &VTABLE,
        };

        let vptr = unsafe { get_vtable(&obj as *const _ as *const ()) }
            .expect("should get vtable");

        assert_eq!(vptr, &VTABLE as *const _ as usize);
    }

    #[test]
    fn test_get_vtable_entry() {
        static VTABLE: TestVtable = TestVtable {
            func1: test_func1 as usize,
            func2: test_func2 as usize,
            func3: test_func3 as usize,
        };

        let vtable = &VTABLE as *const _ as usize;

        let entry0 = unsafe { get_vtable_entry(vtable, 0) }.expect("should get entry");
        let entry1 = unsafe { get_vtable_entry(vtable, 1) }.expect("should get entry");

        assert_eq!(entry0, test_func1 as usize);
        assert_eq!(entry1, test_func2 as usize);
    }

    #[test]
    fn test_estimate_vtable_size() {
        static VTABLE: [usize; 5] = [
            test_func1 as usize,
            test_func2 as usize,
            test_func3 as usize,
            0, // null terminates
            0,
        ];

        let size = unsafe { estimate_vtable_size(VTABLE.as_ptr() as usize, 10) };
        assert_eq!(size, 3);
    }
}
