//! LIST_ENTRY doubly-linked list abstraction

use core::marker::PhantomData;
use core::ptr::NonNull;

/// raw LIST_ENTRY structure matching Windows definition
#[repr(C)]
#[derive(Debug)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

impl ListEntry {
    /// check if this entry is the list head (points to itself)
    pub fn is_empty(&self) -> bool {
        core::ptr::eq(self.flink, self as *const _ as *mut _)
    }

    /// get next entry in list (Flink)
    ///
    /// returns None if this is the last entry (points to head)
    pub fn next(&self, head: *const ListEntry) -> Option<NonNull<ListEntry>> {
        if core::ptr::eq(self.flink, head as *mut _) {
            None
        } else {
            NonNull::new(self.flink)
        }
    }

    /// get previous entry in list (Blink)
    pub fn prev(&self, head: *const ListEntry) -> Option<NonNull<ListEntry>> {
        if core::ptr::eq(self.blink, head as *mut _) {
            None
        } else {
            NonNull::new(self.blink)
        }
    }
}

/// iterator over LIST_ENTRY chain
pub struct ListEntryIter<'a, T> {
    head: *const ListEntry,
    current: *const ListEntry,
    offset: usize,
    _marker: PhantomData<&'a T>,
}

impl<'a, T> ListEntryIter<'a, T> {
    /// create new iterator starting from head
    ///
    /// # Safety
    /// - head must point to valid LIST_ENTRY
    /// - offset must be correct offset of LIST_ENTRY within T
    pub unsafe fn new(head: *const ListEntry, offset: usize) -> Self {
        let first = unsafe { (*head).flink };
        Self {
            head,
            current: first,
            offset,
            _marker: PhantomData,
        }
    }
}

impl<'a, T> Iterator for ListEntryIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        // stop when we've wrapped back to head
        if core::ptr::eq(self.current, self.head) {
            return None;
        }

        // CONTAINING_RECORD macro equivalent
        let container = unsafe {
            let entry_addr = self.current as usize;
            let container_addr = entry_addr - self.offset;
            &*(container_addr as *const T)
        };

        // advance to next entry
        self.current = unsafe { (*self.current).flink };

        Some(container)
    }
}

/// mutable iterator over LIST_ENTRY chain
pub struct ListEntryIterMut<'a, T> {
    head: *mut ListEntry,
    current: *mut ListEntry,
    offset: usize,
    _marker: PhantomData<&'a mut T>,
}

impl<'a, T> ListEntryIterMut<'a, T> {
    /// create new mutable iterator
    ///
    /// # Safety
    /// - head must point to valid LIST_ENTRY
    /// - offset must be correct offset of LIST_ENTRY within T
    /// - caller must ensure exclusive access
    pub unsafe fn new(head: *mut ListEntry, offset: usize) -> Self {
        let first = unsafe { (*head).flink };
        Self {
            head,
            current: first,
            offset,
            _marker: PhantomData,
        }
    }
}

impl<'a, T> Iterator for ListEntryIterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        if core::ptr::eq(self.current, self.head) {
            return None;
        }

        let container = unsafe {
            let entry_addr = self.current as usize;
            let container_addr = entry_addr - self.offset;
            &mut *(container_addr as *mut T)
        };

        self.current = unsafe { (*self.current).flink };

        Some(container)
    }
}

/// safely unlink an entry from its list
///
/// # Safety
/// - entry must be part of a valid doubly-linked list
/// - caller must handle any synchronization
pub unsafe fn unlink_entry(entry: *mut ListEntry) {
    unsafe {
        let flink = (*entry).flink;
        let blink = (*entry).blink;
        (*blink).flink = flink;
        (*flink).blink = blink;
        // clear the entry's links to indicate it's unlinked
        (*entry).flink = entry;
        (*entry).blink = entry;
    }
}

/// relink an entry back into a list after a specific entry
///
/// # Safety
/// - after must be part of a valid list
/// - entry must not currently be linked
pub unsafe fn link_entry_after(entry: *mut ListEntry, after: *mut ListEntry) {
    unsafe {
        let next = (*after).flink;
        (*entry).flink = next;
        (*entry).blink = after;
        (*after).flink = entry;
        (*next).blink = entry;
    }
}
