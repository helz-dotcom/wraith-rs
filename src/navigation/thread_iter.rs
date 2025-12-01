//! Thread enumeration

use crate::arch::segment;
use crate::error::{Result, WraithError};

/// information about the current thread from TEB
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub thread_id: u32,
    pub teb_address: usize,
    pub stack_base: usize,
    pub stack_limit: usize,
}

impl ThreadInfo {
    /// get info for current thread from TEB
    pub fn current() -> Result<Self> {
        // SAFETY: get_teb always returns valid TEB for current thread
        let teb = unsafe { segment::get_teb() };
        if teb.is_null() {
            return Err(WraithError::InvalidTebAccess);
        }

        #[cfg(target_arch = "x86_64")]
        let (tid, stack_base, stack_limit) = {
            // SAFETY: TEB offsets are well-known for x64
            let tid = unsafe { segment::get_current_tid() };
            let stack_base = unsafe { *(teb.add(0x08) as *const u64) } as usize;
            let stack_limit = unsafe { *(teb.add(0x10) as *const u64) } as usize;
            (tid, stack_base, stack_limit)
        };

        #[cfg(target_arch = "x86")]
        let (tid, stack_base, stack_limit) = {
            // SAFETY: TEB offsets are well-known for x86
            let tid = unsafe { segment::get_current_tid() };
            let stack_base = unsafe { *(teb.add(0x04) as *const u32) } as usize;
            let stack_limit = unsafe { *(teb.add(0x08) as *const u32) } as usize;
            (tid, stack_base, stack_limit)
        };

        Ok(Self {
            thread_id: tid,
            teb_address: teb as usize,
            stack_base,
            stack_limit,
        })
    }

    /// check if an address is on this thread's stack
    pub fn is_on_stack(&self, address: usize) -> bool {
        // stack grows downward: limit < address < base
        address >= self.stack_limit && address < self.stack_base
    }
}

/// iterator over threads in current process
pub struct ThreadIterator {
    snapshot: *mut core::ffi::c_void,
    first: bool,
    target_pid: u32,
}

impl ThreadIterator {
    /// create new thread iterator for current process
    pub fn new() -> Result<Self> {
        // SAFETY: get_current_pid always returns valid PID
        let current_pid = unsafe { segment::get_current_pid() };
        Self::for_process(current_pid)
    }

    /// enumerate threads for a specific process
    pub fn for_process(pid: u32) -> Result<Self> {
        // SAFETY: CreateToolhelp32Snapshot is safe to call with valid flags
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(WraithError::from_last_error("CreateToolhelp32Snapshot"));
        }

        Ok(Self {
            snapshot,
            first: true,
            target_pid: pid,
        })
    }
}

impl Iterator for ThreadIterator {
    type Item = ThreadEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = ThreadEntry32 {
            size: core::mem::size_of::<ThreadEntry32>() as u32,
            ..Default::default()
        };

        loop {
            // SAFETY: snapshot is valid, entry is correctly sized
            let success = if self.first {
                self.first = false;
                unsafe { Thread32First(self.snapshot, &mut entry) }
            } else {
                unsafe { Thread32Next(self.snapshot, &mut entry) }
            };

            if success == 0 {
                return None;
            }

            // filter to target process
            if entry.owner_process_id == self.target_pid {
                return Some(ThreadEntry {
                    thread_id: entry.thread_id,
                    owner_process_id: entry.owner_process_id,
                    base_priority: entry.base_priority,
                });
            }
        }
    }
}

impl Drop for ThreadIterator {
    fn drop(&mut self) {
        if self.snapshot != INVALID_HANDLE_VALUE {
            // SAFETY: snapshot is valid handle
            unsafe {
                CloseHandle(self.snapshot);
            }
        }
    }
}

/// thread entry from enumeration
#[derive(Debug, Clone)]
pub struct ThreadEntry {
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_priority: i32,
}

// internal structures for toolhelp
#[repr(C)]
#[derive(Default)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    thread_id: u32,
    owner_process_id: u32,
    base_priority: i32,
    delta_priority: i32,
    flags: u32,
}

const TH32CS_SNAPTHREAD: u32 = 0x00000004;
const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1isize as *mut _;

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> *mut core::ffi::c_void;
    fn Thread32First(snapshot: *mut core::ffi::c_void, entry: *mut ThreadEntry32) -> i32;
    fn Thread32Next(snapshot: *mut core::ffi::c_void, entry: *mut ThreadEntry32) -> i32;
    fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
}

/// get list of all thread IDs in current process
pub fn get_thread_ids() -> Result<Vec<u32>> {
    Ok(ThreadIterator::new()?.map(|t| t.thread_id).collect())
}

/// count threads in current process
pub fn thread_count() -> Result<usize> {
    Ok(ThreadIterator::new()?.count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_thread() {
        let info = ThreadInfo::current().expect("should get thread info");
        assert!(info.thread_id > 0);
        assert!(info.stack_base > info.stack_limit);
    }

    #[test]
    fn test_thread_iterator() {
        let threads: Vec<_> = ThreadIterator::new()
            .expect("should create iterator")
            .collect();

        // should have at least one thread (ourselves)
        assert!(!threads.is_empty());
    }

    #[test]
    fn test_get_thread_ids() {
        let ids = get_thread_ids().expect("should get thread ids");
        assert!(!ids.is_empty());

        // current thread should be in the list
        let current = ThreadInfo::current().expect("should get current thread");
        assert!(ids.contains(&current.thread_id));
    }

    #[test]
    fn test_thread_count() {
        let count = thread_count().expect("should get thread count");
        assert!(count >= 1);
    }
}
