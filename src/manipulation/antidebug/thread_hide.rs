//! Thread hiding from debugger
//!
//! Uses NtSetInformationThread with ThreadHideFromDebugger to prevent
//! debuggers from receiving events for the hidden thread.

use crate::error::Result;
use crate::structures::Teb;
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

// re-use syscall infrastructure
#[cfg(feature = "syscalls")]
use crate::manipulation::syscall::{
    nt_set_information_thread, CURRENT_THREAD, THREAD_HIDE_FROM_DEBUGGER,
};

/// track which threads have been hidden
static HIDDEN_THREADS: LazyLock<Mutex<HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// hide thread from debugger using NtSetInformationThread
///
/// once hidden, the debugger will not receive debug events for this thread
/// and cannot resume it after break. this operation is one-way - cannot be undone.
#[cfg(feature = "syscalls")]
pub fn hide_thread(thread_handle: usize) -> Result<()> {
    nt_set_information_thread(
        thread_handle,
        THREAD_HIDE_FROM_DEBUGGER,
        core::ptr::null(),
        0,
    )
}

/// hide current thread from debugger
#[cfg(feature = "syscalls")]
pub fn hide_current_thread() -> Result<()> {
    hide_thread(CURRENT_THREAD)?;

    // track that this thread is hidden
    if let Ok(teb) = Teb::current() {
        let tid = teb.thread_id();
        if let Ok(mut hidden) = HIDDEN_THREADS.lock() {
            hidden.insert(tid);
        }
    }

    Ok(())
}

/// fallback when syscalls feature is disabled
#[cfg(not(feature = "syscalls"))]
pub fn hide_thread(_thread_handle: usize) -> Result<()> {
    Err(crate::error::WraithError::SyscallNotFound {
        name: "NtSetInformationThread (syscalls feature disabled)".into(),
    })
}

#[cfg(not(feature = "syscalls"))]
pub fn hide_current_thread() -> Result<()> {
    Err(crate::error::WraithError::SyscallNotFound {
        name: "NtSetInformationThread (syscalls feature disabled)".into(),
    })
}

/// check if thread was hidden by us
pub fn is_thread_hidden(tid: u32) -> bool {
    HIDDEN_THREADS
        .lock()
        .map(|h| h.contains(&tid))
        .unwrap_or(false)
}

/// get list of threads hidden by us
pub fn get_hidden_threads() -> Vec<u32> {
    HIDDEN_THREADS
        .lock()
        .map(|h| h.iter().copied().collect())
        .unwrap_or_default()
}

/// number of hidden threads
pub fn hidden_count() -> usize {
    HIDDEN_THREADS.lock().map(|h| h.len()).unwrap_or(0)
}

/// clear tracking (doesn't unhide threads - that's impossible)
pub fn clear_tracking() {
    if let Ok(mut hidden) = HIDDEN_THREADS.lock() {
        hidden.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracking() {
        clear_tracking();

        // manually add for testing (since hiding requires syscalls)
        if let Ok(mut hidden) = HIDDEN_THREADS.lock() {
            hidden.insert(1234);
        }

        assert!(is_thread_hidden(1234));
        assert!(!is_thread_hidden(5678));

        let threads = get_hidden_threads();
        assert!(threads.contains(&1234));

        clear_tracking();
        assert!(!is_thread_hidden(1234));
    }
}
