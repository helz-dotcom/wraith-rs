//! Return address and stack frame spoofing for syscalls
//!
//! This module provides techniques to evade call stack analysis by:
//! - Finding legitimate return address gadgets in system modules
//! - Synthesizing fake stack frames that appear legitimate
//! - Invoking syscalls with spoofed return addresses
//!
//! # Usage
//!
//! ```no_run
//! use wraith::manipulation::spoof::{SpoofedSyscall, GadgetFinder, StackSpoofer};
//!
//! // find gadgets in ntdll for legitimate-looking return addresses
//! let finder = GadgetFinder::new()?;
//! let gadgets = finder.find_jmp_rbx()?;
//!
//! // create spoofed syscall invoker
//! let syscall = SpoofedSyscall::new("NtAllocateVirtualMemory")?;
//!
//! // invoke with spoofed return address
//! let status = unsafe { syscall.call6(args...) };
//! ```

mod gadget;
mod stack;
mod spoofed;
mod trampoline;

pub use gadget::{
    Gadget, GadgetFinder, GadgetType, JmpGadget, RetGadget,
};
#[cfg(feature = "std")]
pub use gadget::GadgetCache;
pub use stack::{
    FakeFrame, FrameTemplate, StackSpoofer, SyntheticStack, COMMON_FRAME_TEMPLATES,
};
pub use spoofed::{SpoofedSyscall, SpoofConfig, SpoofMode};
pub use trampoline::{SpoofTrampoline, TrampolineAllocator};

use crate::error::Result;

/// initialize the global gadget cache by scanning system modules
#[cfg(feature = "std")]
pub fn init_gadget_cache() -> Result<()> {
    gadget::init_global_cache()
}

/// get a reference to the global gadget cache
#[cfg(feature = "std")]
pub fn get_gadget_cache() -> Result<&'static GadgetCache> {
    gadget::get_global_cache()
}
