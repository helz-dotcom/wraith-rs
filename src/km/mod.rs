//! Kernel-mode driver support for wraith-rs
//!
//! This module provides safe abstractions for Windows kernel driver development,
//! including:
//!
//! - Driver/device object management
//! - IRP dispatch and IOCTL handling
//! - Pool memory allocation
//! - Physical memory access via MDL
//! - Process and memory operations
//! - KM<->UM communication primitives
//!
//! # Feature Requirements
//!
//! This module requires the `kernel` feature flag and is intended for use in
//! kernel-mode drivers compiled with `no_std`.
//!
//! # Safety
//!
//! Kernel-mode code runs at elevated privilege levels. Improper use can cause
//! system instability or BSODs. All unsafe operations are carefully documented.

extern crate alloc;

pub mod allocator;
pub mod device;
pub mod driver;
pub mod error;
pub mod ioctl;
pub mod irp;
pub mod memory;
pub mod process;
pub mod shared;
pub mod string;
pub mod sync;

pub use allocator::{PoolAllocator, PoolType};
pub use device::{Device, DeviceFlags, DeviceType};
pub use driver::{Driver, DriverEntry, DriverUnload};
pub use error::{KmError, KmResult};
pub use ioctl::{Ioctl, IoctlCode, IoctlHandler, IoctlMethod, IoctlDispatcher};
pub use irp::{Irp, IrpMajorFunction, IoStackLocation};
pub use memory::{Mdl, MdlFlags, PhysicalMemory, VirtualMemory, KernelMemory};
pub use process::{KmProcess, Eprocess, ProcessAccess as KmProcessAccess};
pub use shared::{SharedMemory, SharedBuffer};
pub use string::{UnicodeString, AnsiString};
pub use sync::{SpinLock, FastMutex, Guarded};
