//! Usermode client for kernel driver communication
//!
//! This module provides a usermode API for communicating with kernel drivers
//! built using the `km` module. It supports:
//!
//! - IOCTL-based communication
//! - Shared memory access
//! - Process memory operations via driver
//!
//! # Example
//!
//! ```no_run
//! use wraith::km_client::{DriverClient, ProcessOps};
//!
//! let client = DriverClient::connect("\\\\.\\MyDriver")?;
//! let mut process = client.open_process(1234)?;
//! let value: u32 = process.read(0x7FFE0000)?;
//! ```

mod driver;
mod process;
mod memory;
pub mod ioctl;

pub use driver::{DriverClient, DriverHandle};
pub use process::ProcessOps;
pub use memory::{RemoteMemory, MemoryProtection};
pub use ioctl::{IoctlCode, IoctlRequest, IoctlResponse};

use std::io;

/// result type for client operations
pub type ClientResult<T> = Result<T, ClientError>;

/// client error types
#[derive(Debug)]
pub enum ClientError {
    /// failed to open driver
    DriverOpenFailed(io::Error),
    /// driver not found
    DriverNotFound,
    /// IOCTL operation failed
    IoctlFailed {
        code: u32,
        error: io::Error,
    },
    /// invalid response from driver
    InvalidResponse {
        expected: usize,
        received: usize,
    },
    /// process operation failed
    ProcessError {
        pid: u32,
        reason: String,
    },
    /// memory operation failed
    MemoryError {
        address: u64,
        reason: String,
    },
    /// buffer too small
    BufferTooSmall {
        required: usize,
        provided: usize,
    },
    /// operation not supported
    NotSupported,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DriverOpenFailed(e) => write!(f, "failed to open driver: {e}"),
            Self::DriverNotFound => write!(f, "driver not found"),
            Self::IoctlFailed { code, error } => write!(f, "IOCTL {code:#x} failed: {error}"),
            Self::InvalidResponse { expected, received } => {
                write!(f, "invalid response: expected {expected} bytes, got {received}")
            }
            Self::ProcessError { pid, reason } => {
                write!(f, "process {pid} error: {reason}")
            }
            Self::MemoryError { address, reason } => {
                write!(f, "memory error at {address:#x}: {reason}")
            }
            Self::BufferTooSmall { required, provided } => {
                write!(f, "buffer too small: need {required}, got {provided}")
            }
            Self::NotSupported => write!(f, "operation not supported"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::DriverOpenFailed(e)
    }
}
