//! Kernel-mode error types

use core::fmt;

/// NTSTATUS type alias
pub type NtStatus = i32;

/// kernel-mode specific errors
#[derive(Debug)]
pub enum KmError {
    /// NT status code error
    NtStatus(NtStatus),

    /// pool allocation failed
    PoolAllocationFailed {
        size: usize,
        pool_type: u32,
    },

    /// MDL operation failed
    MdlOperationFailed {
        reason: &'static str,
    },

    /// physical memory access failed
    PhysicalMemoryFailed {
        address: u64,
        size: usize,
    },

    /// virtual memory operation failed
    VirtualMemoryFailed {
        address: u64,
        size: usize,
        reason: &'static str,
    },

    /// process operation failed
    ProcessOperationFailed {
        pid: u32,
        reason: &'static str,
    },

    /// device creation failed
    DeviceCreationFailed {
        reason: &'static str,
    },

    /// symbolic link creation failed
    SymbolicLinkFailed {
        reason: &'static str,
    },

    /// IOCTL operation failed
    IoctlFailed {
        code: u32,
        reason: &'static str,
    },

    /// invalid parameter
    InvalidParameter {
        context: &'static str,
    },

    /// buffer too small
    BufferTooSmall {
        required: usize,
        provided: usize,
    },

    /// access denied
    AccessDenied {
        context: &'static str,
    },

    /// invalid address
    InvalidAddress {
        address: u64,
    },

    /// not implemented
    NotImplemented {
        feature: &'static str,
    },
}

impl fmt::Display for KmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtStatus(status) => write!(f, "NTSTATUS error: {status:#x}"),
            Self::PoolAllocationFailed { size, pool_type } => {
                write!(f, "pool allocation failed: {size} bytes, type {pool_type}")
            }
            Self::MdlOperationFailed { reason } => {
                write!(f, "MDL operation failed: {reason}")
            }
            Self::PhysicalMemoryFailed { address, size } => {
                write!(f, "physical memory access failed at {address:#x} ({size} bytes)")
            }
            Self::VirtualMemoryFailed { address, size, reason } => {
                write!(f, "virtual memory operation failed at {address:#x} ({size} bytes): {reason}")
            }
            Self::ProcessOperationFailed { pid, reason } => {
                write!(f, "process operation failed for PID {pid}: {reason}")
            }
            Self::DeviceCreationFailed { reason } => {
                write!(f, "device creation failed: {reason}")
            }
            Self::SymbolicLinkFailed { reason } => {
                write!(f, "symbolic link creation failed: {reason}")
            }
            Self::IoctlFailed { code, reason } => {
                write!(f, "IOCTL {code:#x} failed: {reason}")
            }
            Self::InvalidParameter { context } => {
                write!(f, "invalid parameter in {context}")
            }
            Self::BufferTooSmall { required, provided } => {
                write!(f, "buffer too small: need {required} bytes, got {provided}")
            }
            Self::AccessDenied { context } => {
                write!(f, "access denied: {context}")
            }
            Self::InvalidAddress { address } => {
                write!(f, "invalid address: {address:#x}")
            }
            Self::NotImplemented { feature } => {
                write!(f, "not implemented: {feature}")
            }
        }
    }
}

/// result type for kernel operations
pub type KmResult<T> = core::result::Result<T, KmError>;

/// common NTSTATUS codes
pub mod status {
    use super::NtStatus;

    pub const STATUS_SUCCESS: NtStatus = 0;
    pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC0000001_u32 as i32;
    pub const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC0000002_u32 as i32;
    pub const STATUS_INVALID_HANDLE: NtStatus = 0xC0000008_u32 as i32;
    pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000000D_u32 as i32;
    pub const STATUS_NO_SUCH_DEVICE: NtStatus = 0xC000000E_u32 as i32;
    pub const STATUS_NO_SUCH_FILE: NtStatus = 0xC000000F_u32 as i32;
    pub const STATUS_ACCESS_DENIED: NtStatus = 0xC0000022_u32 as i32;
    pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC0000023_u32 as i32;
    pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC0000034_u32 as i32;
    pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC0000035_u32 as i32;
    pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000009A_u32 as i32;
    pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = 0xC0000010_u32 as i32;
    pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC0000004_u32 as i32;
    pub const STATUS_PARTIAL_COPY: NtStatus = 0x8000000D_u32 as i32;
    pub const STATUS_NO_MEMORY: NtStatus = 0xC0000017_u32 as i32;

    /// check if NTSTATUS indicates success
    #[inline]
    pub const fn nt_success(status: NtStatus) -> bool {
        status >= 0
    }

    /// check if NTSTATUS indicates an informational status
    #[inline]
    pub const fn nt_information(status: NtStatus) -> bool {
        (status as u32) >> 30 == 1
    }

    /// check if NTSTATUS indicates a warning
    #[inline]
    pub const fn nt_warning(status: NtStatus) -> bool {
        (status as u32) >> 30 == 2
    }

    /// check if NTSTATUS indicates an error
    #[inline]
    pub const fn nt_error(status: NtStatus) -> bool {
        (status as u32) >> 30 == 3
    }
}

impl From<NtStatus> for KmError {
    fn from(status: NtStatus) -> Self {
        KmError::NtStatus(status)
    }
}

impl KmError {
    /// convert to NTSTATUS for returning from driver dispatch functions
    pub fn to_ntstatus(&self) -> NtStatus {
        match self {
            Self::NtStatus(s) => *s,
            Self::PoolAllocationFailed { .. } => status::STATUS_INSUFFICIENT_RESOURCES,
            Self::MdlOperationFailed { .. } => status::STATUS_UNSUCCESSFUL,
            Self::PhysicalMemoryFailed { .. } => status::STATUS_ACCESS_DENIED,
            Self::VirtualMemoryFailed { .. } => status::STATUS_ACCESS_DENIED,
            Self::ProcessOperationFailed { .. } => status::STATUS_UNSUCCESSFUL,
            Self::DeviceCreationFailed { .. } => status::STATUS_UNSUCCESSFUL,
            Self::SymbolicLinkFailed { .. } => status::STATUS_UNSUCCESSFUL,
            Self::IoctlFailed { .. } => status::STATUS_UNSUCCESSFUL,
            Self::InvalidParameter { .. } => status::STATUS_INVALID_PARAMETER,
            Self::BufferTooSmall { .. } => status::STATUS_BUFFER_TOO_SMALL,
            Self::AccessDenied { .. } => status::STATUS_ACCESS_DENIED,
            Self::InvalidAddress { .. } => status::STATUS_INVALID_PARAMETER,
            Self::NotImplemented { .. } => status::STATUS_NOT_IMPLEMENTED,
        }
    }
}
