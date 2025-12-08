//! IOCTL (I/O Control) handling for KM<->UM communication

use core::ffi::c_void;

use super::error::{status, KmError, KmResult, NtStatus};
use super::irp::Irp;

/// IOCTL transfer method
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlMethod {
    /// use system buffer (small transfers, kernel copies data)
    Buffered = 0,
    /// use MDL for input, direct for output
    InDirect = 1,
    /// use direct for input, MDL for output
    OutDirect = 2,
    /// raw pointers (dangerous, requires manual validation)
    Neither = 3,
}

/// IOCTL code builder
#[derive(Debug, Clone, Copy)]
pub struct IoctlCode(pub u32);

impl IoctlCode {
    /// create IOCTL code from components
    pub const fn new(
        device_type: u32,
        function: u32,
        method: IoctlMethod,
        access: u32,
    ) -> Self {
        let code = (device_type << 16)
            | (access << 14)
            | (function << 2)
            | (method as u32);
        Self(code)
    }

    /// create IOCTL for custom device (0x8000+)
    pub const fn custom(function: u32, method: IoctlMethod, access: IoctlAccess) -> Self {
        Self::new(0x8000, function, method, access as u32)
    }

    /// create buffered IOCTL (most common)
    pub const fn buffered(function: u32, access: IoctlAccess) -> Self {
        Self::custom(function, IoctlMethod::Buffered, access)
    }

    /// get device type
    pub const fn device_type(&self) -> u32 {
        (self.0 >> 16) & 0xFFFF
    }

    /// get function code
    pub const fn function(&self) -> u32 {
        (self.0 >> 2) & 0xFFF
    }

    /// get transfer method
    pub const fn method(&self) -> IoctlMethod {
        match self.0 & 3 {
            0 => IoctlMethod::Buffered,
            1 => IoctlMethod::InDirect,
            2 => IoctlMethod::OutDirect,
            _ => IoctlMethod::Neither,
        }
    }

    /// get access mode
    pub const fn access(&self) -> u32 {
        (self.0 >> 14) & 3
    }

    /// get raw code value
    pub const fn code(&self) -> u32 {
        self.0
    }
}

/// IOCTL access modes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlAccess {
    /// any access allowed
    Any = 0,
    /// read access required
    Read = 1,
    /// write access required
    Write = 2,
    /// read and write access required
    ReadWrite = 3,
}

/// IOCTL request wrapper
pub struct Ioctl<'a> {
    irp: &'a mut Irp,
    code: IoctlCode,
}

impl<'a> Ioctl<'a> {
    /// create from IRP
    pub fn from_irp(irp: &'a mut Irp) -> Option<Self> {
        let code = irp.ioctl_code()?;
        Some(Self {
            irp,
            code: IoctlCode(code),
        })
    }

    /// get IOCTL code
    pub fn code(&self) -> IoctlCode {
        self.code
    }

    /// get function number
    pub fn function(&self) -> u32 {
        self.code.function()
    }

    /// get transfer method
    pub fn method(&self) -> IoctlMethod {
        self.code.method()
    }

    /// get input buffer length
    pub fn input_length(&self) -> usize {
        self.irp.input_buffer_length().unwrap_or(0) as usize
    }

    /// get output buffer length
    pub fn output_length(&self) -> usize {
        self.irp.output_buffer_length().unwrap_or(0) as usize
    }

    /// get input buffer as typed reference
    pub fn input<T>(&self) -> Option<&T> {
        if self.input_length() < core::mem::size_of::<T>() {
            return None;
        }
        self.irp.input_buffer()
    }

    /// get output buffer as typed mutable reference
    pub fn output_mut<T>(&mut self) -> Option<&mut T> {
        if self.output_length() < core::mem::size_of::<T>() {
            return None;
        }
        self.irp.output_buffer_mut()
    }

    /// get input as byte slice
    pub fn input_bytes(&self) -> Option<&[u8]> {
        self.irp.input_bytes()
    }

    /// get output as mutable byte slice
    pub fn output_bytes_mut(&mut self) -> Option<&mut [u8]> {
        self.irp.output_bytes_mut()
    }

    /// complete with success
    pub fn complete_success(self) {
        self.complete_with_info(status::STATUS_SUCCESS, 0);
    }

    /// complete with output size
    pub fn complete_with_output(self, output_size: usize) {
        self.complete_with_info(status::STATUS_SUCCESS, output_size);
    }

    /// complete with error
    pub fn complete_error(self, error: KmError) {
        self.complete_with_info(error.to_ntstatus(), 0);
    }

    /// complete with status and information
    pub fn complete_with_info(mut self, status: NtStatus, information: usize) {
        self.irp.complete_with_info(status, information);
    }
}

/// trait for IOCTL handlers
pub trait IoctlHandler {
    /// handle an IOCTL request
    fn handle(&self, ioctl: Ioctl) -> NtStatus;
}

/// IOCTL dispatcher with registered handlers
pub struct IoctlDispatcher {
    handlers: &'static [(u32, &'static dyn IoctlHandler)],
    default_handler: Option<&'static dyn IoctlHandler>,
}

impl IoctlDispatcher {
    /// create new dispatcher with static handler table
    pub const fn new(handlers: &'static [(u32, &'static dyn IoctlHandler)]) -> Self {
        Self {
            handlers,
            default_handler: None,
        }
    }

    /// create with default handler for unknown IOCTLs
    pub const fn with_default(
        handlers: &'static [(u32, &'static dyn IoctlHandler)],
        default: &'static dyn IoctlHandler,
    ) -> Self {
        Self {
            handlers,
            default_handler: Some(default),
        }
    }

    /// dispatch IOCTL to appropriate handler
    pub fn dispatch(&self, irp: &mut Irp) -> NtStatus {
        let Some(ioctl) = Ioctl::from_irp(irp) else {
            return status::STATUS_INVALID_PARAMETER;
        };

        let function = ioctl.function();

        // find handler
        for (code, handler) in self.handlers {
            if *code == function {
                return handler.handle(ioctl);
            }
        }

        // try default handler
        if let Some(handler) = self.default_handler {
            return handler.handle(ioctl);
        }

        // no handler found
        ioctl.complete_with_info(status::STATUS_INVALID_DEVICE_REQUEST, 0);
        status::STATUS_INVALID_DEVICE_REQUEST
    }
}

/// common IOCTL request structures for KM<->UM communication

/// process memory read request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadMemoryRequest {
    pub process_id: u32,
    pub address: u64,
    pub size: u32,
}

/// process memory write request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WriteMemoryRequest {
    pub process_id: u32,
    pub address: u64,
    pub size: u32,
    // data follows in buffer
}

/// get module base request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GetModuleBaseRequest {
    pub process_id: u32,
    pub module_name_offset: u32, // offset in buffer where name starts
    pub module_name_length: u32,
}

/// module base response
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GetModuleBaseResponse {
    pub base_address: u64,
    pub size: u64,
}

/// allocate memory request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocateMemoryRequest {
    pub process_id: u32,
    pub size: u64,
    pub protection: u32,
    pub preferred_address: u64,
}

/// allocate memory response
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocateMemoryResponse {
    pub allocated_address: u64,
    pub actual_size: u64,
}

/// free memory request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FreeMemoryRequest {
    pub process_id: u32,
    pub address: u64,
}

/// protect memory request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProtectMemoryRequest {
    pub process_id: u32,
    pub address: u64,
    pub size: u64,
    pub new_protection: u32,
}

/// protect memory response
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProtectMemoryResponse {
    pub old_protection: u32,
}

/// predefined IOCTL codes for memory operations
pub mod codes {
    use super::{IoctlAccess, IoctlCode};

    /// read process memory
    pub const READ_MEMORY: IoctlCode = IoctlCode::buffered(0x800, IoctlAccess::ReadWrite);

    /// write process memory
    pub const WRITE_MEMORY: IoctlCode = IoctlCode::buffered(0x801, IoctlAccess::ReadWrite);

    /// get module base
    pub const GET_MODULE_BASE: IoctlCode = IoctlCode::buffered(0x802, IoctlAccess::Read);

    /// allocate virtual memory
    pub const ALLOCATE_MEMORY: IoctlCode = IoctlCode::buffered(0x803, IoctlAccess::ReadWrite);

    /// free virtual memory
    pub const FREE_MEMORY: IoctlCode = IoctlCode::buffered(0x804, IoctlAccess::ReadWrite);

    /// change memory protection
    pub const PROTECT_MEMORY: IoctlCode = IoctlCode::buffered(0x805, IoctlAccess::ReadWrite);

    /// query process info
    pub const QUERY_PROCESS: IoctlCode = IoctlCode::buffered(0x806, IoctlAccess::Read);

    /// copy physical memory
    pub const COPY_PHYSICAL: IoctlCode = IoctlCode::buffered(0x807, IoctlAccess::ReadWrite);

    /// map physical memory
    pub const MAP_PHYSICAL: IoctlCode = IoctlCode::buffered(0x808, IoctlAccess::ReadWrite);

    /// unmap physical memory
    pub const UNMAP_PHYSICAL: IoctlCode = IoctlCode::buffered(0x809, IoctlAccess::ReadWrite);
}

/// macro to define IOCTL handler
#[macro_export]
macro_rules! define_ioctl_handler {
    ($name:ident, |$ioctl:ident| $body:block) => {
        struct $name;

        impl $crate::km::ioctl::IoctlHandler for $name {
            fn handle(&self, $ioctl: $crate::km::ioctl::Ioctl) -> $crate::km::error::NtStatus {
                $body
            }
        }
    };
}

/// macro to create IOCTL dispatcher
#[macro_export]
macro_rules! ioctl_dispatcher {
    ($($code:expr => $handler:expr),* $(,)?) => {
        $crate::km::ioctl::IoctlDispatcher::new(&[
            $(($code, &$handler as &dyn $crate::km::ioctl::IoctlHandler)),*
        ])
    };
}
