//! IRP (I/O Request Packet) handling

use core::ffi::c_void;
use core::ptr::NonNull;

use super::error::{status, NtStatus};
use super::memory::MdlRaw;

/// IRP major function codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpMajorFunction {
    Create = 0x00,
    CreateNamedPipe = 0x01,
    Close = 0x02,
    Read = 0x03,
    Write = 0x04,
    QueryInformation = 0x05,
    SetInformation = 0x06,
    QueryEa = 0x07,
    SetEa = 0x08,
    FlushBuffers = 0x09,
    QueryVolumeInformation = 0x0a,
    SetVolumeInformation = 0x0b,
    DirectoryControl = 0x0c,
    FileSystemControl = 0x0d,
    DeviceControl = 0x0e,
    InternalDeviceControl = 0x0f,
    Shutdown = 0x10,
    LockControl = 0x11,
    Cleanup = 0x12,
    CreateMailslot = 0x13,
    QuerySecurity = 0x14,
    SetSecurity = 0x15,
    Power = 0x16,
    SystemControl = 0x17,
    DeviceChange = 0x18,
    QueryQuota = 0x19,
    SetQuota = 0x1a,
    Pnp = 0x1b,
}

/// IRP structure (simplified)
#[repr(C)]
pub struct IrpRaw {
    pub type_: i16,
    pub size: u16,
    pub mdl_address: *mut MdlRaw,
    pub flags: u32,
    pub associated_irp: IrpAssociatedUnion,
    pub thread_list_entry: [*mut c_void; 2],
    pub io_status: IoStatusBlock,
    pub requestor_mode: i8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub cancel: u8,
    pub cancel_irql: u8,
    pub apc_environment: i8,
    pub allocation_flags: u8,
    pub user_iosb: *mut IoStatusBlock,
    pub user_event: *mut c_void,
    pub overlay: IrpOverlay,
    pub cancel_routine: *mut c_void,
    pub user_buffer: *mut c_void,
    pub tail: IrpTail,
}

/// IRP associated union
#[repr(C)]
pub union IrpAssociatedUnion {
    pub master_irp: *mut IrpRaw,
    pub irp_count: i32,
    pub system_buffer: *mut c_void,
}

/// IRP overlay
#[repr(C)]
pub union IrpOverlay {
    pub async_parameters: AsyncParameters,
    pub allocation_size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AsyncParameters {
    pub user_apc_routine: *mut c_void,
    pub user_apc_context: *mut c_void,
}

/// IRP tail
#[repr(C)]
pub union IrpTail {
    pub overlay: TailOverlay,
    pub apc: [u8; 88],
    pub completion_key: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TailOverlay {
    pub driver_context: [*mut c_void; 4],
    pub thread: *mut c_void,
    pub auxiliary_buffer: *mut c_void,
    pub list_entry: [*mut c_void; 2],
    pub current_stack_location: *mut IoStackLocation,
    pub original_file_object: *mut c_void,
}

/// I/O status block
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoStatusBlock {
    pub status: NtStatus,
    pub information: usize,
}

impl Default for IoStatusBlock {
    fn default() -> Self {
        Self {
            status: status::STATUS_SUCCESS,
            information: 0,
        }
    }
}

/// I/O stack location
#[repr(C)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub parameters: IoStackParameters,
    pub device_object: *mut c_void,
    pub file_object: *mut c_void,
    pub completion_routine: *mut c_void,
    pub context: *mut c_void,
}

/// I/O stack parameters union
#[repr(C)]
pub union IoStackParameters {
    pub create: CreateParameters,
    pub read: ReadWriteParameters,
    pub write: ReadWriteParameters,
    pub device_io_control: DeviceIoControlParameters,
    pub others: OtherParameters,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CreateParameters {
    pub security_context: *mut c_void,
    pub options: u32,
    pub file_attributes: u16,
    pub share_access: u16,
    pub ea_length: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadWriteParameters {
    pub length: u32,
    pub key: u32,
    pub byte_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceIoControlParameters {
    pub output_buffer_length: u32,
    pub input_buffer_length: u32,
    pub io_control_code: u32,
    pub type3_input_buffer: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OtherParameters {
    pub argument1: *mut c_void,
    pub argument2: *mut c_void,
    pub argument3: *mut c_void,
    pub argument4: *mut c_void,
}

/// safe IRP wrapper
pub struct Irp {
    raw: NonNull<IrpRaw>,
}

impl Irp {
    /// wrap raw IRP pointer
    ///
    /// # Safety
    /// ptr must be a valid IRP pointer
    pub unsafe fn from_raw(ptr: *mut c_void) -> Option<Self> {
        NonNull::new(ptr as *mut IrpRaw).map(|raw| Self { raw })
    }

    /// get raw pointer
    pub fn as_raw(&self) -> *mut IrpRaw {
        self.raw.as_ptr()
    }

    /// get current I/O stack location
    pub fn current_stack_location(&self) -> Option<&IoStackLocation> {
        // SAFETY: IRP is valid
        unsafe {
            let tail = &(*self.raw.as_ptr()).tail;
            let overlay = &tail.overlay;
            let stack = overlay.current_stack_location;
            if stack.is_null() {
                None
            } else {
                Some(&*stack)
            }
        }
    }

    /// get mutable current I/O stack location
    pub fn current_stack_location_mut(&mut self) -> Option<&mut IoStackLocation> {
        // SAFETY: we have exclusive access
        unsafe {
            let tail = &mut (*self.raw.as_ptr()).tail;
            let overlay = &mut tail.overlay;
            let stack = overlay.current_stack_location;
            if stack.is_null() {
                None
            } else {
                Some(&mut *stack)
            }
        }
    }

    /// get major function code
    pub fn major_function(&self) -> Option<IrpMajorFunction> {
        self.current_stack_location().map(|stack| {
            // SAFETY: we're reading a valid enum value
            unsafe { core::mem::transmute(stack.major_function) }
        })
    }

    /// get minor function code
    pub fn minor_function(&self) -> Option<u8> {
        self.current_stack_location().map(|stack| stack.minor_function)
    }

    /// get system buffer (for buffered I/O)
    pub fn system_buffer(&self) -> *mut c_void {
        // SAFETY: IRP is valid
        unsafe { (*self.raw.as_ptr()).associated_irp.system_buffer }
    }

    /// get user buffer
    pub fn user_buffer(&self) -> *mut c_void {
        // SAFETY: IRP is valid
        unsafe { (*self.raw.as_ptr()).user_buffer }
    }

    /// get MDL address (for direct I/O)
    pub fn mdl_address(&self) -> *mut MdlRaw {
        // SAFETY: IRP is valid
        unsafe { (*self.raw.as_ptr()).mdl_address }
    }

    /// get IOCTL parameters
    pub fn ioctl_parameters(&self) -> Option<DeviceIoControlParameters> {
        self.current_stack_location().map(|stack| {
            // SAFETY: assuming this is a device control request
            unsafe { stack.parameters.device_io_control }
        })
    }

    /// get IOCTL code
    pub fn ioctl_code(&self) -> Option<u32> {
        self.ioctl_parameters().map(|p| p.io_control_code)
    }

    /// get input buffer length
    pub fn input_buffer_length(&self) -> Option<u32> {
        self.ioctl_parameters().map(|p| p.input_buffer_length)
    }

    /// get output buffer length
    pub fn output_buffer_length(&self) -> Option<u32> {
        self.ioctl_parameters().map(|p| p.output_buffer_length)
    }

    /// get read/write parameters
    pub fn rw_parameters(&self) -> Option<ReadWriteParameters> {
        self.current_stack_location().map(|stack| {
            // SAFETY: assuming this is a read/write request
            unsafe { stack.parameters.read }
        })
    }

    /// get read/write length
    pub fn rw_length(&self) -> Option<u32> {
        self.rw_parameters().map(|p| p.length)
    }

    /// get read/write offset
    pub fn rw_offset(&self) -> Option<u64> {
        self.rw_parameters().map(|p| p.byte_offset)
    }

    /// set I/O status
    pub fn set_status(&mut self, status: NtStatus, information: usize) {
        // SAFETY: we have exclusive access
        unsafe {
            (*self.raw.as_ptr()).io_status.status = status;
            (*self.raw.as_ptr()).io_status.information = information;
        }
    }

    /// get I/O status
    pub fn io_status(&self) -> IoStatusBlock {
        // SAFETY: IRP is valid
        unsafe { (*self.raw.as_ptr()).io_status }
    }

    /// complete the IRP
    pub fn complete(&mut self, status: NtStatus) {
        self.complete_with_info(status, 0);
    }

    /// complete the IRP with information
    pub fn complete_with_info(&mut self, status: NtStatus, information: usize) {
        self.set_status(status, information);
        // SAFETY: IRP is valid
        unsafe {
            IofCompleteRequest(self.raw.as_ptr() as *mut c_void, 0); // IO_NO_INCREMENT
        }
    }

    /// complete with priority boost
    pub fn complete_with_boost(&mut self, status: NtStatus, information: usize, boost: i8) {
        self.set_status(status, information);
        // SAFETY: IRP is valid
        unsafe {
            IofCompleteRequest(self.raw.as_ptr() as *mut c_void, boost);
        }
    }

    /// mark IRP as pending
    pub fn mark_pending(&mut self) {
        // SAFETY: we have exclusive access
        unsafe {
            IoMarkIrpPending(self.raw.as_ptr() as *mut c_void);
        }
    }

    /// get input buffer as typed reference
    pub fn input_buffer<T>(&self) -> Option<&T> {
        let buffer = self.system_buffer();
        let len = self.input_buffer_length()?;

        if buffer.is_null() || (len as usize) < core::mem::size_of::<T>() {
            return None;
        }

        // SAFETY: buffer is valid and large enough
        Some(unsafe { &*(buffer as *const T) })
    }

    /// get output buffer as typed mutable reference
    pub fn output_buffer_mut<T>(&mut self) -> Option<&mut T> {
        let buffer = self.system_buffer();
        let len = self.output_buffer_length()?;

        if buffer.is_null() || (len as usize) < core::mem::size_of::<T>() {
            return None;
        }

        // SAFETY: buffer is valid and large enough
        Some(unsafe { &mut *(buffer as *mut T) })
    }

    /// get input buffer as byte slice
    pub fn input_bytes(&self) -> Option<&[u8]> {
        let buffer = self.system_buffer();
        let len = self.input_buffer_length()?;

        if buffer.is_null() || len == 0 {
            return None;
        }

        // SAFETY: buffer is valid for len bytes
        Some(unsafe { core::slice::from_raw_parts(buffer as *const u8, len as usize) })
    }

    /// get output buffer as mutable byte slice
    pub fn output_bytes_mut(&mut self) -> Option<&mut [u8]> {
        let buffer = self.system_buffer();
        let len = self.output_buffer_length()?;

        if buffer.is_null() || len == 0 {
            return None;
        }

        // SAFETY: buffer is valid for len bytes
        Some(unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, len as usize) })
    }
}

// IRP handling functions
extern "system" {
    fn IofCompleteRequest(Irp: *mut c_void, PriorityBoost: i8);
    fn IoMarkIrpPending(Irp: *mut c_void);
}
