//! Driver handle and connection management

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ptr;

use super::ioctl::IoctlCode;
use super::process::ProcessOps;
use super::{ClientError, ClientResult};

/// handle to opened driver
pub struct DriverHandle {
    handle: *mut std::ffi::c_void,
}

impl DriverHandle {
    /// open driver by symbolic link name
    pub fn open(name: &str) -> ClientResult<Self> {
        let name = CString::new(name).map_err(|_| ClientError::DriverNotFound)?;

        let handle = unsafe {
            CreateFileA(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(ClientError::DriverOpenFailed(io::Error::last_os_error()));
        }

        Ok(Self { handle })
    }

    /// get raw handle
    pub fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle
    }

    /// send IOCTL with input and output buffers
    pub fn ioctl<I, O>(
        &self,
        code: u32,
        input: Option<&I>,
        mut output: Option<&mut O>,
    ) -> ClientResult<u32>
    where
        I: ?Sized,
        O: ?Sized,
    {
        let input_ptr = input.map(|i| i as *const I as *const u8).unwrap_or(ptr::null());
        let input_size = input.map(|i| std::mem::size_of_val(i) as u32).unwrap_or(0);

        let output_size = output.as_ref().map(|o| std::mem::size_of_val(*o) as u32).unwrap_or(0);
        let output_ptr = output
            .as_mut()
            .map(|o| *o as *mut O as *mut u8)
            .unwrap_or(ptr::null_mut());

        let mut bytes_returned = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                code,
                input_ptr as *const _,
                input_size,
                output_ptr as *mut _,
                output_size,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(ClientError::IoctlFailed {
                code,
                error: io::Error::last_os_error(),
            });
        }

        Ok(bytes_returned)
    }

    /// send IOCTL with byte buffers
    pub fn ioctl_raw(
        &self,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> ClientResult<u32> {
        let mut bytes_returned = 0u32;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                code,
                if input.is_empty() { ptr::null() } else { input.as_ptr() as *const _ },
                input.len() as u32,
                if output.is_empty() { ptr::null_mut() } else { output.as_mut_ptr() as *mut _ },
                output.len() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            return Err(ClientError::IoctlFailed {
                code,
                error: io::Error::last_os_error(),
            });
        }

        Ok(bytes_returned)
    }
}

impl Drop for DriverHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

// SAFETY: handle can be sent between threads
unsafe impl Send for DriverHandle {}
unsafe impl Sync for DriverHandle {}

/// high-level driver client
pub struct DriverClient {
    handle: DriverHandle,
}

impl DriverClient {
    /// connect to driver
    pub fn connect(device_name: &str) -> ClientResult<Self> {
        let handle = DriverHandle::open(device_name)?;
        Ok(Self { handle })
    }

    /// get underlying handle
    pub fn handle(&self) -> &DriverHandle {
        &self.handle
    }

    /// open process for memory operations
    pub fn open_process(&self, pid: u32) -> ClientResult<ProcessOps> {
        ProcessOps::new(&self.handle, pid)
    }

    /// read value from remote process
    pub fn read_process_memory<T: Copy>(&self, pid: u32, address: u64) -> ClientResult<T> {
        use super::ioctl::{ReadMemoryRequest, codes};

        let request = ReadMemoryRequest {
            process_id: pid,
            address,
            size: std::mem::size_of::<T>() as u32,
        };

        // separate input and output buffers
        let input_bytes = unsafe {
            std::slice::from_raw_parts(
                &request as *const _ as *const u8,
                std::mem::size_of::<ReadMemoryRequest>(),
            )
        };

        let mut output_buffer = vec![0u8; std::mem::size_of::<T>()];

        let bytes = self.handle.ioctl_raw(
            codes::READ_MEMORY.code(),
            input_bytes,
            &mut output_buffer,
        )?;

        if bytes as usize != std::mem::size_of::<T>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<T>(),
                received: bytes as usize,
            });
        }

        // read value from buffer
        Ok(unsafe { ptr::read(output_buffer.as_ptr() as *const T) })
    }

    /// write value to remote process
    pub fn write_process_memory<T: Copy>(&self, pid: u32, address: u64, value: &T) -> ClientResult<()> {
        use super::ioctl::{WriteMemoryRequest, codes};

        // create buffer with header + data
        let header_size = std::mem::size_of::<WriteMemoryRequest>();
        let data_size = std::mem::size_of::<T>();
        let mut buffer = vec![0u8; header_size + data_size];

        let request = WriteMemoryRequest {
            process_id: pid,
            address,
            size: data_size as u32,
        };

        // copy header
        unsafe {
            ptr::copy_nonoverlapping(
                &request as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
            // copy data
            ptr::copy_nonoverlapping(
                value as *const T as *const u8,
                buffer.as_mut_ptr().add(header_size),
                data_size,
            );
        }

        let _ = self.handle.ioctl_raw(codes::WRITE_MEMORY.code(), &buffer, &mut [])?;
        Ok(())
    }

    /// get module base address
    pub fn get_module_base(&self, pid: u32, module_name: &str) -> ClientResult<u64> {
        use super::ioctl::{GetModuleBaseRequest, GetModuleBaseResponse, codes};

        let name_bytes = module_name.as_bytes();
        let header_size = std::mem::size_of::<GetModuleBaseRequest>();
        let total_size = header_size + name_bytes.len();

        let mut input = vec![0u8; total_size];
        let request = GetModuleBaseRequest {
            process_id: pid,
            module_name_offset: header_size as u32,
            module_name_length: name_bytes.len() as u32,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &request as *const _ as *const u8,
                input.as_mut_ptr(),
                header_size,
            );
            ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                input.as_mut_ptr().add(header_size),
                name_bytes.len(),
            );
        }

        let mut response = MaybeUninit::<GetModuleBaseResponse>::uninit();
        let bytes = self.handle.ioctl(
            codes::GET_MODULE_BASE.code(),
            Some(&input[..]),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<GetModuleBaseResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<GetModuleBaseResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.base_address)
    }

    /// allocate memory in remote process
    pub fn allocate_memory(
        &self,
        pid: u32,
        size: u64,
        protection: u32,
    ) -> ClientResult<u64> {
        use super::ioctl::{AllocateMemoryRequest, AllocateMemoryResponse, codes};

        let request = AllocateMemoryRequest {
            process_id: pid,
            size,
            protection,
            preferred_address: 0,
        };

        let mut response = MaybeUninit::<AllocateMemoryResponse>::uninit();
        let bytes = self.handle.ioctl(
            codes::ALLOCATE_MEMORY.code(),
            Some(&request),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<AllocateMemoryResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<AllocateMemoryResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.allocated_address)
    }

    /// free memory in remote process
    pub fn free_memory(&self, pid: u32, address: u64) -> ClientResult<()> {
        use super::ioctl::{FreeMemoryRequest, codes};

        let request = FreeMemoryRequest {
            process_id: pid,
            address,
        };

        let _ = self.handle.ioctl(codes::FREE_MEMORY.code(), Some(&request), None::<&mut ()>)?;
        Ok(())
    }

    /// change memory protection
    pub fn protect_memory(
        &self,
        pid: u32,
        address: u64,
        size: u64,
        protection: u32,
    ) -> ClientResult<u32> {
        use super::ioctl::{ProtectMemoryRequest, ProtectMemoryResponse, codes};

        let request = ProtectMemoryRequest {
            process_id: pid,
            address,
            size,
            new_protection: protection,
        };

        let mut response = MaybeUninit::<ProtectMemoryResponse>::uninit();
        let bytes = self.handle.ioctl(
            codes::PROTECT_MEMORY.code(),
            Some(&request),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<ProtectMemoryResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<ProtectMemoryResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.old_protection)
    }
}

// Windows API constants
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut _;

// Windows API functions
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileA(
        lpFileName: *const i8,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut std::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;

    fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;

    fn DeviceIoControl(
        hDevice: *mut std::ffi::c_void,
        dwIoControlCode: u32,
        lpInBuffer: *const std::ffi::c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut std::ffi::c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> i32;
}
