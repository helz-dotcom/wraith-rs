//! Process operations through kernel driver

use super::driver::DriverHandle;
use super::ioctl;
use super::{ClientError, ClientResult};

use std::mem::MaybeUninit;
use std::ptr;

/// process memory operations via kernel driver
pub struct ProcessOps<'a> {
    handle: &'a DriverHandle,
    pid: u32,
}

impl<'a> ProcessOps<'a> {
    /// create new process operations
    pub(crate) fn new(handle: &'a DriverHandle, pid: u32) -> ClientResult<Self> {
        Ok(Self { handle, pid })
    }

    /// get process ID
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// read value from process memory
    pub fn read<T: Copy>(&self, address: u64) -> ClientResult<T> {
        let request = ioctl::ReadMemoryRequest {
            process_id: self.pid,
            address,
            size: std::mem::size_of::<T>() as u32,
        };

        let mut buffer = vec![0u8; std::mem::size_of::<T>()];

        let bytes = self.handle.ioctl_raw(
            ioctl::codes::READ_MEMORY.code(),
            unsafe {
                std::slice::from_raw_parts(
                    &request as *const _ as *const u8,
                    std::mem::size_of::<ioctl::ReadMemoryRequest>(),
                )
            },
            &mut buffer,
        )?;

        if bytes as usize != std::mem::size_of::<T>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<T>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { ptr::read(buffer.as_ptr() as *const T) })
    }

    /// read bytes from process memory
    pub fn read_bytes(&self, address: u64, size: usize) -> ClientResult<Vec<u8>> {
        let request = ioctl::ReadMemoryRequest {
            process_id: self.pid,
            address,
            size: size as u32,
        };

        let mut buffer = vec![0u8; size];

        let bytes = self.handle.ioctl_raw(
            ioctl::codes::READ_MEMORY.code(),
            unsafe {
                std::slice::from_raw_parts(
                    &request as *const _ as *const u8,
                    std::mem::size_of::<ioctl::ReadMemoryRequest>(),
                )
            },
            &mut buffer,
        )?;

        buffer.truncate(bytes as usize);
        Ok(buffer)
    }

    /// write value to process memory
    pub fn write<T: Copy>(&self, address: u64, value: &T) -> ClientResult<()> {
        let header_size = std::mem::size_of::<ioctl::WriteMemoryRequest>();
        let data_size = std::mem::size_of::<T>();
        let mut buffer = vec![0u8; header_size + data_size];

        let request = ioctl::WriteMemoryRequest {
            process_id: self.pid,
            address,
            size: data_size as u32,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &request as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
            ptr::copy_nonoverlapping(
                value as *const T as *const u8,
                buffer.as_mut_ptr().add(header_size),
                data_size,
            );
        }

        let _ = self.handle.ioctl_raw(ioctl::codes::WRITE_MEMORY.code(), &buffer, &mut [])?;
        Ok(())
    }

    /// write bytes to process memory
    pub fn write_bytes(&self, address: u64, data: &[u8]) -> ClientResult<()> {
        let header_size = std::mem::size_of::<ioctl::WriteMemoryRequest>();
        let mut buffer = vec![0u8; header_size + data.len()];

        let request = ioctl::WriteMemoryRequest {
            process_id: self.pid,
            address,
            size: data.len() as u32,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &request as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                buffer.as_mut_ptr().add(header_size),
                data.len(),
            );
        }

        let _ = self.handle.ioctl_raw(ioctl::codes::WRITE_MEMORY.code(), &buffer, &mut [])?;
        Ok(())
    }

    /// get module base address
    pub fn get_module_base(&self, module_name: &str) -> ClientResult<u64> {
        let name_bytes = module_name.as_bytes();
        let header_size = std::mem::size_of::<ioctl::GetModuleBaseRequest>();
        let total_size = header_size + name_bytes.len();

        let mut input = vec![0u8; total_size];
        let request = ioctl::GetModuleBaseRequest {
            process_id: self.pid,
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

        let mut response = MaybeUninit::<ioctl::GetModuleBaseResponse>::uninit();

        let bytes = self.handle.ioctl(
            ioctl::codes::GET_MODULE_BASE.code(),
            Some(&input[..]),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<ioctl::GetModuleBaseResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<ioctl::GetModuleBaseResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.base_address)
    }

    /// allocate virtual memory
    pub fn allocate(&self, size: u64, protection: u32) -> ClientResult<u64> {
        let request = ioctl::AllocateMemoryRequest {
            process_id: self.pid,
            size,
            protection,
            preferred_address: 0,
        };

        let mut response = MaybeUninit::<ioctl::AllocateMemoryResponse>::uninit();

        let bytes = self.handle.ioctl(
            ioctl::codes::ALLOCATE_MEMORY.code(),
            Some(&request),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<ioctl::AllocateMemoryResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<ioctl::AllocateMemoryResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.allocated_address)
    }

    /// allocate memory at preferred address
    pub fn allocate_at(&self, address: u64, size: u64, protection: u32) -> ClientResult<u64> {
        let request = ioctl::AllocateMemoryRequest {
            process_id: self.pid,
            size,
            protection,
            preferred_address: address,
        };

        let mut response = MaybeUninit::<ioctl::AllocateMemoryResponse>::uninit();

        let bytes = self.handle.ioctl(
            ioctl::codes::ALLOCATE_MEMORY.code(),
            Some(&request),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<ioctl::AllocateMemoryResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<ioctl::AllocateMemoryResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.allocated_address)
    }

    /// free allocated memory
    pub fn free(&self, address: u64) -> ClientResult<()> {
        let request = ioctl::FreeMemoryRequest {
            process_id: self.pid,
            address,
        };

        let _ = self.handle.ioctl(
            ioctl::codes::FREE_MEMORY.code(),
            Some(&request),
            None::<&mut ()>,
        )?;
        Ok(())
    }

    /// change memory protection
    pub fn protect(&self, address: u64, size: u64, protection: u32) -> ClientResult<u32> {
        let request = ioctl::ProtectMemoryRequest {
            process_id: self.pid,
            address,
            size,
            new_protection: protection,
        };

        let mut response = MaybeUninit::<ioctl::ProtectMemoryResponse>::uninit();

        let bytes = self.handle.ioctl(
            ioctl::codes::PROTECT_MEMORY.code(),
            Some(&request),
            Some(unsafe { response.assume_init_mut() }),
        )?;

        if bytes as usize != std::mem::size_of::<ioctl::ProtectMemoryResponse>() {
            return Err(ClientError::InvalidResponse {
                expected: std::mem::size_of::<ioctl::ProtectMemoryResponse>(),
                received: bytes as usize,
            });
        }

        Ok(unsafe { response.assume_init() }.old_protection)
    }

    /// read null-terminated string
    pub fn read_string(&self, address: u64, max_len: usize) -> ClientResult<String> {
        let bytes = self.read_bytes(address, max_len)?;
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..len]).into_owned().pipe(Ok)
    }

    /// read null-terminated wide string
    pub fn read_wstring(&self, address: u64, max_chars: usize) -> ClientResult<String> {
        let bytes = self.read_bytes(address, max_chars * 2)?;
        let chars: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&chars).pipe(Ok)
    }
}

/// extension trait for pipe operator
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}

impl<T> Pipe for T {}
