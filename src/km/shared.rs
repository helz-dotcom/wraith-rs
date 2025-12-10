//! Shared memory for KM<->UM communication

use core::ffi::c_void;
use core::ptr::NonNull;

use super::error::{status, KmError, KmResult, NtStatus};
use super::memory::{Mdl, AccessMode, LockOperation, PhysicalAddress};

/// shared memory section between kernel and usermode
pub struct SharedMemory {
    section_handle: *mut c_void,
    kernel_address: NonNull<c_void>,
    user_address: Option<NonNull<c_void>>,
    size: usize,
    mdl: Option<Mdl>,
}

impl SharedMemory {
    /// create a new shared memory section
    pub fn create(size: usize) -> KmResult<Self> {
        let mut section_handle: *mut c_void = core::ptr::null_mut();
        let mut large_size = size as i64;
        let mut object_attributes = ObjectAttributes::new();

        // SAFETY: create kernel section
        let status = unsafe {
            ZwCreateSection(
                &mut section_handle,
                SECTION_ALL_ACCESS,
                &mut object_attributes as *mut _ as *mut _,
                &mut large_size,
                PAGE_READWRITE,
                SEC_COMMIT,
                core::ptr::null_mut(),
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::NtStatus(status));
        }

        // map to kernel space
        let mut kernel_address: *mut c_void = core::ptr::null_mut();
        let mut view_size = size;

        // SAFETY: map the section to kernel
        let status = unsafe {
            ZwMapViewOfSection(
                section_handle,
                -1isize as *mut c_void, // current process (kernel)
                &mut kernel_address,
                0,
                0,
                core::ptr::null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_READWRITE,
            )
        };

        if !status::nt_success(status) {
            unsafe { ZwClose(section_handle) };
            return Err(KmError::NtStatus(status));
        }

        let kernel_ptr = NonNull::new(kernel_address).ok_or(KmError::NtStatus(status::STATUS_UNSUCCESSFUL))?;

        Ok(Self {
            section_handle,
            kernel_address: kernel_ptr,
            user_address: None,
            size,
            mdl: None,
        })
    }

    /// map the shared memory to a user process
    pub fn map_to_process(&mut self, process_handle: *mut c_void) -> KmResult<*mut c_void> {
        let mut user_address: *mut c_void = core::ptr::null_mut();
        let mut view_size = self.size;

        // SAFETY: map section to user process
        let status = unsafe {
            ZwMapViewOfSection(
                self.section_handle,
                process_handle,
                &mut user_address,
                0,
                0,
                core::ptr::null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_READWRITE,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::NtStatus(status));
        }

        self.user_address = NonNull::new(user_address);
        Ok(user_address)
    }

    /// get kernel-space pointer
    pub fn kernel_ptr(&self) -> *mut c_void {
        self.kernel_address.as_ptr()
    }

    /// get user-space pointer (if mapped)
    pub fn user_ptr(&self) -> Option<*mut c_void> {
        self.user_address.map(|p| p.as_ptr())
    }

    /// get size
    pub fn size(&self) -> usize {
        self.size
    }

    /// get as typed reference
    pub fn as_ref<T>(&self) -> Option<&T> {
        if core::mem::size_of::<T>() > self.size {
            return None;
        }
        // SAFETY: memory is valid
        Some(unsafe { &*(self.kernel_address.as_ptr() as *const T) })
    }

    /// get as typed mutable reference
    pub fn as_mut<T>(&mut self) -> Option<&mut T> {
        if core::mem::size_of::<T>() > self.size {
            return None;
        }
        // SAFETY: memory is valid and we have exclusive access
        Some(unsafe { &mut *(self.kernel_address.as_ptr() as *mut T) })
    }

    /// get as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: memory is valid
        unsafe { core::slice::from_raw_parts(self.kernel_address.as_ptr() as *const u8, self.size) }
    }

    /// get as mutable byte slice
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: memory is valid
        unsafe { core::slice::from_raw_parts_mut(self.kernel_address.as_ptr() as *mut u8, self.size) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        // unmap from kernel
        unsafe {
            ZwUnmapViewOfSection(-1isize as *mut c_void, self.kernel_address.as_ptr());
        }

        // close section
        if !self.section_handle.is_null() {
            unsafe { ZwClose(self.section_handle) };
        }
    }
}

/// ring buffer for efficient KM<->UM data transfer
#[repr(C)]
pub struct SharedRingBuffer {
    read_index: u32,
    write_index: u32,
    size: u32,
    _padding: u32,
    // data follows
}

impl SharedRingBuffer {
    /// minimum buffer size (header + at least 1 page of data)
    pub const MIN_SIZE: usize = 0x1000;

    /// create in shared memory
    pub fn init(memory: &mut SharedMemory) -> KmResult<&mut Self> {
        let mem_size = memory.size();
        if mem_size < Self::MIN_SIZE {
            return Err(KmError::BufferTooSmall {
                required: Self::MIN_SIZE,
                provided: mem_size,
            });
        }

        let header = memory.as_mut::<SharedRingBuffer>().ok_or(KmError::InvalidParameter {
            context: "buffer too small for header",
        })?;

        header.read_index = 0;
        header.write_index = 0;
        header.size = (mem_size - core::mem::size_of::<SharedRingBuffer>()) as u32;
        header._padding = 0;

        Ok(header)
    }

    /// get data portion pointer
    fn data_ptr(&self) -> *mut u8 {
        let header_size = core::mem::size_of::<SharedRingBuffer>();
        // SAFETY: data follows header
        unsafe { (self as *const Self as *mut u8).add(header_size) }
    }

    /// available space for writing
    pub fn available_write(&self) -> u32 {
        // SAFETY: read_index is a valid u32 that we're reading atomically
        let read = unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.read_index as *const _ as *mut _)
                .load(core::sync::atomic::Ordering::Acquire)
        };
        let write = self.write_index;

        if write >= read {
            self.size - (write - read) - 1
        } else {
            read - write - 1
        }
    }

    /// available data for reading
    pub fn available_read(&self) -> u32 {
        let read = self.read_index;
        // SAFETY: write_index is a valid u32 that we're reading atomically
        let write = unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.write_index as *const _ as *mut _)
                .load(core::sync::atomic::Ordering::Acquire)
        };

        if write >= read {
            write - read
        } else {
            self.size - read + write
        }
    }

    /// write data to ring buffer
    pub fn write(&mut self, data: &[u8]) -> KmResult<()> {
        let len = data.len() as u32;
        if len > self.available_write() {
            return Err(KmError::BufferTooSmall {
                required: len as usize,
                provided: self.available_write() as usize,
            });
        }

        let write = self.write_index;
        let data_ptr = self.data_ptr();

        // handle wrap-around
        let first_chunk = core::cmp::min(len, self.size - write);
        let second_chunk = len - first_chunk;

        // SAFETY: indices are within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr.add(write as usize), first_chunk as usize);
            if second_chunk > 0 {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(first_chunk as usize), data_ptr, second_chunk as usize);
            }
        }

        // update write index with release ordering
        let new_write = (write + len) % self.size;
        // SAFETY: write_index is a valid u32 that we're storing atomically
        unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.write_index as *const _ as *mut _)
                .store(new_write, core::sync::atomic::Ordering::Release);
        }

        Ok(())
    }

    /// read data from ring buffer
    pub fn read(&mut self, buffer: &mut [u8]) -> KmResult<usize> {
        let available = self.available_read();
        let len = core::cmp::min(buffer.len() as u32, available);

        if len == 0 {
            return Ok(0);
        }

        let read = self.read_index;
        let data_ptr = self.data_ptr();

        // handle wrap-around
        let first_chunk = core::cmp::min(len, self.size - read);
        let second_chunk = len - first_chunk;

        // SAFETY: indices are within bounds
        unsafe {
            core::ptr::copy_nonoverlapping(data_ptr.add(read as usize), buffer.as_mut_ptr(), first_chunk as usize);
            if second_chunk > 0 {
                core::ptr::copy_nonoverlapping(data_ptr, buffer.as_mut_ptr().add(first_chunk as usize), second_chunk as usize);
            }
        }

        // update read index with release ordering
        let new_read = (read + len) % self.size;
        // SAFETY: read_index is a valid u32 that we're storing atomically
        unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.read_index as *const _ as *mut _)
                .store(new_read, core::sync::atomic::Ordering::Release);
        }

        Ok(len as usize)
    }
}

/// shared buffer for simple message passing
#[repr(C)]
pub struct SharedBuffer {
    pub sequence: u32,
    pub flags: u32,
    pub request_size: u32,
    pub response_size: u32,
    // data follows
}

impl SharedBuffer {
    /// header size
    pub const HEADER_SIZE: usize = core::mem::size_of::<SharedBuffer>();

    /// flag: request pending
    pub const FLAG_REQUEST_PENDING: u32 = 1;
    /// flag: response ready
    pub const FLAG_RESPONSE_READY: u32 = 2;
    /// flag: busy (kernel processing)
    pub const FLAG_BUSY: u32 = 4;

    /// initialize buffer
    pub fn init(&mut self) {
        self.sequence = 0;
        self.flags = 0;
        self.request_size = 0;
        self.response_size = 0;
    }

    /// get request data pointer
    pub fn request_data(&self) -> *const u8 {
        // SAFETY: data follows header
        unsafe { (self as *const Self as *const u8).add(Self::HEADER_SIZE) }
    }

    /// get response data pointer
    pub fn response_data(&mut self) -> *mut u8 {
        // SAFETY: data follows header
        unsafe { (self as *mut Self as *mut u8).add(Self::HEADER_SIZE) }
    }

    /// check if request is pending
    pub fn has_request(&self) -> bool {
        // SAFETY: flags is a valid u32 that we're reading atomically
        let flags = unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.flags as *const _ as *mut _)
                .load(core::sync::atomic::Ordering::Acquire)
        };
        (flags & Self::FLAG_REQUEST_PENDING) != 0
    }

    /// check if response is ready
    pub fn has_response(&self) -> bool {
        // SAFETY: flags is a valid u32 that we're reading atomically
        let flags = unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.flags as *const _ as *mut _)
                .load(core::sync::atomic::Ordering::Acquire)
        };
        (flags & Self::FLAG_RESPONSE_READY) != 0
    }

    /// mark request as processed, set response
    pub fn set_response(&mut self, size: u32) {
        self.response_size = size;
        // SAFETY: flags is a valid u32 that we're storing atomically
        unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.flags as *const _ as *mut _)
                .store(Self::FLAG_RESPONSE_READY, core::sync::atomic::Ordering::Release);
        }
    }

    /// clear request (kernel side)
    pub fn clear_request(&mut self) {
        // SAFETY: flags is a valid u32 that we're storing atomically
        unsafe {
            core::sync::atomic::AtomicU32::from_ptr(&self.flags as *const _ as *mut _)
                .store(0, core::sync::atomic::Ordering::Release);
        }
    }
}

// object attributes for section creation
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut c_void,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

impl ObjectAttributes {
    fn new() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes: 0x00000040, // OBJ_KERNEL_HANDLE
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        }
    }
}

// section disposition constants
const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;

// page protection
const PAGE_READWRITE: u32 = 0x04;
const SEC_COMMIT: u32 = 0x8000000;
const SECTION_ALL_ACCESS: u32 = 0x000F001F;

// section/memory functions
extern "system" {
    fn ZwCreateSection(
        SectionHandle: *mut *mut c_void,
        DesiredAccess: u32,
        ObjectAttributes: *mut c_void,
        MaximumSize: *mut i64,
        PageProtection: u32,
        AllocationAttributes: u32,
        FileHandle: *mut c_void,
    ) -> NtStatus;

    fn ZwMapViewOfSection(
        SectionHandle: *mut c_void,
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        CommitSize: usize,
        SectionOffset: *mut i64,
        ViewSize: *mut usize,
        InheritDisposition: u32,
        AllocationType: u32,
        Win32Protect: u32,
    ) -> NtStatus;

    fn ZwUnmapViewOfSection(ProcessHandle: *mut c_void, BaseAddress: *mut c_void) -> NtStatus;

    fn ZwClose(Handle: *mut c_void) -> NtStatus;
}
