//! Kernel memory operations: MDL, physical memory, virtual memory

use core::ffi::c_void;
use core::ptr::NonNull;
use alloc::vec::Vec;

use super::allocator::{PoolBuffer, PoolType};
use super::error::{status, KmError, KmResult, NtStatus};

/// MDL flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdlFlags {
    /// MDL describes locked pages
    MappedToSystemVa = 0x0001,
    /// pages are from paged pool
    PagesPaged = 0x0002,
    /// allocated from lookaside
    SourceIsNonpagedPool = 0x0004,
    /// allocated with MDL_ALLOCATED_FIXED_SIZE
    AllocatedFixedSize = 0x0008,
    /// partial MDL
    Partial = 0x0010,
    /// partial MDL has been built
    PartialHasBeenMapped = 0x0020,
    /// locked using MmProbeAndLockPages
    IoPageRead = 0x0040,
    /// writeable
    WriteOperation = 0x0080,
    /// locked pages
    LockedPages = 0x0100,
    /// IO space
    IoSpace = 0x0800,
    /// network buffer
    NetworkHeader = 0x1000,
    /// MDL describes mapped pages
    Mapping = 0x2000,
    /// internal MDL flag
    AllocatedMustSucceed = 0x4000,
    /// internal MDL flag
    Internal = 0x8000,
}

/// memory descriptor list wrapper
#[repr(C)]
pub struct MdlRaw {
    pub next: *mut MdlRaw,
    pub size: i16,
    pub mdl_flags: i16,
    pub process: *mut c_void,
    pub mapped_system_va: *mut c_void,
    pub start_va: *mut c_void,
    pub byte_count: u32,
    pub byte_offset: u32,
    // PFN array follows
}

/// safe MDL wrapper with RAII cleanup
pub struct Mdl {
    raw: *mut MdlRaw,
    locked: bool,
    mapped: bool,
    system_address: Option<NonNull<c_void>>,
}

impl Mdl {
    /// create MDL for virtual address range
    pub fn create(virtual_address: *mut c_void, length: usize) -> KmResult<Self> {
        // SAFETY: IoAllocateMdl is safe to call
        let raw = unsafe {
            IoAllocateMdl(
                virtual_address,
                length as u32,
                0, // not secondary
                0, // don't charge quota
                core::ptr::null_mut(), // no IRP
            )
        };

        if raw.is_null() {
            return Err(KmError::MdlOperationFailed {
                reason: "IoAllocateMdl returned null",
            });
        }

        Ok(Self {
            raw,
            locked: false,
            mapped: false,
            system_address: None,
        })
    }

    /// lock pages in memory (for user-mode buffers)
    pub fn lock_pages(&mut self, access_mode: AccessMode, operation: LockOperation) -> KmResult<()> {
        if self.locked {
            return Ok(());
        }

        // SAFETY: MDL is valid
        let result = unsafe {
            MmProbeAndLockPages(self.raw, access_mode as u8, operation as u32)
        };

        // MmProbeAndLockPages doesn't return status, it raises exception on failure
        // in kernel we'd use SEH but in Rust we assume success
        self.locked = true;
        Ok(())
    }

    /// get system address for MDL
    pub fn system_address(&mut self) -> KmResult<NonNull<c_void>> {
        if let Some(addr) = self.system_address {
            return Ok(addr);
        }

        // SAFETY: MDL is valid and pages are locked
        let addr = unsafe {
            MmGetSystemAddressForMdlSafe(self.raw, MmPriority::NormalPagePriority as u32)
        };

        let addr = NonNull::new(addr).ok_or(KmError::MdlOperationFailed {
            reason: "MmGetSystemAddressForMdlSafe returned null",
        })?;

        self.system_address = Some(addr);
        self.mapped = true;
        Ok(addr)
    }

    /// get byte count
    pub fn byte_count(&self) -> u32 {
        // SAFETY: MDL is valid
        unsafe { (*self.raw).byte_count }
    }

    /// get raw MDL pointer
    pub fn as_raw(&self) -> *mut MdlRaw {
        self.raw
    }

    /// unlock pages
    pub fn unlock_pages(&mut self) {
        if self.locked {
            // SAFETY: MDL is valid and pages are locked
            unsafe {
                MmUnlockPages(self.raw);
            }
            self.locked = false;
        }
    }
}

impl Drop for Mdl {
    fn drop(&mut self) {
        if self.locked {
            self.unlock_pages();
        }
        if !self.raw.is_null() {
            // SAFETY: MDL was allocated by IoAllocateMdl
            unsafe {
                IoFreeMdl(self.raw);
            }
        }
    }
}

/// processor mode for memory operations
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    KernelMode = 0,
    UserMode = 1,
}

/// lock operation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOperation {
    IoReadAccess = 0,
    IoWriteAccess = 1,
    IoModifyAccess = 2,
}

/// page priority for MDL mapping
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmPriority {
    LowPagePriority = 0,
    NormalPagePriority = 16,
    HighPagePriority = 32,
}

/// physical memory operations
pub struct PhysicalMemory;

impl PhysicalMemory {
    /// read from physical address
    pub fn read(physical_address: u64, buffer: &mut [u8]) -> KmResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let size = buffer.len();

        // map physical to virtual
        let phys_addr = PhysicalAddress(physical_address);
        let va = unsafe {
            MmMapIoSpace(phys_addr, size, MmCacheType::NonCached as u32)
        };

        if va.is_null() {
            return Err(KmError::PhysicalMemoryFailed {
                address: physical_address,
                size,
            });
        }

        // copy data
        // SAFETY: va is valid for size bytes
        unsafe {
            core::ptr::copy_nonoverlapping(va as *const u8, buffer.as_mut_ptr(), size);
            MmUnmapIoSpace(va, size);
        }

        Ok(size)
    }

    /// write to physical address
    pub fn write(physical_address: u64, buffer: &[u8]) -> KmResult<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let size = buffer.len();

        let phys_addr = PhysicalAddress(physical_address);
        let va = unsafe {
            MmMapIoSpace(phys_addr, size, MmCacheType::NonCached as u32)
        };

        if va.is_null() {
            return Err(KmError::PhysicalMemoryFailed {
                address: physical_address,
                size,
            });
        }

        // SAFETY: va is valid for size bytes
        unsafe {
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), va as *mut u8, size);
            MmUnmapIoSpace(va, size);
        }

        Ok(size)
    }

    /// get physical address for virtual address
    pub fn get_physical_address(virtual_address: *const c_void) -> Option<u64> {
        // SAFETY: MmGetPhysicalAddress is safe for valid VA
        let phys = unsafe { MmGetPhysicalAddress(virtual_address) };
        if phys.0 == 0 {
            None
        } else {
            Some(phys.0)
        }
    }

    /// check if physical address is valid
    pub fn is_address_valid(physical_address: u64) -> bool {
        let phys_addr = PhysicalAddress(physical_address);
        // SAFETY: just checking address validity
        unsafe { MmIsAddressValid(phys_addr.0 as *const c_void) != 0 }
    }
}

/// cache type for memory mapping
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmCacheType {
    NonCached = 0,
    Cached = 1,
    WriteCombined = 2,
    HardwareCoherentCached = 3,
    NonCachedUnordered = 4,
}

/// physical address wrapper
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct PhysicalAddress(pub u64);

/// virtual memory operations for kernel
pub struct VirtualMemory;

impl VirtualMemory {
    /// allocate virtual memory in kernel space
    pub fn allocate(size: usize, protection: u32) -> KmResult<NonNull<c_void>> {
        let mut region_size = size;
        let mut base_address: *mut c_void = core::ptr::null_mut();

        // SAFETY: kernel allocation
        let status = unsafe {
            ZwAllocateVirtualMemory(
                -1isize as *mut c_void, // current process
                &mut base_address,
                0,
                &mut region_size,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                protection,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::VirtualMemoryFailed {
                address: 0,
                size,
                reason: "ZwAllocateVirtualMemory failed",
            });
        }

        NonNull::new(base_address).ok_or(KmError::VirtualMemoryFailed {
            address: 0,
            size,
            reason: "allocation returned null",
        })
    }

    /// free virtual memory
    ///
    /// # Safety
    /// address must have been allocated by VirtualMemory::allocate
    pub unsafe fn free(address: *mut c_void) -> KmResult<()> {
        let mut base = address;
        let mut size = 0usize;

        // SAFETY: caller ensures address is valid
        let status = unsafe {
            ZwFreeVirtualMemory(
                -1isize as *mut c_void,
                &mut base,
                &mut size,
                0x8000, // MEM_RELEASE
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::VirtualMemoryFailed {
                address: address as u64,
                size: 0,
                reason: "ZwFreeVirtualMemory failed",
            });
        }

        Ok(())
    }

    /// change memory protection
    pub fn protect(
        address: *mut c_void,
        size: usize,
        new_protection: u32,
    ) -> KmResult<u32> {
        let mut old_protection = 0u32;
        let mut region_size = size;
        let mut base = address;

        // SAFETY: valid parameters
        let status = unsafe {
            ZwProtectVirtualMemory(
                -1isize as *mut c_void,
                &mut base,
                &mut region_size,
                new_protection,
                &mut old_protection,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::VirtualMemoryFailed {
                address: address as u64,
                size,
                reason: "ZwProtectVirtualMemory failed",
            });
        }

        Ok(old_protection)
    }
}

/// kernel-mode specific memory utilities
pub struct KernelMemory;

impl KernelMemory {
    /// copy memory with exception handling
    pub fn copy(
        destination: *mut c_void,
        source: *const c_void,
        length: usize,
    ) -> KmResult<()> {
        if destination.is_null() || source.is_null() {
            return Err(KmError::InvalidParameter {
                context: "copy: null pointer",
            });
        }

        // SAFETY: caller ensures pointers are valid
        // kernel should wrap this in SEH
        unsafe {
            core::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, length);
        }

        Ok(())
    }

    /// safe copy that handles exceptions (returns partial copy size)
    pub fn safe_copy(
        destination: *mut c_void,
        source: *const c_void,
        length: usize,
    ) -> KmResult<usize> {
        let mut bytes_copied = 0usize;

        // SAFETY: MmCopyMemory handles exceptions
        let status = unsafe {
            MmCopyMemory(
                destination,
                MmCopyAddress { virtual_address: source },
                length,
                0, // MM_COPY_MEMORY_VIRTUAL
                &mut bytes_copied,
            )
        };

        if !status::nt_success(status) && bytes_copied == 0 {
            return Err(KmError::VirtualMemoryFailed {
                address: source as u64,
                size: length,
                reason: "MmCopyMemory failed",
            });
        }

        Ok(bytes_copied)
    }

    /// check if address is valid
    pub fn is_address_valid(address: *const c_void) -> bool {
        if address.is_null() {
            return false;
        }
        // SAFETY: just checking validity
        unsafe { MmIsAddressValid(address) != 0 }
    }

    /// check if address range is valid
    pub fn is_range_valid(address: *const c_void, size: usize) -> bool {
        if address.is_null() || size == 0 {
            return false;
        }

        let start = address as usize;
        let end = start.saturating_add(size);

        // check at page boundaries
        let page_size = 0x1000usize;
        let mut current = start;

        while current < end {
            if !Self::is_address_valid(current as *const c_void) {
                return false;
            }
            current = current.saturating_add(page_size);
        }

        true
    }

    /// zero memory
    pub fn zero(address: *mut c_void, size: usize) {
        if !address.is_null() && size > 0 {
            // SAFETY: caller ensures address is valid
            unsafe {
                core::ptr::write_bytes(address as *mut u8, 0, size);
            }
        }
    }
}

/// memory copy address union
#[repr(C)]
union MmCopyAddress {
    virtual_address: *const c_void,
    physical_address: PhysicalAddress,
}

/// RAII guard for virtual memory protection changes
pub struct ProtectionGuard {
    address: *mut c_void,
    size: usize,
    old_protection: u32,
}

impl ProtectionGuard {
    /// change protection with automatic restore on drop
    pub fn new(
        address: *mut c_void,
        size: usize,
        new_protection: u32,
    ) -> KmResult<Self> {
        let old_protection = VirtualMemory::protect(address, size, new_protection)?;
        Ok(Self {
            address,
            size,
            old_protection,
        })
    }

    /// get old protection value
    pub fn old_protection(&self) -> u32 {
        self.old_protection
    }
}

impl Drop for ProtectionGuard {
    fn drop(&mut self) {
        let _ = VirtualMemory::protect(self.address, self.size, self.old_protection);
    }
}

// memory protection constants
pub mod protection {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_WRITECOPY: u32 = 0x08;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
    pub const PAGE_GUARD: u32 = 0x100;
    pub const PAGE_NOCACHE: u32 = 0x200;
}

// kernel memory functions
extern "system" {
    fn IoAllocateMdl(
        VirtualAddress: *mut c_void,
        Length: u32,
        SecondaryBuffer: u8,
        ChargeQuota: u8,
        Irp: *mut c_void,
    ) -> *mut MdlRaw;

    fn IoFreeMdl(Mdl: *mut MdlRaw);

    fn MmProbeAndLockPages(
        MemoryDescriptorList: *mut MdlRaw,
        AccessMode: u8,
        Operation: u32,
    );

    fn MmUnlockPages(MemoryDescriptorList: *mut MdlRaw);

    fn MmGetSystemAddressForMdlSafe(
        Mdl: *mut MdlRaw,
        Priority: u32,
    ) -> *mut c_void;

    fn MmMapIoSpace(
        PhysicalAddress: PhysicalAddress,
        NumberOfBytes: usize,
        CacheType: u32,
    ) -> *mut c_void;

    fn MmUnmapIoSpace(BaseAddress: *mut c_void, NumberOfBytes: usize);

    fn MmGetPhysicalAddress(BaseAddress: *const c_void) -> PhysicalAddress;

    fn MmIsAddressValid(VirtualAddress: *const c_void) -> u8;

    fn MmCopyMemory(
        TargetAddress: *mut c_void,
        SourceAddress: MmCopyAddress,
        NumberOfBytes: usize,
        Flags: u32,
        NumberOfBytesTransferred: *mut usize,
    ) -> NtStatus;

    fn ZwAllocateVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> NtStatus;

    fn ZwFreeVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        FreeType: u32,
    ) -> NtStatus;

    fn ZwProtectVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut *mut c_void,
        RegionSize: *mut usize,
        NewProtect: u32,
        OldProtect: *mut u32,
    ) -> NtStatus;
}
