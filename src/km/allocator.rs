//! Kernel pool memory allocation

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr::NonNull;

use super::error::{KmError, KmResult};

/// pool allocation type
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    /// non-paged pool (always resident in physical memory)
    NonPaged = 0,
    /// paged pool (can be paged out)
    Paged = 1,
    /// non-paged pool, no execute
    NonPagedNx = 512,
    /// non-paged pool for session (drivers only)
    NonPagedSession = 32,
    /// paged pool for session
    PagedSession = 33,
}

impl Default for PoolType {
    fn default() -> Self {
        Self::NonPagedNx
    }
}

/// pool allocation tag (4-byte identifier for debugging)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTag(pub u32);

impl PoolTag {
    /// create from 4-character string
    pub const fn from_chars(chars: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(chars))
    }

    /// default tag for wraith allocations
    pub const WRAITH: Self = Self::from_chars(*b"WRAT");
}

impl Default for PoolTag {
    fn default() -> Self {
        Self::WRAITH
    }
}

/// kernel pool allocator
pub struct PoolAllocator {
    pool_type: PoolType,
    tag: PoolTag,
}

impl PoolAllocator {
    /// create new pool allocator with specified type and tag
    pub const fn new(pool_type: PoolType, tag: PoolTag) -> Self {
        Self { pool_type, tag }
    }

    /// create non-paged allocator
    pub const fn non_paged() -> Self {
        Self::new(PoolType::NonPagedNx, PoolTag::WRAITH)
    }

    /// create paged allocator
    pub const fn paged() -> Self {
        Self::new(PoolType::Paged, PoolTag::WRAITH)
    }

    /// allocate memory from pool
    pub fn allocate(&self, size: usize) -> KmResult<NonNull<u8>> {
        if size == 0 {
            return Err(KmError::InvalidParameter {
                context: "allocate: size cannot be zero",
            });
        }

        // SAFETY: calling kernel pool allocation function
        let ptr = unsafe {
            ExAllocatePoolWithTag(self.pool_type as u32, size, self.tag.0)
        };

        NonNull::new(ptr as *mut u8).ok_or(KmError::PoolAllocationFailed {
            size,
            pool_type: self.pool_type as u32,
        })
    }

    /// allocate zeroed memory from pool
    pub fn allocate_zeroed(&self, size: usize) -> KmResult<NonNull<u8>> {
        let ptr = self.allocate(size)?;
        // SAFETY: ptr is valid and we own this memory
        unsafe {
            core::ptr::write_bytes(ptr.as_ptr(), 0, size);
        }
        Ok(ptr)
    }

    /// free previously allocated memory
    ///
    /// # Safety
    /// ptr must have been allocated by this allocator (or one with same tag)
    pub unsafe fn free(&self, ptr: NonNull<u8>) {
        // SAFETY: caller ensures ptr is valid pool allocation
        unsafe {
            ExFreePoolWithTag(ptr.as_ptr() as *mut c_void, self.tag.0);
        }
    }

    /// reallocate memory (allocate new, copy, free old)
    ///
    /// # Safety
    /// old_ptr must have been allocated by this allocator
    pub unsafe fn reallocate(
        &self,
        old_ptr: NonNull<u8>,
        old_size: usize,
        new_size: usize,
    ) -> KmResult<NonNull<u8>> {
        if new_size == 0 {
            // SAFETY: caller ensures old_ptr is valid
            unsafe { self.free(old_ptr) };
            return Err(KmError::InvalidParameter {
                context: "reallocate: new_size cannot be zero",
            });
        }

        let new_ptr = self.allocate(new_size)?;

        // SAFETY: both pointers are valid, copy the smaller of the two sizes
        unsafe {
            let copy_size = core::cmp::min(old_size, new_size);
            core::ptr::copy_nonoverlapping(old_ptr.as_ptr(), new_ptr.as_ptr(), copy_size);
            self.free(old_ptr);
        }

        Ok(new_ptr)
    }
}

/// global pool allocator for use with alloc crate
pub struct KernelAllocator;

impl KernelAllocator {
    const ALLOCATOR: PoolAllocator = PoolAllocator::non_paged();
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // kernel pool allocations are 16-byte aligned on x64, 8-byte on x86
        // for larger alignments we need to over-allocate
        let align = layout.align();
        let size = layout.size();

        if align <= 16 {
            match Self::ALLOCATOR.allocate(size) {
                Ok(ptr) => ptr.as_ptr(),
                Err(_) => core::ptr::null_mut(),
            }
        } else {
            // over-allocate to handle alignment
            let total_size = size + align;
            match Self::ALLOCATOR.allocate(total_size) {
                Ok(ptr) => {
                    let raw = ptr.as_ptr() as usize;
                    let aligned = (raw + align - 1) & !(align - 1);
                    // store original pointer before aligned address
                    let aligned_ptr = aligned as *mut u8;
                    // SAFETY: aligned_ptr - sizeof(usize) is within our allocation
                    unsafe {
                        *((aligned_ptr as *mut usize).offset(-1)) = raw;
                    }
                    aligned_ptr
                }
                Err(_) => core::ptr::null_mut(),
            }
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let align = layout.align();

        let actual_ptr = if align <= 16 {
            ptr
        } else {
            // retrieve original pointer
            // SAFETY: we stored the original pointer at ptr - sizeof(usize) during alloc
            let raw = unsafe { *((ptr as *mut usize).offset(-1)) };
            raw as *mut u8
        };

        if let Some(ptr) = NonNull::new(actual_ptr) {
            // SAFETY: ptr was allocated by our allocator
            unsafe { Self::ALLOCATOR.free(ptr) };
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };

        // SAFETY: allocate new, copy, deallocate old
        unsafe {
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                let copy_size = core::cmp::min(layout.size(), new_size);
                core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }
}

/// RAII wrapper for pool allocations
pub struct PoolBuffer {
    ptr: NonNull<u8>,
    size: usize,
    allocator: PoolAllocator,
}

impl PoolBuffer {
    /// allocate a new pool buffer
    pub fn new(size: usize, pool_type: PoolType) -> KmResult<Self> {
        let allocator = PoolAllocator::new(pool_type, PoolTag::WRAITH);
        let ptr = allocator.allocate(size)?;
        Ok(Self { ptr, size, allocator })
    }

    /// allocate zeroed buffer
    pub fn zeroed(size: usize, pool_type: PoolType) -> KmResult<Self> {
        let allocator = PoolAllocator::new(pool_type, PoolTag::WRAITH);
        let ptr = allocator.allocate_zeroed(size)?;
        Ok(Self { ptr, size, allocator })
    }

    /// get pointer to buffer
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// get buffer as slice
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: buffer is valid for size bytes
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// get buffer as mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: buffer is valid for size bytes and we have exclusive access
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }

    /// get buffer size
    pub fn size(&self) -> usize {
        self.size
    }

    /// leak the buffer, returning the raw pointer
    pub fn leak(self) -> NonNull<u8> {
        let ptr = self.ptr;
        core::mem::forget(self);
        ptr
    }
}

impl Drop for PoolBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated by our allocator
        unsafe { self.allocator.free(self.ptr) };
    }
}

// kernel pool allocation functions
extern "system" {
    fn ExAllocatePoolWithTag(PoolType: u32, NumberOfBytes: usize, Tag: u32) -> *mut c_void;
    fn ExFreePoolWithTag(P: *mut c_void, Tag: u32);
}
