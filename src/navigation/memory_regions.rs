//! Memory region enumeration using VirtualQuery

use crate::error::{Result, WraithError};

/// memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub allocation_base: usize,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: MemoryState,
    pub protect: u32,
    pub memory_type: MemoryType,
}

/// memory state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

/// memory type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Image,   // mapped executable image
    Mapped,  // memory-mapped file
    Private, // private memory
    Unknown,
}

impl MemoryRegion {
    /// check if region is executable
    pub fn is_executable(&self) -> bool {
        (self.protect & PAGE_EXECUTE) != 0
            || (self.protect & PAGE_EXECUTE_READ) != 0
            || (self.protect & PAGE_EXECUTE_READWRITE) != 0
            || (self.protect & PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// check if region is readable
    pub fn is_readable(&self) -> bool {
        (self.protect & PAGE_READONLY) != 0
            || (self.protect & PAGE_READWRITE) != 0
            || (self.protect & PAGE_WRITECOPY) != 0
            || (self.protect & PAGE_EXECUTE_READ) != 0
            || (self.protect & PAGE_EXECUTE_READWRITE) != 0
            || (self.protect & PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// check if region is writable
    pub fn is_writable(&self) -> bool {
        (self.protect & PAGE_READWRITE) != 0
            || (self.protect & PAGE_WRITECOPY) != 0
            || (self.protect & PAGE_EXECUTE_READWRITE) != 0
            || (self.protect & PAGE_EXECUTE_WRITECOPY) != 0
    }

    /// check if region is committed (accessible)
    pub fn is_committed(&self) -> bool {
        self.state == MemoryState::Commit
    }

    /// check if this is part of an image
    pub fn is_image(&self) -> bool {
        self.memory_type == MemoryType::Image
    }

    /// get protection string (e.g., "RWX", "R--", etc.)
    pub fn protection_string(&self) -> &'static str {
        match self.protect {
            PAGE_NOACCESS => "---",
            PAGE_READONLY => "R--",
            PAGE_READWRITE => "RW-",
            PAGE_WRITECOPY => "RC-",
            PAGE_EXECUTE => "--X",
            PAGE_EXECUTE_READ => "R-X",
            PAGE_EXECUTE_READWRITE => "RWX",
            PAGE_EXECUTE_WRITECOPY => "RCX",
            _ => "???",
        }
    }
}

/// iterator over memory regions in current process
pub struct MemoryRegionIterator {
    current_address: usize,
    max_address: usize,
}

impl MemoryRegionIterator {
    /// create new iterator starting from address 0
    pub fn new() -> Self {
        Self {
            current_address: 0,
            max_address: Self::max_user_address(),
        }
    }

    /// create iterator starting from specific address
    pub fn from_address(address: usize) -> Self {
        Self {
            current_address: address,
            max_address: Self::max_user_address(),
        }
    }

    fn max_user_address() -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            0x7FFFFFFFFFFF // typical x64 user space limit
        }
        #[cfg(target_arch = "x86")]
        {
            0x7FFFFFFF // typical x86 user space limit
        }
    }
}

impl Default for MemoryRegionIterator {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for MemoryRegionIterator {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_address >= self.max_address {
            return None;
        }

        let mut mbi = MemoryBasicInformation::default();
        // SAFETY: VirtualQuery is safe to call with valid buffer
        let result = unsafe {
            VirtualQuery(
                self.current_address as *const _,
                &mut mbi,
                core::mem::size_of::<MemoryBasicInformation>(),
            )
        };

        if result == 0 {
            return None;
        }

        // advance to next region
        self.current_address = mbi.base_address + mbi.region_size;

        let state = match mbi.state {
            MEM_COMMIT => MemoryState::Commit,
            MEM_RESERVE => MemoryState::Reserve,
            MEM_FREE => MemoryState::Free,
            _ => MemoryState::Free,
        };

        let memory_type = match mbi.memory_type {
            MEM_IMAGE => MemoryType::Image,
            MEM_MAPPED => MemoryType::Mapped,
            MEM_PRIVATE => MemoryType::Private,
            _ => MemoryType::Unknown,
        };

        Some(MemoryRegion {
            base_address: mbi.base_address,
            allocation_base: mbi.allocation_base,
            allocation_protect: mbi.allocation_protect,
            region_size: mbi.region_size,
            state,
            protect: mbi.protect,
            memory_type,
        })
    }
}

/// find all executable memory regions
pub fn find_executable_regions() -> Vec<MemoryRegion> {
    MemoryRegionIterator::new()
        .filter(|r| r.is_committed() && r.is_executable())
        .collect()
}

/// find all image (module) regions
pub fn find_image_regions() -> Vec<MemoryRegion> {
    MemoryRegionIterator::new()
        .filter(|r| r.is_committed() && r.is_image())
        .collect()
}

/// find all private memory regions
pub fn find_private_regions() -> Vec<MemoryRegion> {
    MemoryRegionIterator::new()
        .filter(|r| r.is_committed() && r.memory_type == MemoryType::Private)
        .collect()
}

/// query single memory region at address
pub fn query_region(address: usize) -> Result<MemoryRegion> {
    let mut mbi = MemoryBasicInformation::default();
    // SAFETY: VirtualQuery is safe to call with valid buffer
    let result = unsafe {
        VirtualQuery(
            address as *const _,
            &mut mbi,
            core::mem::size_of::<MemoryBasicInformation>(),
        )
    };

    if result == 0 {
        return Err(WraithError::ReadFailed {
            address: address as u64,
            size: 0,
        });
    }

    let state = match mbi.state {
        MEM_COMMIT => MemoryState::Commit,
        MEM_RESERVE => MemoryState::Reserve,
        _ => MemoryState::Free,
    };

    let memory_type = match mbi.memory_type {
        MEM_IMAGE => MemoryType::Image,
        MEM_MAPPED => MemoryType::Mapped,
        MEM_PRIVATE => MemoryType::Private,
        _ => MemoryType::Unknown,
    };

    Ok(MemoryRegion {
        base_address: mbi.base_address,
        allocation_base: mbi.allocation_base,
        allocation_protect: mbi.allocation_protect,
        region_size: mbi.region_size,
        state,
        protect: mbi.protect,
        memory_type,
    })
}

// internal structures for VirtualQuery
#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base_address: usize,
    allocation_base: usize,
    allocation_protect: u32,
    #[cfg(target_arch = "x86_64")]
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    memory_type: u32,
}

// memory state constants
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_FREE: u32 = 0x10000;

// memory type constants
const MEM_IMAGE: u32 = 0x1000000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_PRIVATE: u32 = 0x20000;

// page protection constants
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualQuery(
        address: *const core::ffi::c_void,
        buffer: *mut MemoryBasicInformation,
        length: usize,
    ) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_iterator() {
        let regions: Vec<_> = MemoryRegionIterator::new().take(10).collect();
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_find_executable() {
        let exec_regions = find_executable_regions();
        // should find at least our own code
        assert!(!exec_regions.is_empty());
    }

    #[test]
    fn test_query_region() {
        // query our own code
        let addr = test_query_region as usize;
        let region = query_region(addr).expect("should query region");
        assert!(region.is_executable());
        assert!(region.is_committed());
    }

    #[test]
    fn test_protection_string() {
        let region = query_region(test_protection_string as usize).expect("should query");
        let prot_str = region.protection_string();
        // code should be executable
        assert!(prot_str.contains('X'));
    }
}
