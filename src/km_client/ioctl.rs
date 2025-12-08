//! IOCTL definitions shared between kernel and usermode

/// IOCTL code structure
#[derive(Debug, Clone, Copy)]
pub struct IoctlCode(pub u32);

impl IoctlCode {
    /// create IOCTL code from components
    pub const fn new(device_type: u32, function: u32, method: u32, access: u32) -> Self {
        Self((device_type << 16) | (access << 14) | (function << 2) | method)
    }

    /// create for custom device type
    pub const fn custom(function: u32, method: u32, access: u32) -> Self {
        Self::new(0x8000, function, method, access)
    }

    /// create buffered IOCTL
    pub const fn buffered(function: u32, access: u32) -> Self {
        Self::custom(function, 0, access) // METHOD_BUFFERED = 0
    }

    /// get raw code
    pub const fn code(&self) -> u32 {
        self.0
    }
}

/// IOCTL access modes
pub mod access {
    pub const ANY: u32 = 0;
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const READ_WRITE: u32 = 3;
}

/// predefined IOCTL codes (must match kernel module)
pub mod codes {
    use super::IoctlCode;
    use super::access;

    pub const READ_MEMORY: IoctlCode = IoctlCode::buffered(0x800, access::READ_WRITE);
    pub const WRITE_MEMORY: IoctlCode = IoctlCode::buffered(0x801, access::READ_WRITE);
    pub const GET_MODULE_BASE: IoctlCode = IoctlCode::buffered(0x802, access::READ);
    pub const ALLOCATE_MEMORY: IoctlCode = IoctlCode::buffered(0x803, access::READ_WRITE);
    pub const FREE_MEMORY: IoctlCode = IoctlCode::buffered(0x804, access::READ_WRITE);
    pub const PROTECT_MEMORY: IoctlCode = IoctlCode::buffered(0x805, access::READ_WRITE);
    pub const QUERY_PROCESS: IoctlCode = IoctlCode::buffered(0x806, access::READ);
    pub const COPY_PHYSICAL: IoctlCode = IoctlCode::buffered(0x807, access::READ_WRITE);
    pub const MAP_PHYSICAL: IoctlCode = IoctlCode::buffered(0x808, access::READ_WRITE);
    pub const UNMAP_PHYSICAL: IoctlCode = IoctlCode::buffered(0x809, access::READ_WRITE);
}

/// read memory request structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ReadMemoryRequest {
    pub process_id: u32,
    pub address: u64,
    pub size: u32,
}

/// write memory request structure
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
    pub module_name_offset: u32,
    pub module_name_length: u32,
}

/// get module base response
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

/// copy physical memory request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CopyPhysicalRequest {
    pub physical_address: u64,
    pub size: u32,
    pub write: u8,
}

/// map physical memory request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapPhysicalRequest {
    pub physical_address: u64,
    pub size: u64,
}

/// map physical memory response
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapPhysicalResponse {
    pub mapped_address: u64,
}

/// query process info request
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QueryProcessRequest {
    pub process_id: u32,
}

/// query process info response
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QueryProcessResponse {
    pub base_address: u64,
    pub peb_address: u64,
    pub cr3: u64,
    pub is_wow64: u8,
}

/// generic IOCTL request wrapper
pub struct IoctlRequest<T> {
    pub code: IoctlCode,
    pub data: T,
}

impl<T> IoctlRequest<T> {
    pub fn new(code: IoctlCode, data: T) -> Self {
        Self { code, data }
    }
}

/// generic IOCTL response wrapper
pub struct IoctlResponse<T> {
    pub bytes_returned: u32,
    pub data: T,
}
