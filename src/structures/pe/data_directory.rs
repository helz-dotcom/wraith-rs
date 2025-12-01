//! Data directories

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    /// check if directory is present
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// data directory indices
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirectoryType {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    Basereloc = 5,
    Debug = 6,
    Architecture = 7,
    Globalptr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
}

impl DataDirectoryType {
    pub fn index(self) -> usize {
        self as usize
    }
}
