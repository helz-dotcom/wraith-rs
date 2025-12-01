//! Import structures

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImportDescriptor {
    pub original_first_thunk: u32, // RVA to INT (Import Name Table)
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,        // RVA to DLL name
    pub first_thunk: u32, // RVA to IAT (Import Address Table)
}

impl ImportDescriptor {
    /// check if this is the null terminator
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.name == 0 && self.first_thunk == 0
    }
}

/// import lookup table entry (IMAGE_THUNK_DATA)
#[repr(C)]
#[derive(Clone, Copy)]
pub union ThunkData32 {
    pub forwarder_string: u32,
    pub function: u32,
    pub ordinal: u32,
    pub address_of_data: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ThunkData64 {
    pub forwarder_string: u64,
    pub function: u64,
    pub ordinal: u64,
    pub address_of_data: u64,
}

pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;

/// parsed import entry
pub struct ImportLookupEntry {
    pub is_ordinal: bool,
    pub ordinal: u16,
    pub hint: u16,
    pub name: String,
}

/// import by name structure
#[repr(C)]
pub struct ImportByName {
    pub hint: u16,
    pub name: [u8; 1], // variable length
}
