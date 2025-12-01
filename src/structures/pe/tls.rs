//! TLS (Thread Local Storage) structures

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsDirectory32 {
    pub start_address_of_raw_data: u32,
    pub end_address_of_raw_data: u32,
    pub address_of_index: u32,
    pub address_of_callbacks: u32, // pointer to array of PIMAGE_TLS_CALLBACK
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsDirectory64 {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64, // pointer to array of PIMAGE_TLS_CALLBACK
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

pub enum TlsDirectory {
    Tls32(TlsDirectory32),
    Tls64(TlsDirectory64),
}

impl TlsDirectory {
    pub fn callbacks_address(&self) -> u64 {
        match self {
            Self::Tls32(t) => t.address_of_callbacks as u64,
            Self::Tls64(t) => t.address_of_callbacks,
        }
    }
}

/// TLS callback function signature
pub type TlsCallback = unsafe extern "system" fn(
    dll_handle: *mut core::ffi::c_void,
    reason: u32,
    reserved: *mut core::ffi::c_void,
);
