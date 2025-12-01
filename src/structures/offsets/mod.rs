//! Version-specific structure offsets

mod win7;
mod win10;
mod win11;

use crate::error::Result;
use crate::version::{WindowsRelease, WindowsVersion};

/// PEB field offsets
#[derive(Debug, Clone, Copy)]
pub struct PebOffsets {
    pub being_debugged: usize,
    pub ldr: usize,
    pub process_parameters: usize,
    pub image_base: usize,
    pub nt_global_flag: usize,
    pub process_heap: usize,
    pub number_of_processors: usize,
    pub os_major_version: usize,
    pub os_minor_version: usize,
    pub os_build_number: usize,
}

/// TEB field offsets
#[derive(Debug, Clone, Copy)]
pub struct TebOffsets {
    pub seh_frame: usize, // ExceptionList
    pub stack_base: usize,
    pub stack_limit: usize,
    pub tls_slots: usize,
    pub peb: usize,
    pub client_id: usize,
    pub last_error: usize,
}

impl PebOffsets {
    /// get offsets for given Windows version
    pub fn for_version(version: &WindowsVersion) -> Result<&'static Self> {
        let release = version.release();

        if release == WindowsRelease::Windows7 {
            Ok(&win7::PEB_OFFSETS)
        } else if release >= WindowsRelease::Windows11_21H2 {
            Ok(&win11::PEB_OFFSETS)
        } else {
            // Win8, Win8.1, Win10 all use similar offsets
            Ok(&win10::PEB_OFFSETS)
        }
    }
}

impl TebOffsets {
    /// get offsets for given Windows version
    pub fn for_version(version: &WindowsVersion) -> Result<&'static Self> {
        match version.release() {
            WindowsRelease::Windows7 => Ok(&win7::TEB_OFFSETS),
            _ => Ok(&win10::TEB_OFFSETS), // TEB is more stable across versions
        }
    }
}
