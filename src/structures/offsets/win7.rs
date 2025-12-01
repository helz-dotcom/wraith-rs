//! Windows 7 structure offsets

use super::{PebOffsets, TebOffsets};

#[cfg(target_arch = "x86_64")]
pub static PEB_OFFSETS: PebOffsets = PebOffsets {
    being_debugged: 0x02,
    ldr: 0x18,
    process_parameters: 0x20,
    image_base: 0x10,
    nt_global_flag: 0xBC,
    process_heap: 0x30,
    number_of_processors: 0xB8,
    os_major_version: 0x118,
    os_minor_version: 0x11C,
    os_build_number: 0x120,
};

#[cfg(target_arch = "x86")]
pub static PEB_OFFSETS: PebOffsets = PebOffsets {
    being_debugged: 0x02,
    ldr: 0x0C,
    process_parameters: 0x10,
    image_base: 0x08,
    nt_global_flag: 0x68,
    process_heap: 0x18,
    number_of_processors: 0x64,
    os_major_version: 0xA4,
    os_minor_version: 0xA8,
    os_build_number: 0xAC,
};

#[cfg(target_arch = "x86_64")]
pub static TEB_OFFSETS: TebOffsets = TebOffsets {
    seh_frame: 0x00,
    stack_base: 0x08,
    stack_limit: 0x10,
    tls_slots: 0x1480,
    peb: 0x60,
    client_id: 0x40,
    last_error: 0x68,
};

#[cfg(target_arch = "x86")]
pub static TEB_OFFSETS: TebOffsets = TebOffsets {
    seh_frame: 0x00,
    stack_base: 0x04,
    stack_limit: 0x08,
    tls_slots: 0xE10,
    peb: 0x30,
    client_id: 0x20,
    last_error: 0x34,
};
