//! TLS (Thread Local Storage) callback handling

use super::allocator::MappedMemory;
use super::parser::ParsedPe;
use crate::error::{Result, WraithError};
use crate::structures::pe::{DataDirectoryType, TlsCallback, TlsDirectory32, TlsDirectory64};

const DLL_PROCESS_ATTACH: u32 = 1;
const TLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

/// process TLS directory and execute callbacks
pub fn process_tls(pe: &ParsedPe, memory: &mut MappedMemory) -> Result<()> {
    let tls_dir = match pe.data_directory(DataDirectoryType::Tls) {
        Some(d) if d.is_present() => d,
        _ => return Ok(()), // no TLS
    };

    // read TLS directory based on bitness
    let callbacks_va = if pe.is_64bit() {
        let tls: TlsDirectory64 = memory.read_at(tls_dir.virtual_address as usize)?;
        allocate_tls_index_64(memory, &tls)?;
        tls.address_of_callbacks
    } else {
        let tls: TlsDirectory32 = memory.read_at(tls_dir.virtual_address as usize)?;
        allocate_tls_index_32(memory, &tls)?;
        tls.address_of_callbacks as u64
    };

    // no callbacks to execute
    if callbacks_va == 0 {
        return Ok(());
    }

    // callbacks array is at a VA, convert to offset in our memory
    let callbacks_offset = (callbacks_va as usize).saturating_sub(memory.base());

    // bounds check
    if callbacks_offset >= memory.size() {
        return Err(WraithError::TlsCallbackFailed { index: 0 });
    }

    // execute each callback
    let mut callback_index = 0;
    loop {
        let callback_va: usize = if pe.is_64bit() {
            let offset = callbacks_offset + callback_index * 8;
            if offset + 8 > memory.size() {
                break;
            }
            memory.read_at::<u64>(offset)? as usize
        } else {
            let offset = callbacks_offset + callback_index * 4;
            if offset + 4 > memory.size() {
                break;
            }
            memory.read_at::<u32>(offset)? as usize
        };

        // null callback marks end
        if callback_va == 0 {
            break;
        }

        execute_tls_callback(memory, callback_va, callback_index)?;
        callback_index += 1;
    }

    Ok(())
}

/// allocate TLS index for 64-bit PE
fn allocate_tls_index_64(memory: &mut MappedMemory, tls: &TlsDirectory64) -> Result<()> {
    if tls.address_of_index == 0 {
        return Ok(());
    }

    // allocate a TLS slot via Windows API
    let index = unsafe { TlsAlloc() };
    if index == TLS_OUT_OF_INDEXES {
        return Err(WraithError::TlsCallbackFailed { index: 0 });
    }

    // write index to the PE's designated location
    let index_offset = (tls.address_of_index as usize).saturating_sub(memory.base());
    if index_offset + 4 <= memory.size() {
        memory.write_value_at(index_offset, index)?;
    }

    Ok(())
}

/// allocate TLS index for 32-bit PE
fn allocate_tls_index_32(memory: &mut MappedMemory, tls: &TlsDirectory32) -> Result<()> {
    if tls.address_of_index == 0 {
        return Ok(());
    }

    let index = unsafe { TlsAlloc() };
    if index == TLS_OUT_OF_INDEXES {
        return Err(WraithError::TlsCallbackFailed { index: 0 });
    }

    let index_offset = (tls.address_of_index as usize).saturating_sub(memory.base());
    if index_offset + 4 <= memory.size() {
        memory.write_value_at(index_offset, index)?;
    }

    Ok(())
}

/// execute a TLS callback
fn execute_tls_callback(memory: &MappedMemory, callback_va: usize, index: usize) -> Result<()> {
    // verify callback is within our mapped image
    if callback_va < memory.base() || callback_va >= memory.base() + memory.size() {
        return Err(WraithError::TlsCallbackFailed { index });
    }

    // SAFETY: we've verified the address is within our mapped image
    // the callback signature matches TlsCallback type
    let callback: TlsCallback = unsafe { core::mem::transmute(callback_va) };

    // SAFETY: calling the TLS callback with correct parameters
    unsafe {
        callback(
            memory.base() as *mut _,
            DLL_PROCESS_ATTACH,
            core::ptr::null_mut(),
        );
    }

    Ok(())
}

/// execute TLS callbacks with a specific reason
pub fn execute_tls_callbacks_with_reason(
    pe: &ParsedPe,
    memory: &MappedMemory,
    reason: u32,
) -> Result<()> {
    let tls_dir = match pe.data_directory(DataDirectoryType::Tls) {
        Some(d) if d.is_present() => d,
        _ => return Ok(()),
    };

    let callbacks_va = if pe.is_64bit() {
        let tls: TlsDirectory64 = memory.read_at(tls_dir.virtual_address as usize)?;
        tls.address_of_callbacks
    } else {
        let tls: TlsDirectory32 = memory.read_at(tls_dir.virtual_address as usize)?;
        tls.address_of_callbacks as u64
    };

    if callbacks_va == 0 {
        return Ok(());
    }

    let callbacks_offset = (callbacks_va as usize).saturating_sub(memory.base());
    if callbacks_offset >= memory.size() {
        return Ok(());
    }

    let mut callback_index = 0;
    loop {
        let callback_va: usize = if pe.is_64bit() {
            let offset = callbacks_offset + callback_index * 8;
            if offset + 8 > memory.size() {
                break;
            }
            memory.read_at::<u64>(offset)? as usize
        } else {
            let offset = callbacks_offset + callback_index * 4;
            if offset + 4 > memory.size() {
                break;
            }
            memory.read_at::<u32>(offset)? as usize
        };

        if callback_va == 0 {
            break;
        }

        if callback_va >= memory.base() && callback_va < memory.base() + memory.size() {
            let callback: TlsCallback = unsafe { core::mem::transmute(callback_va) };
            unsafe {
                callback(memory.base() as *mut _, reason, core::ptr::null_mut());
            }
        }

        callback_index += 1;
    }

    Ok(())
}

#[link(name = "kernel32")]
extern "system" {
    fn TlsAlloc() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_alloc() {
        let index = unsafe { TlsAlloc() };
        assert_ne!(index, TLS_OUT_OF_INDEXES);
    }
}
