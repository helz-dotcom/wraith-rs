//! Import resolution

use super::allocator::MappedMemory;
use super::parser::ParsedPe;
use crate::error::{Result, WraithError};
use crate::navigation::ModuleQuery;
use crate::structures::pe::{DataDirectoryType, ExportDirectory, ImportDescriptor};
use crate::structures::pe::imports::{IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64};
use crate::structures::Peb;

/// resolve all imports using standard module resolution
pub fn resolve_imports(pe: &ParsedPe, memory: &mut MappedMemory) -> Result<()> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);

    resolve_imports_custom(pe, memory, |dll_name, proc_name| {
        resolve_export_with_forwarding(&query, dll_name, proc_name, 0)
    })
}

/// resolve export with forwarding support (max 10 levels deep to prevent infinite loops)
fn resolve_export_with_forwarding(
    query: &ModuleQuery,
    dll_name: &str,
    proc_name: &str,
    depth: usize,
) -> Option<usize> {
    if depth > 10 {
        return None; // prevent infinite forwarding loops
    }

    let module = query.find_by_name(dll_name).ok()?;

    match module.get_export(proc_name) {
        Ok(addr) => Some(addr),
        Err(WraithError::ForwardedExport { forwarder }) => {
            // parse forwarder string: "DllName.FunctionName" or "DllName.#123" for ordinal
            let dot_pos = forwarder.find('.')?;
            let fwd_dll = &forwarder[..dot_pos];
            let fwd_func = &forwarder[dot_pos + 1..];

            // add .dll extension if not present
            let fwd_dll_name = if fwd_dll.to_lowercase().ends_with(".dll") {
                fwd_dll.to_string()
            } else {
                format!("{}.dll", fwd_dll)
            };

            // check for ordinal import (#123)
            if fwd_func.starts_with('#') {
                let ordinal: u16 = fwd_func[1..].parse().ok()?;
                let fwd_module = query.find_by_name(&fwd_dll_name).ok()?;
                fwd_module.get_export_by_ordinal(ordinal).ok()
            } else {
                resolve_export_with_forwarding(query, &fwd_dll_name, fwd_func, depth + 1)
            }
        }
        Err(_) => None,
    }
}

/// resolve imports with custom resolver function
pub fn resolve_imports_custom<F>(pe: &ParsedPe, memory: &mut MappedMemory, resolver: F) -> Result<()>
where
    F: Fn(&str, &str) -> Option<usize>,
{
    let import_dir = match pe.data_directory(DataDirectoryType::Import) {
        Some(d) if d.is_present() => d,
        _ => return Ok(()), // no imports
    };

    let import_rva = import_dir.virtual_address as usize;
    let mut desc_offset = 0;

    loop {
        let desc: ImportDescriptor = memory.read_at(import_rva + desc_offset)?;

        // null descriptor marks end
        if desc.is_null() {
            break;
        }

        resolve_module_imports(pe, memory, &desc, &resolver)?;

        desc_offset += core::mem::size_of::<ImportDescriptor>();
    }

    Ok(())
}

/// resolve imports for a single module
fn resolve_module_imports<F>(
    pe: &ParsedPe,
    memory: &mut MappedMemory,
    desc: &ImportDescriptor,
    resolver: &F,
) -> Result<()>
where
    F: Fn(&str, &str) -> Option<usize>,
{
    // read DLL name from mapped memory
    let dll_name = read_string_from_memory(memory, desc.name as usize)?;

    // get INT (Import Name Table) and IAT (Import Address Table) RVAs
    let int_rva = if desc.original_first_thunk != 0 {
        desc.original_first_thunk as usize
    } else {
        desc.first_thunk as usize
    };
    let iat_rva = desc.first_thunk as usize;

    let mut thunk_offset = 0;
    let thunk_size = if pe.is_64bit() { 8 } else { 4 };

    loop {
        // read thunk value
        let thunk_value: u64 = if pe.is_64bit() {
            memory.read_at(int_rva + thunk_offset)?
        } else {
            memory.read_at::<u32>(int_rva + thunk_offset)? as u64
        };

        // zero thunk marks end
        if thunk_value == 0 {
            break;
        }

        let resolved_address = resolve_single_import(pe, memory, &dll_name, thunk_value, resolver)?;

        // write resolved address to IAT
        if pe.is_64bit() {
            memory.write_value_at(iat_rva + thunk_offset, resolved_address as u64)?;
        } else {
            memory.write_value_at(iat_rva + thunk_offset, resolved_address as u32)?;
        }

        thunk_offset += thunk_size;
    }

    Ok(())
}

/// resolve a single import (by name or ordinal)
fn resolve_single_import<F>(
    pe: &ParsedPe,
    memory: &MappedMemory,
    dll_name: &str,
    thunk_value: u64,
    resolver: &F,
) -> Result<usize>
where
    F: Fn(&str, &str) -> Option<usize>,
{
    // check if import by ordinal
    let is_ordinal = if pe.is_64bit() {
        thunk_value & IMAGE_ORDINAL_FLAG64 != 0
    } else {
        (thunk_value as u32) & IMAGE_ORDINAL_FLAG32 != 0
    };

    if is_ordinal {
        let ordinal = (thunk_value & 0xFFFF) as u16;

        // ordinal imports require special handling via GetProcAddress
        // or we need to resolve from the target module's export table
        return Err(WraithError::ImportResolutionFailed {
            dll: dll_name.to_string(),
            function: format!("ordinal #{ordinal}"),
        });
    }

    // import by name - read hint/name structure
    let hint_name_rva = thunk_value as usize;
    let _hint: u16 = memory.read_at(hint_name_rva)?;
    let name = read_string_from_memory(memory, hint_name_rva + 2)?;

    resolver(dll_name, &name).ok_or_else(|| WraithError::ImportResolutionFailed {
        dll: dll_name.to_string(),
        function: name,
    })
}

/// get export from mapped PE by name
pub fn get_mapped_export(pe: &ParsedPe, memory: &MappedMemory, name: &str) -> Result<usize> {
    let export_dir = pe
        .data_directory(DataDirectoryType::Export)
        .ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no export directory".into(),
        })?;

    if !export_dir.is_present() {
        return Err(WraithError::InvalidPeFormat {
            reason: "export directory not present".into(),
        });
    }

    let exports: ExportDirectory = memory.read_at(export_dir.virtual_address as usize)?;

    let num_names = exports.number_of_names as usize;
    let names_rva = exports.address_of_names as usize;
    let ordinals_rva = exports.address_of_name_ordinals as usize;
    let functions_rva = exports.address_of_functions as usize;

    for i in 0..num_names {
        let name_rva: u32 = memory.read_at(names_rva + i * 4)?;
        let export_name = read_string_from_memory(memory, name_rva as usize)?;

        if export_name == name {
            let ordinal: u16 = memory.read_at(ordinals_rva + i * 2)?;
            let func_rva: u32 = memory.read_at(functions_rva + ordinal as usize * 4)?;

            // check for forwarded export
            if func_rva >= export_dir.virtual_address
                && func_rva < export_dir.virtual_address + export_dir.size
            {
                // forwarded exports point to a string like "NTDLL.RtlAllocateHeap"
                return Err(WraithError::InvalidPeFormat {
                    reason: format!("forwarded export: {name}"),
                });
            }

            return Ok(memory.base() + func_rva as usize);
        }
    }

    Err(WraithError::ModuleNotFound {
        name: format!("export {name} not found"),
    })
}

/// get export from mapped PE by ordinal
pub fn get_mapped_export_by_ordinal(
    pe: &ParsedPe,
    memory: &MappedMemory,
    ordinal: u16,
) -> Result<usize> {
    let export_dir = pe
        .data_directory(DataDirectoryType::Export)
        .ok_or_else(|| WraithError::InvalidPeFormat {
            reason: "no export directory".into(),
        })?;

    if !export_dir.is_present() {
        return Err(WraithError::InvalidPeFormat {
            reason: "export directory not present".into(),
        });
    }

    let exports: ExportDirectory = memory.read_at(export_dir.virtual_address as usize)?;

    let index = ordinal as usize - exports.base as usize;
    if index >= exports.number_of_functions as usize {
        return Err(WraithError::InvalidPeFormat {
            reason: "ordinal out of range".into(),
        });
    }

    let functions_rva = exports.address_of_functions as usize;
    let func_rva: u32 = memory.read_at(functions_rva + index * 4)?;

    Ok(memory.base() + func_rva as usize)
}

/// max length for import/export names to prevent unbounded reads
const MAX_NAME_LENGTH: usize = 512;

/// read null-terminated string from mapped memory
fn read_string_from_memory(memory: &MappedMemory, rva: usize) -> Result<String> {
    let slice = memory.as_slice();

    if rva >= slice.len() {
        return Err(WraithError::ReadFailed {
            address: (memory.base() + rva) as u64,
            size: 1,
        });
    }

    let max_end = (rva + MAX_NAME_LENGTH).min(slice.len());
    let mut end = rva;
    while end < max_end && slice[end] != 0 {
        end += 1;
    }

    // check if we hit the limit without finding null terminator
    if end >= max_end && (end >= slice.len() || slice[end] != 0) {
        return Err(WraithError::InvalidPeFormat {
            reason: "string too long or missing null terminator".into(),
        });
    }

    String::from_utf8(slice[rva..end].to_vec()).map_err(|_| WraithError::InvalidPeFormat {
        reason: "invalid UTF-8 in import name".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_string() {
        use crate::manipulation::manual_map::allocator::allocate_anywhere;

        let mut mem = allocate_anywhere(0x100).unwrap();
        let test_str = b"Hello\0World\0";
        mem.write_at(0, test_str).unwrap();

        let s1 = read_string_from_memory(&mem, 0).unwrap();
        assert_eq!(s1, "Hello");

        let s2 = read_string_from_memory(&mem, 6).unwrap();
        assert_eq!(s2, "World");
    }
}
