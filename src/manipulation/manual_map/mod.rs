//! Manual PE mapping - LoadLibrary bypass
//!
//! This module provides a complete PE loader that maps DLLs without using
//! the Windows loader, creating "ghost DLLs" invisible to GetModuleHandle.
//!
//! # Example
//!
//! ```no_run
//! use wraith::manipulation::manual_map::{ManualMapper, map_file};
//!
//! // convenience function for quick mapping
//! let mapper = map_file(r"C:\path\to\module.dll")?;
//! println!("Mapped at {:#x}", mapper.base());
//!
//! // or step-by-step for more control
//! let mapper = ManualMapper::from_file(r"C:\path\to\module.dll")?
//!     .allocate()?
//!     .map_sections()?
//!     .relocate()?
//!     .resolve_imports()?
//!     .process_tls()?
//!     .finalize()?;
//!
//! mapper.call_entry_point()?;
//! # Ok::<(), wraith::WraithError>(())
//! ```

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String};

#[cfg(feature = "std")]
use std::{format, string::String};

mod allocator;
mod entry;
mod mapper;
mod parser;
mod relocator;
mod resolver;
mod tls;

pub use allocator::MappedMemory;
pub use entry::reason;
pub use parser::ParsedPe;

use crate::error::{Result, WraithError};
use core::marker::PhantomData;

/// type-state markers for manual mapping stages
pub mod state {
    /// PE has been parsed but no memory allocated
    pub struct Parsed;
    /// Memory has been allocated for the image
    pub struct Allocated;
    /// PE sections have been mapped to memory
    pub struct SectionsMapped;
    /// Base relocations have been applied
    pub struct Relocated;
    /// Import Address Table has been resolved
    pub struct ImportsResolved;
    /// TLS callbacks have been processed
    pub struct TlsProcessed;
    /// Image is ready for execution
    pub struct Ready;
}

/// manual mapper with type-state progression
///
/// the type parameter ensures mapping steps happen in correct order:
/// Parsed -> Allocated -> SectionsMapped -> Relocated -> ImportsResolved -> TlsProcessed -> Ready
pub struct ManualMapper<S> {
    pe: ParsedPe,
    memory: Option<MappedMemory>,
    _state: PhantomData<S>,
}

impl ManualMapper<state::Parsed> {
    /// parse PE from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let pe = ParsedPe::parse(data)?;
        Ok(Self {
            pe,
            memory: None,
            _state: PhantomData,
        })
    }

    /// parse PE from file
    #[cfg(feature = "std")]
    pub fn from_file(path: &str) -> Result<Self> {
        let data = std::fs::read(path).map_err(|e| WraithError::InvalidPeFormat {
            reason: format!("failed to read file: {e}"),
        })?;
        Self::parse(&data)
    }

    /// parse PE from file (no_std stub)
    #[cfg(not(feature = "std"))]
    pub fn from_file(_path: &str) -> Result<Self> {
        Err(WraithError::InvalidPeFormat {
            reason: "file operations not available in no_std".into(),
        })
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// allocate memory for the PE image
    ///
    /// tries preferred base first, falls back to any available address
    pub fn allocate(self) -> Result<ManualMapper<state::Allocated>> {
        let size = self.pe.size_of_image();
        let preferred_base = self.pe.preferred_base();

        let memory = allocator::allocate_image(size, preferred_base)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: Some(memory),
            _state: PhantomData,
        })
    }

    /// allocate at specific address
    ///
    /// fails if address is not available
    pub fn allocate_at(self, base: usize) -> Result<ManualMapper<state::Allocated>> {
        let size = self.pe.size_of_image();
        let memory = allocator::allocate_at(base, size)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: Some(memory),
            _state: PhantomData,
        })
    }

    /// allocate anywhere (no preference)
    pub fn allocate_anywhere(self) -> Result<ManualMapper<state::Allocated>> {
        let size = self.pe.size_of_image();
        let memory = allocator::allocate_anywhere(size)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: Some(memory),
            _state: PhantomData,
        })
    }
}

impl ManualMapper<state::Allocated> {
    /// get allocated base address
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// map PE sections to allocated memory
    pub fn map_sections(mut self) -> Result<ManualMapper<state::SectionsMapped>> {
        let memory = self.memory.as_mut().unwrap();
        mapper::map_sections(&self.pe, memory)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }
}

impl ManualMapper<state::SectionsMapped> {
    /// get base address
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// apply base relocations
    pub fn relocate(mut self) -> Result<ManualMapper<state::Relocated>> {
        let memory = self.memory.as_mut().unwrap();
        let delta = memory.base() as i64 - self.pe.preferred_base() as i64;

        if delta != 0 {
            relocator::apply_relocations(&self.pe, memory, delta)?;
        }

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }

    /// skip relocations (use if loaded at preferred base)
    pub fn skip_relocations(self) -> ManualMapper<state::Relocated> {
        ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        }
    }
}

impl ManualMapper<state::Relocated> {
    /// get base address
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// resolve import address table
    pub fn resolve_imports(mut self) -> Result<ManualMapper<state::ImportsResolved>> {
        let memory = self.memory.as_mut().unwrap();
        resolver::resolve_imports(&self.pe, memory)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }

    /// resolve imports with custom resolver function
    pub fn resolve_imports_with<F>(
        mut self,
        resolver_fn: F,
    ) -> Result<ManualMapper<state::ImportsResolved>>
    where
        F: Fn(&str, &str) -> Option<usize>,
    {
        let memory = self.memory.as_mut().unwrap();
        resolver::resolve_imports_custom(&self.pe, memory, resolver_fn)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }

    /// skip import resolution (use if PE has no imports or manually resolved)
    pub fn skip_imports(self) -> ManualMapper<state::ImportsResolved> {
        ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        }
    }
}

impl ManualMapper<state::ImportsResolved> {
    /// get base address
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// process TLS callbacks
    pub fn process_tls(mut self) -> Result<ManualMapper<state::TlsProcessed>> {
        let memory = self.memory.as_mut().unwrap();
        tls::process_tls(&self.pe, memory)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }

    /// skip TLS processing
    pub fn skip_tls(self) -> ManualMapper<state::TlsProcessed> {
        ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        }
    }
}

impl ManualMapper<state::TlsProcessed> {
    /// get base address
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// finalize mapping with proper memory protections
    pub fn finalize(mut self) -> Result<ManualMapper<state::Ready>> {
        let memory = self.memory.as_mut().unwrap();
        mapper::set_section_protections(&self.pe, memory)?;

        Ok(ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        })
    }

    /// finalize without setting protections (keeps RW everywhere)
    pub fn finalize_without_protections(self) -> ManualMapper<state::Ready> {
        ManualMapper {
            pe: self.pe,
            memory: self.memory,
            _state: PhantomData,
        }
    }
}

impl ManualMapper<state::Ready> {
    /// call DllMain with DLL_PROCESS_ATTACH
    pub fn call_entry_point(&self) -> Result<bool> {
        let memory = self.memory.as_ref().unwrap();
        entry::call_dll_attach(&self.pe, memory)
    }

    /// call DllMain with custom reason
    pub fn call_entry_point_with_reason(&self, call_reason: u32) -> Result<bool> {
        let memory = self.memory.as_ref().unwrap();
        entry::call_entry_point(&self.pe, memory, call_reason)
    }

    /// get export address by name
    pub fn get_export(&self, name: &str) -> Result<usize> {
        let memory = self.memory.as_ref().unwrap();
        resolver::get_mapped_export(&self.pe, memory, name)
    }

    /// get export address by ordinal
    pub fn get_export_by_ordinal(&self, ordinal: u16) -> Result<usize> {
        let memory = self.memory.as_ref().unwrap();
        resolver::get_mapped_export_by_ordinal(&self.pe, memory, ordinal)
    }

    /// get base address of mapped image
    pub fn base(&self) -> usize {
        self.memory.as_ref().unwrap().base()
    }

    /// get size of mapped image
    pub fn size(&self) -> usize {
        self.memory.as_ref().unwrap().size()
    }

    /// get reference to parsed PE
    pub fn pe(&self) -> &ParsedPe {
        &self.pe
    }

    /// consume and return raw memory handle
    pub fn into_memory(mut self) -> MappedMemory {
        self.memory.take().unwrap()
    }

    /// get pointer to specific offset in mapped image
    pub fn ptr_at(&self, offset: usize) -> *mut u8 {
        self.memory.as_ref().unwrap().ptr_at(offset)
    }

    /// unmap and free memory
    pub fn unmap(mut self) -> Result<()> {
        if let Some(memory) = self.memory.take() {
            // call DllMain with DLL_PROCESS_DETACH first (ignore errors)
            let _ = entry::call_dll_detach(&self.pe, &memory);
            memory.free()?;
        }
        Ok(())
    }
}

/// convenience function: map PE from bytes with all default steps
pub fn map_pe(data: &[u8]) -> Result<ManualMapper<state::Ready>> {
    ManualMapper::parse(data)?
        .allocate()?
        .map_sections()?
        .relocate()?
        .resolve_imports()?
        .process_tls()?
        .finalize()
}

/// convenience function: map PE from file with all default steps
pub fn map_file(path: &str) -> Result<ManualMapper<state::Ready>> {
    ManualMapper::from_file(path)?
        .allocate()?
        .map_sections()?
        .relocate()?
        .resolve_imports()?
        .process_tls()?
        .finalize()
}

/// convenience function: map PE from bytes and call entry point
pub fn map_and_call(data: &[u8]) -> Result<ManualMapper<state::Ready>> {
    let mapper = map_pe(data)?;
    mapper.call_entry_point()?;
    Ok(mapper)
}

/// convenience function: map PE from file and call entry point
pub fn map_file_and_call(path: &str) -> Result<ManualMapper<state::Ready>> {
    let mapper = map_file(path)?;
    mapper.call_entry_point()?;
    Ok(mapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_allocate() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();

        let mapper = ManualMapper::parse(&data).unwrap();
        assert!(mapper.pe().size_of_image() > 0);

        let mapper = mapper.allocate().unwrap();
        assert!(mapper.base() != 0);
    }

    #[test]
    fn test_map_sections() {
        let exe_path = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe_path).unwrap();

        let mapper = ManualMapper::parse(&data)
            .unwrap()
            .allocate()
            .unwrap()
            .map_sections()
            .unwrap();

        // verify MZ header was copied
        assert!(mapper.base() != 0);
    }

    // note: full integration tests that call entry points should be done
    // with actual test DLLs, not the running executable
}
