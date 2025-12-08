//! Remote memory utilities

use super::driver::DriverHandle;
use super::process::ProcessOps;
use super::{ClientError, ClientResult};

/// memory protection constants
pub mod MemoryProtection {
    pub const NOACCESS: u32 = 0x01;
    pub const READONLY: u32 = 0x02;
    pub const READWRITE: u32 = 0x04;
    pub const WRITECOPY: u32 = 0x08;
    pub const EXECUTE: u32 = 0x10;
    pub const EXECUTE_READ: u32 = 0x20;
    pub const EXECUTE_READWRITE: u32 = 0x40;
    pub const EXECUTE_WRITECOPY: u32 = 0x80;
    pub const GUARD: u32 = 0x100;
    pub const NOCACHE: u32 = 0x200;
}

/// RAII wrapper for allocated remote memory
pub struct RemoteMemory<'a> {
    process: &'a ProcessOps<'a>,
    address: u64,
    size: u64,
}

impl<'a> RemoteMemory<'a> {
    /// allocate remote memory
    pub fn allocate(
        process: &'a ProcessOps<'a>,
        size: u64,
        protection: u32,
    ) -> ClientResult<Self> {
        let address = process.allocate(size, protection)?;
        Ok(Self {
            process,
            address,
            size,
        })
    }

    /// allocate at preferred address
    pub fn allocate_at(
        process: &'a ProcessOps<'a>,
        address: u64,
        size: u64,
        protection: u32,
    ) -> ClientResult<Self> {
        let address = process.allocate_at(address, size, protection)?;
        Ok(Self {
            process,
            address,
            size,
        })
    }

    /// get base address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// get size
    pub fn size(&self) -> u64 {
        self.size
    }

    /// write data to this memory
    pub fn write(&self, data: &[u8]) -> ClientResult<()> {
        if data.len() as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: data.len(),
                provided: self.size as usize,
            });
        }
        self.process.write_bytes(self.address, data)
    }

    /// write value to this memory
    pub fn write_value<T: Copy>(&self, value: &T) -> ClientResult<()> {
        if std::mem::size_of::<T>() as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: std::mem::size_of::<T>(),
                provided: self.size as usize,
            });
        }
        self.process.write(self.address, value)
    }

    /// write at offset
    pub fn write_at(&self, offset: u64, data: &[u8]) -> ClientResult<()> {
        if offset + data.len() as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: (offset + data.len() as u64) as usize,
                provided: self.size as usize,
            });
        }
        self.process.write_bytes(self.address + offset, data)
    }

    /// read data from this memory
    pub fn read(&self, size: usize) -> ClientResult<Vec<u8>> {
        if size as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: size,
                provided: self.size as usize,
            });
        }
        self.process.read_bytes(self.address, size)
    }

    /// read value from this memory
    pub fn read_value<T: Copy>(&self) -> ClientResult<T> {
        if std::mem::size_of::<T>() as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: std::mem::size_of::<T>(),
                provided: self.size as usize,
            });
        }
        self.process.read(self.address)
    }

    /// read at offset
    pub fn read_at(&self, offset: u64, size: usize) -> ClientResult<Vec<u8>> {
        if offset + size as u64 > self.size {
            return Err(ClientError::BufferTooSmall {
                required: (offset + size as u64) as usize,
                provided: self.size as usize,
            });
        }
        self.process.read_bytes(self.address + offset, size)
    }

    /// change protection
    pub fn protect(&self, protection: u32) -> ClientResult<u32> {
        self.process.protect(self.address, self.size, protection)
    }

    /// leak the memory (don't free on drop)
    pub fn leak(self) -> u64 {
        let addr = self.address;
        std::mem::forget(self);
        addr
    }
}

impl<'a> Drop for RemoteMemory<'a> {
    fn drop(&mut self) {
        let _ = self.process.free(self.address);
    }
}

/// memory scanner for pattern matching
pub struct MemoryScanner<'a> {
    process: &'a ProcessOps<'a>,
}

impl<'a> MemoryScanner<'a> {
    /// create new scanner
    pub fn new(process: &'a ProcessOps<'a>) -> Self {
        Self { process }
    }

    /// scan for pattern in range
    pub fn scan_range(
        &self,
        start: u64,
        size: usize,
        pattern: &[u8],
        mask: &[u8],
    ) -> ClientResult<Vec<u64>> {
        let mut results = Vec::new();

        // read in chunks to avoid huge allocations
        const CHUNK_SIZE: usize = 0x10000;
        let mut offset = 0;

        while offset < size {
            let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
            let chunk = self.process.read_bytes(start + offset as u64, chunk_size)?;

            // scan chunk
            for i in 0..chunk.len().saturating_sub(pattern.len()) {
                let mut matched = true;
                for (j, (&p, &m)) in pattern.iter().zip(mask.iter()).enumerate() {
                    if m != 0 && chunk[i + j] != p {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    results.push(start + offset as u64 + i as u64);
                }
            }

            offset += chunk_size - pattern.len(); // overlap to catch patterns at chunk boundaries
        }

        Ok(results)
    }

    /// scan for exact bytes
    pub fn scan_bytes(&self, start: u64, size: usize, bytes: &[u8]) -> ClientResult<Vec<u64>> {
        let mask = vec![0xFF; bytes.len()];
        self.scan_range(start, size, bytes, &mask)
    }

    /// scan for IDA-style pattern (e.g., "48 8B ?? ?? 00 00 00")
    pub fn scan_ida_pattern(&self, start: u64, size: usize, pattern: &str) -> ClientResult<Vec<u64>> {
        let (bytes, mask) = parse_ida_pattern(pattern)?;
        self.scan_range(start, size, &bytes, &mask)
    }
}

/// parse IDA-style pattern
fn parse_ida_pattern(pattern: &str) -> ClientResult<(Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = pattern.split_whitespace().collect();
    let mut bytes = Vec::with_capacity(parts.len());
    let mut mask = Vec::with_capacity(parts.len());

    for part in parts {
        if part == "?" || part == "??" {
            bytes.push(0);
            mask.push(0);
        } else {
            let byte = u8::from_str_radix(part, 16)
                .map_err(|_| ClientError::MemoryError {
                    address: 0,
                    reason: format!("invalid pattern byte: {}", part),
                })?;
            bytes.push(byte);
            mask.push(0xFF);
        }
    }

    Ok((bytes, mask))
}

/// protection guard for temporary protection changes
pub struct ProtectionGuard<'a> {
    process: &'a ProcessOps<'a>,
    address: u64,
    size: u64,
    old_protection: u32,
}

impl<'a> ProtectionGuard<'a> {
    /// temporarily change protection
    pub fn new(
        process: &'a ProcessOps<'a>,
        address: u64,
        size: u64,
        new_protection: u32,
    ) -> ClientResult<Self> {
        let old_protection = process.protect(address, size, new_protection)?;
        Ok(Self {
            process,
            address,
            size,
            old_protection,
        })
    }
}

impl<'a> Drop for ProtectionGuard<'a> {
    fn drop(&mut self) {
        let _ = self.process.protect(self.address, self.size, self.old_protection);
    }
}
