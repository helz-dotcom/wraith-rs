//! DOS header (IMAGE_DOS_HEADER)

pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DosHeader {
    pub e_magic: u16, // must be DOS_SIGNATURE
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32, // offset to NT headers
}

impl DosHeader {
    /// validate DOS signature
    pub fn is_valid(&self) -> bool {
        self.e_magic == DOS_SIGNATURE
    }

    /// get offset to NT headers
    pub fn nt_headers_offset(&self) -> usize {
        self.e_lfanew as usize
    }
}
