//! Windows version detection and release mapping

use crate::arch::segment;
use crate::error::{Result, WraithError};
use core::cmp::Ordering;

/// represents a specific Windows version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

/// named Windows releases with known build numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WindowsRelease {
    Windows7,       // 7601
    Windows8,       // 9200
    Windows81,      // 9600
    Windows10_1507, // 10240
    Windows10_1511, // 10586
    Windows10_1607, // 14393
    Windows10_1703, // 15063
    Windows10_1709, // 16299
    Windows10_1803, // 17134
    Windows10_1809, // 17763
    Windows10_1903, // 18362
    Windows10_1909, // 18363
    Windows10_2004, // 19041
    Windows10_20H2, // 19042
    Windows10_21H1, // 19043
    Windows10_21H2, // 19044
    Windows10_22H2, // 19045
    Windows11_21H2, // 22000
    Windows11_22H2, // 22621
    Windows11_23H2, // 22631
    Windows11_24H2, // 26100
    Unknown,
}

impl WindowsVersion {
    /// minimum supported version (Windows 7 SP1)
    pub const MIN_SUPPORTED: Self = Self {
        major: 6,
        minor: 1,
        build: 7601,
    };

    /// get current Windows version from PEB
    ///
    /// reads OSMajorVersion, OSMinorVersion, OSBuildNumber from PEB
    pub fn current() -> Result<Self> {
        // SAFETY: segment::get_peb returns valid PEB pointer for current process
        let peb = unsafe { segment::get_peb() };
        if peb.is_null() {
            return Err(WraithError::InvalidPebAccess);
        }

        // offsets are consistent across all Windows versions for these fields
        // x64: OSMajorVersion @ 0x118, OSMinorVersion @ 0x11C, OSBuildNumber @ 0x120
        // x86: OSMajorVersion @ 0xA4, OSMinorVersion @ 0xA8, OSBuildNumber @ 0xAC

        #[cfg(target_arch = "x86_64")]
        let (major, minor, build) = unsafe {
            let major = (peb.add(0x118) as *const u32).read_unaligned();
            let minor = (peb.add(0x11C) as *const u32).read_unaligned();
            let build = (peb.add(0x120) as *const u16).read_unaligned() as u32;
            (major, minor, build)
        };

        #[cfg(target_arch = "x86")]
        let (major, minor, build) = unsafe {
            let major = (peb.add(0xA4) as *const u32).read_unaligned();
            let minor = (peb.add(0xA8) as *const u32).read_unaligned();
            let build = (peb.add(0xAC) as *const u16).read_unaligned() as u32;
            (major, minor, build)
        };

        let version = Self { major, minor, build };

        if version < Self::MIN_SUPPORTED {
            return Err(WraithError::UnsupportedWindowsVersion {
                major,
                minor,
                build,
            });
        }

        Ok(version)
    }

    /// map version to named release
    pub fn release(&self) -> WindowsRelease {
        match (self.major, self.minor, self.build) {
            (6, 1, _) => WindowsRelease::Windows7,
            (6, 2, _) => WindowsRelease::Windows8,
            (6, 3, _) => WindowsRelease::Windows81,
            (10, 0, b) if b >= 26100 => WindowsRelease::Windows11_24H2,
            (10, 0, b) if b >= 22631 => WindowsRelease::Windows11_23H2,
            (10, 0, b) if b >= 22621 => WindowsRelease::Windows11_22H2,
            (10, 0, b) if b >= 22000 => WindowsRelease::Windows11_21H2,
            (10, 0, b) if b >= 19045 => WindowsRelease::Windows10_22H2,
            (10, 0, b) if b >= 19044 => WindowsRelease::Windows10_21H2,
            (10, 0, b) if b >= 19043 => WindowsRelease::Windows10_21H1,
            (10, 0, b) if b >= 19042 => WindowsRelease::Windows10_20H2,
            (10, 0, b) if b >= 19041 => WindowsRelease::Windows10_2004,
            (10, 0, b) if b >= 18363 => WindowsRelease::Windows10_1909,
            (10, 0, b) if b >= 18362 => WindowsRelease::Windows10_1903,
            (10, 0, b) if b >= 17763 => WindowsRelease::Windows10_1809,
            (10, 0, b) if b >= 17134 => WindowsRelease::Windows10_1803,
            (10, 0, b) if b >= 16299 => WindowsRelease::Windows10_1709,
            (10, 0, b) if b >= 15063 => WindowsRelease::Windows10_1703,
            (10, 0, b) if b >= 14393 => WindowsRelease::Windows10_1607,
            (10, 0, b) if b >= 10586 => WindowsRelease::Windows10_1511,
            (10, 0, b) if b >= 10240 => WindowsRelease::Windows10_1507,
            _ => WindowsRelease::Unknown,
        }
    }

    /// check if current version is at least the given release
    pub fn is_at_least(&self, release: WindowsRelease) -> bool {
        self.release() >= release
    }

    /// check if this version has the LdrpHashTable (Windows 8+)
    pub fn supports_hash_table(&self) -> bool {
        self.is_at_least(WindowsRelease::Windows8)
    }

    /// check if this version has the LdrpModuleBaseAddressIndex (Win8+)
    pub fn supports_base_address_index(&self) -> bool {
        self.is_at_least(WindowsRelease::Windows8)
    }

    /// check if Windows 11 (different PEB layout in some areas)
    pub fn is_windows_11(&self) -> bool {
        self.build >= 22000
    }
}

impl PartialOrd for WindowsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WindowsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.build.cmp(&other.build),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl core::fmt::Display for WindowsVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

impl core::fmt::Display for WindowsRelease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Windows7 => write!(f, "Windows 7"),
            Self::Windows8 => write!(f, "Windows 8"),
            Self::Windows81 => write!(f, "Windows 8.1"),
            Self::Windows10_1507 => write!(f, "Windows 10 1507"),
            Self::Windows10_1511 => write!(f, "Windows 10 1511"),
            Self::Windows10_1607 => write!(f, "Windows 10 1607"),
            Self::Windows10_1703 => write!(f, "Windows 10 1703"),
            Self::Windows10_1709 => write!(f, "Windows 10 1709"),
            Self::Windows10_1803 => write!(f, "Windows 10 1803"),
            Self::Windows10_1809 => write!(f, "Windows 10 1809"),
            Self::Windows10_1903 => write!(f, "Windows 10 1903"),
            Self::Windows10_1909 => write!(f, "Windows 10 1909"),
            Self::Windows10_2004 => write!(f, "Windows 10 2004"),
            Self::Windows10_20H2 => write!(f, "Windows 10 20H2"),
            Self::Windows10_21H1 => write!(f, "Windows 10 21H1"),
            Self::Windows10_21H2 => write!(f, "Windows 10 21H2"),
            Self::Windows10_22H2 => write!(f, "Windows 10 22H2"),
            Self::Windows11_21H2 => write!(f, "Windows 11 21H2"),
            Self::Windows11_22H2 => write!(f, "Windows 11 22H2"),
            Self::Windows11_23H2 => write!(f, "Windows 11 23H2"),
            Self::Windows11_24H2 => write!(f, "Windows 11 24H2"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        let win10 = WindowsVersion {
            major: 10,
            minor: 0,
            build: 19041,
        };
        let win11 = WindowsVersion {
            major: 10,
            minor: 0,
            build: 22000,
        };
        assert!(win10 < win11);
    }

    #[test]
    fn test_release_mapping() {
        let win11 = WindowsVersion {
            major: 10,
            minor: 0,
            build: 22621,
        };
        assert_eq!(win11.release(), WindowsRelease::Windows11_22H2);
    }
}
