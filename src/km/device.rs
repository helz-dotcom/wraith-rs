//! Device object management

use core::ffi::c_void;
use core::ptr::NonNull;

use super::driver::UnicodeStringRaw;
use super::error::{status, KmError, KmResult, NtStatus};
use super::string::UnicodeString;

/// device object raw structure
#[repr(C)]
pub struct DeviceObjectRaw {
    pub type_: i16,
    pub size: u16,
    pub reference_count: i32,
    pub driver_object: *mut c_void,
    pub next_device: *mut DeviceObjectRaw,
    pub attached_device: *mut DeviceObjectRaw,
    pub current_irp: *mut c_void,
    pub timer: *mut c_void,
    pub flags: u32,
    pub characteristics: u32,
    pub vpb: *mut c_void,
    pub device_extension: *mut c_void,
    pub device_type: u32,
    pub stack_size: i8,
    // ... more fields
}

/// device type constants
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Unknown = 0x00000022,
    Beep = 0x00000001,
    CdRom = 0x00000002,
    CdRomFileSystem = 0x00000003,
    Controller = 0x00000004,
    Disk = 0x00000007,
    DiskFileSystem = 0x00000008,
    FileSystem = 0x00000009,
    Keyboard = 0x0000000b,
    Mouse = 0x0000000f,
    Network = 0x00000012,
    Null = 0x00000015,
    Parallel = 0x00000016,
    Physical = 0x00000017,
    Printer = 0x00000018,
    Scanner = 0x00000019,
    Serial = 0x0000001b,
    Screen = 0x0000001c,
    Sound = 0x0000001d,
    Transport = 0x00000021,
    Ks = 0x0000002f,
}

/// device characteristics
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCharacteristics {
    None = 0,
    RemovableMedia = 0x00000001,
    ReadOnlyDevice = 0x00000002,
    FloppyDiskette = 0x00000004,
    WriteOnceMedia = 0x00000008,
    RemoteDevice = 0x00000010,
    DeviceIsMounted = 0x00000020,
    VirtualVolume = 0x00000040,
    SecureOpen = 0x00000100,
}

/// device flags
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFlags {
    None = 0,
    BufferedIo = 0x00000004,
    DirectIo = 0x00000010,
    DoExclusive = 0x00000800,
    PowerPageable = 0x00001000,
    DoBufferedIo = 0x00000004,
    DoDirectIo = 0x00000010,
}

/// safe device object wrapper
pub struct Device {
    raw: NonNull<DeviceObjectRaw>,
    symbolic_link: Option<UnicodeString>,
}

impl Device {
    /// wrap raw device object pointer
    ///
    /// # Safety
    /// ptr must be a valid DEVICE_OBJECT pointer
    pub unsafe fn from_raw(ptr: *mut c_void) -> Option<Self> {
        NonNull::new(ptr as *mut DeviceObjectRaw).map(|raw| Self {
            raw,
            symbolic_link: None,
        })
    }

    /// get raw pointer
    pub fn as_raw(&self) -> *mut DeviceObjectRaw {
        self.raw.as_ptr()
    }

    /// set device flags
    pub fn set_flags(&mut self, flags: u32) {
        // SAFETY: we have exclusive access
        unsafe {
            (*self.raw.as_ptr()).flags = flags;
        }
    }

    /// add device flag
    pub fn add_flag(&mut self, flag: DeviceFlags) {
        // SAFETY: we have exclusive access
        unsafe {
            (*self.raw.as_ptr()).flags |= flag as u32;
        }
    }

    /// remove device flag
    pub fn remove_flag(&mut self, flag: DeviceFlags) {
        // SAFETY: we have exclusive access
        unsafe {
            (*self.raw.as_ptr()).flags &= !(flag as u32);
        }
    }

    /// get device flags
    pub fn flags(&self) -> u32 {
        // SAFETY: device object is valid
        unsafe { (*self.raw.as_ptr()).flags }
    }

    /// get device type
    pub fn device_type(&self) -> u32 {
        // SAFETY: device object is valid
        unsafe { (*self.raw.as_ptr()).device_type }
    }

    /// get device extension
    pub fn extension<T>(&self) -> Option<&T> {
        // SAFETY: device object is valid
        unsafe {
            let ext = (*self.raw.as_ptr()).device_extension;
            if ext.is_null() {
                None
            } else {
                Some(&*(ext as *const T))
            }
        }
    }

    /// get mutable device extension
    pub fn extension_mut<T>(&mut self) -> Option<&mut T> {
        // SAFETY: we have exclusive access
        unsafe {
            let ext = (*self.raw.as_ptr()).device_extension;
            if ext.is_null() {
                None
            } else {
                Some(&mut *(ext as *mut T))
            }
        }
    }

    /// create symbolic link for this device
    pub fn create_symbolic_link(&mut self, link_name: &UnicodeString, device_name: &UnicodeString) -> KmResult<()> {
        // SAFETY: valid unicode strings
        let status = unsafe {
            IoCreateSymbolicLink(
                link_name.as_ptr() as *const _,
                device_name.as_ptr() as *const _,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::SymbolicLinkFailed {
                reason: "IoCreateSymbolicLink failed",
            });
        }

        Ok(())
    }

    /// delete symbolic link
    pub fn delete_symbolic_link(link_name: &UnicodeString) -> KmResult<()> {
        // SAFETY: valid unicode string
        let status = unsafe {
            IoDeleteSymbolicLink(link_name.as_ptr() as *const _)
        };

        if !status::nt_success(status) {
            return Err(KmError::SymbolicLinkFailed {
                reason: "IoDeleteSymbolicLink failed",
            });
        }

        Ok(())
    }

    /// set DO_BUFFERED_IO flag (for small data transfers)
    pub fn set_buffered_io(&mut self) {
        self.add_flag(DeviceFlags::BufferedIo);
    }

    /// set DO_DIRECT_IO flag (for large data transfers)
    pub fn set_direct_io(&mut self) {
        self.add_flag(DeviceFlags::DirectIo);
    }

    /// clear the DO_DEVICE_INITIALIZING flag (required after device creation)
    pub fn initialization_complete(&mut self) {
        // SAFETY: we have exclusive access
        unsafe {
            (*self.raw.as_ptr()).flags &= !0x00000080; // ~DO_DEVICE_INITIALIZING
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // Note: IoDeleteDevice should be called explicitly before drop
        // to properly clean up symbolic links first
    }
}

/// delete device object
pub fn delete_device(device: *mut c_void) {
    if !device.is_null() {
        // SAFETY: caller ensures device is valid
        unsafe {
            IoDeleteDevice(device);
        }
    }
}

/// device builder for common setup patterns
pub struct DeviceBuilder<'a> {
    driver: &'a mut super::driver::Driver,
    name: Option<UnicodeString>,
    symbolic_link: Option<UnicodeString>,
    device_type: u32,
    characteristics: u32,
    exclusive: bool,
    flags: u32,
}

impl<'a> DeviceBuilder<'a> {
    /// create new device builder
    pub fn new(driver: &'a mut super::driver::Driver) -> Self {
        Self {
            driver,
            name: None,
            symbolic_link: None,
            device_type: DeviceType::Unknown as u32,
            characteristics: 0,
            exclusive: false,
            flags: 0,
        }
    }

    /// set device name (e.g., "\\Device\\MyDevice")
    pub fn name(mut self, name: UnicodeString) -> Self {
        self.name = Some(name);
        self
    }

    /// set symbolic link name (e.g., "\\DosDevices\\MyDevice")
    pub fn symbolic_link(mut self, link: UnicodeString) -> Self {
        self.symbolic_link = Some(link);
        self
    }

    /// set device type
    pub fn device_type(mut self, dtype: DeviceType) -> Self {
        self.device_type = dtype as u32;
        self
    }

    /// set device characteristics
    pub fn characteristics(mut self, chars: u32) -> Self {
        self.characteristics = chars;
        self
    }

    /// set exclusive access
    pub fn exclusive(mut self) -> Self {
        self.exclusive = true;
        self
    }

    /// use buffered I/O
    pub fn buffered_io(mut self) -> Self {
        self.flags |= DeviceFlags::BufferedIo as u32;
        self
    }

    /// use direct I/O
    pub fn direct_io(mut self) -> Self {
        self.flags |= DeviceFlags::DirectIo as u32;
        self
    }

    /// build the device
    pub fn build(self) -> KmResult<Device> {
        let name = self.name.ok_or(KmError::InvalidParameter {
            context: "device name required",
        })?;

        let mut device = self.driver.create_device(
            &name,
            self.device_type,
            self.characteristics,
            self.exclusive,
        )?;

        if self.flags != 0 {
            device.add_flag(unsafe { core::mem::transmute(self.flags) });
        }

        if let Some(ref link) = self.symbolic_link {
            device.create_symbolic_link(link, &name)?;
        }

        device.initialization_complete();

        Ok(device)
    }
}

// kernel device functions
extern "system" {
    fn IoDeleteDevice(DeviceObject: *mut c_void);
    fn IoCreateSymbolicLink(
        SymbolicLinkName: *const c_void,
        DeviceName: *const c_void,
    ) -> NtStatus;
    fn IoDeleteSymbolicLink(SymbolicLinkName: *const c_void) -> NtStatus;
}
