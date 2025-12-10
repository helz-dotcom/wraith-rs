//! Driver object management

use core::ffi::c_void;
use core::ptr::NonNull;

use super::device::Device;
use super::error::{status, KmError, KmResult, NtStatus};
use super::irp::{Irp, IrpMajorFunction};
use super::string::UnicodeString;

/// driver object wrapper
#[repr(C)]
pub struct DriverObjectRaw {
    pub type_: i16,
    pub size: i16,
    pub device_object: *mut c_void,
    pub flags: u32,
    pub driver_start: *mut c_void,
    pub driver_size: u32,
    pub driver_section: *mut c_void,
    pub driver_extension: *mut DriverExtensionRaw,
    pub driver_name: UnicodeStringRaw,
    pub hardware_database: *mut UnicodeStringRaw,
    pub fast_io_dispatch: *mut c_void,
    pub driver_init: *mut c_void,
    pub driver_start_io: *mut c_void,
    pub driver_unload: Option<DriverUnload>,
    pub major_function: [Option<DriverDispatch>; 28],
}

/// driver extension
#[repr(C)]
pub struct DriverExtensionRaw {
    pub driver_object: *mut DriverObjectRaw,
    pub add_device: *mut c_void,
    pub count: u32,
    pub service_key_name: UnicodeStringRaw,
}

/// raw unicode string (for FFI)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeStringRaw {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

/// driver entry function signature
pub type DriverEntry = unsafe extern "system" fn(
    driver_object: *mut DriverObjectRaw,
    registry_path: *const UnicodeStringRaw,
) -> NtStatus;

/// driver unload function signature
pub type DriverUnload = unsafe extern "system" fn(driver_object: *mut DriverObjectRaw);

/// IRP dispatch function signature
pub type DriverDispatch = unsafe extern "system" fn(
    device_object: *mut c_void,
    irp: *mut c_void,
) -> NtStatus;

/// safe driver object wrapper
pub struct Driver {
    raw: NonNull<DriverObjectRaw>,
}

impl Driver {
    /// wrap raw driver object pointer
    ///
    /// # Safety
    /// ptr must be a valid DRIVER_OBJECT pointer
    pub unsafe fn from_raw(ptr: *mut DriverObjectRaw) -> Option<Self> {
        NonNull::new(ptr).map(|raw| Self { raw })
    }

    /// get raw pointer
    pub fn as_raw(&self) -> *mut DriverObjectRaw {
        self.raw.as_ptr()
    }

    /// set driver unload routine
    pub fn set_unload(&mut self, unload: DriverUnload) {
        // SAFETY: we have exclusive access through mut reference
        unsafe {
            (*self.raw.as_ptr()).driver_unload = Some(unload);
        }
    }

    /// set major function handler
    pub fn set_major_function(&mut self, function: IrpMajorFunction, handler: DriverDispatch) {
        let index = function as usize;
        if index < 28 {
            // SAFETY: valid index
            unsafe {
                (*self.raw.as_ptr()).major_function[index] = Some(handler);
            }
        }
    }

    /// set all major functions to same handler
    pub fn set_all_major_functions(&mut self, handler: DriverDispatch) {
        // SAFETY: we have exclusive access
        unsafe {
            for i in 0..28 {
                (*self.raw.as_ptr()).major_function[i] = Some(handler);
            }
        }
    }

    /// get driver name
    pub fn name(&self) -> &[u16] {
        // SAFETY: driver object is valid
        unsafe {
            let name = &(*self.raw.as_ptr()).driver_name;
            if name.buffer.is_null() || name.length == 0 {
                return &[];
            }
            core::slice::from_raw_parts(name.buffer, (name.length / 2) as usize)
        }
    }

    /// get driver start address
    pub fn start_address(&self) -> *mut c_void {
        // SAFETY: driver object is valid
        unsafe { (*self.raw.as_ptr()).driver_start }
    }

    /// get driver size
    pub fn size(&self) -> u32 {
        // SAFETY: driver object is valid
        unsafe { (*self.raw.as_ptr()).driver_size }
    }

    /// create a device
    pub fn create_device(
        &mut self,
        name: &UnicodeString,
        device_type: u32,
        characteristics: u32,
        exclusive: bool,
    ) -> KmResult<Device> {
        let mut device_object: *mut c_void = core::ptr::null_mut();

        // SAFETY: valid driver object
        let status = unsafe {
            IoCreateDevice(
                self.raw.as_ptr(),
                0, // device extension size
                name.as_ptr() as *const _,
                device_type,
                characteristics,
                if exclusive { 1 } else { 0 },
                &mut device_object,
            )
        };

        if !status::nt_success(status) {
            return Err(KmError::DeviceCreationFailed {
                reason: "IoCreateDevice failed",
            });
        }

        // SAFETY: IoCreateDevice succeeded
        unsafe { Device::from_raw(device_object) }
            .ok_or(KmError::DeviceCreationFailed {
                reason: "device object is null",
            })
    }
}

/// driver builder for setting up dispatch routines
pub struct DriverBuilder {
    driver: Driver,
}

impl DriverBuilder {
    /// create builder from raw driver object
    ///
    /// # Safety
    /// ptr must be valid DRIVER_OBJECT
    pub unsafe fn new(ptr: *mut DriverObjectRaw) -> Option<Self> {
        // SAFETY: caller ensures ptr is valid
        unsafe { Driver::from_raw(ptr) }.map(|driver| Self { driver })
    }

    /// set unload routine
    pub fn unload(mut self, handler: DriverUnload) -> Self {
        self.driver.set_unload(handler);
        self
    }

    /// set create handler (IRP_MJ_CREATE)
    pub fn create(mut self, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(IrpMajorFunction::Create, handler);
        self
    }

    /// set close handler (IRP_MJ_CLOSE)
    pub fn close(mut self, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(IrpMajorFunction::Close, handler);
        self
    }

    /// set device control handler (IRP_MJ_DEVICE_CONTROL)
    pub fn device_control(mut self, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(IrpMajorFunction::DeviceControl, handler);
        self
    }

    /// set read handler (IRP_MJ_READ)
    pub fn read(mut self, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(IrpMajorFunction::Read, handler);
        self
    }

    /// set write handler (IRP_MJ_WRITE)
    pub fn write(mut self, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(IrpMajorFunction::Write, handler);
        self
    }

    /// set custom major function handler
    pub fn major_function(mut self, function: IrpMajorFunction, handler: DriverDispatch) -> Self {
        self.driver.set_major_function(function, handler);
        self
    }

    /// build and return the configured driver
    pub fn build(self) -> Driver {
        self.driver
    }
}

/// helper trait for implementing driver entry
pub trait DriverImpl {
    /// called during driver initialization
    fn init(driver: &mut Driver, registry_path: &UnicodeString) -> KmResult<()>;

    /// called during driver unload
    fn unload(driver: &Driver);

    /// handle IRP_MJ_CREATE
    fn create(_device: *mut c_void, _irp: &mut Irp) -> NtStatus {
        status::STATUS_SUCCESS
    }

    /// handle IRP_MJ_CLOSE
    fn close(_device: *mut c_void, _irp: &mut Irp) -> NtStatus {
        status::STATUS_SUCCESS
    }

    /// handle IRP_MJ_DEVICE_CONTROL
    fn device_control(_device: *mut c_void, _irp: &mut Irp) -> NtStatus {
        status::STATUS_NOT_IMPLEMENTED
    }

    /// handle IRP_MJ_READ
    fn read(_device: *mut c_void, _irp: &mut Irp) -> NtStatus {
        status::STATUS_NOT_IMPLEMENTED
    }

    /// handle IRP_MJ_WRITE
    fn write(_device: *mut c_void, _irp: &mut Irp) -> NtStatus {
        status::STATUS_NOT_IMPLEMENTED
    }
}

/// macro to generate driver entry boilerplate
#[macro_export]
macro_rules! driver_entry {
    ($impl_type:ty) => {
        #[no_mangle]
        pub unsafe extern "system" fn DriverEntry(
            driver_object: *mut $crate::km::driver::DriverObjectRaw,
            registry_path: *const $crate::km::driver::UnicodeStringRaw,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: called from kernel with valid parameters
            unsafe { __driver_entry_impl::<$impl_type>(driver_object, registry_path) }
        }

        unsafe fn __driver_entry_impl<T: $crate::km::driver::DriverImpl>(
            driver_object: *mut $crate::km::driver::DriverObjectRaw,
            registry_path: *const $crate::km::driver::UnicodeStringRaw,
        ) -> $crate::km::error::NtStatus {
            use $crate::km::driver::DriverImpl;
            use $crate::km::error::status;

            // SAFETY: driver_object is provided by the kernel
            let Some(mut driver) = (unsafe { $crate::km::Driver::from_raw(driver_object) }) else {
                return status::STATUS_INVALID_PARAMETER;
            };

            // set up dispatch routines
            driver.set_unload(__driver_unload::<T>);
            driver.set_major_function($crate::km::IrpMajorFunction::Create, __dispatch_create::<T>);
            driver.set_major_function($crate::km::IrpMajorFunction::Close, __dispatch_close::<T>);
            driver.set_major_function($crate::km::IrpMajorFunction::DeviceControl, __dispatch_device_control::<T>);
            driver.set_major_function($crate::km::IrpMajorFunction::Read, __dispatch_read::<T>);
            driver.set_major_function($crate::km::IrpMajorFunction::Write, __dispatch_write::<T>);

            // create unicode string wrapper for registry path
            if registry_path.is_null() {
                return status::STATUS_INVALID_PARAMETER;
            }

            let reg_string = $crate::km::UnicodeString::empty(); // simplified

            match T::init(&mut driver, &reg_string) {
                Ok(()) => status::STATUS_SUCCESS,
                Err(e) => e.to_ntstatus(),
            }
        }

        unsafe extern "system" fn __driver_unload<T: $crate::km::driver::DriverImpl>(
            driver_object: *mut $crate::km::driver::DriverObjectRaw
        ) {
            // SAFETY: driver_object is valid from kernel
            if let Some(driver) = unsafe { $crate::km::Driver::from_raw(driver_object) } {
                T::unload(&driver);
            }
        }

        unsafe extern "system" fn __dispatch_create<T: $crate::km::driver::DriverImpl>(
            device: *mut core::ffi::c_void,
            irp: *mut core::ffi::c_void,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: irp is valid from kernel
            if let Some(mut irp_wrapper) = unsafe { $crate::km::Irp::from_raw(irp) } {
                let status = T::create(device, &mut irp_wrapper);
                irp_wrapper.complete(status);
                status
            } else {
                $crate::km::error::status::STATUS_INVALID_PARAMETER
            }
        }

        unsafe extern "system" fn __dispatch_close<T: $crate::km::driver::DriverImpl>(
            device: *mut core::ffi::c_void,
            irp: *mut core::ffi::c_void,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: irp is valid from kernel
            if let Some(mut irp_wrapper) = unsafe { $crate::km::Irp::from_raw(irp) } {
                let status = T::close(device, &mut irp_wrapper);
                irp_wrapper.complete(status);
                status
            } else {
                $crate::km::error::status::STATUS_INVALID_PARAMETER
            }
        }

        unsafe extern "system" fn __dispatch_device_control<T: $crate::km::driver::DriverImpl>(
            device: *mut core::ffi::c_void,
            irp: *mut core::ffi::c_void,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: irp is valid from kernel
            if let Some(mut irp_wrapper) = unsafe { $crate::km::Irp::from_raw(irp) } {
                let status = T::device_control(device, &mut irp_wrapper);
                irp_wrapper.complete(status);
                status
            } else {
                $crate::km::error::status::STATUS_INVALID_PARAMETER
            }
        }

        unsafe extern "system" fn __dispatch_read<T: $crate::km::driver::DriverImpl>(
            device: *mut core::ffi::c_void,
            irp: *mut core::ffi::c_void,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: irp is valid from kernel
            if let Some(mut irp_wrapper) = unsafe { $crate::km::Irp::from_raw(irp) } {
                let status = T::read(device, &mut irp_wrapper);
                irp_wrapper.complete(status);
                status
            } else {
                $crate::km::error::status::STATUS_INVALID_PARAMETER
            }
        }

        unsafe extern "system" fn __dispatch_write<T: $crate::km::driver::DriverImpl>(
            device: *mut core::ffi::c_void,
            irp: *mut core::ffi::c_void,
        ) -> $crate::km::error::NtStatus {
            // SAFETY: irp is valid from kernel
            if let Some(mut irp_wrapper) = unsafe { $crate::km::Irp::from_raw(irp) } {
                let status = T::write(device, &mut irp_wrapper);
                irp_wrapper.complete(status);
                status
            } else {
                $crate::km::error::status::STATUS_INVALID_PARAMETER
            }
        }
    };
}

// kernel driver functions
extern "system" {
    fn IoCreateDevice(
        DriverObject: *mut DriverObjectRaw,
        DeviceExtensionSize: u32,
        DeviceName: *const c_void,
        DeviceType: u32,
        DeviceCharacteristics: u32,
        Exclusive: u8,
        DeviceObject: *mut *mut c_void,
    ) -> NtStatus;
}
