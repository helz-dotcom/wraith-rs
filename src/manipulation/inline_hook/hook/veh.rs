//! VEH (Vectored Exception Handler) hooking
//!
//! VEH hooks use Windows Vectored Exception Handling to intercept execution.
//! By placing a hardware breakpoint (debug register) or INT3 at the target,
//! execution triggers an exception that our handler catches and redirects.
//!
//! # Advantages
//! - No code modification at the hook site (INT3 is single byte, hardware BP is zero bytes)
//! - Harder to detect than inline hooks
//! - Works even on read-only memory
//! - Hardware breakpoints are invisible to code integrity checks
//!
//! # Limitations
//! - Only 4 hardware breakpoints available per thread
//! - Performance overhead from exception handling
//! - Must manage debug registers carefully
//! - VEH handler is visible to GetVectoredExceptionHandlerCount

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;

#[cfg(feature = "std")]
use std::string::String;

use crate::error::{Result, WraithError};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// exception handler return values
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// exception codes
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;

/// debug register indices
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DebugRegister {
    Dr0 = 0,
    Dr1 = 1,
    Dr2 = 2,
    Dr3 = 3,
}

/// breakpoint condition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BreakCondition {
    /// break on execution
    Execute = 0b00,
    /// break on write
    Write = 0b01,
    /// break on I/O (typically not supported)
    Io = 0b10,
    /// break on read/write
    ReadWrite = 0b11,
}

/// breakpoint length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BreakLength {
    Byte = 0b00,
    Word = 0b01,
    Qword = 0b10, // or undefined on 32-bit
    Dword = 0b11,
}

/// VEH hook type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VehHookType {
    /// use hardware breakpoint (debug register)
    Hardware(DebugRegister),
    /// use INT3 software breakpoint
    Int3,
}

/// information about a VEH hook target
struct VehHookTarget {
    /// address of the hooked function
    target: usize,
    /// address of the detour function
    detour: usize,
    /// original byte at target (for INT3 hooks)
    original_byte: u8,
    /// hook type
    hook_type: VehHookType,
    /// whether this slot is active
    active: bool,
}

/// maximum number of VEH hooks we support
const MAX_VEH_HOOKS: usize = 64;

/// global VEH hook registry
static VEH_HOOKS: VehHookRegistry = VehHookRegistry::new();

/// VEH handler handle
static VEH_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// flag indicating VEH handler is installed
static VEH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// thread-safe hook registry
struct VehHookRegistry {
    hooks: UnsafeCell<[Option<VehHookTarget>; MAX_VEH_HOOKS]>,
}

impl VehHookRegistry {
    const fn new() -> Self {
        // initialize with None values
        const INIT: Option<VehHookTarget> = None;
        Self {
            hooks: UnsafeCell::new([INIT; MAX_VEH_HOOKS]),
        }
    }

    fn find_hook(&self, address: usize) -> Option<(usize, usize)> {
        // SAFETY: single-threaded access during exception handling
        let hooks = unsafe { &*self.hooks.get() };
        for hook in hooks.iter().flatten() {
            if hook.active && hook.target == address {
                return Some((hook.target, hook.detour));
            }
        }
        None
    }

    fn register(&self, target: VehHookTarget) -> Result<usize> {
        // SAFETY: we maintain proper synchronization
        let hooks = unsafe { &mut *self.hooks.get() };
        for (i, slot) in hooks.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(target);
                return Ok(i);
            }
        }
        Err(WraithError::HookInstallFailed {
            target: 0,
            reason: "VEH hook registry full".into(),
        })
    }

    fn unregister(&self, index: usize) -> Option<VehHookTarget> {
        // SAFETY: we maintain proper synchronization
        let hooks = unsafe { &mut *self.hooks.get() };
        if index < MAX_VEH_HOOKS {
            hooks[index].take()
        } else {
            None
        }
    }

    fn get(&self, index: usize) -> Option<&VehHookTarget> {
        // SAFETY: read-only access
        let hooks = unsafe { &*self.hooks.get() };
        hooks.get(index).and_then(|h| h.as_ref())
    }
}

// SAFETY: we use atomic operations for synchronization
unsafe impl Sync for VehHookRegistry {}

/// VEH hook instance using hardware breakpoints
pub struct VehHook {
    /// registry index
    index: usize,
    /// hook type
    hook_type: VehHookType,
    /// whether to restore on drop
    auto_restore: bool,
}

impl VehHook {
    /// create a VEH hook using a hardware breakpoint
    ///
    /// # Arguments
    /// * `target` - address of the function to hook
    /// * `detour` - address of the detour function
    /// * `dr` - which debug register to use (Dr0-Dr3)
    ///
    /// # Example
    /// ```ignore
    /// let hook = VehHook::hardware(target_addr, my_detour as usize, DebugRegister::Dr0)?;
    /// ```
    pub fn hardware(target: usize, detour: usize, dr: DebugRegister) -> Result<Self> {
        ensure_veh_handler()?;

        // set hardware breakpoint in debug registers
        set_hardware_breakpoint(dr, target, BreakCondition::Execute, BreakLength::Byte)?;

        let hook = VehHookTarget {
            target,
            detour,
            original_byte: 0,
            hook_type: VehHookType::Hardware(dr),
            active: true,
        };

        let index = VEH_HOOKS.register(hook)?;

        Ok(Self {
            index,
            hook_type: VehHookType::Hardware(dr),
            auto_restore: true,
        })
    }

    /// create a VEH hook using INT3 software breakpoint
    ///
    /// # Arguments
    /// * `target` - address of the function to hook
    /// * `detour` - address of the detour function
    ///
    /// # Example
    /// ```ignore
    /// let hook = VehHook::int3(target_addr, my_detour as usize)?;
    /// ```
    pub fn int3(target: usize, detour: usize) -> Result<Self> {
        ensure_veh_handler()?;

        // read original byte and write INT3
        // SAFETY: target is valid function address
        let original_byte = unsafe { *(target as *const u8) };

        // change protection and write INT3
        let _guard = crate::util::memory::ProtectionGuard::new(target, 1, 0x40)?;
        unsafe {
            *(target as *mut u8) = 0xCC;
        }

        let hook = VehHookTarget {
            target,
            detour,
            original_byte,
            hook_type: VehHookType::Int3,
            active: true,
        };

        let index = VEH_HOOKS.register(hook)?;

        Ok(Self {
            index,
            hook_type: VehHookType::Int3,
            auto_restore: true,
        })
    }

    /// check if hook is active
    pub fn is_active(&self) -> bool {
        VEH_HOOKS.get(self.index).map_or(false, |h| h.active)
    }

    /// get the target address
    pub fn target(&self) -> Option<usize> {
        VEH_HOOKS.get(self.index).map(|h| h.target)
    }

    /// get the detour address
    pub fn detour(&self) -> Option<usize> {
        VEH_HOOKS.get(self.index).map(|h| h.detour)
    }

    /// get the hook type
    pub fn hook_type(&self) -> VehHookType {
        self.hook_type
    }

    /// set whether to auto-restore on drop
    pub fn set_auto_restore(&mut self, restore: bool) {
        self.auto_restore = restore;
    }

    /// leak the hook (keep active after drop)
    pub fn leak(mut self) {
        self.auto_restore = false;
        core::mem::forget(self);
    }

    /// restore the hook
    pub fn restore(self) -> Result<()> {
        if let Some(hook) = VEH_HOOKS.unregister(self.index) {
            match hook.hook_type {
                VehHookType::Hardware(dr) => {
                    clear_hardware_breakpoint(dr)?;
                }
                VehHookType::Int3 => {
                    // restore original byte
                    let _guard = crate::util::memory::ProtectionGuard::new(
                        hook.target, 1, 0x40,
                    )?;
                    unsafe {
                        *(hook.target as *mut u8) = hook.original_byte;
                    }
                }
            }
        }

        // prevent drop from running
        core::mem::forget(self);
        Ok(())
    }
}

impl Drop for VehHook {
    fn drop(&mut self) {
        if self.auto_restore {
            if let Some(hook) = VEH_HOOKS.unregister(self.index) {
                match hook.hook_type {
                    VehHookType::Hardware(dr) => {
                        let _ = clear_hardware_breakpoint(dr);
                    }
                    VehHookType::Int3 => {
                        if let Ok(_guard) = crate::util::memory::ProtectionGuard::new(
                            hook.target, 1, 0x40,
                        ) {
                            unsafe {
                                *(hook.target as *mut u8) = hook.original_byte;
                            }
                        }
                    }
                }
            }
        }
    }
}

// SAFETY: VehHook operates on process-wide exception handling
unsafe impl Send for VehHook {}
unsafe impl Sync for VehHook {}

/// ensure VEH handler is installed
fn ensure_veh_handler() -> Result<()> {
    if VEH_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    let handler = unsafe {
        AddVectoredExceptionHandler(1, Some(veh_handler))
    };

    if handler.is_null() {
        return Err(WraithError::from_last_error("AddVectoredExceptionHandler"));
    }

    VEH_HANDLER.store(handler as usize, Ordering::Release);
    VEH_INSTALLED.store(true, Ordering::Release);

    Ok(())
}

/// the vectored exception handler
extern "system" fn veh_handler(exception_info: *mut ExceptionPointers) -> i32 {
    if exception_info.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // SAFETY: exception_info is valid during exception handling
    let info = unsafe { &*exception_info };
    let record = unsafe { &*info.exception_record };
    let context = unsafe { &mut *info.context_record };

    let exception_code = record.exception_code;

    // handle breakpoint exceptions
    if exception_code == EXCEPTION_BREAKPOINT || exception_code == EXCEPTION_SINGLE_STEP {
        #[cfg(target_arch = "x86_64")]
        let exception_address = context.rip as usize;
        #[cfg(target_arch = "x86")]
        let exception_address = context.eip as usize;

        // check if this is one of our hooks
        if let Some((target, detour)) = VEH_HOOKS.find_hook(exception_address) {
            // for INT3, the exception address is after the INT3
            let adjusted_addr = if exception_code == EXCEPTION_BREAKPOINT {
                exception_address.saturating_sub(1)
            } else {
                exception_address
            };

            if adjusted_addr == target || exception_address == target {
                // redirect to detour
                #[cfg(target_arch = "x86_64")]
                {
                    context.rip = detour as u64;
                }
                #[cfg(target_arch = "x86")]
                {
                    context.eip = detour as u32;
                }

                // for hardware breakpoints, we need to set RF flag to prevent re-triggering
                if exception_code == EXCEPTION_SINGLE_STEP {
                    #[cfg(target_arch = "x86_64")]
                    {
                        context.eflags |= 0x10000; // RF flag
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        context.eflags |= 0x10000; // RF flag
                    }
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// set a hardware breakpoint
fn set_hardware_breakpoint(
    dr: DebugRegister,
    address: usize,
    condition: BreakCondition,
    length: BreakLength,
) -> Result<()> {
    let mut context = unsafe { core::mem::zeroed::<Context>() };

    #[cfg(target_arch = "x86_64")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }
    #[cfg(target_arch = "x86")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }

    let thread = unsafe { GetCurrentThread() };

    if unsafe { GetThreadContext(thread, &mut context) } == 0 {
        return Err(WraithError::from_last_error("GetThreadContext"));
    }

    // set the debug register address
    match dr {
        DebugRegister::Dr0 => context.dr0 = address as u64,
        DebugRegister::Dr1 => context.dr1 = address as u64,
        DebugRegister::Dr2 => context.dr2 = address as u64,
        DebugRegister::Dr3 => context.dr3 = address as u64,
    }

    // configure DR7
    let dr_index = dr as u8;
    let enable_bit = 1u64 << (dr_index * 2); // local enable
    let condition_bits = (condition as u64) << (16 + dr_index * 4);
    let length_bits = (length as u64) << (18 + dr_index * 4);

    // clear old settings for this DR
    let clear_mask = !(0b11u64 << (dr_index * 2) | 0b1111u64 << (16 + dr_index * 4));
    context.dr7 &= clear_mask;

    // set new settings
    context.dr7 |= enable_bit | condition_bits | length_bits;

    if unsafe { SetThreadContext(thread, &context) } == 0 {
        return Err(WraithError::from_last_error("SetThreadContext"));
    }

    Ok(())
}

/// clear a hardware breakpoint
fn clear_hardware_breakpoint(dr: DebugRegister) -> Result<()> {
    let mut context = unsafe { core::mem::zeroed::<Context>() };

    #[cfg(target_arch = "x86_64")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }
    #[cfg(target_arch = "x86")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }

    let thread = unsafe { GetCurrentThread() };

    if unsafe { GetThreadContext(thread, &mut context) } == 0 {
        return Err(WraithError::from_last_error("GetThreadContext"));
    }

    // clear the debug register
    match dr {
        DebugRegister::Dr0 => context.dr0 = 0,
        DebugRegister::Dr1 => context.dr1 = 0,
        DebugRegister::Dr2 => context.dr2 = 0,
        DebugRegister::Dr3 => context.dr3 = 0,
    }

    // disable in DR7
    let dr_index = dr as u8;
    let disable_mask = !(0b11u64 << (dr_index * 2) | 0b1111u64 << (16 + dr_index * 4));
    context.dr7 &= disable_mask;

    if unsafe { SetThreadContext(thread, &context) } == 0 {
        return Err(WraithError::from_last_error("SetThreadContext"));
    }

    Ok(())
}

/// get available debug register
pub fn get_available_debug_register() -> Result<DebugRegister> {
    let mut context = unsafe { core::mem::zeroed::<Context>() };

    #[cfg(target_arch = "x86_64")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }
    #[cfg(target_arch = "x86")]
    {
        context.context_flags = CONTEXT_DEBUG_REGISTERS;
    }

    let thread = unsafe { GetCurrentThread() };

    if unsafe { GetThreadContext(thread, &mut context) } == 0 {
        return Err(WraithError::from_last_error("GetThreadContext"));
    }

    // check which debug registers are free
    for i in 0..4u8 {
        let is_enabled = (context.dr7 & (1u64 << (i * 2))) != 0;
        if !is_enabled {
            return Ok(match i {
                0 => DebugRegister::Dr0,
                1 => DebugRegister::Dr1,
                2 => DebugRegister::Dr2,
                _ => DebugRegister::Dr3,
            });
        }
    }

    Err(WraithError::GadgetNotFound {
        gadget_type: "available debug register",
    })
}

// context flags
#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;

/// EXCEPTION_RECORD structure
#[repr(C)]
struct ExceptionRecord {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *mut ExceptionRecord,
    exception_address: *mut core::ffi::c_void,
    number_parameters: u32,
    exception_information: [usize; 15],
}

/// EXCEPTION_POINTERS structure
#[repr(C)]
struct ExceptionPointers {
    exception_record: *mut ExceptionRecord,
    context_record: *mut Context,
}

/// CONTEXT structure (simplified, only what we need)
#[repr(C)]
#[cfg(target_arch = "x86_64")]
struct Context {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: u32,
    mx_csr: u32,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    eflags: u32,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    _padding: [u8; 512], // FP/vector state we don't care about
}

#[repr(C)]
#[cfg(target_arch = "x86")]
struct Context {
    context_flags: u32,
    dr0: u32,
    dr1: u32,
    dr2: u32,
    dr3: u32,
    dr6: u32,
    dr7: u32,
    float_save: [u8; 112],
    seg_gs: u32,
    seg_fs: u32,
    seg_es: u32,
    seg_ds: u32,
    edi: u32,
    esi: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    ebp: u32,
    eip: u32,
    seg_cs: u32,
    eflags: u32,
    esp: u32,
    seg_ss: u32,
    extended_registers: [u8; 512],
}

#[cfg(target_arch = "x86_64")]
impl Context {
    // make dr fields accessible as u64 regardless of actual type
}

#[cfg(target_arch = "x86")]
impl Context {
    // x86 context has 32-bit debug registers
}

type VectoredHandler = Option<extern "system" fn(*mut ExceptionPointers) -> i32>;

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(first: u32, handler: VectoredHandler) -> *mut core::ffi::c_void;
    fn RemoveVectoredExceptionHandler(handle: *mut core::ffi::c_void) -> u32;
    fn GetCurrentThread() -> *mut core::ffi::c_void;
    fn GetThreadContext(thread: *mut core::ffi::c_void, context: *mut Context) -> i32;
    fn SetThreadContext(thread: *mut core::ffi::c_void, context: *const Context) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_veh_handler() {
        ensure_veh_handler().expect("should install VEH handler");
        assert!(VEH_INSTALLED.load(Ordering::Relaxed));
    }

    #[test]
    fn test_get_available_dr() {
        let dr = get_available_debug_register();
        // might fail if all DRs are in use by debugger
        if dr.is_ok() {
            let dr = dr.unwrap();
            assert!(matches!(
                dr,
                DebugRegister::Dr0
                    | DebugRegister::Dr1
                    | DebugRegister::Dr2
                    | DebugRegister::Dr3
            ));
        }
    }
}
