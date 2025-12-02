//! Unified error types for wraith-rs

use core::fmt;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::string::String;

#[cfg(feature = "std")]
use std::string::String;

/// all errors that can occur in wraith-rs
#[derive(Debug)]
pub enum WraithError {
    // === version/architecture ===
    /// windows version not supported by this library
    UnsupportedWindowsVersion { major: u32, minor: u32, build: u32 },

    /// architecture not supported (e.g., ARM)
    UnsupportedArchitecture,

    // === structure access ===
    /// failed to access PEB
    InvalidPebAccess,

    /// failed to access TEB
    InvalidTebAccess,

    /// structure data appears corrupted
    CorruptedStructure {
        name: &'static str,
        reason: &'static str,
    },

    /// null pointer where non-null expected
    NullPointer { context: &'static str },

    // === navigation ===
    /// module with given name not found
    ModuleNotFound { name: String },

    /// address does not belong to any loaded module
    AddressNotInModule { address: u64 },

    /// thread with given ID not found
    ThreadNotFound { tid: u32 },

    // === manipulation ===
    /// failed to unlink module from PEB lists
    UnlinkFailed { module: String, reason: String },

    /// failed to restore module links
    RelinkFailed { module: String, reason: String },

    /// PEB module list appears corrupted
    ListCorrupted { list_type: ModuleListType },

    // === manual mapping ===
    /// PE file format invalid or unsupported
    InvalidPeFormat { reason: String },

    /// memory allocation failed
    AllocationFailed { size: usize, protection: u32 },

    /// failed to map PE section
    MappingFailed { section: String, reason: String },

    /// failed to process relocation entry
    RelocationFailed { rva: u32, reason: String },

    /// failed to resolve import
    ImportResolutionFailed { dll: String, function: String },

    /// export is forwarded to another module
    ForwardedExport { forwarder: String },

    /// TLS callback execution failed
    TlsCallbackFailed { index: usize },

    /// DllMain returned FALSE
    EntryPointFailed { status: i32 },

    // === syscalls ===
    /// failed to enumerate syscalls from ntdll
    SyscallEnumerationFailed { reason: String },

    /// syscall with given name/hash not found
    SyscallNotFound { name: String },

    /// syscall returned error status
    SyscallFailed { name: String, status: i32 },

    /// ntdll.dll not found in loaded modules
    NtdllNotFound,

    // === hooks ===
    /// failed to detect hooks in function
    HookDetectionFailed { function: String, reason: String },

    /// failed to remove hook
    UnhookFailed { function: String, reason: String },

    /// function integrity check failed
    IntegrityCheckFailed { function: String },

    /// clean copy of module not available
    CleanCopyUnavailable,

    // === inline hooks ===
    /// failed to install inline hook
    HookInstallFailed { target: u64, reason: String },

    /// failed to restore hook
    HookRestoreFailed { target: u64, reason: String },

    /// instruction decoding failed
    InstructionDecodeFailed { address: u64, reason: String },

    /// trampoline allocation failed
    TrampolineAllocationFailed { near: u64, size: usize },

    /// hook conflict detected (target already hooked)
    HookConflict { target: u64, existing_type: String },

    /// insufficient space for hook at target
    InsufficientHookSpace { target: u64, available: usize, required: usize },

    // === memory ===
    /// memory read operation failed
    ReadFailed { address: u64, size: usize },

    /// memory write operation failed
    WriteFailed { address: u64, size: usize },

    /// failed to change memory protection
    ProtectionChangeFailed { address: u64, size: usize },

    // === pattern scanning ===
    /// failed to parse pattern string
    PatternParseFailed { reason: String },

    // === remote process ===
    /// failed to open remote process
    ProcessOpenFailed { pid: u32, reason: String },

    /// process with given ID not found
    ProcessNotFound { pid: u32 },

    /// failed to create remote thread
    RemoteThreadFailed { reason: String },

    /// failed to inject into remote process
    InjectionFailed { method: String, reason: String },

    /// failed to enumerate remote modules
    RemoteModuleEnumFailed { reason: String },

    /// failed to duplicate handle
    HandleDuplicateFailed { reason: String },

    /// section mapping failed
    SectionMappingFailed { reason: String },

    /// APC queue operation failed
    ApcQueueFailed { reason: String },

    /// thread context operation failed
    ThreadContextFailed { reason: String },

    /// thread suspend/resume failed
    ThreadSuspendResumeFailed { reason: String },

    // === spoofing ===
    /// no suitable gadget found for spoofing
    GadgetNotFound { gadget_type: &'static str },

    /// failed to build spoof trampoline
    SpoofTrampolineFailed { reason: String },

    /// stack frame synthesis failed
    StackSynthesisFailed { reason: String },

    // === win32 ===
    /// underlying Win32 API returned error
    Win32Error { code: u32, context: &'static str },
}

/// which PEB module list had an issue
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleListType {
    InLoadOrder,
    InMemoryOrder,
    InInitializationOrder,
}

impl fmt::Display for ModuleListType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InLoadOrder => write!(f, "InLoadOrderModuleList"),
            Self::InMemoryOrder => write!(f, "InMemoryOrderModuleList"),
            Self::InInitializationOrder => write!(f, "InInitializationOrderModuleList"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WraithError {}

impl fmt::Display for WraithError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedWindowsVersion { major, minor, build } => {
                write!(f, "unsupported Windows version: {major}.{minor}.{build}")
            }
            Self::UnsupportedArchitecture => {
                write!(f, "unsupported architecture (only x86/x64 supported)")
            }
            Self::InvalidPebAccess => {
                write!(f, "failed to access PEB")
            }
            Self::InvalidTebAccess => {
                write!(f, "failed to access TEB")
            }
            Self::CorruptedStructure { name, reason } => {
                write!(f, "corrupted structure {name}: {reason}")
            }
            Self::NullPointer { context } => {
                write!(f, "unexpected null pointer in {context}")
            }
            Self::ModuleNotFound { name } => {
                write!(f, "module not found: {name}")
            }
            Self::AddressNotInModule { address } => {
                write!(f, "address {address:#x} not in any loaded module")
            }
            Self::ThreadNotFound { tid } => {
                write!(f, "thread {tid} not found")
            }
            Self::UnlinkFailed { module, reason } => {
                write!(f, "failed to unlink {module}: {reason}")
            }
            Self::RelinkFailed { module, reason } => {
                write!(f, "failed to relink {module}: {reason}")
            }
            Self::ListCorrupted { list_type } => {
                write!(f, "PEB {list_type} appears corrupted")
            }
            Self::InvalidPeFormat { reason } => {
                write!(f, "invalid PE format: {reason}")
            }
            Self::AllocationFailed { size, protection } => {
                write!(
                    f,
                    "failed to allocate {size} bytes with protection {protection:#x}"
                )
            }
            Self::MappingFailed { section, reason } => {
                write!(f, "failed to map section {section}: {reason}")
            }
            Self::RelocationFailed { rva, reason } => {
                write!(f, "relocation failed at RVA {rva:#x}: {reason}")
            }
            Self::ImportResolutionFailed { dll, function } => {
                write!(f, "failed to resolve {dll}!{function}")
            }
            Self::ForwardedExport { forwarder } => {
                write!(f, "export forwarded to {forwarder}")
            }
            Self::TlsCallbackFailed { index } => {
                write!(f, "TLS callback {index} failed")
            }
            Self::EntryPointFailed { status } => {
                write!(f, "entry point returned {status}")
            }
            Self::SyscallEnumerationFailed { reason } => {
                write!(f, "syscall enumeration failed: {reason}")
            }
            Self::SyscallNotFound { name } => {
                write!(f, "syscall not found: {name}")
            }
            Self::SyscallFailed { name, status } => {
                write!(f, "syscall {name} failed with status {status:#x}")
            }
            Self::NtdllNotFound => {
                write!(f, "ntdll.dll not found in loaded modules")
            }
            Self::HookDetectionFailed { function, reason } => {
                write!(f, "hook detection failed for {function}: {reason}")
            }
            Self::UnhookFailed { function, reason } => {
                write!(f, "unhook failed for {function}: {reason}")
            }
            Self::IntegrityCheckFailed { function } => {
                write!(f, "integrity check failed for {function}")
            }
            Self::CleanCopyUnavailable => {
                write!(f, "clean copy of module not available for comparison")
            }
            Self::HookInstallFailed { target, reason } => {
                write!(f, "failed to install hook at {target:#x}: {reason}")
            }
            Self::HookRestoreFailed { target, reason } => {
                write!(f, "failed to restore hook at {target:#x}: {reason}")
            }
            Self::InstructionDecodeFailed { address, reason } => {
                write!(f, "instruction decode failed at {address:#x}: {reason}")
            }
            Self::TrampolineAllocationFailed { near, size } => {
                write!(f, "failed to allocate {size} bytes trampoline near {near:#x}")
            }
            Self::HookConflict { target, existing_type } => {
                write!(f, "hook conflict at {target:#x}: already hooked ({existing_type})")
            }
            Self::InsufficientHookSpace { target, available, required } => {
                write!(
                    f,
                    "insufficient hook space at {target:#x}: need {required} bytes, have {available}"
                )
            }
            Self::ReadFailed { address, size } => {
                write!(f, "failed to read {size} bytes at {address:#x}")
            }
            Self::WriteFailed { address, size } => {
                write!(f, "failed to write {size} bytes at {address:#x}")
            }
            Self::ProtectionChangeFailed { address, size } => {
                write!(
                    f,
                    "failed to change protection for {size} bytes at {address:#x}"
                )
            }
            Self::PatternParseFailed { reason } => {
                write!(f, "failed to parse pattern: {reason}")
            }
            Self::ProcessOpenFailed { pid, reason } => {
                write!(f, "failed to open process {pid}: {reason}")
            }
            Self::ProcessNotFound { pid } => {
                write!(f, "process {pid} not found")
            }
            Self::RemoteThreadFailed { reason } => {
                write!(f, "remote thread creation failed: {reason}")
            }
            Self::InjectionFailed { method, reason } => {
                write!(f, "injection via {method} failed: {reason}")
            }
            Self::RemoteModuleEnumFailed { reason } => {
                write!(f, "remote module enumeration failed: {reason}")
            }
            Self::HandleDuplicateFailed { reason } => {
                write!(f, "handle duplication failed: {reason}")
            }
            Self::SectionMappingFailed { reason } => {
                write!(f, "section mapping failed: {reason}")
            }
            Self::ApcQueueFailed { reason } => {
                write!(f, "APC queue operation failed: {reason}")
            }
            Self::ThreadContextFailed { reason } => {
                write!(f, "thread context operation failed: {reason}")
            }
            Self::ThreadSuspendResumeFailed { reason } => {
                write!(f, "thread suspend/resume failed: {reason}")
            }
            Self::GadgetNotFound { gadget_type } => {
                write!(f, "no suitable {gadget_type} gadget found")
            }
            Self::SpoofTrampolineFailed { reason } => {
                write!(f, "spoof trampoline failed: {reason}")
            }
            Self::StackSynthesisFailed { reason } => {
                write!(f, "stack frame synthesis failed: {reason}")
            }
            Self::Win32Error { code, context } => {
                write!(f, "Win32 error {code:#x} in {context}")
            }
        }
    }
}

/// result type alias using WraithError
pub type Result<T> = core::result::Result<T, WraithError>;

impl WraithError {
    /// create Win32Error from GetLastError
    pub fn from_last_error(context: &'static str) -> Self {
        // SAFETY: GetLastError is always safe to call
        let code = unsafe { GetLastError() };
        Self::Win32Error { code, context }
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}
