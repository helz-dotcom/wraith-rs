//! Gadget finder for legitimate return addresses
//!
//! Scans system modules (ntdll, kernel32, etc.) for code gadgets that can be
//! used as legitimate-looking return addresses for syscall spoofing.
//!
//! # Builder API
//!
//! The recommended way to find gadgets is using the builder pattern:
//!
//! ```ignore
//! // find jmp rbx gadgets
//! let gadgets = GadgetFinder::new()?
//!     .jmp(Register::Rbx)
//!     .in_module("ntdll.dll")
//!     .find()?;
//!
//! // find any jmp with wildcard
//! let gadgets = GadgetFinder::new()?
//!     .pattern("jmp ???")
//!     .in_module("kernel32.dll")
//!     .find()?;
//!
//! // find specific pattern
//! let gadgets = GadgetFinder::new()?
//!     .pattern("jmp rbx")
//!     .find_in_system_modules()?;
//! ```

use crate::error::{Result, WraithError};
use crate::navigation::ModuleQuery;
use crate::structures::Peb;

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::sync::OnceLock;

#[cfg(feature = "std")]
static GADGET_CACHE: OnceLock<Result<GadgetCache>> = OnceLock::new();

/// initialize the global gadget cache
#[cfg(feature = "std")]
pub fn init_global_cache() -> Result<()> {
    let result = GADGET_CACHE.get_or_init(GadgetCache::build);
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(WraithError::SyscallEnumerationFailed {
            reason: format!("failed to build gadget cache: {}", e),
        }),
    }
}

/// get global gadget cache reference
#[cfg(feature = "std")]
pub fn get_global_cache() -> Result<&'static GadgetCache> {
    let result = GADGET_CACHE.get_or_init(GadgetCache::build);
    match result {
        Ok(cache) => Ok(cache),
        Err(e) => Err(WraithError::SyscallEnumerationFailed {
            reason: format!("failed to get gadget cache: {}", e),
        }),
    }
}

/// type of gadget instruction sequence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GadgetType {
    /// jmp rbx - jump to address in rbx
    JmpRbx,
    /// jmp rax - jump to address in rax
    JmpRax,
    /// jmp rcx - jump to address in rcx
    JmpRcx,
    /// jmp rdx - jump to address in rdx
    JmpRdx,
    /// jmp r8 - jump to address in r8
    JmpR8,
    /// jmp r9 - jump to address in r9
    JmpR9,
    /// jmp [rbx] - indirect jump through rbx
    JmpIndirectRbx,
    /// jmp [rax] - indirect jump through rax
    JmpIndirectRax,
    /// call rbx - call address in rbx
    CallRbx,
    /// call rax - call address in rax
    CallRax,
    /// ret - simple return
    Ret,
    /// add rsp, N; ret - stack cleanup before return
    AddRspRet { offset: u8 },
    /// pop reg; ret - pop register then return
    PopRet { register: u8 },
    /// push rbx; ret - push rbx onto stack and return (for setting up returns)
    PushRbxRet,
}

impl GadgetType {
    /// get the bytes that make up this gadget type
    #[cfg(target_arch = "x86_64")]
    #[must_use]
    pub fn bytes(&self) -> &'static [u8] {
        match self {
            Self::JmpRbx => &[0xFF, 0xE3],        // jmp rbx
            Self::JmpRax => &[0xFF, 0xE0],        // jmp rax
            Self::JmpRcx => &[0xFF, 0xE1],        // jmp rcx
            Self::JmpRdx => &[0xFF, 0xE2],        // jmp rdx
            Self::JmpR8 => &[0x41, 0xFF, 0xE0],   // jmp r8
            Self::JmpR9 => &[0x41, 0xFF, 0xE1],   // jmp r9
            Self::JmpIndirectRbx => &[0xFF, 0x23], // jmp [rbx]
            Self::JmpIndirectRax => &[0xFF, 0x20], // jmp [rax]
            Self::CallRbx => &[0xFF, 0xD3],       // call rbx
            Self::CallRax => &[0xFF, 0xD0],       // call rax
            Self::Ret => &[0xC3],                 // ret
            Self::AddRspRet { .. } => &[],        // variable, handled separately
            Self::PopRet { .. } => &[],           // variable, handled separately
            Self::PushRbxRet => &[0x53, 0xC3],    // push rbx; ret
        }
    }

    /// get friendly name for this gadget type
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::JmpRbx => "jmp rbx",
            Self::JmpRax => "jmp rax",
            Self::JmpRcx => "jmp rcx",
            Self::JmpRdx => "jmp rdx",
            Self::JmpR8 => "jmp r8",
            Self::JmpR9 => "jmp r9",
            Self::JmpIndirectRbx => "jmp [rbx]",
            Self::JmpIndirectRax => "jmp [rax]",
            Self::CallRbx => "call rbx",
            Self::CallRax => "call rax",
            Self::Ret => "ret",
            Self::AddRspRet { offset: _ } => "add rsp, N; ret",
            Self::PopRet { .. } => "pop reg; ret",
            Self::PushRbxRet => "push rbx; ret",
        }
    }

    /// parse a gadget type from a pattern string
    /// supports wildcards: "jmp ???" matches any jmp reg
    #[must_use]
    pub fn from_pattern(pattern: &str) -> Option<GadgetPattern> {
        let pattern = pattern.trim().to_lowercase();
        let parts: Vec<&str> = pattern.split_whitespace().collect();

        if parts.is_empty() {
            return None;
        }

        match parts[0] {
            "jmp" => {
                if parts.len() < 2 {
                    return None;
                }
                let operand = parts[1];
                if operand == "???" {
                    Some(GadgetPattern::JmpAny)
                } else if let Some(reg) = Register::from_str(operand) {
                    if operand.starts_with('[') && operand.ends_with(']') {
                        Some(GadgetPattern::JmpIndirect(reg))
                    } else {
                        Some(GadgetPattern::Jmp(reg))
                    }
                } else if operand.starts_with('[') && operand.ends_with(']') {
                    let inner = &operand[1..operand.len()-1];
                    if inner == "???" {
                        Some(GadgetPattern::JmpIndirectAny)
                    } else if let Some(reg) = Register::from_str(inner) {
                        Some(GadgetPattern::JmpIndirect(reg))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            "call" => {
                if parts.len() < 2 {
                    return None;
                }
                let operand = parts[1];
                if operand == "???" {
                    Some(GadgetPattern::CallAny)
                } else if let Some(reg) = Register::from_str(operand) {
                    Some(GadgetPattern::Call(reg))
                } else {
                    None
                }
            }
            "ret" => Some(GadgetPattern::Ret),
            "pop" => {
                if parts.len() < 2 {
                    return Some(GadgetPattern::PopRetAny);
                }
                let operand = parts[1].trim_end_matches(';');
                if operand == "???" {
                    Some(GadgetPattern::PopRetAny)
                } else if let Some(reg) = Register::from_str(operand) {
                    Some(GadgetPattern::PopRet(reg))
                } else {
                    None
                }
            }
            "add" => {
                // "add rsp, ???; ret" or "add rsp, N; ret"
                if parts.len() >= 3 && parts[1].trim_end_matches(',') == "rsp" {
                    Some(GadgetPattern::AddRspRet)
                } else {
                    None
                }
            }
            "???" => {
                // wildcard instruction - match the operand
                if parts.len() < 2 {
                    Some(GadgetPattern::Any)
                } else {
                    let operand = parts[1];
                    if let Some(reg) = Register::from_str(operand) {
                        Some(GadgetPattern::AnyWithReg(reg))
                    } else {
                        Some(GadgetPattern::Any)
                    }
                }
            }
            _ => None,
        }
    }
}

/// x86-64 registers for gadget operands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    /// parse register from string
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rax" => Some(Self::Rax),
            "rbx" => Some(Self::Rbx),
            "rcx" => Some(Self::Rcx),
            "rdx" => Some(Self::Rdx),
            "rsi" => Some(Self::Rsi),
            "rdi" => Some(Self::Rdi),
            "rbp" => Some(Self::Rbp),
            "rsp" => Some(Self::Rsp),
            "r8" => Some(Self::R8),
            "r9" => Some(Self::R9),
            "r10" => Some(Self::R10),
            "r11" => Some(Self::R11),
            "r12" => Some(Self::R12),
            "r13" => Some(Self::R13),
            "r14" => Some(Self::R14),
            "r15" => Some(Self::R15),
            _ => None,
        }
    }

    /// get the register name
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rbx => "rbx",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::Rbp => "rbp",
            Self::Rsp => "rsp",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
        }
    }
}

/// pattern for gadget matching (supports wildcards)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GadgetPattern {
    /// jmp reg
    Jmp(Register),
    /// jmp [reg]
    JmpIndirect(Register),
    /// any jmp (wildcard)
    JmpAny,
    /// any jmp [reg] (wildcard)
    JmpIndirectAny,
    /// call reg
    Call(Register),
    /// any call (wildcard)
    CallAny,
    /// ret
    Ret,
    /// add rsp, N; ret
    AddRspRet,
    /// pop reg; ret
    PopRet(Register),
    /// any pop; ret
    PopRetAny,
    /// match any gadget
    Any,
    /// match any gadget using specific register
    AnyWithReg(Register),
}

impl GadgetPattern {
    /// check if a gadget type matches this pattern
    #[must_use]
    pub fn matches(&self, gadget: &GadgetType) -> bool {
        match self {
            Self::Jmp(reg) => match (reg, gadget) {
                (Register::Rax, GadgetType::JmpRax) => true,
                (Register::Rbx, GadgetType::JmpRbx) => true,
                (Register::Rcx, GadgetType::JmpRcx) => true,
                (Register::Rdx, GadgetType::JmpRdx) => true,
                (Register::R8, GadgetType::JmpR8) => true,
                (Register::R9, GadgetType::JmpR9) => true,
                _ => false,
            },
            Self::JmpIndirect(reg) => match (reg, gadget) {
                (Register::Rax, GadgetType::JmpIndirectRax) => true,
                (Register::Rbx, GadgetType::JmpIndirectRbx) => true,
                _ => false,
            },
            Self::JmpAny => matches!(
                gadget,
                GadgetType::JmpRax
                    | GadgetType::JmpRbx
                    | GadgetType::JmpRcx
                    | GadgetType::JmpRdx
                    | GadgetType::JmpR8
                    | GadgetType::JmpR9
            ),
            Self::JmpIndirectAny => matches!(
                gadget,
                GadgetType::JmpIndirectRax | GadgetType::JmpIndirectRbx
            ),
            Self::Call(reg) => match (reg, gadget) {
                (Register::Rax, GadgetType::CallRax) => true,
                (Register::Rbx, GadgetType::CallRbx) => true,
                _ => false,
            },
            Self::CallAny => matches!(gadget, GadgetType::CallRax | GadgetType::CallRbx),
            Self::Ret => matches!(gadget, GadgetType::Ret),
            Self::AddRspRet => matches!(gadget, GadgetType::AddRspRet { .. }),
            Self::PopRet(reg) => {
                if let GadgetType::PopRet { register } = gadget {
                    Self::reg_index(*reg) == Some(*register)
                } else {
                    false
                }
            }
            Self::PopRetAny => matches!(gadget, GadgetType::PopRet { .. }),
            Self::Any => true,
            Self::AnyWithReg(reg) => Self::gadget_uses_reg(gadget, *reg),
        }
    }

    fn reg_index(reg: Register) -> Option<u8> {
        match reg {
            Register::Rax => Some(0),
            Register::Rcx => Some(1),
            Register::Rdx => Some(2),
            Register::Rbx => Some(3),
            Register::Rsp => Some(4),
            Register::Rbp => Some(5),
            Register::Rsi => Some(6),
            Register::Rdi => Some(7),
            Register::R8 => Some(8),
            Register::R9 => Some(9),
            Register::R10 => Some(10),
            Register::R11 => Some(11),
            Register::R12 => Some(12),
            Register::R13 => Some(13),
            Register::R14 => Some(14),
            Register::R15 => Some(15),
        }
    }

    fn gadget_uses_reg(gadget: &GadgetType, reg: Register) -> bool {
        match (gadget, reg) {
            (GadgetType::JmpRax | GadgetType::JmpIndirectRax | GadgetType::CallRax, Register::Rax) => true,
            (GadgetType::JmpRbx | GadgetType::JmpIndirectRbx | GadgetType::CallRbx | GadgetType::PushRbxRet, Register::Rbx) => true,
            (GadgetType::JmpRcx, Register::Rcx) => true,
            (GadgetType::JmpRdx, Register::Rdx) => true,
            (GadgetType::JmpR8, Register::R8) => true,
            (GadgetType::JmpR9, Register::R9) => true,
            (GadgetType::PopRet { register }, _) => Self::reg_index(reg) == Some(*register),
            _ => false,
        }
    }

    /// get all concrete gadget types matching this pattern
    #[must_use]
    pub fn matching_types(&self) -> Vec<GadgetType> {
        match self {
            Self::Jmp(reg) => match reg {
                Register::Rax => vec![GadgetType::JmpRax],
                Register::Rbx => vec![GadgetType::JmpRbx],
                Register::Rcx => vec![GadgetType::JmpRcx],
                Register::Rdx => vec![GadgetType::JmpRdx],
                Register::R8 => vec![GadgetType::JmpR8],
                Register::R9 => vec![GadgetType::JmpR9],
                _ => vec![],
            },
            Self::JmpIndirect(reg) => match reg {
                Register::Rax => vec![GadgetType::JmpIndirectRax],
                Register::Rbx => vec![GadgetType::JmpIndirectRbx],
                _ => vec![],
            },
            Self::JmpAny => vec![
                GadgetType::JmpRax,
                GadgetType::JmpRbx,
                GadgetType::JmpRcx,
                GadgetType::JmpRdx,
                GadgetType::JmpR8,
                GadgetType::JmpR9,
            ],
            Self::JmpIndirectAny => vec![GadgetType::JmpIndirectRax, GadgetType::JmpIndirectRbx],
            Self::Call(reg) => match reg {
                Register::Rax => vec![GadgetType::CallRax],
                Register::Rbx => vec![GadgetType::CallRbx],
                _ => vec![],
            },
            Self::CallAny => vec![GadgetType::CallRax, GadgetType::CallRbx],
            Self::Ret => vec![GadgetType::Ret],
            Self::AddRspRet => vec![], // handled specially (variable bytes)
            Self::PopRet(_) => vec![], // handled specially (variable bytes)
            Self::PopRetAny => vec![], // handled specially (variable bytes)
            Self::Any => vec![
                GadgetType::JmpRax,
                GadgetType::JmpRbx,
                GadgetType::JmpRcx,
                GadgetType::JmpRdx,
                GadgetType::JmpR8,
                GadgetType::JmpR9,
                GadgetType::JmpIndirectRax,
                GadgetType::JmpIndirectRbx,
                GadgetType::CallRax,
                GadgetType::CallRbx,
                GadgetType::Ret,
                GadgetType::PushRbxRet,
            ],
            Self::AnyWithReg(reg) => {
                let mut types = vec![];
                for t in [
                    GadgetType::JmpRax,
                    GadgetType::JmpRbx,
                    GadgetType::JmpRcx,
                    GadgetType::JmpRdx,
                    GadgetType::JmpR8,
                    GadgetType::JmpR9,
                    GadgetType::JmpIndirectRax,
                    GadgetType::JmpIndirectRbx,
                    GadgetType::CallRax,
                    GadgetType::CallRbx,
                    GadgetType::PushRbxRet,
                ] {
                    if Self::gadget_uses_reg(&t, *reg) {
                        types.push(t);
                    }
                }
                types
            }
        }
    }
}

/// a found gadget with its location and type
#[derive(Debug, Clone)]
pub struct Gadget {
    /// absolute address of the gadget
    pub address: usize,
    /// type of gadget
    pub gadget_type: GadgetType,
    /// module containing this gadget
    pub module_name: String,
    /// offset within the module
    pub module_offset: usize,
    /// is this in a system module (more trustworthy)
    pub is_system_module: bool,
}

impl Gadget {
    /// check if gadget is still valid (bytes haven't changed)
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let bytes = self.gadget_type.bytes();
        if bytes.is_empty() {
            return true; // variable-length gadgets need special handling
        }

        // SAFETY: we're reading from a previously-validated code address
        let actual = unsafe { core::slice::from_raw_parts(self.address as *const u8, bytes.len()) };
        actual == bytes
    }
}

/// jmp-type gadget (for jumping to syscall stub)
#[derive(Debug, Clone)]
pub struct JmpGadget {
    pub gadget: Gadget,
}

impl JmpGadget {
    #[must_use]
    pub fn address(&self) -> usize {
        self.gadget.address
    }
}

/// ret-type gadget (for return address spoofing)
#[derive(Debug, Clone)]
pub struct RetGadget {
    pub gadget: Gadget,
    /// number of bytes the ret pops (for add rsp, N; ret patterns)
    pub stack_adjustment: usize,
}

impl RetGadget {
    #[must_use]
    pub fn address(&self) -> usize {
        self.gadget.address
    }
}

/// cache of found gadgets organized by type and module
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct GadgetCache {
    /// gadgets indexed by type
    by_type: HashMap<GadgetType, Vec<Gadget>>,
    /// gadgets indexed by module name (lowercase)
    by_module: HashMap<String, Vec<Gadget>>,
    /// preferred jmp rbx gadget in ntdll
    preferred_jmp_rbx: Option<Gadget>,
    /// preferred jmp rax gadget in ntdll
    preferred_jmp_rax: Option<Gadget>,
    /// preferred ret gadget in kernel32
    preferred_ret: Option<Gadget>,
}

#[cfg(feature = "std")]
impl GadgetCache {
    /// build gadget cache by scanning system modules
    pub fn build() -> Result<Self> {
        let finder = GadgetFinder::new()?;

        let mut by_type: HashMap<GadgetType, Vec<Gadget>> = HashMap::new();
        let mut by_module: HashMap<String, Vec<Gadget>> = HashMap::new();

        // scan key system modules
        let modules = ["ntdll.dll", "kernel32.dll", "kernelbase.dll"];

        for module_name in modules {
            if let Ok(gadgets) = finder.scan_module_all(module_name) {
                for gadget in gadgets {
                    let module_lower = gadget.module_name.to_lowercase();

                    by_type
                        .entry(gadget.gadget_type)
                        .or_default()
                        .push(gadget.clone());

                    by_module.entry(module_lower).or_default().push(gadget);
                }
            }
        }

        // find preferred gadgets
        let preferred_jmp_rbx = by_type
            .get(&GadgetType::JmpRbx)
            .and_then(|v| v.iter().find(|g| g.module_name.eq_ignore_ascii_case("ntdll.dll")))
            .cloned();

        let preferred_jmp_rax = by_type
            .get(&GadgetType::JmpRax)
            .and_then(|v| v.iter().find(|g| g.module_name.eq_ignore_ascii_case("ntdll.dll")))
            .cloned();

        let preferred_ret = by_type
            .get(&GadgetType::Ret)
            .and_then(|v| {
                v.iter()
                    .find(|g| g.module_name.eq_ignore_ascii_case("kernel32.dll"))
            })
            .cloned();

        Ok(Self {
            by_type,
            by_module,
            preferred_jmp_rbx,
            preferred_jmp_rax,
            preferred_ret,
        })
    }

    /// get preferred jmp rbx gadget (in ntdll)
    #[must_use]
    pub fn jmp_rbx(&self) -> Option<&Gadget> {
        self.preferred_jmp_rbx.as_ref()
    }

    /// get preferred jmp rax gadget (in ntdll)
    #[must_use]
    pub fn jmp_rax(&self) -> Option<&Gadget> {
        self.preferred_jmp_rax.as_ref()
    }

    /// get preferred ret gadget (in kernel32)
    #[must_use]
    pub fn ret_gadget(&self) -> Option<&Gadget> {
        self.preferred_ret.as_ref()
    }

    /// get all gadgets of a specific type
    #[must_use]
    pub fn get_by_type(&self, gadget_type: GadgetType) -> &[Gadget] {
        self.by_type.get(&gadget_type).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// get all gadgets in a specific module
    #[must_use]
    pub fn get_by_module(&self, module_name: &str) -> &[Gadget] {
        self.by_module
            .get(&module_name.to_lowercase())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// get first available jmp gadget (tries rbx, then rax)
    #[must_use]
    pub fn any_jmp_gadget(&self) -> Option<&Gadget> {
        self.preferred_jmp_rbx
            .as_ref()
            .or(self.preferred_jmp_rax.as_ref())
            .or_else(|| {
                self.by_type
                    .get(&GadgetType::JmpRbx)
                    .and_then(|v| v.first())
            })
            .or_else(|| {
                self.by_type
                    .get(&GadgetType::JmpRax)
                    .and_then(|v| v.first())
            })
    }

    /// search gadgets using a pattern
    #[must_use]
    pub fn find_by_pattern(&self, pattern: &GadgetPattern) -> Vec<&Gadget> {
        let mut results = Vec::new();
        for (gadget_type, gadgets) in &self.by_type {
            if pattern.matches(gadget_type) {
                results.extend(gadgets.iter());
            }
        }
        results
    }
}

/// scanner for finding gadgets in loaded modules
pub struct GadgetFinder {
    peb: Peb,
}

impl GadgetFinder {
    /// create new gadget finder
    pub fn new() -> Result<Self> {
        Ok(Self {
            peb: Peb::current()?,
        })
    }

    /// find all jmp rbx gadgets in a module
    pub fn find_jmp_rbx(&self, module_name: &str) -> Result<Vec<JmpGadget>> {
        self.find_gadgets_of_type(module_name, GadgetType::JmpRbx)
            .map(|gadgets| gadgets.into_iter().map(|g| JmpGadget { gadget: g }).collect())
    }

    /// find all jmp rax gadgets in a module
    pub fn find_jmp_rax(&self, module_name: &str) -> Result<Vec<JmpGadget>> {
        self.find_gadgets_of_type(module_name, GadgetType::JmpRax)
            .map(|gadgets| gadgets.into_iter().map(|g| JmpGadget { gadget: g }).collect())
    }

    /// find all ret gadgets in a module
    pub fn find_ret(&self, module_name: &str) -> Result<Vec<RetGadget>> {
        self.find_gadgets_of_type(module_name, GadgetType::Ret)
            .map(|gadgets| {
                gadgets
                    .into_iter()
                    .map(|g| RetGadget {
                        gadget: g,
                        stack_adjustment: 0,
                    })
                    .collect()
            })
    }

    /// find gadgets of a specific type in a module
    pub fn find_gadgets_of_type(
        &self,
        module_name: &str,
        gadget_type: GadgetType,
    ) -> Result<Vec<Gadget>> {
        let query = ModuleQuery::new(&self.peb);
        let module = query.find_by_name(module_name)?;

        let bytes = gadget_type.bytes();
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        let base = module.base();
        let size = module.size();
        let name = module.name();
        let is_system = is_system_module(&name);

        // scan for the byte pattern
        // SAFETY: module memory is mapped and readable
        let data = unsafe { core::slice::from_raw_parts(base as *const u8, size) };

        let mut gadgets = Vec::new();
        let pattern_len = bytes.len();

        // scan for gadget bytes
        for offset in 0..=(size.saturating_sub(pattern_len)) {
            if &data[offset..offset + pattern_len] == bytes {
                gadgets.push(Gadget {
                    address: base + offset,
                    gadget_type,
                    module_name: name.clone(),
                    module_offset: offset,
                    is_system_module: is_system,
                });
            }
        }

        Ok(gadgets)
    }

    /// find add rsp, N; ret gadgets (for stack cleanup)
    pub fn find_add_rsp_ret(&self, module_name: &str) -> Result<Vec<RetGadget>> {
        let query = ModuleQuery::new(&self.peb);
        let module = query.find_by_name(module_name)?;

        let base = module.base();
        let size = module.size();
        let name = module.name();
        let is_system = is_system_module(&name);

        // SAFETY: module memory is mapped and readable
        let data = unsafe { core::slice::from_raw_parts(base as *const u8, size) };

        let mut gadgets = Vec::new();

        // patterns for add rsp, imm8; ret
        // 48 83 C4 XX C3 = add rsp, XX; ret (5 bytes)
        for offset in 0..=(size.saturating_sub(5)) {
            if data[offset] == 0x48
                && data[offset + 1] == 0x83
                && data[offset + 2] == 0xC4
                && data[offset + 4] == 0xC3
            {
                let stack_adj = data[offset + 3] as usize;
                gadgets.push(RetGadget {
                    gadget: Gadget {
                        address: base + offset,
                        gadget_type: GadgetType::AddRspRet {
                            offset: data[offset + 3],
                        },
                        module_name: name.clone(),
                        module_offset: offset,
                        is_system_module: is_system,
                    },
                    stack_adjustment: stack_adj,
                });
            }
        }

        // also look for add rsp, imm32; ret
        // 48 81 C4 XX XX XX XX C3 = add rsp, XXXXXXXX; ret (8 bytes)
        for offset in 0..=(size.saturating_sub(8)) {
            if data[offset] == 0x48
                && data[offset + 1] == 0x81
                && data[offset + 2] == 0xC4
                && data[offset + 7] == 0xC3
            {
                let stack_adj = u32::from_le_bytes([
                    data[offset + 3],
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                ]) as usize;

                gadgets.push(RetGadget {
                    gadget: Gadget {
                        address: base + offset,
                        gadget_type: GadgetType::AddRspRet {
                            offset: 0, // too large for u8
                        },
                        module_name: name.clone(),
                        module_offset: offset,
                        is_system_module: is_system,
                    },
                    stack_adjustment: stack_adj,
                });
            }
        }

        Ok(gadgets)
    }

    /// find pop reg; ret gadgets
    pub fn find_pop_ret(&self, module_name: &str) -> Result<Vec<RetGadget>> {
        let query = ModuleQuery::new(&self.peb);
        let module = query.find_by_name(module_name)?;

        let base = module.base();
        let size = module.size();
        let name = module.name();
        let is_system = is_system_module(&name);

        // SAFETY: module memory is mapped and readable
        let data = unsafe { core::slice::from_raw_parts(base as *const u8, size) };

        let mut gadgets = Vec::new();

        // pop rax; ret = 58 C3
        // pop rcx; ret = 59 C3
        // pop rdx; ret = 5A C3
        // pop rbx; ret = 5B C3
        // pop rsp; ret = 5C C3 (dangerous, skip)
        // pop rbp; ret = 5D C3
        // pop rsi; ret = 5E C3
        // pop rdi; ret = 5F C3
        for offset in 0..=(size.saturating_sub(2)) {
            let first = data[offset];
            if (0x58..=0x5F).contains(&first) && first != 0x5C && data[offset + 1] == 0xC3 {
                gadgets.push(RetGadget {
                    gadget: Gadget {
                        address: base + offset,
                        gadget_type: GadgetType::PopRet {
                            register: first - 0x58,
                        },
                        module_name: name.clone(),
                        module_offset: offset,
                        is_system_module: is_system,
                    },
                    stack_adjustment: 8, // one pop
                });
            }
        }

        // also check for REX.W pop; ret (pop r8-r15)
        // 41 58 C3 = pop r8; ret
        // 41 59 C3 = pop r9; ret
        // etc.
        for offset in 0..=(size.saturating_sub(3)) {
            if data[offset] == 0x41
                && (0x58..=0x5F).contains(&data[offset + 1])
                && data[offset + 1] != 0x5C
                && data[offset + 2] == 0xC3
            {
                gadgets.push(RetGadget {
                    gadget: Gadget {
                        address: base + offset,
                        gadget_type: GadgetType::PopRet {
                            register: data[offset + 1] - 0x58 + 8,
                        },
                        module_name: name.clone(),
                        module_offset: offset,
                        is_system_module: is_system,
                    },
                    stack_adjustment: 8,
                });
            }
        }

        Ok(gadgets)
    }

    /// scan a module for all gadget types
    pub fn scan_module_all(&self, module_name: &str) -> Result<Vec<Gadget>> {
        let mut all_gadgets = Vec::new();

        // basic jmp gadgets
        for gadget_type in [
            GadgetType::JmpRbx,
            GadgetType::JmpRax,
            GadgetType::JmpRcx,
            GadgetType::JmpRdx,
            GadgetType::CallRbx,
            GadgetType::CallRax,
            GadgetType::Ret,
            GadgetType::PushRbxRet,
        ] {
            if let Ok(gadgets) = self.find_gadgets_of_type(module_name, gadget_type) {
                all_gadgets.extend(gadgets);
            }
        }

        // add rsp, N; ret gadgets
        if let Ok(ret_gadgets) = self.find_add_rsp_ret(module_name) {
            all_gadgets.extend(ret_gadgets.into_iter().map(|r| r.gadget));
        }

        // pop; ret gadgets
        if let Ok(pop_gadgets) = self.find_pop_ret(module_name) {
            all_gadgets.extend(pop_gadgets.into_iter().map(|r| r.gadget));
        }

        Ok(all_gadgets)
    }

    /// find the best jmp gadget for syscall spoofing
    /// prefers ntdll > kernelbase > kernel32
    pub fn find_best_jmp_gadget(&self) -> Result<JmpGadget> {
        // try ntdll first (most legitimate for syscalls)
        if let Ok(gadgets) = self.find_jmp_rbx("ntdll.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        if let Ok(gadgets) = self.find_jmp_rax("ntdll.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        // try kernelbase
        if let Ok(gadgets) = self.find_jmp_rbx("kernelbase.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        // try kernel32
        if let Ok(gadgets) = self.find_jmp_rbx("kernel32.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        Err(WraithError::SyscallEnumerationFailed {
            reason: "no suitable jmp gadget found".into(),
        })
    }

    /// find a ret gadget that looks legitimate
    pub fn find_best_ret_gadget(&self) -> Result<RetGadget> {
        // prefer kernel32 ret gadgets (look like normal API returns)
        if let Ok(gadgets) = self.find_ret("kernel32.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        if let Ok(gadgets) = self.find_ret("kernelbase.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        if let Ok(gadgets) = self.find_ret("ntdll.dll") {
            if let Some(g) = gadgets.into_iter().next() {
                return Ok(g);
            }
        }

        Err(WraithError::SyscallEnumerationFailed {
            reason: "no suitable ret gadget found".into(),
        })
    }

    // ========== Builder API ==========

    /// start building a jmp gadget search
    ///
    /// # Example
    /// ```ignore
    /// let gadgets = GadgetFinder::new()?
    ///     .jmp(Register::Rbx)
    ///     .in_module("ntdll.dll")
    ///     .find()?;
    /// ```
    #[must_use]
    pub fn jmp(self, register: Register) -> GadgetSearch {
        GadgetSearch {
            finder: self,
            pattern: GadgetPattern::Jmp(register),
            module: None,
            system_modules_only: false,
        }
    }

    /// start building a jmp [reg] (indirect) gadget search
    #[must_use]
    pub fn jmp_indirect(self, register: Register) -> GadgetSearch {
        GadgetSearch {
            finder: self,
            pattern: GadgetPattern::JmpIndirect(register),
            module: None,
            system_modules_only: false,
        }
    }

    /// start building a call gadget search
    #[must_use]
    pub fn call(self, register: Register) -> GadgetSearch {
        GadgetSearch {
            finder: self,
            pattern: GadgetPattern::Call(register),
            module: None,
            system_modules_only: false,
        }
    }

    /// start building a ret gadget search
    #[must_use]
    pub fn ret(self) -> GadgetSearch {
        GadgetSearch {
            finder: self,
            pattern: GadgetPattern::Ret,
            module: None,
            system_modules_only: false,
        }
    }

    /// start building a pop; ret gadget search
    #[must_use]
    pub fn pop_ret(self, register: Register) -> GadgetSearch {
        GadgetSearch {
            finder: self,
            pattern: GadgetPattern::PopRet(register),
            module: None,
            system_modules_only: false,
        }
    }

    /// start building a search using a pattern string
    ///
    /// # Supported patterns
    /// - `"jmp rbx"` - specific jmp
    /// - `"jmp ???"` - any jmp reg (wildcard)
    /// - `"jmp [rax]"` - indirect jmp
    /// - `"call ???"` - any call
    /// - `"ret"` - simple return
    /// - `"pop ???; ret"` - any pop then ret
    /// - `"??? rbx"` - any instruction using rbx
    ///
    /// # Example
    /// ```ignore
    /// let gadgets = GadgetFinder::new()?
    ///     .pattern("jmp ???")
    ///     .in_module("ntdll.dll")
    ///     .find()?;
    /// ```
    pub fn pattern(self, pattern_str: &str) -> Result<GadgetSearch> {
        let pattern = GadgetType::from_pattern(pattern_str).ok_or_else(|| {
            WraithError::PatternParseFailed {
                reason: format!("invalid gadget pattern: {}", pattern_str),
            }
        })?;

        Ok(GadgetSearch {
            finder: self,
            pattern,
            module: None,
            system_modules_only: false,
        })
    }

    /// find gadgets matching a pattern in a module
    pub fn find_by_pattern(
        &self,
        module_name: &str,
        pattern: &GadgetPattern,
    ) -> Result<Vec<Gadget>> {
        let mut results = Vec::new();

        // handle concrete gadget types
        for gadget_type in pattern.matching_types() {
            if let Ok(gadgets) = self.find_gadgets_of_type(module_name, gadget_type) {
                results.extend(gadgets);
            }
        }

        // handle variable-length patterns specially
        match pattern {
            GadgetPattern::AddRspRet => {
                if let Ok(ret_gadgets) = self.find_add_rsp_ret(module_name) {
                    results.extend(ret_gadgets.into_iter().map(|r| r.gadget));
                }
            }
            GadgetPattern::PopRet(reg) => {
                if let Ok(pop_gadgets) = self.find_pop_ret(module_name) {
                    let reg_idx = GadgetPattern::reg_index(*reg);
                    results.extend(
                        pop_gadgets
                            .into_iter()
                            .filter(|g| {
                                if let GadgetType::PopRet { register } = g.gadget.gadget_type {
                                    reg_idx == Some(register)
                                } else {
                                    false
                                }
                            })
                            .map(|r| r.gadget),
                    );
                }
            }
            GadgetPattern::PopRetAny => {
                if let Ok(pop_gadgets) = self.find_pop_ret(module_name) {
                    results.extend(pop_gadgets.into_iter().map(|r| r.gadget));
                }
            }
            _ => {}
        }

        Ok(results)
    }
}

/// builder for gadget searches with fluent API
pub struct GadgetSearch {
    finder: GadgetFinder,
    pattern: GadgetPattern,
    module: Option<String>,
    system_modules_only: bool,
}

impl GadgetSearch {
    /// search only in a specific module
    #[must_use]
    pub fn in_module(mut self, module_name: &str) -> Self {
        self.module = Some(module_name.to_string());
        self
    }

    /// search only in system modules (ntdll, kernel32, etc.)
    #[must_use]
    pub fn system_modules_only(mut self) -> Self {
        self.system_modules_only = true;
        self
    }

    /// execute the search and return matching gadgets
    pub fn find(self) -> Result<Vec<Gadget>> {
        if let Some(module_name) = &self.module {
            self.finder.find_by_pattern(module_name, &self.pattern)
        } else {
            self.find_in_system_modules()
        }
    }

    /// search in all common system modules
    pub fn find_in_system_modules(self) -> Result<Vec<Gadget>> {
        let modules = ["ntdll.dll", "kernel32.dll", "kernelbase.dll"];
        let mut all_gadgets = Vec::new();

        for module_name in modules {
            if let Ok(gadgets) = self.finder.find_by_pattern(module_name, &self.pattern) {
                all_gadgets.extend(gadgets);
            }
        }

        if all_gadgets.is_empty() {
            Err(WraithError::GadgetNotFound {
                gadget_type: "matching pattern",
            })
        } else {
            Ok(all_gadgets)
        }
    }

    /// get the first matching gadget (convenience method)
    pub fn find_first(self) -> Result<Gadget> {
        self.find()?
            .into_iter()
            .next()
            .ok_or(WraithError::GadgetNotFound {
                gadget_type: "matching pattern",
            })
    }

    /// get the underlying pattern
    #[must_use]
    pub fn get_pattern(&self) -> &GadgetPattern {
        &self.pattern
    }
}

/// check if a module is a system module
fn is_system_module(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == "ntdll.dll"
        || lower == "kernel32.dll"
        || lower == "kernelbase.dll"
        || lower == "user32.dll"
        || lower == "gdi32.dll"
        || lower == "advapi32.dll"
        || lower == "msvcrt.dll"
        || lower == "ws2_32.dll"
        || lower == "ole32.dll"
        || lower == "combase.dll"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_jmp_rbx_ntdll() {
        let finder = GadgetFinder::new().expect("should create finder");
        let gadgets = finder.find_jmp_rbx("ntdll.dll").expect("should find gadgets");

        // ntdll should have jmp rbx gadgets
        assert!(!gadgets.is_empty(), "should find jmp rbx gadgets in ntdll");

        // verify first gadget is valid
        let first = &gadgets[0];
        assert!(first.gadget.is_valid(), "gadget should be valid");
        assert!(first.gadget.is_system_module, "should be system module");
    }

    #[test]
    fn test_find_ret_gadgets() {
        let finder = GadgetFinder::new().expect("should create finder");
        let gadgets = finder.find_ret("kernel32.dll").expect("should find gadgets");

        // kernel32 should have many ret gadgets
        assert!(!gadgets.is_empty(), "should find ret gadgets in kernel32");

        // verify gadget is valid
        let first = &gadgets[0];
        assert!(first.gadget.is_valid(), "gadget should be valid");
    }

    #[test]
    fn test_find_add_rsp_ret() {
        let finder = GadgetFinder::new().expect("should create finder");

        if let Ok(gadgets) = finder.find_add_rsp_ret("ntdll.dll") {
            // just check we can find them without crashing
            for g in gadgets.iter().take(5) {
                assert!(g.stack_adjustment > 0, "should have stack adjustment");
            }
        }
    }

    #[test]
    fn test_gadget_cache() {
        let cache = GadgetCache::build().expect("should build cache");

        // should have found some gadgets
        assert!(cache.jmp_rbx().is_some() || cache.jmp_rax().is_some());
    }

    #[test]
    fn test_best_jmp_gadget() {
        let finder = GadgetFinder::new().expect("should create finder");
        let gadget = finder.find_best_jmp_gadget().expect("should find gadget");

        assert!(gadget.gadget.is_valid(), "best gadget should be valid");
    }
}
