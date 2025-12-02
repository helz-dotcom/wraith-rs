//! Gadget finder for legitimate return addresses
//!
//! Scans system modules (ntdll, kernel32, etc.) for code gadgets that can be
//! used as legitimate-looking return addresses for syscall spoofing.

use crate::error::{Result, WraithError};
use crate::navigation::ModuleQuery;
use crate::structures::Peb;
use std::collections::HashMap;
use std::sync::OnceLock;

/// global gadget cache
static GADGET_CACHE: OnceLock<Result<GadgetCache>> = OnceLock::new();

/// initialize the global gadget cache
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
    pub fn is_valid(&self) -> bool {
        let bytes = self.gadget_type.bytes();
        if bytes.is_empty() {
            return true; // variable-length gadgets need special handling
        }

        // SAFETY: we're reading from a previously-validated code address
        let actual = unsafe { std::slice::from_raw_parts(self.address as *const u8, bytes.len()) };
        actual == bytes
    }
}

/// jmp-type gadget (for jumping to syscall stub)
#[derive(Debug, Clone)]
pub struct JmpGadget {
    pub gadget: Gadget,
}

impl JmpGadget {
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
    pub fn address(&self) -> usize {
        self.gadget.address
    }
}

/// cache of found gadgets organized by type and module
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
    pub fn jmp_rbx(&self) -> Option<&Gadget> {
        self.preferred_jmp_rbx.as_ref()
    }

    /// get preferred jmp rax gadget (in ntdll)
    pub fn jmp_rax(&self) -> Option<&Gadget> {
        self.preferred_jmp_rax.as_ref()
    }

    /// get preferred ret gadget (in kernel32)
    pub fn ret_gadget(&self) -> Option<&Gadget> {
        self.preferred_ret.as_ref()
    }

    /// get all gadgets of a specific type
    pub fn get_by_type(&self, gadget_type: GadgetType) -> &[Gadget] {
        self.by_type.get(&gadget_type).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// get all gadgets in a specific module
    pub fn get_by_module(&self, module_name: &str) -> &[Gadget] {
        self.by_module
            .get(&module_name.to_lowercase())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// get first available jmp gadget (tries rbx, then rax)
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
        let data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };

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
        let data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };

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
        let data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };

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
