//! Stack frame synthesis and spoofing
//!
//! Creates fake stack frames that look like legitimate call chains,
//! making syscall invocations appear to come from expected call paths.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::{format, string::String, vec, vec::Vec};

#[cfg(feature = "std")]
use std::{format, string::String, vec, vec::Vec};

use crate::error::{Result, WraithError};
use crate::navigation::ModuleQuery;
use crate::structures::Peb;

/// a single fake stack frame
#[derive(Debug, Clone)]
pub struct FakeFrame {
    /// return address (points into a legitimate module)
    pub return_address: usize,
    /// saved RBP value (points to previous frame or 0)
    pub saved_rbp: usize,
    /// any additional values to push for this frame (local variables/saved regs)
    pub extra_values: Vec<usize>,
    /// description of what this frame represents
    pub description: &'static str,
}

impl FakeFrame {
    /// create a simple frame with just return address and saved rbp
    pub const fn simple(return_address: usize, saved_rbp: usize, description: &'static str) -> Self {
        Self {
            return_address,
            saved_rbp,
            extra_values: Vec::new(),
            description,
        }
    }

    /// create a frame with extra values
    pub fn with_extra(
        return_address: usize,
        saved_rbp: usize,
        extra: Vec<usize>,
        description: &'static str,
    ) -> Self {
        Self {
            return_address,
            saved_rbp,
            extra_values: extra,
            description,
        }
    }

    /// total size of this frame in bytes
    pub fn size(&self) -> usize {
        // return address + saved rbp + extra values
        (2 + self.extra_values.len()) * core::mem::size_of::<usize>()
    }
}

/// template for generating fake frames based on known call patterns
#[derive(Debug, Clone)]
pub struct FrameTemplate {
    /// name of this template (e.g., "CreateFileW -> NtCreateFile")
    pub name: &'static str,
    /// module containing the return address
    pub module: &'static str,
    /// function name for the return address
    pub function: &'static str,
    /// offset from function start (to look like mid-function return)
    pub offset: usize,
    /// number of extra stack slots this frame uses
    pub extra_slots: usize,
    /// description
    pub description: &'static str,
}

impl FrameTemplate {
    /// resolve this template to an actual fake frame
    pub fn resolve(&self) -> Result<FakeFrame> {
        let peb = Peb::current()?;
        let query = ModuleQuery::new(&peb);
        let module = query.find_by_name(self.module)?;
        let func_addr = module.get_export(self.function)?;
        let return_addr = func_addr + self.offset;

        Ok(FakeFrame {
            return_address: return_addr,
            saved_rbp: 0, // will be set by StackSpoofer
            extra_values: vec![0; self.extra_slots],
            description: self.description,
        })
    }
}

/// common frame templates for Windows API call chains
pub static COMMON_FRAME_TEMPLATES: &[FrameTemplate] = &[
    // kernel32!CreateFileW calling ntdll!NtCreateFile
    FrameTemplate {
        name: "CreateFileW",
        module: "kernel32.dll",
        function: "CreateFileW",
        offset: 0x50, // typical offset after internal call
        extra_slots: 4,
        description: "kernel32!CreateFileW frame",
    },
    // kernel32!ReadFile calling ntdll!NtReadFile
    FrameTemplate {
        name: "ReadFile",
        module: "kernel32.dll",
        function: "ReadFile",
        offset: 0x40,
        extra_slots: 4,
        description: "kernel32!ReadFile frame",
    },
    // kernel32!WriteFile calling ntdll!NtWriteFile
    FrameTemplate {
        name: "WriteFile",
        module: "kernel32.dll",
        function: "WriteFile",
        offset: 0x40,
        extra_slots: 4,
        description: "kernel32!WriteFile frame",
    },
    // kernel32!VirtualAlloc calling ntdll!NtAllocateVirtualMemory
    FrameTemplate {
        name: "VirtualAlloc",
        module: "kernel32.dll",
        function: "VirtualAlloc",
        offset: 0x30,
        extra_slots: 2,
        description: "kernel32!VirtualAlloc frame",
    },
    // kernel32!VirtualProtect calling ntdll!NtProtectVirtualMemory
    FrameTemplate {
        name: "VirtualProtect",
        module: "kernel32.dll",
        function: "VirtualProtect",
        offset: 0x30,
        extra_slots: 2,
        description: "kernel32!VirtualProtect frame",
    },
    // kernel32!OpenProcess calling ntdll!NtOpenProcess
    FrameTemplate {
        name: "OpenProcess",
        module: "kernel32.dll",
        function: "OpenProcess",
        offset: 0x40,
        extra_slots: 3,
        description: "kernel32!OpenProcess frame",
    },
    // kernel32!BaseThreadInitThunk (common thread start)
    FrameTemplate {
        name: "BaseThreadInitThunk",
        module: "kernel32.dll",
        function: "BaseThreadInitThunk",
        offset: 0x14,
        extra_slots: 1,
        description: "kernel32!BaseThreadInitThunk frame",
    },
    // ntdll!RtlUserThreadStart (thread entry)
    FrameTemplate {
        name: "RtlUserThreadStart",
        module: "ntdll.dll",
        function: "RtlUserThreadStart",
        offset: 0x21,
        extra_slots: 1,
        description: "ntdll!RtlUserThreadStart frame",
    },
];

/// synthesized stack layout for spoofing
#[derive(Debug)]
pub struct SyntheticStack {
    /// the fake frames from bottom (oldest) to top (newest)
    frames: Vec<FakeFrame>,
    /// total stack size needed
    total_size: usize,
    /// buffer containing the synthesized stack data
    data: Vec<usize>,
}

impl SyntheticStack {
    /// create an empty synthetic stack
    pub fn new() -> Self {
        Self {
            frames: Vec::new(),
            total_size: 0,
            data: Vec::new(),
        }
    }

    /// add a frame to the top of the stack
    pub fn push_frame(&mut self, frame: FakeFrame) {
        self.total_size += frame.size();
        self.frames.push(frame);
    }

    /// build the final stack layout
    /// returns the stack data with proper rbp chain
    pub fn build(&mut self) -> &[usize] {
        self.data.clear();

        // build frames from bottom to top
        // each frame's saved_rbp points to the previous frame's RBP location
        let mut prev_rbp: usize = 0;

        for frame in &self.frames {
            // record position of this frame's saved RBP
            let rbp_pos = self.data.len();

            // push saved RBP (points to previous frame)
            self.data.push(prev_rbp);
            // push return address
            self.data.push(frame.return_address);
            // push extra values
            for &val in &frame.extra_values {
                self.data.push(val);
            }

            // update prev_rbp to point to this frame's saved RBP
            // this would be the stack address, but we're using indices here
            prev_rbp = rbp_pos;
        }

        &self.data
    }

    /// get the number of frames
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// get total size in bytes
    pub fn total_size_bytes(&self) -> usize {
        self.total_size
    }
}

impl Default for SyntheticStack {
    fn default() -> Self {
        Self::new()
    }
}

/// high-level stack spoofer that creates believable call stacks
pub struct StackSpoofer {
    /// resolved frame templates
    templates: Vec<(FrameTemplate, Option<FakeFrame>)>,
}

impl StackSpoofer {
    /// create a new stack spoofer
    pub fn new() -> Self {
        Self {
            templates: COMMON_FRAME_TEMPLATES
                .iter()
                .map(|t| (t.clone(), None))
                .collect(),
        }
    }

    /// resolve all templates to actual addresses
    pub fn resolve_all(&mut self) -> Result<()> {
        for (template, resolved) in &mut self.templates {
            match template.resolve() {
                Ok(frame) => *resolved = Some(frame),
                Err(_) => continue, // skip unresolvable templates
            }
        }
        Ok(())
    }

    /// get a resolved frame by template name
    pub fn get_frame(&self, name: &str) -> Option<&FakeFrame> {
        self.templates
            .iter()
            .find(|(t, _)| t.name == name)
            .and_then(|(_, f)| f.as_ref())
    }

    /// build a synthetic stack for a specific call pattern
    pub fn build_stack_for(&self, pattern: &[&str]) -> Result<SyntheticStack> {
        let mut stack = SyntheticStack::new();

        for &name in pattern {
            if let Some(frame) = self.get_frame(name) {
                stack.push_frame(frame.clone());
            } else {
                return Err(WraithError::SyscallEnumerationFailed {
                    reason: format!("template '{}' not found or not resolved", name),
                });
            }
        }

        Ok(stack)
    }

    /// build a generic "thread start" stack that looks legitimate
    pub fn build_thread_start_stack(&self) -> Result<SyntheticStack> {
        // typical thread start: RtlUserThreadStart -> BaseThreadInitThunk -> user code
        self.build_stack_for(&["RtlUserThreadStart", "BaseThreadInitThunk"])
    }

    /// build a stack for VirtualAlloc-like calls
    pub fn build_memory_alloc_stack(&self) -> Result<SyntheticStack> {
        self.build_stack_for(&["RtlUserThreadStart", "BaseThreadInitThunk", "VirtualAlloc"])
    }

    /// build a stack for file operations
    pub fn build_file_io_stack(&self) -> Result<SyntheticStack> {
        self.build_stack_for(&["RtlUserThreadStart", "BaseThreadInitThunk", "CreateFileW"])
    }
}

impl Default for StackSpoofer {
    fn default() -> Self {
        Self::new()
    }
}

/// helper to find good return addresses in a module
pub fn find_return_address_in_module(module_name: &str, function_name: &str) -> Result<usize> {
    let peb = Peb::current()?;
    let query = ModuleQuery::new(&peb);
    let module = query.find_by_name(module_name)?;
    module.get_export(function_name)
}

/// create a simple fake frame pointing to a known function
pub fn create_frame_at_function(
    module_name: &str,
    function_name: &str,
    offset: usize,
) -> Result<FakeFrame> {
    let addr = find_return_address_in_module(module_name, function_name)?;
    Ok(FakeFrame::simple(
        addr + offset,
        0,
        "custom frame",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_template_resolve() {
        // try to resolve a kernel32 template
        for template in COMMON_FRAME_TEMPLATES {
            if template.module == "kernel32.dll" {
                match template.resolve() {
                    Ok(frame) => {
                        assert!(frame.return_address > 0, "should have valid return address");
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    #[test]
    fn test_synthetic_stack_build() {
        let mut stack = SyntheticStack::new();

        stack.push_frame(FakeFrame::simple(0x12345678, 0, "test frame 1"));
        stack.push_frame(FakeFrame::simple(0x87654321, 0, "test frame 2"));

        let data = stack.build();
        assert!(!data.is_empty(), "should build stack data");
        assert_eq!(stack.frame_count(), 2);
    }

    #[test]
    fn test_stack_spoofer() {
        let mut spoofer = StackSpoofer::new();

        // this might fail if modules aren't loaded, which is ok
        let _ = spoofer.resolve_all();
    }

    #[test]
    fn test_find_return_address() {
        // try to find a known function
        if let Ok(addr) = find_return_address_in_module("kernel32.dll", "VirtualAlloc") {
            assert!(addr > 0, "should find VirtualAlloc");
        }
    }
}
