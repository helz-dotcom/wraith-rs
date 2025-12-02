# wraith-rs

[![Crates.io](https://img.shields.io/crates/v/wraith-rs.svg)](https://crates.io/crates/wraith-rs)
[![Documentation](https://docs.rs/wraith-rs/badge.svg)](https://docs.rs/wraith-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Safe, idiomatic Rust abstractions for Windows process internals and security research.

## What is wraith-rs?

wraith-rs provides high-level APIs for interacting with Windows internals that are typically only accessible through undocumented structures and techniques. It's designed for security researchers, anti-cheat developers, and anyone who needs to understand or manipulate Windows processes at a low level.

```rust
use wraith::{Peb, Teb};
use wraith::navigation::ModuleQuery;

// Access process internals without raw pointers
let peb = Peb::current()?;
let teb = Teb::current()?;

println!("Image base: {:#x}", peb.image_base());
println!("Thread ID: {}", teb.thread_id());

// Find and inspect loaded modules
let query = ModuleQuery::new(&peb);
let ntdll = query.find_by_name("ntdll.dll")?;
let nt_open_process = ntdll.get_export("NtOpenProcess")?;
```

## Features

### Core Navigation
- **PEB/TEB Access**: Safe wrappers around Process/Thread Environment Blocks with version-aware field offsets (Windows 7 through Windows 11 24H2)
- **Module Enumeration**: Iterate loaded modules via all three PEB lists (InLoadOrder, InMemoryOrder, InInitializationOrder)
- **Export Resolution**: Find exported functions by name, ordinal, or hash
- **Memory Region Queries**: Enumerate process memory regions with protection info
- **Thread Enumeration**: List threads in the current process
- **Pattern Scanning**: Scan memory for byte patterns with wildcard support (IDA-style signatures)

### Advanced Manipulation

| Feature | Description |
|---------|-------------|
| **Module Unlinking** | Remove modules from PEB lists (hide from `GetModuleHandle`, `EnumProcessModules`) |
| **Manual PE Mapping** | Load DLLs without `LoadLibrary` - invisible to module enumeration |
| **Direct Syscalls** | Invoke syscalls directly via `syscall` instruction, bypassing usermode hooks |
| **Indirect Syscalls** | Jump to ntdll's syscall instruction for cleaner call stacks |
| **Spoofed Syscalls** | Return address spoofing, stack frame synthesis, gadget-based indirection |
| **Hook Detection** | Detect inline hooks (jmp, mov/jmp, push/ret, int3) in loaded modules |
| **Hook Removal** | Restore hooked functions using clean copies from disk |
| **Inline Hooking** | Install detour hooks on functions with automatic trampoline generation |
| **Anti-Debug** | Manipulate PEB.BeingDebugged, NtGlobalFlag, heap flags, hide threads |
| **Remote Process** | Cross-process memory read/write, module enumeration, thread creation, injection |

## Comparison with Other Libraries

| Feature | wraith-rs | ntapi | windows-sys | pelite |
|---------|-----------|-------|-------------|--------|
| PEB/TEB access | Safe wrappers | Raw FFI | Not covered | No |
| Version-aware offsets | Win7-Win11 | Manual | N/A | N/A |
| Module enumeration | Iterator API | Manual | Manual | No |
| Pattern scanning | Module + region scanning | No | No | No |
| Module unlinking | Built-in | Manual | No | No |
| Manual PE mapping | Full pipeline | No | No | Parse only |
| Syscall invocation | Direct + Indirect + Spoofed | No | No | No |
| Hook detection | Pattern + disk comparison | No | No | No |
| Remote process ops | Full (read/write/inject) | Manual | Manual | No |
| Zero dependencies* | Yes | Yes | Yes | Yes |

*Core functionality has no required dependencies. Optional `log` integration available.

### Why not just use ntapi/windows-sys?

Those are FFI bindings - they give you the raw function signatures. wraith-rs builds on top of those concepts to provide:

1. **Safety**: No raw pointer juggling. Bounds checking on PE parsing. Validation on all inputs.
2. **Ergonomics**: Iterator patterns, builder APIs, proper error types.
3. **Portability**: Version-aware offsets mean code works across Windows versions without `#[cfg]` everywhere.
4. **Completeness**: Full workflows (parse PE → allocate → map → relocate → resolve imports → call entry point) not just primitives.

## Installation

```toml
[dependencies]
wraith-rs = "0.1"
```

Or with specific features:

```toml
[dependencies]
wraith-rs = { version = "0.1", features = ["full"] }
```

## Feature Flags

```toml
[features]
default = ["navigation", "unlink"]

navigation = []           # Module/thread enumeration, memory queries
unlink = ["navigation"]   # Module unlinking from PEB lists
manual-map = ["navigation"] # Manual PE mapping (LoadLibrary bypass)
syscalls = ["navigation"]  # Direct/indirect syscall invocation
spoof = ["syscalls"]      # Return address spoofing, gadget finding, stack synthesis
hooks = ["syscalls", "manual-map"] # Hook detection and removal
inline-hook = ["hooks"]   # Inline hooking framework for function interception
antidebug = []            # Anti-debugging techniques
remote = ["syscalls"]     # Cross-process operations and injection

full = ["navigation", "unlink", "manual-map", "syscalls", "spoof", "hooks", "inline-hook", "antidebug", "remote"]
```

## Usage Examples

### Module Enumeration

```rust
use wraith::Peb;
use wraith::navigation::{ModuleIterator, ModuleListType};

let peb = Peb::current()?;

for module in ModuleIterator::new(&peb, ModuleListType::InLoadOrder)? {
    println!("{} @ {:#x} ({} bytes)",
        module.name(),
        module.base(),
        module.size()
    );
}
```

### Pattern Scanning

```rust
use wraith::util::{Scanner, Pattern, find_pattern_in_module};

// Scan a module for an IDA-style pattern
let matches = find_pattern_in_module("ntdll.dll", "48 8B 05 ?? ?? ?? ?? 48 89")?;
for m in &matches {
    println!("Found at {:#x} (offset {:#x})", m.address, m.offset);
}

// Use the Scanner builder for more control
let scanner = Scanner::new("E8 ?? ?? ?? ?? 90")?
    .alignment(1)       // check every byte (default)
    .max_results(100);  // limit results

// Scan a specific module
let peb = wraith::Peb::current()?;
let query = wraith::navigation::ModuleQuery::new(&peb);
let ntdll = query.find_by_name("ntdll.dll")?;
let calls = scanner.scan_module(&ntdll)?;
println!("Found {} CALL instructions", calls.len());

// Scan all executable memory regions
let results = scanner.scan_executable_regions()?;

// Code-style pattern (bytes + mask)
let pattern = Pattern::from_code(
    &[0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00],
    "xxx????"  // x = exact, ? = wildcard
)?;
let scanner = Scanner::from_pattern(pattern);
```

### Direct Syscalls

```rust
use wraith::manipulation::syscall::{SyscallTable, DirectSyscall};

// Enumerate syscalls from ntdll
let table = SyscallTable::enumerate()?;

// Get NtClose
let entry = table.get("NtClose").unwrap();
println!("NtClose SSN: {}", entry.ssn);

// Invoke directly (bypasses any usermode hooks)
let syscall = DirectSyscall::from_entry(entry);
let status = unsafe { syscall.call1(invalid_handle) };
```

### Spoofed Syscalls

```rust
use wraith::manipulation::spoof::{
    SpoofedSyscall, SpoofConfig, SpoofMode,
    GadgetFinder, StackSpoofer,
};

// Create a spoofed syscall with default gadget-based spoofing
let syscall = SpoofedSyscall::new("NtAllocateVirtualMemory")?;

// The syscall will use a jmp gadget from ntdll to make
// the return address appear legitimate
let status = unsafe {
    syscall.call6(
        process_handle,
        &mut base_address as *mut _ as usize,
        0,
        &mut region_size as *mut _ as usize,
        allocation_type,
        protection,
    )
};

// Find gadgets manually for custom use
let finder = GadgetFinder::new()?;
let jmp_gadgets = finder.find_jmp_rbx("ntdll.dll")?;
let ret_gadgets = finder.find_ret("kernel32.dll")?;

for gadget in jmp_gadgets.iter().take(3) {
    println!("jmp rbx @ {:#x} in {}",
        gadget.address(),
        gadget.gadget.module_name
    );
}

// Use different spoof modes
let simple_spoof = SpoofedSyscall::with_config(
    "NtClose",
    SpoofConfig::simple(spoof_address)
)?;

// Stack synthesis for more complex scenarios
let mut spoofer = StackSpoofer::new();
spoofer.resolve_all()?;
let fake_stack = spoofer.build_thread_start_stack()?;
```

### Hook Detection

```rust
use wraith::manipulation::hooks::{HookDetector, scan_for_hooks};

// Scan common system DLLs for hooks
let hooks = scan_for_hooks()?;

for hook in hooks {
    println!("[HOOKED] {}!{} - {}",
        hook.module_name,
        hook.function_name,
        hook.hook_type
    );
    if let Some(dest) = hook.hook_destination {
        println!("  Redirects to: {:#x}", dest);
    }
}
```

### Manual PE Mapping

```rust
use wraith::manipulation::manual_map::ManualMapper;

// Map a DLL without LoadLibrary - invisible to GetModuleHandle
let mapper = ManualMapper::from_file("my.dll")?
    .allocate()?
    .map_sections()?
    .relocate()?
    .resolve_imports()?
    .process_tls()?
    .finalize()?;

// Call DllMain
mapper.call_entry_point()?;

// Get exports from the mapped image
let func = mapper.get_export("MyFunction")?;
```

### Module Unlinking

```rust
use wraith::navigation::ModuleQuery;
use wraith::manipulation::unlink::unlink_module;

let peb = Peb::current()?;
let query = ModuleQuery::new(&peb);
let handle = query.get_module_handle("target.dll")?;

// Remove from all PEB lists
let guard = unlink_module(handle)?;

// Module is now hidden from GetModuleHandle, EnumProcessModules, etc.
// Guard automatically relinks on drop, or call guard.leak() to keep hidden
```

### Anti-Debug

```rust
use wraith::manipulation::antidebug;

// Check current debug status
let status = antidebug::get_debug_status()?;
println!("BeingDebugged: {}", status.being_debugged);
println!("NtGlobalFlag: {:#x}", status.nt_global_flag);

// Clear debug indicators
antidebug::clear_being_debugged()?;
antidebug::clear_nt_global_flag()?;
antidebug::clear_heap_flags()?;

// Hide current thread from debugger
antidebug::hide_current_thread()?;
```

### Remote Process Operations

```rust
use wraith::manipulation::remote::{
    RemoteProcess, ProcessAccess, enumerate_remote_modules,
    inject_shellcode, inject_via_section, create_remote_thread,
};

// Open a process with full access
let proc = RemoteProcess::open(target_pid, ProcessAccess::all())?;

// Read/write memory across process boundaries
let value: u32 = proc.read_value(address)?;
proc.write_value(address, &0xDEADBEEF_u32)?;

// Read strings from remote process
let str = proc.read_string(address, 256)?;
let wstr = proc.read_wstring(address, 256)?;

// Allocate executable memory and write shellcode
let alloc = proc.allocate_rwx(shellcode.len())?;
proc.write(alloc.base(), &shellcode)?;

// Create remote thread to execute
let thread = create_remote_thread(&proc, alloc.base(), 0, Default::default())?;
thread.wait_infinite()?;

// Enumerate modules in remote process
let modules = enumerate_remote_modules(&proc)?;
for module in &modules {
    println!("{} @ {:#x}", module.name, module.base);
}

// Injection methods
let result = inject_shellcode(&proc, &shellcode)?;  // CreateRemoteThread
let result = inject_via_section(&proc, &data, true)?;  // NtMapViewOfSection
```

## Windows Version Support

wraith-rs uses version-specific offset tables for accurate structure access:

| Windows Version | Build | Status |
|-----------------|-------|--------|
| Windows 7 SP1 | 7601 | Supported |
| Windows 8.1 | 9600 | Supported |
| Windows 10 (1507-22H2) | 10240-19045 | Supported |
| Windows 11 21H2 | 22000 | Supported |
| Windows 11 22H2 | 22621 | Supported |
| Windows 11 23H2 | 22631 | Supported |
| Windows 11 24H2 | 26100 | Supported |

Unknown versions fall back to Windows 10 offsets with a warning.

## Architecture Support

- **x86_64**: Full support
- **x86 (32-bit)**: Supported for most features
- **ARM64**: Not currently supported

## Safety

wraith-rs uses `#![deny(unsafe_op_in_unsafe_fn)]` and documents all safety invariants. The library is designed to be safe against:

- **Malformed PE files**: Bounds checking on all RVAs and array accesses
- **Corrupted PEB lists**: Iteration limits and null checks prevent infinite loops
- **Invalid syscall addresses**: Validation that target contains actual syscall instruction
- **Buffer overflows**: String reads are bounded, no unbounded loops

However, many operations are inherently unsafe at the OS level (modifying PEB, invoking syscalls, mapping executable code). The library makes these as safe as possible but cannot prevent all misuse.

## Intended Use

This library is designed for:

- Security research and authorized penetration testing
- Anti-cheat and anti-tamper development
- EDR/AV development and testing
- Malware analysis and reverse engineering
- Educational purposes

**Users are responsible for ensuring they have proper authorization before using these techniques on any system or software.**

## Contributing

Contributions are welcome! Please ensure:

1. Code compiles with `cargo build --all-features`
2. Tests pass with `cargo test --all-features`
3. No new clippy warnings
4. Unsafe code has `// SAFETY:` comments explaining invariants

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*wraith-rs is not affiliated with Microsoft. Windows is a trademark of Microsoft Corporation.*
