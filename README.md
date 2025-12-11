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
| **Inline Hooking** | Install detour hooks on functions with automatic trampoline generation (iced-x86 powered) |
| **Instruction Decoding** | Full x86/x64 instruction decoding using iced-x86 for accurate disassembly |
| **Instruction Relocation** | Proper instruction relocation for trampolines, handling all relative addressing modes |
| **IAT Hooking** | Hook imports via Import Address Table modification (per-module) |
| **EAT Hooking** | Hook exports via Export Address Table modification (affects GetProcAddress) |
| **VEH Hooking** | Exception-based hooks using hardware breakpoints or INT3 |
| **VMT Hooking** | Hook C++ virtual functions via vtable modification or shadow VMT |
| **Anti-Debug** | Manipulate PEB.BeingDebugged, NtGlobalFlag, heap flags, hide threads |
| **Remote Process** | Cross-process memory read/write, module enumeration, thread creation, injection |
| **Kernel Driver** | Full kernel driver development support with IOCTL, shared memory, and process operations |
| **KM↔UM Communication** | Usermode client library for interacting with kernel drivers |

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
| Instruction decoding | iced-x86 powered | No | No | No |
| Kernel driver support | Full (IOCTL, MDL, process ops) | No | No | No |
| Zero dependencies* | Yes | Yes | Yes | Yes |

*Core functionality has no required dependencies. Optional `log` and `iced-x86` integration available.

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
inline-hook = ["hooks"]   # Comprehensive hooking with iced-x86 instruction decoding/relocation
antidebug = []            # Anti-debugging techniques
remote = ["syscalls"]     # Cross-process operations and injection

# Kernel mode features
kernel = ["alloc"]        # Kernel driver support (no_std + alloc)
kernel-client = ["std"]   # Usermode client for kernel driver communication

full = ["navigation", "unlink", "manual-map", "syscalls", "spoof", "hooks", "inline-hook", "antidebug", "remote"]
full-with-kernel = ["full", "kernel-client"]  # All features including kernel client
```

Note: The `inline-hook` feature automatically includes `iced-x86` for proper x86/x64 instruction decoding and relocation.

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
    GadgetFinder, GadgetSearch, Register, GadgetPattern,
    StackSpoofer,
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

// Find gadgets with the builder API
let finder = GadgetFinder::new()?;

// Type-safe register-based search
let jmp_gadgets = finder.jmp(Register::Rbx)
    .in_module("ntdll.dll")
    .find()?;

// Pattern-based search with wildcards
let finder = GadgetFinder::new()?;
let any_jmp = finder.pattern("jmp ???")?
    .in_module("ntdll.dll")
    .find()?;

// Find any instruction using a specific register
let finder = GadgetFinder::new()?;
let rbx_gadgets = finder.pattern("??? rbx")?
    .find_in_system_modules()?;

// Get first matching gadget
let finder = GadgetFinder::new()?;
let gadget = finder.ret()
    .in_module("kernel32.dll")
    .find_first()?;

for gadget in jmp_gadgets.iter().take(3) {
    println!("jmp rbx @ {:#x} in {}",
        gadget.address,
        gadget.module_name
    );
}

// Legacy API still works
let finder = GadgetFinder::new()?;
let jmp_gadgets = finder.find_jmp_rbx("ntdll.dll")?;
let ret_gadgets = finder.find_ret("kernel32.dll")?;

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

### IAT Hooking

```rust
use wraith::manipulation::inline_hook::{
    IatHook, enumerate_iat_entries, find_iat_entry, hook_import,
};

// Hook an import in the current module's IAT
let hook = hook_import("kernel32.dll", "CreateFileW", my_detour as usize)?;
let original = hook.original(); // get original function address

// Or hook in a specific module
let hook = IatHook::new("target.exe", "kernel32.dll", "VirtualAlloc", detour)?;

// Hook is restored automatically on drop, or call .leak() to keep it
hook.leak();

// Enumerate all IAT entries in a module
let peb = wraith::Peb::current()?;
let query = wraith::navigation::ModuleQuery::new(&peb);
let module = query.current_module()?;
for entry in enumerate_iat_entries(&module)? {
    println!("{}!{} @ {:#x}",
        entry.dll_name,
        entry.function_name.unwrap_or_default(),
        entry.current_value
    );
}
```

### EAT Hooking

```rust
use wraith::manipulation::inline_hook::{
    EatHook, EatHookBuilder, enumerate_eat_entries, find_eat_entry,
};

// Hook an export in ntdll's EAT
// Note: detour must be within ±2GB of module for RVA encoding
let hook = EatHook::new("ntdll.dll", "NtQueryInformationProcess", my_detour as usize)?;

// Future GetProcAddress calls for this export will return our detour
let original = hook.original();

// Use the builder pattern
let hook = EatHookBuilder::new()
    .module("kernel32.dll")
    .function("GetProcAddress")
    .detour(my_detour as usize)
    .build()?;

// Enumerate exports
let peb = wraith::Peb::current()?;
let query = wraith::navigation::ModuleQuery::new(&peb);
let ntdll = query.ntdll()?;
for entry in enumerate_eat_entries(&ntdll)? {
    if let Some(name) = &entry.function_name {
        println!("{} ordinal={} RVA={:#x}{}",
            name,
            entry.ordinal,
            entry.current_rva,
            if entry.is_forwarded { " (forwarded)" } else { "" }
        );
    }
}
```

### VEH Hooking

```rust
use wraith::manipulation::inline_hook::{
    VehHook, DebugRegister, get_available_debug_register,
    veh_hook_hardware, veh_hook_int3,
};

// Hardware breakpoint hook (uses debug registers, no code modification)
let dr = get_available_debug_register()?; // Dr0-Dr3
let hook = VehHook::hardware(target_addr, my_detour as usize, dr)?;

// Or use convenience function (auto-selects available DR)
let hook = veh_hook_hardware(target_addr, my_detour as usize)?;

// INT3 software breakpoint hook (single byte modification)
let hook = VehHook::int3(target_addr, my_detour as usize)?;
// or: let hook = veh_hook_int3(target_addr, my_detour as usize)?;

// Hooks are restored automatically on drop
```

### VMT Hooking

```rust
use wraith::manipulation::inline_hook::{
    VmtHook, ShadowVmt, VmtHookBuilder,
    get_vtable, get_vtable_entry, estimate_vtable_size,
};

// Direct VMT hook (affects all instances of the class)
let hook = unsafe { VmtHook::new(object_ptr, vtable_index, my_detour as usize)? };
let original: fn() = unsafe { std::mem::transmute(hook.original()) };

// Use builder pattern
let hook = VmtHookBuilder::new()
    .vtable(vtable_address)
    .index(5)
    .detour(my_detour as usize)
    .build()?;

// Shadow VMT for instance-specific hooking (doesn't affect other objects)
let mut shadow = unsafe { ShadowVmt::new(object_ptr as *mut (), vtable_size)? };
shadow.hook(3, my_virtual_func3 as usize)?;
shadow.hook(5, my_virtual_func5 as usize)?;

// Get original functions
let original_func3 = shadow.original(3).unwrap();
let original_func5 = shadow.original(5).unwrap();

// Utility functions
let vtable = unsafe { get_vtable(object_ptr)? };
let func_addr = unsafe { get_vtable_entry(vtable, 0)? };
let vtable_size = unsafe { estimate_vtable_size(vtable, 100) }; // scan up to 100 entries
```

### Instruction Decoding (iced-x86)

```rust
use wraith::manipulation::inline_hook::asm::{
    iced_decoder::{InstructionDecoder, decode_one, find_instruction_boundary},
    iced_relocator::{InstructionRelocator, relocate_one, instruction_needs_relocation},
};

// Create a decoder for the current architecture
let decoder = InstructionDecoder::native();

// Decode a single instruction
let bytes = [0xE9, 0x00, 0x01, 0x00, 0x00]; // jmp +0x100
if let Some(decoded) = decode_one(0x1000, &bytes) {
    println!("Length: {}", decoded.length);
    println!("Is relative: {}", decoded.is_relative);
    println!("Is control flow: {}", decoded.is_control_flow);
    if let Some(target) = decoded.branch_target {
        println!("Branch target: {:#x}", target);
    }
}

// Find instruction boundary for hooking (need at least 5 bytes)
let prologue = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x28];
if let Some(boundary) = find_instruction_boundary(0x1000, &prologue, 5) {
    println!("Safe to overwrite {} bytes", boundary);
}

// Decode all instructions in a function prologue
let instructions = decoder.decode_all(0x1000, &prologue);
for insn in &instructions {
    println!("{:?} ({} bytes)", insn.mnemonic(), insn.length);
}

// Check if instruction needs relocation when moved
if instruction_needs_relocation(&[0xE9, 0x00, 0x00, 0x00, 0x00], 0x1000) {
    println!("JMP rel32 needs relocation");
}

// Relocate instruction from old address to new address
let result = relocate_one(&[0xE9, 0x00, 0x01, 0x00, 0x00], 0x1000, 0x2000);
if result.success {
    println!("Relocated {} bytes -> {} bytes",
        result.original_length, result.new_length);
}

// Relocate a block of instructions
let relocator = InstructionRelocator::native();
match relocator.relocate_block(&prologue, 0x1000, 0x2000) {
    Ok(relocated_bytes) => {
        println!("Relocated block: {} bytes", relocated_bytes.len());
    }
    Err(e) => println!("Relocation failed: {}", e),
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

### Kernel Driver Development

The `kernel` feature provides full support for Windows kernel driver development:

```rust
#![no_std]
#![no_main]

extern crate alloc;

use wraith::km::{
    Driver, Device, DeviceBuilder, DeviceType,
    Irp, IrpMajorFunction, IoctlDispatcher,
    KmProcess, KernelMemory, PhysicalMemory,
    PoolAllocator, PoolType, SpinLock,
    UnicodeString,
};
use wraith::km::error::{KmResult, status};
use wraith::km::ioctl::{Ioctl, IoctlCode, codes};
use wraith::driver_entry;

// Define your driver implementation
struct MyDriver;

impl wraith::km::driver::DriverImpl for MyDriver {
    fn init(driver: &mut Driver, _registry_path: &UnicodeString) -> KmResult<()> {
        // Create device
        let device_name = UnicodeString::from_str("\\Device\\MyDriver")?;
        let link_name = UnicodeString::from_str("\\DosDevices\\MyDriver")?;

        let mut device = DeviceBuilder::new(driver)
            .name(device_name)
            .symbolic_link(link_name)
            .device_type(DeviceType::Unknown)
            .buffered_io()
            .build()?;

        Ok(())
    }

    fn unload(_driver: &Driver) {
        // Cleanup
    }

    fn device_control(_device: *mut core::ffi::c_void, irp: &mut Irp) -> i32 {
        let Some(ioctl) = Ioctl::from_irp(irp) else {
            return status::STATUS_INVALID_PARAMETER;
        };

        match ioctl.function() {
            0x800 => {
                // Handle read memory request
                if let Some(req) = ioctl.input::<ReadMemoryRequest>() {
                    let mut proc = KmProcess::open(req.process_id)?;
                    let data = proc.read_bytes(req.address, req.size as usize)?;
                    // Copy to output buffer...
                }
                status::STATUS_SUCCESS
            }
            _ => status::STATUS_INVALID_DEVICE_REQUEST,
        }
    }
}

// Generate driver entry point
driver_entry!(MyDriver);
```

#### Kernel Memory Operations

```rust
use wraith::km::memory::{PhysicalMemory, KernelMemory, Mdl, VirtualMemory};
use wraith::km::allocator::{PoolAllocator, PoolType, PoolBuffer};

// Pool allocation
let allocator = PoolAllocator::non_paged();
let ptr = allocator.allocate(4096)?;
// ... use memory
unsafe { allocator.free(ptr) };

// Or use RAII wrapper
let buffer = PoolBuffer::zeroed(4096, PoolType::NonPagedNx)?;
buffer.as_mut_slice()[0..4].copy_from_slice(&[1, 2, 3, 4]);

// Physical memory access
let mut data = [0u8; 16];
PhysicalMemory::read(0x1000, &mut data)?;
PhysicalMemory::write(0x1000, &data)?;

// Get physical address for virtual
let phys = PhysicalMemory::get_physical_address(virtual_ptr);

// MDL operations
let mut mdl = Mdl::create(buffer_ptr, size)?;
mdl.lock_pages(AccessMode::KernelMode, LockOperation::IoReadAccess)?;
let system_addr = mdl.system_address()?;
```

#### Kernel Process Operations

```rust
use wraith::km::process::{KmProcess, Eprocess};

// Open process by PID
let mut proc = KmProcess::open(target_pid)?;

// Read/write process memory
let value: u32 = proc.read(address)?;
proc.write(address, &new_value)?;

// Read bytes
let data = proc.read_bytes(address, size)?;
proc.write_bytes(address, &data)?;

// Allocate memory in target process
let alloc = proc.allocate(0x1000, PAGE_EXECUTE_READWRITE, None)?;

// Get module base
let kernel32_base = proc.get_module_base(&wide_string("kernel32.dll"))?;

// Access EPROCESS directly
let eprocess = proc.eprocess();
let cr3 = eprocess.cr3();
let image_name = eprocess.image_file_name();
```

### Kernel Client (Usermode)

The `kernel-client` feature provides a usermode API to communicate with kernel drivers:

```rust
use wraith::km_client::{DriverClient, ProcessOps, MemoryProtection};

// Connect to driver
let client = DriverClient::connect("\\\\.\\MyDriver")?;

// Open process for memory operations
let process = client.open_process(target_pid)?;

// Read/write memory via driver
let value: u32 = process.read(address)?;
process.write(address, &new_value)?;

// Read bytes
let data = process.read_bytes(address, 256)?;
process.write_bytes(address, &data)?;

// Get module base
let base = process.get_module_base("ntdll.dll")?;

// Allocate memory
let alloc = process.allocate(0x1000, MemoryProtection::READWRITE)?;
process.write_bytes(alloc, &shellcode)?;

// Change protection
let old_prot = process.protect(address, 0x1000, MemoryProtection::EXECUTE_READ)?;

// RAII memory allocation
use wraith::km_client::RemoteMemory;
let mem = RemoteMemory::allocate(&process, 0x1000, MemoryProtection::READWRITE)?;
mem.write(&data)?;
// Automatically freed on drop

// Pattern scanning in remote process
use wraith::km_client::MemoryScanner;
let scanner = MemoryScanner::new(&process);
let matches = scanner.scan_ida_pattern(start, size, "48 8B 05 ?? ?? ?? ??")?;
```

#### Shared Memory Communication

```rust
// Kernel side
use wraith::km::shared::{SharedMemory, SharedBuffer};

let mut shared = SharedMemory::create(0x10000)?;
let user_ptr = shared.map_to_process(process_handle)?;

// Use SharedBuffer for request/response
let buffer = shared.as_mut::<SharedBuffer>().unwrap();
buffer.init();

// Check for requests from usermode
if buffer.has_request() {
    let data = buffer.request_data();
    // Process request...
    buffer.set_response(response_size);
}

// Or use ring buffer for streaming data
use wraith::km::shared::SharedRingBuffer;
let ring = SharedRingBuffer::init(&mut shared)?;
ring.write(&data)?;
let bytes_read = ring.read(&mut buffer)?;
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

## Building Kernel Drivers

To build a kernel driver using wraith-rs:

1. Install the Windows Driver Kit (WDK)
2. Use a kernel-compatible Rust target (e.g., `x86_64-pc-windows-msvc` with custom linker settings)
3. Configure your driver crate:

```toml
[dependencies]
wraith-rs = { version = "0.1", default-features = false, features = ["kernel"] }

[profile.release]
panic = "abort"
lto = true

[lib]
crate-type = ["staticlib"]
```

4. Set up `#![no_std]` and provide a global allocator:

```rust
#![no_std]
#![no_main]

extern crate alloc;

use wraith::km::allocator::KernelAllocator;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
```

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
