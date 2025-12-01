//! Example: Detect hooks in system DLLs
//!
//! This example scans ntdll.dll, kernel32.dll, and kernelbase.dll
//! for inline hooks commonly placed by EDR/AV software.
//!
//! Run with: cargo run --example detect_hooks --features hooks

use wraith::manipulation::hooks::{scan_for_hooks, HookDetector, HookType};
use wraith::navigation::ModuleQuery;
use wraith::structures::Peb;

fn main() {
    println!("Hook Detection Demo");
    println!("===================\n");

    // scan all common system DLLs
    println!("Scanning ntdll.dll, kernel32.dll, kernelbase.dll for hooks...\n");

    match scan_for_hooks() {
        Ok(hooks) => {
            if hooks.is_empty() {
                println!("No hooks detected!");
                println!("\nThis could mean:");
                println!("  - No EDR/AV is hooking these DLLs");
                println!("  - Hooks are using patterns not detected");
                println!("  - You're running in a clean environment");
            } else {
                println!("Detected {} hook(s):\n", hooks.len());

                for (i, hook) in hooks.iter().enumerate() {
                    println!("{}. {}", i + 1, hook.function_name);
                    println!("   Module: {}", hook.module_name);
                    println!("   Address: {:#x}", hook.function_address);
                    println!("   Type: {}", hook.hook_type);

                    if let Some(dest) = hook.hook_destination {
                        println!("   Destination: {:#x}", dest);

                        // try to identify what module owns the destination
                        if let Ok(peb) = Peb::current() {
                            let query = ModuleQuery::new(&peb);
                            if let Ok(module) = query.find_by_address(dest) {
                                println!("   Destination module: {}", module.name());
                            }
                        }
                    }

                    // show bytes
                    print!("   Hooked bytes: ");
                    for b in hook.hooked_bytes.iter().take(16) {
                        print!("{:02x} ", b);
                    }
                    println!();

                    if !hook.original_bytes.is_empty() {
                        print!("   Original bytes: ");
                        for b in hook.original_bytes.iter().take(16) {
                            print!("{:02x} ", b);
                        }
                        println!();
                    }

                    println!();
                }

                // summary by type
                println!("Summary by hook type:");
                let jmp_count = hooks.iter().filter(|h| h.hook_type == HookType::JmpRel32).count();
                let indirect_count = hooks.iter().filter(|h| h.hook_type == HookType::JmpIndirect).count();
                let mov_jmp_count = hooks.iter().filter(|h| h.hook_type == HookType::MovJmpRax).count();
                let bp_count = hooks.iter().filter(|h| h.hook_type == HookType::Breakpoint).count();
                let unknown_count = hooks.iter().filter(|h| h.hook_type == HookType::Unknown).count();

                if jmp_count > 0 { println!("  - jmp rel32: {}", jmp_count); }
                if indirect_count > 0 { println!("  - jmp indirect: {}", indirect_count); }
                if mov_jmp_count > 0 { println!("  - mov rax; jmp rax: {}", mov_jmp_count); }
                if bp_count > 0 { println!("  - breakpoints: {}", bp_count); }
                if unknown_count > 0 { println!("  - unknown modifications: {}", unknown_count); }
            }
        }
        Err(e) => {
            eprintln!("Failed to scan for hooks: {}", e);
        }
    }

    // also demonstrate checking a specific function
    println!("\n---\n");
    println!("Checking specific functions in ntdll.dll...\n");

    let functions_to_check = [
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtQueryInformationProcess",
        "LdrLoadDll",
    ];

    if let Ok(peb) = Peb::current() {
        let query = ModuleQuery::new(&peb);
        if let Ok(ntdll) = query.find_by_name("ntdll.dll") {
            let detector = match HookDetector::new(&ntdll) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Failed to create detector: {}", e);
                    return;
                }
            };

            for name in &functions_to_check {
                match ntdll.get_export(name) {
                    Ok(addr) => match detector.check_function(name, addr) {
                        Ok(Some(hook)) => {
                            println!("  [HOOKED] {} ({:#x}) - {}", name, addr, hook.hook_type);
                        }
                        Ok(None) => {
                            println!("  [CLEAN]  {} ({:#x})", name, addr);
                        }
                        Err(e) => {
                            println!("  [ERROR]  {} - {}", name, e);
                        }
                    },
                    Err(_) => {
                        println!("  [N/A]    {} - export not found", name);
                    }
                }
            }
        }
    }
}
