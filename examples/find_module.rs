//! Example: Find a specific module and get exports
//!
//! Run with: cargo run --example find_module --features navigation

use wraith::navigation::ModuleQuery;
use wraith::structures::Peb;

fn main() {
    let peb = Peb::current().expect("failed to get PEB");
    let query = ModuleQuery::new(&peb);

    // find ntdll
    match query.ntdll() {
        Ok(ntdll) => {
            println!("Found ntdll.dll:");
            println!("  Base: {:#x}", ntdll.base());
            println!("  Size: {:#x}", ntdll.size());
            println!("  Path: {}", ntdll.full_path());

            // get some exports
            if let Ok(addr) = ntdll.get_export("NtOpenProcess") {
                println!("  NtOpenProcess: {:#x}", addr);
            }
            if let Ok(addr) = ntdll.get_export("NtReadVirtualMemory") {
                println!("  NtReadVirtualMemory: {:#x}", addr);
            }
            if let Ok(addr) = ntdll.get_export("NtClose") {
                println!("  NtClose: {:#x}", addr);
            }
        }
        Err(e) => eprintln!("Failed to find ntdll: {}", e),
    }

    println!();

    // find kernel32
    match query.kernel32() {
        Ok(kernel32) => {
            println!("Found kernel32.dll:");
            println!("  Base: {:#x}", kernel32.base());
            println!("  Size: {:#x}", kernel32.size());

            if let Ok(addr) = kernel32.get_export("LoadLibraryA") {
                println!("  LoadLibraryA: {:#x}", addr);
            }
            if let Ok(addr) = kernel32.get_export("GetProcAddress") {
                println!("  GetProcAddress: {:#x}", addr);
            }
        }
        Err(e) => eprintln!("Failed to find kernel32: {}", e),
    }

    println!();

    // find module by address
    let our_addr = main as usize;
    match query.find_by_address(our_addr) {
        Ok(module) => {
            println!("Module containing main(): {}", module.name());
            println!("  Base: {:#x}", module.base());
        }
        Err(e) => eprintln!("Failed to find module: {}", e),
    }
}
