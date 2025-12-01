//! Example: Manual map a DLL
//!
//! This example demonstrates how to manually map a PE file into memory,
//! bypassing the Windows loader. The resulting "ghost DLL" is invisible
//! to GetModuleHandle and EnumProcessModules.
//!
//! Run with: cargo run --example manual_map --features manual-map -- <dll_path>

use wraith::manipulation::manual_map::{ManualMapper, map_file};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <dll_path>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} C:\\Windows\\System32\\version.dll", args[0]);
        return;
    }

    let dll_path = &args[1];
    println!("Manual mapping: {}", dll_path);
    println!();

    // method 1: step-by-step for full control
    println!("=== Step-by-step mapping ===");

    match ManualMapper::from_file(dll_path) {
        Ok(mapper) => {
            println!("[+] Parsed PE successfully");
            println!("    Is 64-bit: {}", mapper.pe().is_64bit());
            println!("    Preferred base: {:#x}", mapper.pe().preferred_base());
            println!("    Size of image: {:#x}", mapper.pe().size_of_image());
            println!("    Is DLL: {}", mapper.pe().is_dll());
            println!("    Supports ASLR: {}", mapper.pe().supports_aslr());
            println!("    Has relocations: {}", mapper.pe().has_relocations());
            println!("    Has TLS: {}", mapper.pe().has_tls());
            println!();

            // allocate
            let mapper = match mapper.allocate() {
                Ok(m) => {
                    println!("[+] Allocated at: {:#x}", m.base());
                    let delta = m.base() as i64 - m.pe().preferred_base() as i64;
                    println!("    Delta from preferred: {:#x}", delta);
                    m
                }
                Err(e) => {
                    eprintln!("[-] Allocation failed: {}", e);
                    return;
                }
            };

            // map sections
            let mapper = match mapper.map_sections() {
                Ok(m) => {
                    println!("[+] Sections mapped");
                    m
                }
                Err(e) => {
                    eprintln!("[-] Section mapping failed: {}", e);
                    return;
                }
            };

            // relocate
            let mapper = match mapper.relocate() {
                Ok(m) => {
                    println!("[+] Relocations applied");
                    m
                }
                Err(e) => {
                    eprintln!("[-] Relocation failed: {}", e);
                    return;
                }
            };

            // resolve imports
            let mapper = match mapper.resolve_imports() {
                Ok(m) => {
                    println!("[+] Imports resolved");
                    m
                }
                Err(e) => {
                    eprintln!("[-] Import resolution failed: {}", e);
                    // try to continue without imports for demonstration
                    println!("    (continuing without imports)");
                    return;
                }
            };

            // process TLS
            let mapper = match mapper.process_tls() {
                Ok(m) => {
                    println!("[+] TLS processed");
                    m
                }
                Err(e) => {
                    eprintln!("[-] TLS processing failed: {}", e);
                    return;
                }
            };

            // finalize with protections
            let mapper = match mapper.finalize() {
                Ok(m) => {
                    println!("[+] Finalized with correct protections");
                    m
                }
                Err(e) => {
                    eprintln!("[-] Finalization failed: {}", e);
                    return;
                }
            };

            // call entry point
            match mapper.call_entry_point() {
                Ok(true) => println!("[+] DllMain returned TRUE"),
                Ok(false) => println!("[*] DllMain returned FALSE"),
                Err(e) => eprintln!("[-] Entry point failed: {}", e),
            }

            println!();
            println!("=== Mapping complete ===");
            println!("    Base: {:#x}", mapper.base());
            println!("    Size: {:#x}", mapper.size());

            // try to get some exports
            println!();
            println!("=== Looking for exports ===");
            for export_name in &["DllMain", "GetFileVersionInfoA", "GetFileVersionInfoW"] {
                match mapper.get_export(export_name) {
                    Ok(addr) => println!("    {}: {:#x}", export_name, addr),
                    Err(_) => {}
                }
            }

            // cleanup
            println!();
            println!("=== Cleanup ===");
            if let Err(e) = mapper.unmap() {
                eprintln!("[-] Unmap failed: {}", e);
            } else {
                println!("[+] Memory freed");
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to parse PE: {}", e);
        }
    }

    // method 2: convenience function
    println!();
    println!("=== Using convenience function ===");
    match map_file(dll_path) {
        Ok(mapper) => {
            println!("[+] Mapped successfully at {:#x}", mapper.base());
            if let Err(e) = mapper.unmap() {
                eprintln!("[-] Unmap failed: {}", e);
            } else {
                println!("[+] Cleanup complete");
            }
        }
        Err(e) => {
            eprintln!("[-] Map failed: {}", e);
        }
    }
}
