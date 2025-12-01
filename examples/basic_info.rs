//! basic test of Phase 1 functionality

use wraith::arch::segment;
use wraith::structures::{Peb, Teb};
use wraith::util::{hash::djb2_hash, pattern::PatternScanner};
use wraith::version::WindowsVersion;

fn main() {
    println!("=== wraith-rs Phase 1 Test ===\n");

    // test version detection
    println!("[*] Testing Windows version detection...");
    match WindowsVersion::current() {
        Ok(version) => {
            println!("    Version: {}", version);
            println!("    Release: {}", version.release());
            println!("    Is Windows 11: {}", version.is_windows_11());
        }
        Err(e) => {
            println!("    ERROR: {}", e);
            return;
        }
    }

    // test raw segment access
    println!("\n[*] Testing segment register access...");
    unsafe {
        let peb_ptr = segment::get_peb();
        let teb_ptr = segment::get_teb();
        let pid = segment::get_current_pid();
        let tid = segment::get_current_tid();

        println!("    PEB address: {:p}", peb_ptr);
        println!("    TEB address: {:p}", teb_ptr);
        println!("    Process ID:  {}", pid);
        println!("    Thread ID:   {}", tid);
    }

    // test PEB wrapper
    println!("\n[*] Testing PEB wrapper...");
    match Peb::current() {
        Ok(peb) => {
            println!("    PEB pointer:      {:p}", peb.as_ptr());
            println!("    Image base:       {:#x}", peb.image_base());
            println!("    Being debugged:   {}", peb.being_debugged());
            println!("    NtGlobalFlag:     {:#x}", peb.nt_global_flag());
            println!("    Process heap:     {:#x}", peb.process_heap());
            println!("    Num processors:   {}", peb.number_of_processors());

            // test LDR access
            if let Some(ldr) = peb.ldr() {
                println!("    LDR initialized:  {}", ldr.initialized != 0);
            }
        }
        Err(e) => println!("    ERROR: {}", e),
    }

    // test TEB wrapper
    println!("\n[*] Testing TEB wrapper...");
    match Teb::current() {
        Ok(teb) => {
            println!("    TEB pointer:  {:p}", teb.as_ptr());
            println!("    Process ID:   {}", teb.process_id());
            println!("    Thread ID:    {}", teb.thread_id());
            println!("    Stack base:   {:#x}", teb.stack_base());
            println!("    Stack limit:  {:#x}", teb.stack_limit());
            println!("    Last error:   {}", teb.last_error());
        }
        Err(e) => println!("    ERROR: {}", e),
    }

    // test pattern scanner
    println!("\n[*] Testing pattern scanner...");
    let test_data: [u8; 16] = [
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20,
        0x49,
    ];
    let scanner = PatternScanner::new(&test_data);

    match scanner.find("48 89 5C 24 08") {
        Some(offset) => println!("    Pattern '48 89 5C 24 08' found at offset {}", offset),
        None => println!("    Pattern not found (unexpected!)"),
    }

    match scanner.find("48 89 ? ? 08") {
        Some(offset) => println!("    Pattern '48 89 ? ? 08' found at offset {}", offset),
        None => println!("    Wildcard pattern not found (unexpected!)"),
    }

    match scanner.find("FF FF FF") {
        Some(_) => println!("    Pattern 'FF FF FF' found (unexpected!)"),
        None => println!("    Pattern 'FF FF FF' not found (expected)"),
    }

    // test hash functions
    println!("\n[*] Testing hash functions...");
    let ntdll_hash = djb2_hash(b"ntdll.dll");
    let kernel32_hash = djb2_hash(b"kernel32.dll");
    println!("    djb2('ntdll.dll'):    {:#x}", ntdll_hash);
    println!("    djb2('kernel32.dll'): {:#x}", kernel32_hash);

    println!("\n=== All tests completed! ===");
}
