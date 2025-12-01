//! Example: Anti-debug techniques
//!
//! This example demonstrates various anti-debug techniques including:
//! - PEB.BeingDebugged flag clearing
//! - NtGlobalFlag debug bits clearing
//! - Heap debug flag clearing
//! - Thread hiding from debugger
//!
//! Run with: cargo run --example antidebug --features "antidebug,syscalls"

use wraith::manipulation::antidebug;

fn main() {
    println!("Anti-Debug Demo");
    println!("===============\n");

    // check initial state
    println!("Initial debug state:");
    print_debug_state();

    // apply anti-debug measures
    println!("\nApplying anti-debug measures...\n");

    // 1. clear PEB flags
    match antidebug::full_peb_cleanup() {
        Ok(()) => println!("[OK] PEB flags cleared (BeingDebugged, NtGlobalFlag)"),
        Err(e) => eprintln!("[FAIL] PEB cleanup: {}", e),
    }

    // 2. clear heap flags
    match antidebug::clear_heap_flags() {
        Ok(()) => println!("[OK] Heap debug flags cleared"),
        Err(e) => eprintln!("[FAIL] Heap cleanup: {}", e),
    }

    // 3. hide current thread from debugger
    // note: this is irreversible and may cause issues if a debugger IS attached
    #[cfg(feature = "syscalls")]
    {
        println!("\nThread hiding (requires syscalls feature):");
        match antidebug::hide_current_thread() {
            Ok(()) => {
                println!("[OK] Current thread hidden from debugger");
                println!("     (debugger will not receive events from this thread)");
            }
            Err(e) => eprintln!("[FAIL] Thread hiding: {}", e),
        }
    }

    #[cfg(not(feature = "syscalls"))]
    {
        println!("\n[SKIP] Thread hiding (syscalls feature not enabled)");
    }

    // check final state
    println!("\nFinal debug state:");
    print_debug_state();

    // demonstrate detection functions
    println!("\n--- Additional Checks ---\n");

    // is_debugger_present combines all checks
    match antidebug::is_debugger_present() {
        Ok(true) => println!("is_debugger_present(): TRUE (some indicator still present)"),
        Ok(false) => println!("is_debugger_present(): FALSE (all indicators cleared)"),
        Err(e) => eprintln!("is_debugger_present(): error - {}", e),
    }

    // get detailed status
    match antidebug::get_debug_status() {
        Ok(status) => {
            println!("\nDetailed status:");
            print!("{}", status);
        }
        Err(e) => eprintln!("get_debug_status(): error - {}", e),
    }

    // show hidden threads
    let hidden = antidebug::get_hidden_threads();
    if !hidden.is_empty() {
        println!("\nHidden thread IDs: {:?}", hidden);
    }
}

fn print_debug_state() {
    // BeingDebugged
    match antidebug::check_being_debugged() {
        Ok(true) => println!("  BeingDebugged: TRUE"),
        Ok(false) => println!("  BeingDebugged: FALSE"),
        Err(e) => println!("  BeingDebugged: error - {}", e),
    }

    // NtGlobalFlag
    match antidebug::check_nt_global_flag() {
        Ok(true) => println!("  NtGlobalFlag debug bits: SET"),
        Ok(false) => println!("  NtGlobalFlag debug bits: CLEAR"),
        Err(e) => println!("  NtGlobalFlag: error - {}", e),
    }

    // Heap flags
    match antidebug::check_heap_flags() {
        Ok(true) => println!("  Heap debug flags: SET"),
        Ok(false) => println!("  Heap debug flags: CLEAR"),
        Err(e) => println!("  Heap flags: error - {}", e),
    }
}
