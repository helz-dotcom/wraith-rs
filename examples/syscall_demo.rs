//! Example: Direct syscall demonstration
//!
//! This example shows how to enumerate syscalls from ntdll and invoke them
//! directly, bypassing usermode hooks.
//!
//! Run with: cargo run --example syscall_demo --features syscalls

use wraith::manipulation::syscall::{
    get_syscall_table, nt_close, DirectSyscall, IndirectSyscall,
    nt_allocate_virtual_memory, nt_free_virtual_memory, nt_protect_virtual_memory,
    CURRENT_PROCESS, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};

fn main() {
    println!("Syscall Enumeration Demo");
    println!("========================\n");

    // enumerate syscalls
    match get_syscall_table() {
        Ok(table) => {
            println!("Enumerated {} syscalls\n", table.len());

            // show some common syscalls
            let common = [
                "NtOpenProcess",
                "NtClose",
                "NtReadVirtualMemory",
                "NtWriteVirtualMemory",
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
                "NtSetInformationThread",
                "NtQuerySystemInformation",
            ];

            println!("{:<30} {:>6} {:>18}", "Syscall", "SSN", "Address");
            println!("{:-<60}", "");

            for name in &common {
                if let Some(entry) = table.get(name) {
                    println!(
                        "{:<30} {:>6} {:#18x}",
                        entry.name, entry.ssn, entry.address
                    );
                }
            }

            // test NtClose with invalid handle (should return STATUS_INVALID_HANDLE)
            println!("\n--- Testing NtClose (typed wrapper) ---");
            let invalid_handle = 0xDEADBEEF_usize;
            match nt_close(invalid_handle) {
                Ok(()) => println!("NtClose succeeded (unexpected)"),
                Err(e) => println!("NtClose failed as expected: {}", e),
            }

            // test direct syscall
            println!("\n--- Direct Syscall Test ---");
            if let Some(entry) = table.get("NtClose") {
                let syscall = DirectSyscall::from_entry(entry);
                // SAFETY: calling NtClose with invalid handle is safe (just returns error)
                let status = unsafe { syscall.call1(invalid_handle) };
                println!("Direct syscall NtClose returned: {:#x}", status);
                println!(
                    "Success: {} (STATUS_INVALID_HANDLE expected)",
                    if status == 0xC0000008_u32 as i32 {
                        "YES"
                    } else {
                        "NO"
                    }
                );
            }

            // test indirect syscall
            println!("\n--- Indirect Syscall Test ---");
            if let Some(entry) = table.get("NtClose") {
                if let Ok(syscall) = IndirectSyscall::from_entry(entry) {
                    // SAFETY: calling NtClose with invalid handle is safe
                    let status = unsafe { syscall.call1(invalid_handle) };
                    println!("Indirect syscall NtClose returned: {:#x}", status);
                    println!(
                        "Jumped to syscall instruction at: {:#x}",
                        syscall.syscall_address()
                    );
                } else {
                    println!("Could not create indirect syscall (no syscall address found)");
                }
            }

            // test memory allocation syscall
            println!("\n--- Memory Allocation Test ---");
            match nt_allocate_virtual_memory(
                CURRENT_PROCESS,
                0,
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) {
                Ok((base, size)) => {
                    println!("Allocated {} bytes at {:#x}", size, base);

                    // change protection to RWX
                    match nt_protect_virtual_memory(CURRENT_PROCESS, base, 4096, PAGE_EXECUTE_READWRITE)
                    {
                        Ok(old) => println!("Changed protection from {:#x} to RWX", old),
                        Err(e) => println!("Failed to change protection: {}", e),
                    }

                    // free the memory
                    match nt_free_virtual_memory(CURRENT_PROCESS, base, MEM_RELEASE) {
                        Ok(()) => println!("Memory freed successfully"),
                        Err(e) => println!("Failed to free memory: {}", e),
                    }
                }
                Err(e) => println!("Allocation failed: {}", e),
            }

            // show first 10 syscalls by SSN
            println!("\n--- First 10 Syscalls by SSN ---");
            println!("{:<30} {:>6} {:>18}", "Name", "SSN", "Syscall Addr");
            println!("{:-<60}", "");
            for entry in table.entries().iter().take(10) {
                let syscall_addr = entry
                    .syscall_address
                    .map(|a| format!("{:#x}", a))
                    .unwrap_or_else(|| "N/A".to_string());
                println!("{:<30} {:>6} {:>18}", entry.name, entry.ssn, syscall_addr);
            }
        }
        Err(e) => {
            eprintln!("Failed to enumerate syscalls: {}", e);
        }
    }

    println!("\nDone!");
}
