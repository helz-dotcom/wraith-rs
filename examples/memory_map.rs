//! Example: Display process memory map
//!
//! Run with: cargo run --example memory_map --features navigation

use wraith::navigation::{MemoryRegionIterator, MemoryState, MemoryType};

fn main() {
    println!("Process Memory Map:");
    println!("{:-<100}", "");
    println!(
        "{:>18} {:>12} {:>10} {:>10} {:>10}",
        "Address", "Size", "State", "Protect", "Type"
    );
    println!("{:-<100}", "");

    for region in MemoryRegionIterator::new() {
        if region.state == MemoryState::Free {
            continue; // skip free regions
        }

        let state_str = match region.state {
            MemoryState::Commit => "Commit",
            MemoryState::Reserve => "Reserve",
            MemoryState::Free => "Free",
        };

        let type_str = match region.memory_type {
            MemoryType::Image => "Image",
            MemoryType::Mapped => "Mapped",
            MemoryType::Private => "Private",
            MemoryType::Unknown => "Unknown",
        };

        let protect_str = region.protection_string();

        println!(
            "{:#018x} {:>12} {:>10} {:>10} {:>10}",
            region.base_address,
            format_size(region.region_size),
            state_str,
            protect_str,
            type_str
        );
    }
}

fn format_size(size: usize) -> String {
    if size >= 1024 * 1024 {
        format!("{} MB", size / (1024 * 1024))
    } else if size >= 1024 {
        format!("{} KB", size / 1024)
    } else {
        format!("{} B", size)
    }
}
