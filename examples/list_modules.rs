//! Example: List all loaded modules
//!
//! Run with: cargo run --example list_modules --features navigation

use wraith::navigation::{ModuleIterator, ModuleListType};
use wraith::structures::Peb;

fn main() {
    println!("Loaded Modules:");
    println!("{:-<80}", "");

    let peb = Peb::current().expect("failed to get PEB");

    for module in
        ModuleIterator::new(&peb, ModuleListType::InLoadOrder).expect("failed to create iterator")
    {
        println!(
            "{:#018x} - {:#010x} | {}",
            module.base(),
            module.size(),
            module.name()
        );
    }
}
