//! Export structures

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,                     // RVA to DLL name
    pub base: u32,                     // ordinal base
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,     // RVA to EAT
    pub address_of_names: u32,         // RVA to name pointers
    pub address_of_name_ordinals: u32, // RVA to ordinal array
}
