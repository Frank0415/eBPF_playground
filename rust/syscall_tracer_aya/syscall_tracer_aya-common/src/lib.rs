#![no_std]

pub const MAX_PATH_LEN:usize = 512;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MmapEvent {
    pub pid: u32,
    pub addr: u64,
    pub len: u64,
    pub prot: u64,
    pub flags: u64,
    pub fd: u64,
    pub off: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MmapEvent {} 