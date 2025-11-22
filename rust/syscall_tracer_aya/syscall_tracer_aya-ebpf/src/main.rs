#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext, helpers::bpf_probe_read_user_str_bytes};
use aya_log_ebpf::info;

use aya_ebpf::maps::RingBuf; //library for the map
use aya_ebpf::macros::map; //library for the macro

use syscall_tracer_aya_common::MmapEvent;

use core::str::from_utf8_unchecked;

/*
struct mmap_params { // gathered from /sys/kernel/tracing/events/syscalls/sys_enter_mmap
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;

	__s32 __syscall_nr;
	__u64 addr;
	__u64 len;
	__u64 prot;
	__u64 flags;
	__u64 fd;
	__u64 off;
};
*/

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn syscall_tracer_aya(ctx: TracePointContext) -> u32 {
    match try_syscall_tracer_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_syscall_tracer_aya(ctx: TracePointContext) -> Result<u32, u32> { 
    // Read the mmap arguments from the tracepoint context based on the format offsets
    let pid: i32 = unsafe { ctx.read_at(4).map_err(|_| 1u32)? };
    let addr: u64 = unsafe { ctx.read_at(16).map_err(|_| 1u32)? };
    let len: u64 = unsafe { ctx.read_at(24).map_err(|_| 1u32)? };
    let prot: u64 = unsafe { ctx.read_at(32).map_err(|_| 1u32)? };
    let flags: u64 = unsafe { ctx.read_at(40).map_err(|_| 1u32)? };
    let fd: u64 = unsafe { ctx.read_at(48).map_err(|_| 1u32)? };
    let off: u64 = unsafe { ctx.read_at(56).map_err(|_| 1u32)? };
    
    // Create an event to store in RingBuf
    let event = MmapEvent {
        pid: pid as u32,
        addr,
        len,
        prot,
        flags,
        fd,
        off,
    };
    
    // Reserve space in the RingBuf and write the event
    if let Some(mut entry) = EVENTS.reserve::<MmapEvent>(0) {
        unsafe {
            core::ptr::write_unaligned(entry.as_mut_ptr() as *mut MmapEvent, event);
        }
        entry.submit(0);
    }
    
    info!(&ctx, "mmap syscall: pid={}, addr=0x{:x}, len={}", pid, addr, len);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
