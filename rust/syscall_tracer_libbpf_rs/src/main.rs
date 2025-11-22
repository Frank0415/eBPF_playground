use std::mem::MaybeUninit;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use chrono::Local;

mod tracer_rs {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tracer.skel.rs"
    ));
}

#[repr(C)]
struct Event {
    pid: i32,
    com: [u8; 16],
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    off: u64,
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<Event>() {
        eprintln!("Invalid event size");
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const Event) };
    
    // Convert comm to string
    let comm_len = event.com.iter().position(|&c| c == 0).unwrap_or(16);
    let comm = String::from_utf8_lossy(&event.com[..comm_len]);
    
    let now = Local::now();
    
    println!(
        "[{}] PID: {:<7} COMM: {:<16} mmap(addr=0x{:x}, len={}, prot=0x{:x}, flags=0x{:x}, fd={}, off={})",
        now.format("%H:%M:%S"),
        event.pid,
        comm,
        event.addr,
        event.len,
        event.prot,
        event.flags,
        event.fd,
        event.off
    );

    0
}

fn main() {
    let skel_builder = tracer_rs::TracerSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let mut skel = open_skel.load().unwrap();
    skel.attach().unwrap();

    // Build ringbuffer
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.syscall_count_map, handle_event).expect("Failed to add ringbuf");
    let ringbuf = builder.build().expect("Failed to build ringbuf");

    println!("eBPF program loaded and attached. Listening for mmap events... Press Ctrl+C to exit.");

    // Poll ringbuffer for events
    loop {
        ringbuf.poll(std::time::Duration::from_millis(100)).ok();
    }
}
