use aya::programs::TracePoint;
use aya::maps::RingBuf;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use std::mem;
use syscall_tracer_aya_common::MmapEvent;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/syscall_tracer_aya"
    )))?; // load the pre-compiled rust code into a variable
    match aya_log::EbpfLogger::init(&mut ebpf) { // start to display logger in user space
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        } 
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("syscall_tracer_aya").unwrap().try_into()?; // Convert the main function of the eBPF code into Tracepoint code
    program.load()?; // Load the main program function (the syscall_tracer_aya() function)
    program.attach("syscalls", "sys_enter_mmap")?; // attach to the tracepoint

    // Get the RingBuf map and start reading events
    let mut ringbuf = RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;
    
    // Spawn a task to read from the RingBuf
    tokio::task::spawn(async move {
        loop {
            // Poll the ringbuf for new data
            match ringbuf.next() {
                Some(item) => {
                    let data = item.as_ref();
                    if data.len() >= mem::size_of::<MmapEvent>() {
                        let event: MmapEvent = unsafe {
                            std::ptr::read_unaligned(data.as_ptr() as *const MmapEvent)
                        };
                        
                        println!(
                            "mmap: PID={}, addr=0x{:016x}, len={}, prot=0x{:x}, flags=0x{:x}, fd={}, off={}",
                            event.pid, event.addr, event.len, event.prot, event.flags, event.fd, event.off
                        );
                    }
                }
                None => {
                    // No data available, sleep briefly
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                }
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    println!("Tracing mmap syscalls...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
