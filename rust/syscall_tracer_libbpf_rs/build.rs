use libbpf_cargo::SkeletonBuilder;
use std::process::Command;

fn main() {
    // Generate vmlinux.h if it doesn't exist
    if !std::path::Path::new("src/bpf/vmlinux.h").exists() {
        let output = Command::new("bpftool")
            .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .output()
            .expect("Failed to run bpftool");
        std::fs::write("src/bpf/vmlinux.h", output.stdout).expect("Failed to write vmlinux.h");
    }

    SkeletonBuilder::new()
        .source("src/bpf/tracer.bpf.c")
        .build_and_generate("src/bpf/tracer.skel.rs")
        .unwrap();
    println!("cargo:rerun-if-changed=src/bpf/tracer.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/tracer.h");
}