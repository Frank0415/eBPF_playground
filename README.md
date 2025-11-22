# eBPF-playground

Contains a series of examples to experiment and play with eBPF, in both `C` (`libbpf`) and `Rust` (`libbpf-rs` and `aya`). Each folder contains its own `README.md` with relevant information and instructions.

Run `make` in the root directory to build all examples in C with their binaries in `build/` and `cargo build` in the root directory to build all examples in Rust with their binaries in `target/` (FIX: not working, only building syscall_tracer_libbpf_rs).

# C

Some code or information in this part references [bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial).

# Rust

Some code or information in this part references 

- [libbpf-rs/examples](https://github.com/libbpf/libbpf-rs/blob/master/examples/)
- [aya book](https://aya-rs.dev/book)

# Contributing

This repository uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit messages. Please make sure to follow the convention when contributing.
