all: build

build: tracer.skel.h
	gcc -I. -o tracer tracer.c -lbpf

tracer.skel.h: tracer.bpf.o
	bpftool gen skeleton tracer.bpf.o > tracer.skel.h

tracer.bpf.o: tracer.bpf.c vmlinux.h
	clang -g -O2 -target bpf -c tracer.bpf.c -o tracer.bpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f tracer tracer.bpf.o

cleanall: clean
	rm -f tracer.skel.h vmlinux.h