# Fixture

`hello.bpf.c` declares a `BPF_MAP_TYPE_HASH` map named `counters`
(key `__u32`, value `__u64`) and a `sys_enter_write` tracepoint program.

Build it (needs clang with a BPF target) into the object the example and
live tests load:

    clang -O2 -g -target bpf -c hello.bpf.c -o hello.bpf.o

Running the example or the live-spec test then requires `CAP_BPF`
(in practice, root) to load and attach.
