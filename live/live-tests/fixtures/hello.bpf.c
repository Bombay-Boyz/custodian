#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// A real, declared BPF_MAP_TYPE_HASH map -- exists purely for the
// userspace typed map API (Custodian.Map) to exercise via
// readMap/writeMap/deleteMap/mapKeys. The tracepoint program below
// doesn't touch it; this fixture is proving the userspace map API
// works against a genuine kernel-created map object, not testing
// kernel<->userspace data flow (a reasonable future enhancement, not
// in this test's scope).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    bpf_printk("custodian: sys_enter_write from PID %d\n", bpf_get_current_pid_tgid() >> 32);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
