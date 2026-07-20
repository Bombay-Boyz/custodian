#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    bpf_printk("custodian: sys_enter_write from PID %d\n", bpf_get_current_pid_tgid() >> 32);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
