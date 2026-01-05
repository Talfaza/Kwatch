//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/*
This data will be sent to golang userspace
*/
struct event_t {
  u32 pid;
  u32 ppid;
  u32 uid;
  u64 cgroup_id;
  u8 command[16];
};

/* Force event_t type to be emitted to BTF (needed for bpf2go -type) */
const struct event_t *unused_event_t SEC(".rodata.unused");

/*
Ring Buffer
*/
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

/*
Tracepoint attached to execve (the syscall that runs new program)
*/
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
  struct event_t *e;

  /*
  Get current task struct
  */
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  /*
  Check PID namespace level - containers have level > 0
  Host processes have level 0, so we skip them
  */
  struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
  if (!ns) {
    return 0;
  }

  struct pid_namespace *pid_ns = BPF_CORE_READ(ns, pid_ns_for_children);
  if (!pid_ns) {
    return 0;
  }

  unsigned int ns_level = BPF_CORE_READ(pid_ns, level);
  if (ns_level == 0) {
    return 0; // Skip host processes
  }

  /*
  Reserve space in the Ring Buffer
  */
  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->ppid = BPF_CORE_READ(task, real_parent, tgid);
  e->cgroup_id = bpf_get_current_cgroup_id();

  /*
  Read the filename being executed from execve args
  args[0] is the filename pointer
  */
  const char *filename = (const char *)ctx->args[0];
  bpf_probe_read_user_str(&e->command, sizeof(e->command), filename);

  bpf_ringbuf_submit(e, 0);

  return 0;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";