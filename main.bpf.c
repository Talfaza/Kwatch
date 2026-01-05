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
  u8 command[16];
};

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
  Reserve space in the Ring Buffer
  If the buffer is full, drop event
  */

  e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    return 0;
  }

  /*
  Get current task struct to find PPID (Parent PID)
  */
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid();
  e->ppid = BPF_CORE_READ(task, real_parent, tgid);

  /*
  Get the command name
  */
  bpf_get_current_comm(&e->command, sizeof(e->command));

  /*
  Send to golang userspace
  */
  bpf_ringbuf_submit(e, 0);

  return 0;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";