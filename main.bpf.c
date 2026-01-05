#include "vmlinux.h"
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

// TODO: Tracepoint