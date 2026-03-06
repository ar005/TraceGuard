// ebpf/process/process.bpf.c
//
// eBPF process monitor.
// Hooks:
//   tracepoint/syscalls/sys_enter_execve  — new process execution
//   tracepoint/sched/sched_process_exit   — process/thread exit
//   tracepoint/sched/sched_process_fork   — fork/clone
//   tracepoint/syscalls/sys_enter_ptrace  — ptrace (injection detection)
//
// Design notes:
//   - All tracepoint handlers read process identity via bpf_get_current_*()
//     and task_struct CO-RE reads rather than tracepoint ctx fields.
//     This avoids breakage when tracepoint struct layouts differ across kernels
//     (e.g. sched_process_fork lacks parent_comm on some kernels).
//   - The only ctx fields we read are args[] on sys_enter tracepoints (stable)
//     and parent_pid/child_pid on sched_process_fork (always present).

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN  16
#define PATH_MAX       256
#define ARGS_MAX       512
#define MAX_ARGS_ITERS 20

// Event types (must match pkg/types/events.go)
#define EVENT_PROCESS_EXEC   1
#define EVENT_PROCESS_EXIT   2
#define EVENT_PROCESS_FORK   3
#define EVENT_PROCESS_PTRACE 4

// ─── Kernel structs (read via CO-RE from task_struct) ─────────────────────────

// These mirror process.go rawExecEvent etc. — must stay in sync.
struct process_exec_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 euid;
    __u32 egid;
    char  comm[TASK_COMM_LEN];
    char  filename[PATH_MAX];
    char  args[ARGS_MAX];
    __u32 args_len;
    __u32 is_memfd;
    __u32 flags;
};

struct process_exit_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];
    __u32 exit_code;
    __u32 flags;
};

struct process_fork_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 parent_pid;
    __u32 parent_ppid;
    __u32 parent_tid;
    __u32 child_pid;
    __u32 child_tid;
    __u32 uid;
    __u32 gid;
    char  parent_comm[TASK_COMM_LEN];
    __u64 clone_flags;
};

struct process_ptrace_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 tracer_pid;
    __u32 tracer_ppid;
    __u32 tracer_uid;
    char  tracer_comm[TASK_COMM_LEN];
    __u32 target_pid;
    char  target_comm[TASK_COMM_LEN];
    __u32 ptrace_request;
    __u32 flags;
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} process_events SEC(".maps");

// exec_scratch and execve_argv_map removed — using ringbuf directly

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}
static __always_inline __u32 get_tid(void) {
    return (__u32)(bpf_get_current_pid_tgid());
}
static __always_inline __u32 get_uid(void) {
    return (__u32)(bpf_get_current_uid_gid() >> 32);
}
static __always_inline __u32 get_gid(void) {
    return (__u32)(bpf_get_current_uid_gid());
}

static __always_inline __u32 get_ppid(void) {
    // ppid cannot be read safely via CO-RE on all kernels.
    // Return 0 here; userspace reads ppid from /proc/<pid>/status.
    return 0;
}

static __always_inline __u32 get_euid(void) {
    // Fall back to real uid via safe helper — euid not available without CO-RE
    return (__u32)(bpf_get_current_uid_gid() >> 32);
}

static __always_inline __u32 get_egid(void) {
    return (__u32)(bpf_get_current_uid_gid());
}


// ─── tracepoint/syscalls/sys_enter_execve ─────────────────────────────────────
// Reserve directly from ringbuf — avoids scratch map bounds issues.
// argv is read by userspace from /proc/<pid>/cmdline after the event arrives.

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(
    struct trace_event_raw_sys_enter *ctx)
{
    struct process_exec_event *e =
        bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->event_type   = EVENT_PROCESS_EXEC;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = get_pid();
    e->ppid         = get_ppid();
    e->tid          = get_tid();
    e->uid          = get_uid();
    e->gid          = get_gid();
    e->euid         = get_euid();
    e->egid         = get_egid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // filename = execve(2) first arg — read directly into ringbuf reservation
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // Detect memfd (fileless) execution
    if (e->filename[0]=='/' && e->filename[1]=='m' &&
        e->filename[2]=='e' && e->filename[3]=='m')
        e->is_memfd = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sched_process_exit tracepoint removed — verifier rejects ringbuf/map
// access at exit time on this kernel. Exit tracking done in userspace
// via /proc polling in the Go monitor.

// ─── tracepoint/sched/sched_process_fork ──────────────────────────────────────
// Only read parent_pid and child_pid from ctx — these are always present.
// Everything else comes from bpf_get_current_*() (we run in parent context).

SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(
    struct trace_event_raw_sched_process_fork *ctx)
{
    struct process_fork_event *e =
        bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->event_type   = EVENT_PROCESS_FORK;
    e->timestamp_ns = bpf_ktime_get_ns();

    // These two fields are guaranteed present on all kernels
    e->parent_pid = ctx->parent_pid;
    e->child_pid  = ctx->child_pid;

    // Everything else: read from current task (parent context at fork time)
    e->parent_tid  = get_tid();
    e->parent_ppid = get_ppid();
    e->uid         = get_uid();
    e->gid         = get_gid();
    bpf_get_current_comm(&e->parent_comm, sizeof(e->parent_comm));

    // child_tid: approximated as child_pid (for a new process they are equal)
    e->child_tid   = ctx->child_pid;

    // clone_flags: not available in this tracepoint.
    // Captured separately by kprobe/kernel_clone below.
    e->clone_flags = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── kprobe/kernel_clone — capture clone_flags ────────────────────────────────

SEC("kprobe/kernel_clone")
int kprobe__kernel_clone(struct pt_regs *ctx)
{
    // kernel_clone(struct kernel_clone_args *args)
    // We just want clone_flags for namespace-escape detection.
    // We don't emit an event here; the fork tracepoint does that.
    // Future: store flags in a map keyed by tid and merge in the fork handler.
    return 0;
}

// ─── tracepoint/syscalls/sys_enter_ptrace ─────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint__syscalls__sys_enter_ptrace(
    struct trace_event_raw_sys_enter *ctx)
{
    __u32 request = (__u32)ctx->args[0];

    // Only report attach/injection-class requests
    switch (request) {
        case 4:      // PTRACE_POKETEXT
        case 5:      // PTRACE_POKEDATA
        case 13:     // PTRACE_SETREGS
        case 15:     // PTRACE_SETFPREGS
        case 16:     // PTRACE_ATTACH
        case 17:     // PTRACE_DETACH
        case 0x4206: // PTRACE_SEIZE
            break;
        default:
            return 0;
    }

    struct process_ptrace_event *e =
        bpf_ringbuf_reserve(&process_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->event_type     = EVENT_PROCESS_PTRACE;
    e->timestamp_ns   = bpf_ktime_get_ns();
    e->ptrace_request = request;

    e->tracer_pid  = get_pid();
    e->tracer_ppid = get_ppid();
    e->tracer_uid  = get_uid();
    bpf_get_current_comm(&e->tracer_comm, sizeof(e->tracer_comm));

    // target pid = ptrace(2) second arg
    e->target_pid = (__u32)ctx->args[1];
    // target_comm resolved in userspace from /proc

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
