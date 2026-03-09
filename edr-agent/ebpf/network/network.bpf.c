// ebpf/network/network.bpf.c
//
// eBPF program for per-process network connection monitoring.
//
// Hooks:
//   - fentry/tcp_connect            → outbound TCP SYN sent
//   - fexit/tcp_connect             → outbound TCP after local port assigned
//   - fexit/inet_csk_accept         → inbound TCP accepted
//   - tracepoint/sock/inet_sock_set_state → TCP state transitions
//   - fentry/tcp_close              → TCP socket closed (with byte counters)
//   - kprobe/udp_sendmsg            → UDP send
//   - kprobe/udp_recvmsg            → UDP receive
//
// inet_sock layout note (CO-RE):
//   dst IP/port live in sock_common (__sk_common):
//     skc_daddr   = dst IPv4
//     skc_dport   = dst port  (network byte order)
//     skc_addrpair / skc_portpair on some kernels
//   src IP/port live in inet_sock directly:
//     inet_saddr  = src IPv4
//     inet_sport  = src port (network byte order)
//   IPv6 addresses:
//     skc_v6_rcv_saddr = src IPv6
//     skc_v6_daddr     = dst IPv6

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ─── Constants ────────────────────────────────────────────────────────────────

#define TASK_COMM_LEN  16
#define AF_INET        2
#define AF_INET6       10
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17

// TCP states
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11

// Event types (must match pkg/types/events.go)
#define EVENT_NET_CONNECT   10
#define EVENT_NET_ACCEPT    11
#define EVENT_NET_CLOSE     12
#define EVENT_NET_UDP_SEND  13
#define EVENT_NET_UDP_RECV  14
#define EVENT_NET_STATE     15

// ─── Event structs ────────────────────────────────────────────────────────────

struct net_event_v4 {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    __u32 src_ip;       // host byte order
    __u32 dst_ip;       // host byte order
    __u16 src_port;     // host byte order
    __u16 dst_port;     // host byte order
    __u8  protocol;
    __u8  direction;    // 0=outbound 1=inbound
    __u8  tcp_state;
    __u8  pad;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 sock_cookie;
};

struct net_event_v6 {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    __u8  src_ip[16];
    __u8  dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  direction;
    __u8  tcp_state;
    __u8  pad;
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 sock_cookie;
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} network_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);  // sock_cookie
    __type(value, struct net_event_v4);
} active_conns_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u64);  // sock_cookie
    __type(value, struct net_event_v6);
} active_conns_v6 SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (parent)
        bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

static __always_inline void fill_base_v4(struct net_event_v4 *e,
                                          __u32 event_type,
                                          __u64 cookie)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = event_type;
    e->pid          = get_pid();
    e->ppid         = get_ppid();
    e->uid          = (__u32)(bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->sock_cookie  = cookie;
}

static __always_inline void fill_base_v6(struct net_event_v6 *e,
                                          __u32 event_type,
                                          __u64 cookie)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = event_type;
    e->pid          = get_pid();
    e->ppid         = get_ppid();
    e->uid          = (__u32)(bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->sock_cookie  = cookie;
}

// Read IPv4 addresses from sock.
// src (local)  → inet_sock.inet_saddr / inet_sock.inet_sport
// dst (remote) → sock.__sk_common.skc_daddr / skc_dport
static __always_inline void read_sock_v4(struct sock *sk,
                                          __u32 *src_ip, __u16 *src_port,
                                          __u32 *dst_ip, __u16 *dst_port)
{
    struct inet_sock *inet = (struct inet_sock *)sk;

    // src: fields directly on inet_sock
    __be32 saddr = 0;
    __be16 sport = 0;
    bpf_core_read(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_core_read(&sport, sizeof(sport), &inet->inet_sport);

    // dst: fields live in the embedded sock_common (__sk_common)
    __be32 daddr = 0;
    __be16 dport = 0;
    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    // Convert from network byte order to host byte order
    *src_ip   = bpf_ntohl(saddr);
    *src_port = bpf_ntohs(sport);
    *dst_ip   = bpf_ntohl(daddr);
    *dst_port = bpf_ntohs(dport);
}

// Read IPv6 addresses from sock.
static __always_inline void read_sock_v6(struct sock *sk,
                                          __u8 src_ip[16], __u16 *src_port,
                                          __u8 dst_ip[16], __u16 *dst_port)
{
    struct inet_sock *inet = (struct inet_sock *)sk;

    bpf_core_read(src_ip, 16, &sk->__sk_common.skc_v6_rcv_saddr);
    bpf_core_read(dst_ip, 16, &sk->__sk_common.skc_v6_daddr);

    __be16 sport = 0, dport = 0;
    bpf_core_read(&sport, sizeof(sport), &inet->inet_sport);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    *src_port = bpf_ntohs(sport);
    *dst_port = bpf_ntohs(dport);
}

// ─── fentry/tcp_connect ───────────────────────────────────────────────────────

SEC("fentry/tcp_connect")
int BPF_PROG(fentry_tcp_connect, struct sock *sk)
{
    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    __u64 cookie = bpf_get_socket_cookie(sk);

    if (family == AF_INET) {
        struct net_event_v4 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) return 0;
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v4(e, EVENT_NET_CONNECT, cookie);
        read_sock_v4(sk, &e->src_ip, &e->src_port, &e->dst_ip, &e->dst_port);
        e->protocol  = IPPROTO_TCP;
        e->direction = 0;
        e->tcp_state = TCP_SYN_SENT;
        bpf_map_update_elem(&active_conns_v4, &cookie, e, BPF_ANY);
        bpf_ringbuf_submit(e, 0);

    } else if (family == AF_INET6) {
        struct net_event_v6 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) return 0;
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v6(e, EVENT_NET_CONNECT, cookie);
        read_sock_v6(sk, e->src_ip, &e->src_port, e->dst_ip, &e->dst_port);
        e->protocol  = IPPROTO_TCP;
        e->direction = 0;
        e->tcp_state = TCP_SYN_SENT;
        bpf_map_update_elem(&active_conns_v6, &cookie, e, BPF_ANY);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ─── fexit/inet_csk_accept ────────────────────────────────────────────────────

// inet_csk_accept signature changed across kernel versions:
//   < 5.13:  (struct sock *sk, int flags, int *err, bool kern) → ret
//   >= 5.13: (struct sock *sk, int flags, int *err)            → ret
// The 'bool kern' argument was removed in commit 3f66b083c5b7.
// We omit it here to support kernels >= 5.13.  On older kernels this
// fexit will fail to load and the Go monitor falls back to kretprobe.
SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit_inet_csk_accept,
             struct sock *sk, int flags, int *err,
             struct sock *ret)
{
    if (!ret) return 0;

    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &ret->__sk_common.skc_family);

    __u64 cookie = bpf_get_socket_cookie(ret);

    if (family == AF_INET) {
        struct net_event_v4 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) return 0;
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v4(e, EVENT_NET_ACCEPT, cookie);
        read_sock_v4(ret, &e->src_ip, &e->src_port, &e->dst_ip, &e->dst_port);
        e->protocol  = IPPROTO_TCP;
        e->direction = 1;
        e->tcp_state = TCP_ESTABLISHED;
        bpf_map_update_elem(&active_conns_v4, &cookie, e, BPF_ANY);
        bpf_ringbuf_submit(e, 0);

    } else if (family == AF_INET6) {
        struct net_event_v6 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) return 0;
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v6(e, EVENT_NET_ACCEPT, cookie);
        read_sock_v6(ret, e->src_ip, &e->src_port, e->dst_ip, &e->dst_port);
        e->protocol  = IPPROTO_TCP;
        e->direction = 1;
        e->tcp_state = TCP_ESTABLISHED;
        bpf_map_update_elem(&active_conns_v6, &cookie, e, BPF_ANY);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ─── tracepoint/sock/inet_sock_set_state ─────────────────────────────────────
// vmlinux.h already defines trace_event_raw_inet_sock_set_state so we must
// NOT redefine it — use the vmlinux.h definition directly.

SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    int newstate = ctx->newstate;

    if (newstate != TCP_ESTABLISHED &&
        newstate != TCP_CLOSE       &&
        newstate != TCP_CLOSE_WAIT  &&
        newstate != TCP_FIN_WAIT1   &&
        newstate != TCP_TIME_WAIT)
        return 0;

    __u16 family = ctx->family;

    // Use the skaddr pointer as a cookie proxy for matching with active_conns
    __u64 cookie = (__u64)(unsigned long)ctx->skaddr;

    __u32 event_type = (newstate == TCP_CLOSE || newstate == TCP_CLOSE_WAIT)
                        ? EVENT_NET_CLOSE : EVENT_NET_STATE;

    if (family == AF_INET) {
        struct net_event_v4 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) return 0;
        __builtin_memset(e, 0, sizeof(*e));

        e->timestamp_ns = bpf_ktime_get_ns();
        e->event_type   = event_type;
        e->pid          = get_pid();
        e->uid          = (__u32)(bpf_get_current_uid_gid() >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->sock_cookie  = cookie;
        e->protocol     = IPPROTO_TCP;
        e->tcp_state    = (__u8)newstate;

        // Read addresses directly from tracepoint ctx (already host byte order)
        __builtin_memcpy(&e->src_ip, ctx->saddr, 4);
        __builtin_memcpy(&e->dst_ip, ctx->daddr, 4);
        e->src_ip   = bpf_ntohl(e->src_ip);
        e->dst_ip   = bpf_ntohl(e->dst_ip);
        e->src_port = ctx->sport;
        e->dst_port = ctx->dport;

        if (event_type == EVENT_NET_CLOSE) {
            struct net_event_v4 *cached =
                bpf_map_lookup_elem(&active_conns_v4, &cookie);
            if (cached) {
                e->bytes_sent = cached->bytes_sent;
                e->bytes_recv = cached->bytes_recv;
                bpf_map_delete_elem(&active_conns_v4, &cookie);
            }
        }
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ─── fentry/tcp_close ────────────────────────────────────────────────────────

SEC("fentry/tcp_close")
int BPF_PROG(fentry_tcp_close, struct sock *sk, long timeout)
{
    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    __u64 cookie = bpf_get_socket_cookie(sk);

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u64 bytes_sent = 0, bytes_recv = 0;
    bpf_core_read(&bytes_sent, sizeof(bytes_sent), &tp->bytes_sent);
    bpf_core_read(&bytes_recv, sizeof(bytes_recv), &tp->bytes_received);

    if (family == AF_INET) {
        struct net_event_v4 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) { bpf_map_delete_elem(&active_conns_v4, &cookie); return 0; }
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v4(e, EVENT_NET_CLOSE, cookie);
        read_sock_v4(sk, &e->src_ip, &e->src_port, &e->dst_ip, &e->dst_port);
        e->protocol   = IPPROTO_TCP;
        e->tcp_state  = TCP_CLOSE;
        e->bytes_sent = bytes_sent;
        e->bytes_recv = bytes_recv;
        bpf_map_delete_elem(&active_conns_v4, &cookie);
        bpf_ringbuf_submit(e, 0);

    } else if (family == AF_INET6) {
        struct net_event_v6 *e =
            bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
        if (!e) { bpf_map_delete_elem(&active_conns_v6, &cookie); return 0; }
        __builtin_memset(e, 0, sizeof(*e));
        fill_base_v6(e, EVENT_NET_CLOSE, cookie);
        read_sock_v6(sk, e->src_ip, &e->src_port, e->dst_ip, &e->dst_port);
        e->protocol   = IPPROTO_TCP;
        e->tcp_state  = TCP_CLOSE;
        e->bytes_sent = bytes_sent;
        e->bytes_recv = bytes_recv;
        bpf_map_delete_elem(&active_conns_v6, &cookie);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ─── kprobe/udp_sendmsg ───────────────────────────────────────────────────────
// ssize_t udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx)
{
    struct sock   *sk  = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t         len = (size_t)PT_REGS_PARM3(ctx);

    if (!sk) return 0;

    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct net_event_v4 *e =
        bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_NET_UDP_SEND;
    e->pid          = get_pid();
    e->ppid         = get_ppid();
    e->uid          = (__u32)(bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->protocol     = IPPROTO_UDP;
    e->direction    = 0;
    e->bytes_sent   = len;
    e->sock_cookie  = bpf_get_socket_cookie(sk);

    // Try to get dst from msghdr->msg_name (unconnected UDP)
    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    if (msg_name) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), msg_name);
        e->dst_ip   = bpf_ntohl(sin.sin_addr.s_addr);
        e->dst_port = bpf_ntohs(sin.sin_port);
    }

    // src always from socket
    struct inet_sock *inet = (struct inet_sock *)sk;
    __be32 saddr = 0; __be16 sport = 0;
    bpf_core_read(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_core_read(&sport, sizeof(sport), &inet->inet_sport);
    e->src_ip   = bpf_ntohl(saddr);
    e->src_port = bpf_ntohs(sport);

    // If no msg_name (connected UDP), fill dst from sk
    if (!msg_name) {
        __be32 daddr = 0; __be16 dport = 0;
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        e->dst_ip   = bpf_ntohl(daddr);
        e->dst_port = bpf_ntohs(dport);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─── kprobe/udp_recvmsg ───────────────────────────────────────────────────────

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct net_event_v4 *e =
        bpf_ringbuf_reserve(&network_events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_NET_UDP_RECV;
    e->pid          = get_pid();
    e->uid          = (__u32)(bpf_get_current_uid_gid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->protocol     = IPPROTO_UDP;
    e->direction    = 1;
    e->sock_cookie  = bpf_get_socket_cookie(sk);

    struct inet_sock *inet = (struct inet_sock *)sk;
    __be32 saddr = 0; __be16 sport = 0;
    __be32 daddr = 0; __be16 dport = 0;
    bpf_core_read(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_core_read(&sport, sizeof(sport), &inet->inet_sport);
    bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    e->src_ip   = bpf_ntohl(saddr);
    e->src_port = bpf_ntohs(sport);
    e->dst_ip   = bpf_ntohl(daddr);
    e->dst_port = bpf_ntohs(dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
