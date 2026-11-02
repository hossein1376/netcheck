// SPDX-License-Identifier: GPL-2.0
// Linux meter probe. Counts bytes per socket inside the kernel; the daemon
// reads the `flows` map once per snapshot. `struct flow` and `struct process`
// must match src/meter/linux.rs. Do not reorder fields.
//
// Hooks read return values with bpf_get_func_ret, so they keep working when a
// kernel changes these functions' arguments.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define PROTO_TCP 1
#define PROTO_UDP 2

// Only the fields the probe reads. preserve_access_index lets libbpf relocate
// them against the running kernel's BTF, so no vmlinux.h is needed.
struct in6_addr {
    union {
        __u8 u6_addr8[16];
    } in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
    struct sock *sk;
} __attribute__((preserve_access_index));

struct task_struct {
    struct task_struct *group_leader;
    __u64 start_time;
    int tgid;
    char comm[16];
} __attribute__((preserve_access_index));

// The daemon's PID namespace, set before load when the daemon runs in a
// nested one (a container). Zero means the root namespace, where task->tgid
// is already the PID the daemon sees.
const volatile struct {
    __u64 dev;
    __u64 ino;
} pidns = {};

struct flow {
    __u64 rx;
    __u64 tx;
    __u64 start_ns;  // process start, ns since boot (monotonic)
    __u32 tgid;
    __u16 family;
    __u8 proto;
    __u8 closed;
    __u16 lport;  // host order
    __u16 rport;  // host order; 0 when not connected
    __u8 laddr[16];
    __u8 raddr[16];
    char comm[16];
    __u32 ns_tgid;  // PID in the daemon's namespace; 0 when not visible there
};

// A process seen for the first time, so the daemon can read its path while
// it still exists.
struct process {
    __u64 start_ns;
    __u32 tgid;
    __u32 ns_tgid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);  // socket cookie
    __type(value, struct flow);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);  // tgid
    __type(value, __u64);  // start_ns
} seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} processes SEC(".maps");

static __always_inline void fill_addrs(struct sock *sk, struct flow *f) {
    f->family = sk->__sk_common.skc_family;
    f->lport = sk->__sk_common.skc_num;
    f->rport = bpf_ntohs(sk->__sk_common.skc_dport);
    if (f->family == AF_INET) {
        __be32 local = sk->__sk_common.skc_rcv_saddr;
        __be32 remote = sk->__sk_common.skc_daddr;
        __builtin_memcpy(f->laddr, &local, 4);
        __builtin_memcpy(f->raddr, &remote, 4);
    } else if (f->family == AF_INET6) {
        bpf_probe_read_kernel(f->laddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(f->raddr, 16, &sk->__sk_common.skc_v6_daddr);
    }
}

static __always_inline __u32 ns_tgid(void) {
    if (!pidns.ino) {
        return 0;
    }
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(pidns.dev, pidns.ino, &ns, sizeof(ns))) {
        return 0;
    }
    return ns.tgid;
}

static __always_inline void note_process(__u32 tgid, __u32 local_tgid, __u64 start_ns) {
    __u64 *known = bpf_map_lookup_elem(&seen, &tgid);
    if (known && *known == start_ns) {
        return;
    }
    bpf_map_update_elem(&seen, &tgid, &start_ns, BPF_ANY);
    struct process *event = bpf_ringbuf_reserve(&processes, sizeof(*event), 0);
    if (!event) {
        return;
    }
    event->tgid = tgid;
    event->ns_tgid = local_tgid;
    event->start_ns = start_ns;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline void count(struct sock *sk, __u8 proto, __s64 rx, __s64 tx) {
    if (!sk || (rx <= 0 && tx <= 0)) {
        return;
    }
    __u64 cookie = bpf_get_socket_cookie(sk);
    struct flow *f = bpf_map_lookup_elem(&flows, &cookie);
    if (!f) {
        struct task_struct *task = bpf_get_current_task_btf();
        struct task_struct *leader = task->group_leader;
        struct flow fresh = {};
        fresh.tgid = task->tgid;
        fresh.ns_tgid = ns_tgid();
        fresh.start_ns = leader->start_time;
        fresh.proto = proto;
        // The process name, not the thread's ("Socket Thread" and the like).
        bpf_probe_read_kernel_str(fresh.comm, sizeof(fresh.comm), leader->comm);
        fill_addrs(sk, &fresh);
        bpf_map_update_elem(&flows, &cookie, &fresh, BPF_NOEXIST);
        f = bpf_map_lookup_elem(&flows, &cookie);
        if (!f) {
            return;
        }
        note_process(fresh.tgid, fresh.ns_tgid, fresh.start_ns);
    } else if (f->rport == 0) {
        // Connected after its first byte (or a UDP socket that connected later).
        fill_addrs(sk, f);
    }
    if (rx > 0) {
        __sync_fetch_and_add(&f->rx, rx);
    }
    if (tx > 0) {
        __sync_fetch_and_add(&f->tx, tx);
    }
}

// Every hooked function returns int: narrow before widening, or -EAGAIN from
// a non-blocking read turns into four billion bytes.
static __always_inline __s64 returned(void *ctx) {
    __u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    return (__s64)(int)ret;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sent, struct sock *sk) {
    count(sk, PROTO_TCP, 0, returned(ctx));
    return 0;
}

SEC("fexit/tcp_recvmsg")
int BPF_PROG(tcp_received, struct sock *sk) {
    count(sk, PROTO_TCP, returned(ctx), 0);
    return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(udp_sent, struct sock *sk) {
    count(sk, PROTO_UDP, 0, returned(ctx));
    return 0;
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(udp_received, struct sock *sk) {
    count(sk, PROTO_UDP, returned(ctx), 0);
    return 0;
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(udp6_sent, struct sock *sk) {
    count(sk, PROTO_UDP, 0, returned(ctx));
    return 0;
}

SEC("fexit/udpv6_recvmsg")
int BPF_PROG(udp6_received, struct sock *sk) {
    count(sk, PROTO_UDP, returned(ctx), 0);
    return 0;
}

// inet6_release calls inet_release, so this sees IPv4 and IPv6 sockets once.
SEC("fentry/inet_release")
int BPF_PROG(released, struct socket *sock) {
    struct sock *sk = sock->sk;
    if (!sk) {
        return 0;
    }
    __u64 cookie = bpf_get_socket_cookie(sk);
    struct flow *f = bpf_map_lookup_elem(&flows, &cookie);
    if (f) {
        f->closed = 1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
