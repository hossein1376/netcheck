// macOS meter. One snapshot per second of cumulative socket counters.
// Frame layout matches src/frame.rs. Do not add padding.

#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef void *NStatSourceRef;
typedef void *NStatManagerRef;

extern NStatManagerRef NStatManagerCreate(CFAllocatorRef, dispatch_queue_t,
                                          void (^)(NStatSourceRef, void *));
extern void NStatManagerSetFlags(NStatManagerRef, int);
extern int NStatManagerAddAllTCPWithFilter(NStatManagerRef, uint64_t, uint64_t);
extern int NStatManagerAddAllUDPWithFilter(NStatManagerRef, uint64_t, uint64_t);
extern void NStatSourceSetDescriptionBlock(NStatSourceRef, void (^)(CFDictionaryRef));
extern void NStatSourceSetCountsBlock(NStatSourceRef, void (^)(CFDictionaryRef));
extern void NStatSourceSetRemovedBlock(NStatSourceRef, void (^)(void));
extern void NStatManagerQueryAllSourcesUpdate(NStatManagerRef, void (^)(void));

extern CFStringRef kNStatSrcKeyPID;
extern CFStringRef kNStatSrcKeyProcessName;
extern CFStringRef kNStatSrcKeyRxBytes;
extern CFStringRef kNStatSrcKeyTxBytes;
extern CFStringRef kNStatSrcKeyLocal;
extern CFStringRef kNStatSrcKeyRemote;
extern CFStringRef kNStatSrcKeyProvider;

// Our own keys in each merged source dictionary.
static NSString *const kNCNew = @"netcheck.new";
static NSString *const kNCStart = @"netcheck.start";
static NSString *const kNCPath = @"netcheck.path";

// Source id -> merged description and counts. Ids are never reused in a run.
static NSMutableDictionary *g_events;
static NSMutableSet *g_closing;
static uint64_t g_next_id = 0;
// Sources added before the first snapshot existed before the meter started.
static BOOL g_baselined = NO;
static BOOL g_once = NO;

// Record the owning process once, while it is most likely still alive.
static void note_process(NSMutableDictionary *event) {
    if (event[kNCStart] != nil) {
        return;
    }
    pid_t pid = [event[(__bridge NSString *)kNStatSrcKeyPID] intValue];
    if (pid <= 0) {
        return;
    }
    uint64_t start = 0;
    struct proc_bsdinfo info;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) == (int)sizeof(info)) {
        start = info.pbi_start_tvsec;
    }
    NSString *path = @"";
    char buf[PROC_PIDPATHINFO_MAXSIZE];
    int n = proc_pidpath(pid, buf, sizeof(buf));
    if (n > 0) {
        path = [[NSString alloc] initWithBytes:buf length:(NSUInteger)n encoding:NSUTF8StringEncoding] ?: @"";
    }
    event[kNCStart] = @(start);
    event[kNCPath] = path;
}

static void merge_event(NSNumber *key, NSDictionary *update) {
    if (update == nil || key == nil) {
        return;
    }
    @synchronized(g_events) {
        NSMutableDictionary *existing = g_events[key];
        if (existing == nil) {
            // Late update for a source that was already removed.
            return;
        }
        NSString *rx_key = (__bridge NSString *)kNStatSrcKeyRxBytes;
        NSString *tx_key = (__bridge NSString *)kNStatSrcKeyTxBytes;
        unsigned long long old_rx = [existing[rx_key] unsignedLongLongValue];
        unsigned long long old_tx = [existing[tx_key] unsignedLongLongValue];
        [existing addEntriesFromDictionary:update];
        if ([existing[rx_key] unsignedLongLongValue] < old_rx) {
            existing[rx_key] = @(old_rx);
        }
        if ([existing[tx_key] unsignedLongLongValue] < old_tx) {
            existing[tx_key] = @(old_tx);
        }
        note_process(existing);
    }
}

static void append_u16(NSMutableData *data, uint16_t value) {
    uint16_t le = CFSwapInt16HostToLittle(value);
    [data appendBytes:&le length:2];
}

static void append_u32(NSMutableData *data, uint32_t value) {
    uint32_t le = CFSwapInt32HostToLittle(value);
    [data appendBytes:&le length:4];
}

static void append_u64(NSMutableData *data, uint64_t value) {
    uint64_t le = CFSwapInt64HostToLittle(value);
    [data appendBytes:&le length:8];
}

static void append_addr(NSMutableData *data, NSData *addr) {
    uint8_t family = 0;
    uint16_t port = 0;
    uint8_t raw[16] = {0};
    if (addr.length >= sizeof(struct sockaddr)) {
        const struct sockaddr *sa = addr.bytes;
        if (sa->sa_family == AF_INET && addr.length >= sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *in = addr.bytes;
            family = 4;
            port = ntohs(in->sin_port);
            memcpy(raw, &in->sin_addr, 4);
        } else if (sa->sa_family == AF_INET6 && addr.length >= sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *in6 = addr.bytes;
            family = 6;
            port = ntohs(in6->sin6_port);
            memcpy(raw, &in6->sin6_addr, 16);
        }
    }
    [data appendBytes:&family length:1];
    append_u16(data, port);
    [data appendBytes:raw length:16];
}

static int write_msg(NSData *payload) {
    uint32_t len = CFSwapInt32HostToLittle((uint32_t)payload.length);
    if (fwrite(&len, 1, 4, stdout) != 4) {
        return -1;
    }
    if (fwrite(payload.bytes, 1, payload.length, stdout) != payload.length) {
        return -1;
    }
    return 0;
}

static int write_snapshot(void) {
    NSDictionary *rows;
    NSSet *closing;
    @synchronized(g_events) {
        rows = [g_events copy];
        closing = [g_closing copy];
    }

    NSMutableData *start = [NSMutableData dataWithCapacity:9];
    uint8_t kind = 1;
    [start appendBytes:&kind length:1];
    uint8_t zeros[8] = {0};
    [start appendBytes:zeros length:8];
    if (write_msg(start) != 0) {
        return -1;
    }

    uint32_t count = 0;
    for (NSNumber *key in rows) {
        NSDictionary *event = rows[key];
        uint32_t pid = [event[(__bridge NSString *)kNStatSrcKeyPID] unsignedIntValue];
        if (pid == 0) {
            continue;
        }
        NSString *provider = event[(__bridge NSString *)kNStatSrcKeyProvider];
        uint8_t proto = 0;
        if ([provider caseInsensitiveCompare:@"TCP"] == NSOrderedSame) {
            proto = 1;
        } else if ([provider caseInsensitiveCompare:@"UDP"] == NSOrderedSame) {
            proto = 2;
        } else {
            continue;
        }

        NSString *name = event[(__bridge NSString *)kNStatSrcKeyProcessName] ?: @"";
        NSData *utf = [name dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
        uint8_t name_len = (uint8_t)MIN((NSUInteger)64, utf.length);
        uint8_t name_buf[64] = {0};
        if (name_len > 0) {
            memcpy(name_buf, utf.bytes, name_len);
        }

        NSString *path = event[kNCPath] ?: @"";
        NSData *path_utf = [path dataUsingEncoding:NSUTF8StringEncoding] ?: [NSData data];
        uint16_t path_len = (uint16_t)MIN((NSUInteger)PROC_PIDPATHINFO_MAXSIZE, path_utf.length);

        NSMutableData *payload = [NSMutableData dataWithCapacity:144 + path_len];
        uint8_t socket_kind = 2;
        [payload appendBytes:&socket_kind length:1];
        append_u64(payload, key.unsignedLongLongValue);
        uint8_t flags = [event[kNCNew] boolValue] ? 1 : 0;
        [payload appendBytes:&flags length:1];
        append_u32(payload, pid);
        append_u64(payload, [event[kNCStart] unsignedLongLongValue]);
        [payload appendBytes:&proto length:1];
        [payload appendBytes:&name_len length:1];
        [payload appendBytes:name_buf length:64];
        append_addr(payload, event[(__bridge NSString *)kNStatSrcKeyLocal]);
        append_addr(payload, event[(__bridge NSString *)kNStatSrcKeyRemote]);
        append_u64(payload, [event[(__bridge NSString *)kNStatSrcKeyRxBytes] unsignedLongLongValue]);
        append_u64(payload, [event[(__bridge NSString *)kNStatSrcKeyTxBytes] unsignedLongLongValue]);
        append_u16(payload, path_len);
        [payload appendBytes:path_utf.bytes length:path_len];
        if (write_msg(payload) != 0) {
            return -1;
        }
        count++;
    }

    NSMutableData *end = [NSMutableData dataWithCapacity:5];
    uint8_t end_kind = 3;
    [end appendBytes:&end_kind length:1];
    append_u32(end, count);
    if (write_msg(end) != 0 || fflush(stdout) != 0) {
        return -1;
    }
    @synchronized(g_events) {
        for (id key in closing) {
            [g_events removeObjectForKey:key];
            [g_closing removeObject:key];
        }
        g_baselined = YES;
    }
    return (int)count;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--once") == 0) {
                g_once = YES;
            }
        }
        signal(SIGPIPE, SIG_IGN);
        g_events = [NSMutableDictionary dictionary];
        g_closing = [NSMutableSet set];

        dispatch_queue_t queue = dispatch_queue_create("netcheck.nstat", DISPATCH_QUEUE_SERIAL);
        NStatManagerRef manager = NStatManagerCreate(kCFAllocatorDefault, queue,
            ^(NStatSourceRef source, void *unknown) {
                (void)unknown;
                NSNumber *key = @(++g_next_id);
                @synchronized(g_events) {
                    g_events[key] = [NSMutableDictionary dictionaryWithObject:@(g_baselined) forKey:kNCNew];
                }
                NStatSourceSetDescriptionBlock(source, ^(CFDictionaryRef description) {
                    merge_event(key, (__bridge NSDictionary *)description);
                });
                NStatSourceSetCountsBlock(source, ^(CFDictionaryRef counts) {
                    merge_event(key, (__bridge NSDictionary *)counts);
                });
                NStatSourceSetRemovedBlock(source, ^{
                    @synchronized(g_events) {
                        [g_closing addObject:key];
                    }
                });
            });
        if (manager == NULL) {
            fprintf(stderr, "NetworkStatistics manager failed to start\n");
            return 1;
        }
        NStatManagerSetFlags(manager, 0);
        NStatManagerAddAllTCPWithFilter(manager, 0, 0);
        NStatManagerAddAllUDPWithFilter(manager, 0, 0);

        if (fwrite("NC02", 1, 4, stdout) != 4) {
            return 1;
        }
        fflush(stdout);

        __block int ticks = 0;
        dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), NSEC_PER_SEC,
                                  100 * NSEC_PER_MSEC);
        dispatch_source_set_event_handler(timer, ^{
            NStatManagerQueryAllSourcesUpdate(manager, ^{
                ticks += 1;
                int wrote = write_snapshot();
                if (wrote < 0) {
                    _exit(1);
                }
                if (g_once && (wrote > 0 || ticks >= 3)) {
                    _exit(0);
                }
            });
        });
        dispatch_resume(timer);
        dispatch_main();
    }
    return 0;
}
