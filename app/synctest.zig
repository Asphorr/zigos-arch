// synctest — exercise libc.Cond / RwLock / Sem / Once in one canonical
// producer/consumer scenario before any real app depends on them.
//
//   Mutex      protects the ring buffer state (head/tail/count)
//   Cond       not_full (producer backpressure) + not_empty (consumer wait)
//   Sem        permits — limits total items "in flight" (rate-limit gate)
//   RwLock     guards stats counters (produced/consumed/checksum)
//   Once       lazily initializes the Sem (proves call-once exclusion)
//
// 3 producers push 10 items each (= 30 total). 2 consumers drain. Each item
// is `producer_id * 1000 + iter`, so the checksum (sum produced minus sum
// consumed) must be exactly zero if every produced item was consumed exactly
// once. Mismatch = lost or duplicated item = primitive bug.

const std = @import("std");
const libc = @import("libc");

const RING_SIZE: u32 = 4;
const MAX_IN_FLIGHT: u32 = 8;
const N_PRODUCERS: u32 = 3;
const N_CONSUMERS: u32 = 2;
const ITEMS_PER_PRODUCER: u32 = 10;
const TOTAL: u32 = N_PRODUCERS * ITEMS_PER_PRODUCER;

const Item = u32;

// --- Ring (Mutex + 2 Conds) ---
var ring: [RING_SIZE]Item = undefined;
var head: u32 = 0;
var tail: u32 = 0;
var count: u32 = 0;
var mu: libc.Mutex = .{};
var not_full: libc.Cond = .{};
var not_empty: libc.Cond = .{};

// --- In-flight rate limit (Sem) ---
var permits: libc.Sem = .{};

// --- Stats (RwLock) ---
var stats_lock: libc.RwLock = .{};
var produced: u32 = 0;
var consumed: u32 = 0;
var checksum: i64 = 0;

// --- Termination ---
var producers_done: u32 = 0;

// --- Once init ---
var init_once: libc.Once = .{};
fn initOnce() void {
    permits.init(MAX_IN_FLIGHT);
    libc.klog("[synctest] Once: permits initialized\n");
}

fn produce(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const id: u32 = @intCast(@intFromPtr(arg));
    init_once.call(&initOnce);

    var i: u32 = 0;
    while (i < ITEMS_PER_PRODUCER) : (i += 1) {
        permits.wait(); // rate limit
        const item: Item = id * 1000 + i;

        mu.lock();
        while (count == RING_SIZE) not_full.wait(&mu);
        ring[tail] = item;
        tail = (tail + 1) % RING_SIZE;
        count += 1;
        not_empty.signal();
        mu.unlock();

        stats_lock.lockExclusive();
        produced += 1;
        checksum += @as(i64, item);
        stats_lock.unlockExclusive();
    }

    // Last producer to finish kicks consumers waiting on an empty ring so
    // they re-check producers_done and exit. Broadcast not signal because
    // multiple consumers may be parked.
    _ = @atomicRmw(u32, &producers_done, .Add, 1, .release);
    not_empty.broadcast();
    return null;
}

fn consume(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = arg;
    init_once.call(&initOnce);

    while (true) {
        mu.lock();
        while (count == 0) {
            if (@atomicLoad(u32, &producers_done, .acquire) == N_PRODUCERS) {
                mu.unlock();
                return null;
            }
            not_empty.wait(&mu);
        }
        const item = ring[head];
        head = (head + 1) % RING_SIZE;
        count -= 1;
        not_full.signal();
        mu.unlock();

        permits.post(); // free a token so producers can keep pushing

        stats_lock.lockExclusive();
        consumed += 1;
        checksum -= @as(i64, item);
        stats_lock.unlockExclusive();
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[synctest] start: 3 producers x 10 items, 2 consumers, ring=4, permits=8\n");

    var prods: [N_PRODUCERS]?*libc.Tcb = .{null} ** N_PRODUCERS;
    var cons: [N_CONSUMERS]?*libc.Tcb = .{null} ** N_CONSUMERS;

    var i: u32 = 0;
    while (i < N_PRODUCERS) : (i += 1) {
        prods[i] = libc.pthreadCreate(produce, @ptrFromInt(@as(usize, i)));
        if (prods[i] == null) {
            libc.print("\x1b[31m[synctest] producer create failed\x1b[0m\n");
            libc.exit();
        }
    }
    i = 0;
    while (i < N_CONSUMERS) : (i += 1) {
        cons[i] = libc.pthreadCreate(consume, null);
        if (cons[i] == null) {
            libc.print("\x1b[31m[synctest] consumer create failed\x1b[0m\n");
            libc.exit();
        }
    }

    i = 0;
    while (i < N_PRODUCERS) : (i += 1) {
        if (prods[i]) |t| _ = libc.pthreadJoin(t);
    }
    i = 0;
    while (i < N_CONSUMERS) : (i += 1) {
        if (cons[i]) |t| _ = libc.pthreadJoin(t);
    }

    stats_lock.lockShared();
    const p = produced;
    const c = consumed;
    const cs = checksum;
    stats_lock.unlockShared();

    var buf: [128]u8 = undefined;
    if (p == TOTAL and c == TOTAL and cs == 0) {
        const out = std.fmt.bufPrint(&buf, "[synctest] OK produced={d} consumed={d} checksum={d}\n", .{ p, c, cs }) catch "OK\n";
        libc.print(out);
        libc.klog(out);
    } else {
        const out = std.fmt.bufPrint(&buf, "\x1b[31m[synctest] FAIL produced={d} consumed={d} checksum={d}\x1b[0m\n", .{ p, c, cs }) catch "FAIL\n";
        libc.print(out);
        libc.klog(out);
    }

    libc.exit();
}
