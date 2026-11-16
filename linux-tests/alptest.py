# alptest.py — Alpine's python3 under ZigOS, as Alpine ships it: the
# interpreter, the native modules of its standard library and the libraries
# behind them, threads, processes, files, sockets. A check that holds prints
# nothing; the script ends with "alptest.py: OK" and status 0, or names what
# differed. /etc/alptest.sh runs it.
import os
import sys
import tempfile

fails = 0


def check(name, fn, want):
    """fn() must give want; an exception counts as what it gave."""
    global fails
    try:
        got = fn()
    except BaseException as e:
        got = f"{type(e).__name__}: {e}"
    if got != want:
        print(f"alptest.py: FAIL {name}: got {got!r}, want {want!r}", flush=True)
        fails += 1


# The interpreter and pure modules.
check("version", lambda: sys.version_info[:2], (3, 12))
check("sysname", lambda: os.uname().sysname, "Linux")
check("eval", lambda: sum(i * i for i in range(10)), 285)
check("unicode", lambda: "ёж".upper(), "ЁЖ")


def j():
    import json
    return json.loads(json.dumps({"a": [1, 2, {"b": None}]}))


check("json", j, {"a": [1, 2, {"b": None}]})


def r():
    import re
    return re.findall(r"(\w+)=(\d+)", "x=1 yy=22 z=c")


check("re", r, [("x", "1"), ("yy", "22")])


# Native modules and the shared libraries they need.
def h():
    import hashlib  # libcrypto
    return hashlib.sha256(b"zigos").hexdigest()[:16] + hashlib.md5(b"zigos").hexdigest()[:8]


check("hashlib", h, "384270d489b1402c40ff1fb9")


def z():
    import bz2
    import lzma
    import zlib
    data = b"zigos " * 1000
    ok = zlib.decompress(zlib.compress(data)) == data
    ok = ok and bz2.decompress(bz2.compress(data)) == data
    ok = ok and lzma.decompress(lzma.compress(data)) == data
    return (ok, zlib.crc32(b"zigos"))


check("compress", z, (True, 1436499377))


def dec():
    from decimal import Decimal  # libmpdec
    return str(Decimal("1.1") + Decimal("2.2"))


check("decimal", dec, "3.3")


def sq(path):
    import sqlite3
    db = sqlite3.connect(path)
    db.execute("create table t (n integer)")
    db.executemany("insert into t values (?)", [(i,) for i in range(100)])
    db.commit()
    got = db.execute("select sum(n), count(*) from t").fetchone()
    db.close()
    return got


check("sqlite-mem", lambda: sq(":memory:"), (4950, 100))
tmp = tempfile.mkdtemp(prefix="alptest.")
# A database in a file takes fcntl locks.
check("sqlite-file", lambda: sq(os.path.join(tmp, "t.db")), (4950, 100))


def ct():
    import ctypes  # libffi
    libc = ctypes.CDLL(None)
    n = libc.strlen(b"zigos")
    # A callback: libffi makes a closure in executable memory.
    arr = (ctypes.c_int * 5)(5, 3, 4, 1, 2)
    cmp = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
    libc.qsort(arr, 5, ctypes.sizeof(ctypes.c_int), cmp(lambda a, b: a[0] - b[0]))
    return (n, list(arr))


check("ctypes", ct, (5, [1, 2, 3, 4, 5]))


def ssl_ca():
    import ssl  # libssl
    ctx = ssl.create_default_context()
    ctx.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
    return len(ctx.get_ca_certs()) > 50


check("ssl", ssl_ca, True)
check("urandom", lambda: len(set(os.urandom(64))) > 16, True)


# Threads.
def th():
    import threading
    total = [0]
    lock = threading.Lock()

    def work():
        for _ in range(10000):
            with lock:
                total[0] += 1

    ts = [threading.Thread(target=work) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return total[0]


check("threads", th, 40000)


def pool():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(4) as ex:
        return sum(ex.map(lambda x: x * x, range(100)))


check("threadpool", pool, 328350)


# Processes.
def sub():
    import subprocess
    a = subprocess.run(["echo", "sub"], capture_output=True, text=True).stdout
    b = subprocess.run("echo $((2 + 3))", shell=True, capture_output=True, text=True).stdout
    c = subprocess.run([sys.executable, "-c", "import sys; sys.exit(7)"]).returncode
    return (a, b, c)


check("subprocess", sub, ("sub\n", "5\n", 7))


def pipe_in():
    import subprocess
    p = subprocess.Popen(["tr", "a-z", "A-Z"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate(b"zigos\n" * 2000)
    return (len(out), out[:6], p.returncode)


check("communicate", pipe_in, (12000, b"ZIGOS\n", 0))


def sig():
    import signal
    got = []
    signal.signal(signal.SIGUSR1, lambda n, f: got.append(n))
    os.kill(os.getpid(), signal.SIGUSR1)
    return got


check("signal", sig, [10])


# Files.
def files():
    import shutil
    d = os.path.join(tmp, "tree")
    os.makedirs(os.path.join(d, "a", "b"))
    with open(os.path.join(d, "a", "f.txt"), "w") as f:
        f.write("hello\n" * 100)
    os.symlink("f.txt", os.path.join(d, "a", "link"))
    shutil.copytree(d, d + "2", symlinks=True)
    os.rename(d + "2", d + "3")
    walked = sorted(os.path.relpath(os.path.join(r, n), d + "3") for r, ds, fs in os.walk(d + "3") for n in ds + fs)
    size = os.stat(os.path.join(d + "3", "a", "f.txt")).st_size
    link = os.readlink(os.path.join(d + "3", "a", "link"))
    shutil.rmtree(d + "3")
    return (walked, size, link, os.path.exists(d + "3"))


check("files", files, (["a", "a/b", "a/f.txt", "a/link"], 600, "f.txt", False))


def mm():
    import mmap
    p = os.path.join(tmp, "m")
    with open(p, "wb") as f:
        f.write(b"\0" * 8192)
    with open(p, "r+b") as f:
        m = mmap.mmap(f.fileno(), 8192)
        m[4096:4101] = b"zigos"
        m.flush()
        m.close()
    with open(p, "rb") as f:
        f.seek(4096)
        return f.read(5)


check("mmap", mm, b"zigos")


# Sockets: TCP over loopback with a thread for the server, then asyncio on
# epoll.
def tcp():
    import socket
    import threading
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        data = b""
        while not data.endswith(b"\n"):
            data += c.recv(4096)
        c.sendall(data.upper())
        c.close()

    t = threading.Thread(target=serve)
    t.start()
    cl = socket.create_connection(srv.getsockname())
    cl.sendall(b"over loopback\n")
    got = b""
    while True:
        part = cl.recv(4096)
        if not part:
            break
        got += part
    cl.close()
    t.join()
    srv.close()
    return got


check("tcp", tcp, b"OVER LOOPBACK\n")


def aio():
    import asyncio

    async def main():
        async def echo(reader, writer):
            line = await reader.readline()
            writer.write(line.upper())
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"asyncio\n")
        await writer.drain()
        got = await reader.read()
        writer.close()
        server.close()
        await server.wait_closed()
        await asyncio.sleep(0.05)
        return got

    return asyncio.run(main())


check("asyncio", aio, b"ASYNCIO\n")


def aio2():
    import asyncio

    async def main():
        proc = await asyncio.create_subprocess_exec("echo", "async", stdout=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        return out

    return asyncio.run(main())


check("asyncio-proc", aio2, b"async\n")


def tm():
    import time
    t0 = time.monotonic()
    time.sleep(0.2)
    dt = time.monotonic() - t0
    return 0.18 < dt < 2.0


check("sleep", tm, True)

import shutil

shutil.rmtree(tmp, ignore_errors=True)
if fails == 0:
    print("alptest.py: OK", flush=True)
sys.exit(1 if fails else 0)
