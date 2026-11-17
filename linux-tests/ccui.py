# ccui.py — Claude Code's interactive screen on a pty: start `claude`, answer
# what it asks the terminal, press a few keys, print each screen it drew as
# "ccui| ..." lines (ASCII stand-ins for the box and symbol glyphs). Exits 0
# when a screen came up and changed under the keys.
#
# In the image as /etc/ccui.py (tools/add_rootfs_to_image.sh); cctest.sh runs
# it after the install.

import codecs
import fcntl
import functools
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

ROWS, COLS = 40, 110

# A write per line: each keeps its place among the kernel's own lines.
print = functools.partial(print, flush=True)

ASCII = {
    '─': '-', '━': '-', '═': '-', '│': '|', '┃': '|', '║': '|', '…': '~',
    '·': '.', '•': '*', '❯': '>', '›': '>', '✻': '*', '✓': 'v', '✔': 'v',
    '●': 'o', '○': 'o', '◯': 'o', '⎿': 'L', '→': '>', '←': '<', '↑': '^',
    '↓': 'v', '\xa0': ' ',
}


def plain(ch):
    if ch < '\x7f':
        return ch
    if ch in ASCII:
        return ASCII[ch]
    o = ord(ch)
    if 0x2500 <= o <= 0x257f:
        return '+'
    if 0x2580 <= o <= 0x259f:
        return '#'
    return '?'


class Term:
    """Enough of a terminal to hold the screen a full-screen program draws."""

    def __init__(self, fd):
        self.fd = fd
        self.g = [[' '] * COLS for _ in range(ROWS)]
        self.r = 0
        self.c = 0
        self.saved = (0, 0)
        self.st = 0  # 0 text, 1 ESC, 2 CSI, 3 string, 4 string + ESC, 5 charset
        self.par = ''
        self.osc = ''
        self.dec = codecs.getincrementaldecoder('utf-8')('replace')
        self.nbytes = 0
        self.asked = []

    def reply(self, s):
        try:
            os.write(self.fd, s.encode())
        except OSError:
            pass

    def scroll(self):
        self.g.pop(0)
        self.g.append([' '] * COLS)

    def lf(self):
        if self.r == ROWS - 1:
            self.scroll()
        else:
            self.r += 1

    def put(self, ch):
        if self.c >= COLS:
            self.c = 0
            self.lf()
        self.g[self.r][self.c] = ch
        self.c += 1

    def csi(self, final):
        p = self.par
        body = p.lstrip('?><=')
        if body != p:
            if final in 'nuqc':
                self.asked.append('CSI ' + p + final)
            return
        nums = [int(x) if x.isdigit() else 0 for x in body.split(';')] if body else []
        n = nums[0] if nums and nums[0] else 1
        col = min(self.c, COLS - 1)
        if final == 'A':
            self.r = max(0, self.r - n)
        elif final == 'B':
            self.r = min(ROWS - 1, self.r + n)
        elif final == 'C':
            self.c = min(COLS - 1, self.c + n)
        elif final == 'D':
            self.c = max(0, col - n)
        elif final == 'E':
            self.r = min(ROWS - 1, self.r + n)
            self.c = 0
        elif final == 'F':
            self.r = max(0, self.r - n)
            self.c = 0
        elif final == 'G':
            self.c = min(COLS - 1, n - 1)
        elif final == 'd':
            self.r = min(ROWS - 1, n - 1)
        elif final in 'Hf':
            self.r = min(ROWS - 1, n - 1)
            self.c = min(COLS - 1, (nums[1] if len(nums) > 1 and nums[1] else 1) - 1)
        elif final == 'J':
            m = nums[0] if nums else 0
            if m == 0:
                self.g[self.r][col:] = [' '] * (COLS - col)
                for i in range(self.r + 1, ROWS):
                    self.g[i] = [' '] * COLS
            elif m == 1:
                for i in range(self.r):
                    self.g[i] = [' '] * COLS
                self.g[self.r][:col + 1] = [' '] * (col + 1)
            else:
                self.g = [[' '] * COLS for _ in range(ROWS)]
        elif final == 'K':
            m = nums[0] if nums else 0
            if m == 0:
                self.g[self.r][col:] = [' '] * (COLS - col)
            elif m == 1:
                self.g[self.r][:col + 1] = [' '] * (col + 1)
            else:
                self.g[self.r] = [' '] * COLS
        elif final == 'S':
            for _ in range(n):
                self.scroll()
        elif final == 'n' and nums[:1] == [6]:
            self.asked.append('CSI 6n')
            self.reply('\x1b[%d;%dR' % (self.r + 1, col + 1))
        elif final == 'c':
            self.asked.append('CSI c')
            self.reply('\x1b[?1;2c')
        elif final == 's':
            self.saved = (self.r, self.c)
        elif final == 'u':
            self.r, self.c = self.saved

    def string(self):
        if self.osc.startswith(('10;?', '11;?')):
            self.asked.append('OSC ' + self.osc[:2])
            rgb = 'ffff/ffff/ffff' if self.osc[1] == '0' else '0000/0000/0000'
            self.reply('\x1b]%s;rgb:%s\x1b\\' % (self.osc[:2], rgb))

    def feed(self, data):
        self.nbytes += len(data)
        for ch in self.dec.decode(data):
            st = self.st
            if st == 0:
                if ch == '\x1b':
                    self.st = 1
                elif ch == '\r':
                    self.c = 0
                elif ch == '\n':
                    self.lf()
                elif ch == '\b':
                    self.c = max(0, min(self.c, COLS - 1) - 1)
                elif ch == '\t':
                    self.c = min(COLS - 1, (self.c // 8 + 1) * 8)
                elif ch >= ' ' and ch != '\x7f':
                    self.put(ch)
            elif st == 1:
                self.st = 0
                if ch == '[':
                    self.st = 2
                    self.par = ''
                elif ch in ']P_^X':
                    self.st = 3
                    self.osc = ''
                elif ch in '()*+#%':
                    self.st = 5
                elif ch == '7':
                    self.saved = (self.r, self.c)
                elif ch == '8':
                    self.r, self.c = self.saved
                elif ch == 'M':
                    self.r = max(0, self.r - 1)
                elif ch == 'D':
                    self.lf()
                elif ch == 'E':
                    self.c = 0
                    self.lf()
            elif st == 2:
                if '@' <= ch <= '~':
                    self.st = 0
                    self.csi(ch)
                else:
                    self.par += ch
            elif st == 3:
                if ch == '\x07':
                    self.st = 0
                    self.string()
                elif ch == '\x1b':
                    self.st = 4
                else:
                    self.osc += ch
            elif st == 4:
                self.st = 0
                self.string()
            else:
                self.st = 0

    def lines(self):
        return [''.join(plain(ch) for ch in row).rstrip() for row in self.g]

    def show(self, title):
        print('ccui: screen "%s", %d bytes drawn so far' % (title, self.nbytes))
        blank = True
        for line in self.lines():
            if line:
                print('ccui| ' + line)
                blank = False
            elif not blank:
                print('ccui|')
                blank = True


def pump(t, fd, limit, quiet):
    """Feed `t` what the program writes: up to `limit` s, and once it has
    written, until `quiet` s of silence. False when the pty closed."""
    po = select.poll()
    po.register(fd, select.POLLIN)
    end = time.monotonic() + limit
    last = None
    while True:
        now = time.monotonic()
        if now >= end or (last is not None and now - last >= quiet):
            return True
        if po.poll(200):
            try:
                data = os.read(fd, 65536)
            except OSError:
                return False
            if not data:
                return False
            t.feed(data)
            last = time.monotonic()


def reap(pid, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        p, status = os.waitpid(pid, os.WNOHANG)
        if p:
            return status
        time.sleep(0.2)
    os.kill(pid, signal.SIGKILL)
    return os.waitpid(pid, 0)[1]


def main():
    pid, fd = pty.fork()
    if pid == 0:
        os.environ['TERM'] = 'xterm-256color'
        os.execvp('claude', ['claude'] + sys.argv[1:])
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))
    except OSError as e:
        print('ccui: TIOCSWINSZ: %s' % e)
    t = Term(fd)
    t0 = time.monotonic()
    alive = pump(t, fd, 120, 5)
    first = t.lines()
    print('ccui: first screen after %.1f s' % (time.monotonic() - t0))
    t.show('start')
    changed = False
    for name, keys in (('Down', b'\x1b[B'), ('Enter', b'\r'), ('Down', b'\x1b[B')):
        if not alive:
            break
        before = t.lines()
        os.write(fd, keys)
        alive = pump(t, fd, 30, 4)
        changed = changed or t.lines() != before
        t.show('after ' + name)
    # Ctrl+C twice, close together: the first only asks for the second.
    if alive:
        os.write(fd, b'\x03')
        alive = pump(t, fd, 1, 0.3)
    if alive:
        os.write(fd, b'\x03')
        alive = pump(t, fd, 10, 3)
    status = reap(pid, 15)
    print('ccui: asked the terminal: %s' % (', '.join(sorted(set(t.asked))) or 'nothing'))
    print('ccui: claude left with status 0x%x' % status)
    text = sum(1 for line in first if line.strip())
    if text < 3:
        print('ccui: FAIL the first screen has %d lines of text' % text)
        return 1
    if not changed:
        print('ccui: FAIL the screen did not change under the keys')
        return 1
    print('ccui: OK')
    return 0


sys.exit(main())
